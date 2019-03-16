# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import tempfile
import yaml
from socket import getfqdn, socket

from clusterdock.models import Cluster, Node
from clusterdock.utils import wait_for_condition

from . import kerberos_helper

DEFAULT_NAMESPACE = 'clusterdock'
EARLIEST_MAPR_VERSION_WITH_LICENSE_AND_CENTOS_7 = (6, 0, 0)
MAPR_CONFIG_DIR = '/opt/mapr/conf'
MAPR_SERVERTICKET_FILE = 'maprserverticket'
MCS_SERVER_PORT = 8443
SECURE_CONFIG_CONTAINER_DIR = '/etc/clusterdock/secure'
SSL_KEYSTORE_FILES = 'ssl_keystore'
SSL_TRUSTSTORE_FILES = 'ssl_truststore'

SECURE_FILES = [
    MAPR_SERVERTICKET_FILE,
    SSL_KEYSTORE_FILES,
    SSL_TRUSTSTORE_FILES
]


logger = logging.getLogger('clusterdock.{}'.format(__name__))


def main(args):
    if args.license_url and not args.license_credentials:
        raise Exception('--license-credentials is a required argument if --license-url is provided.')

    image_prefix = '{}/{}/clusterdock:mapr{}'.format(args.registry,
                                                     args.namespace or DEFAULT_NAMESPACE,
                                                     args.mapr_version)
    if args.mep_version:
        image_prefix = '{}_mep{}'.format(image_prefix, args.mep_version)
    primary_node_image = '{}_{}'.format(image_prefix, 'primary-node')
    secondary_node_image = '{}_{}'.format(image_prefix, 'secondary-node')

    node_disks = yaml.load(args.node_disks)

    # MapR-FS needs each fileserver node to have a disk allocated for it, so fail fast if the
    # node disks map is missing any nodes.
    if set(args.primary_node + args.secondary_nodes) != set(node_disks):
        raise Exception('Not all nodes are accounted for in the --node-disks dictionary')

    primary_node = Node(hostname=args.primary_node[0],
                        group='primary',
                        image=primary_node_image,
                        ports=[{MCS_SERVER_PORT: MCS_SERVER_PORT}
                               if args.predictable
                               else MCS_SERVER_PORT],
                        devices=node_disks.get(args.primary_node[0]),
                        # Secure cluster needs the ticket to execute rest of commands
                        # after cluster start.
                        environment=['MAPR_TICKETFILE_LOCATION=/opt/mapr/conf/mapruserticket']
                        if args.secure or args.kerberos else [])

    secondary_nodes = [Node(hostname=hostname,
                            group='secondary',
                            image=secondary_node_image,
                            devices=node_disks.get(hostname))
                       for hostname in args.secondary_nodes]

    nodes = [primary_node] + secondary_nodes
    if args.kerberos:
        logger.info('Creating KDC node...')
        kerberos_helper_instance = kerberos_helper.Kerberos_Helper(args.network)
        kerberos_config_host_dir = os.path.realpath(os.path.expanduser(args.clusterdock_config_directory))
        volumes = [{kerberos_config_host_dir: kerberos_helper.KERBEROS_CONFIG_CONTAINER_DIR}]
        for node in nodes:
            node.volumes.extend(volumes)

        kdc_node = Node(hostname=kerberos_helper.KDC_HOSTNAME, group=kerberos_helper.KDC_GROUPNAME,
                        image=kerberos_helper.KDC_IMAGE_NAME, volumes=volumes)

    cluster = Cluster(*nodes + ([kdc_node] if args.kerberos else []))

    if args.secure or args.kerberos:
        secure_config_host_dir = os.path.expanduser(args.secure_config_directory)
        volumes = [{secure_config_host_dir: SECURE_CONFIG_CONTAINER_DIR}]
        for node in cluster.nodes:
            node.volumes.extend(volumes)

    # MapR versions 6.0.0 onwards use CentOS 7 which needs following settings.
    mapr_version_tuple = tuple(int(i) for i in args.mapr_version.split('.'))
    if mapr_version_tuple >= EARLIEST_MAPR_VERSION_WITH_LICENSE_AND_CENTOS_7:
        for node in cluster.nodes:
            node.volumes.append({'/sys/fs/cgroup': '/sys/fs/cgroup'})
            temp_dir_name = tempfile.mkdtemp()
            logger.debug('Created temporary directory %s', temp_dir_name)
            node.volumes.append({temp_dir_name: '/run'})
    cluster.primary_node = primary_node
    cluster.start(args.network, pull_images=args.always_pull)

    # Keep track of whether to suppress DEBUG-level output in commands.
    quiet = not args.verbose

    if args.kerberos:
        cluster.kdc_node = kdc_node
        kerberos_helper_instance.configure_kdc(kdc_node, nodes,
                                               args.kerberos_principals,
                                               args.kerberos_ticket_lifetime,
                                               quiet=quiet)
        if args.kerberos_principals:
            kerberos_helper.create_kerberos_cluster_users(nodes, args.kerberos_principals, quiet=quiet)

    logger.info('Generating new UUIDs ...')
    cluster.execute('/opt/mapr/server/mruuidgen > /opt/mapr/hostid')

    if not (args.secure or args.kerberos):
        logger.info('Configuring the cluster ...')
        for node in cluster:
            configure_command = ('/opt/mapr/server/configure.sh -C {0} -Z {0} -RM {0} -HS {0} '
                                 '-u mapr -g mapr -D {1}'.format(
                                     primary_node.fqdn,
                                     ','.join(node_disks.get(node.hostname))
                                 ))
            node.execute("bash -c '{}'".format(configure_command))
    else:
        logger.info('Configuring native security for the cluster ...')
        configure_command = ('/opt/mapr/server/configure.sh -secure -genkeys -C {0} -Z {0} -RM {0} -HS {0} '
                             '-u mapr -g mapr -D {1}'.format(
                                 primary_node.fqdn,
                                 ','.join(node_disks.get(primary_node.hostname))
                             ))
        source_files = ['{}/{}'.format(MAPR_CONFIG_DIR, file) for file in SECURE_FILES]
        commands = [configure_command,
                    'chmod 600 {}/{}'.format(MAPR_CONFIG_DIR, SSL_KEYSTORE_FILES),
                    'cp -f {src} {dest_dir}'.format(src=' '.join(source_files),
                                                    dest_dir=SECURE_CONFIG_CONTAINER_DIR)]
        primary_node.execute(' && '.join(commands))
        for node in secondary_nodes:
            source_files = ['{}/{}'.format(SECURE_CONFIG_CONTAINER_DIR, file)
                            for file in SECURE_FILES]
            configure_command = ('/opt/mapr/server/configure.sh -secure -C {0} -Z {0} -RM {0} -HS {0} '
                                 '-u mapr -g mapr -D {1}'.format(
                                     primary_node.fqdn,
                                     ','.join(node_disks.get(node.hostname))
                                 ))
            commands = ['cp -f {src} {dest_dir}'.format(src=' '.join(source_files),
                                                        dest_dir=MAPR_CONFIG_DIR),
                        configure_command]
            node.execute(' && '.join(commands))

    logger.info('Waiting for MapR Control System server to come online ...')

    def condition(address, port):
        return socket().connect_ex((address, port)) == 0

    def success(time):
        logger.info('MapR Control System server is online after %s seconds.', time)

    def failure(timeout):
        raise TimeoutError('Timed out after {} seconds waiting '
                           'for MapR Control System server to come online.'.format(timeout))
    wait_for_condition(condition=condition,
                       condition_args=[primary_node.ip_address, MCS_SERVER_PORT],
                       time_between_checks=3, timeout=180, success=success, failure=failure)
    mcs_server_host_port = primary_node.host_ports.get(MCS_SERVER_PORT)

    _configure_after_mcs_server_start(primary_node, secondary_nodes, args, mapr_version_tuple,
                                      kerberos_helper_instance.mapr_principal if args.kerberos else None)

    logger.info('MapR Control System server is now accessible at https://%s:%s',
                getfqdn(), mcs_server_host_port)


def _configure_after_mcs_server_start(primary_node, secondary_nodes, args,
                                      mapr_version_tuple, mapr_principal=None):
    logger.info('Creating /apps/spark directory on %s ...', primary_node.hostname)
    spark_directory_command = ['hadoop fs -mkdir -p /apps/spark',
                               'hadoop fs -chmod 777 /apps/spark']
    primary_node.execute("bash -c '{}'".format('; '.join(spark_directory_command)))

    logger.info('Creating MapR sample Stream named /sample-stream on %s ...', primary_node.hostname)
    primary_node.execute('maprcli stream create -path /sample-stream '
                         '-produceperm p -consumeperm p -topicperm p')

    if mapr_version_tuple >= EARLIEST_MAPR_VERSION_WITH_LICENSE_AND_CENTOS_7 and args.license_url:
        _apply_license(args, primary_node)

    if not args.dont_register_gateway:
        _register_gateway(primary_node)

    if args.secure or args.kerberos:
        primary_node.execute('echo mapr | sudo -u mapr maprlogin password')

    if args.kerberos:
        _kerberize_cluster(primary_node, secondary_nodes, mapr_principal)


def _kerberize_cluster(primary_node, secondary_nodes, mapr_principal):
    commands = ['service mapr-warden stop',
                'service mapr-zookeeper stop',
                ('/opt/mapr/server/configure.sh -K -P {0} -C {1} -Z {1} '
                 .format(mapr_principal, primary_node.fqdn))]
    primary_node.execute(' && '.join(commands))
    for node in secondary_nodes:
        node.execute(commands[2])

    logger.info('After kerberization, waiting for MapR Control System server to come online ...')

    def condition(address, port):
        return socket().connect_ex((address, port)) == 0

    def success(time):
        logger.info('MapR Control System server is online after %s seconds.', time)

    def failure(timeout):
        raise TimeoutError('Timed out after {} seconds waiting '
                           'for MapR Control System server to come online.'.format(timeout))
    wait_for_condition(condition=condition,
                       condition_args=[primary_node.ip_address, MCS_SERVER_PORT],
                       time_between_checks=3, timeout=180, success=success, failure=failure)
    primary_node.execute('kinit -kt {} {}'.format(kerberos_helper.MAPR_CONF_KEYTAB_FILEPATH, mapr_principal))
    primary_node.execute('maprlogin kerberos')


def _apply_license(args, primary_node):
    license_commands = ['curl --user {} {} > /tmp/lic'.format(args.license_credentials,
                                                              args.license_url),
                        '/opt/mapr/bin/maprcli license add -license /tmp/lic -is_file true',
                        'rm -rf /tmp/lic']
    logger.info('Applying license ...')
    primary_node.execute(' && '.join(license_commands))


def _register_gateway(primary_node):
    logger.info('Registering gateway with the cluster ...')
    register_gateway_commands = ["cat /opt/mapr/conf/mapr-clusters.conf | egrep -o '^[^ ]* '"
                                 ' > /tmp/cluster-name',
                                 'maprcli cluster gateway set -dstcluster $(cat '
                                 '/tmp/cluster-name) -gateways {}'.format(primary_node.fqdn),
                                 'rm /tmp/cluster-name']
    primary_node.execute(' && '.join(register_gateway_commands))
