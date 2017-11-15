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
import tempfile
import yaml
from socket import getfqdn, socket

from clusterdock.models import Cluster, Node
from clusterdock.utils import wait_for_condition

DEFAULT_NAMESPACE = 'clusterdock'
MCS_SERVER_PORT = 8443

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
                        devices=node_disks.get(args.primary_node[0]))

    secondary_nodes = [Node(hostname=hostname,
                            group='secondary',
                            image=secondary_node_image,
                            devices=node_disks.get(hostname))
                       for hostname in args.secondary_nodes]

    cluster = Cluster(primary_node, *secondary_nodes)
    # MapR 6.0.0 uses CentOS 7 which  needs following settings.
    if args.mapr_version.startswith('6.0.0'):
        for node in cluster.nodes:
            node.volumes.append({'/sys/fs/cgroup': '/sys/fs/cgroup'})
            temp_dir_name = tempfile.mkdtemp()
            logger.debug('Created temporary directory %s', temp_dir_name)
            node.volumes.append({temp_dir_name: '/run'})
    cluster.primary_node = primary_node
    cluster.start(args.network, pull_images=args.always_pull)

    logger.info('Generating new UUIDs ...')
    cluster.execute('/opt/mapr/server/mruuidgen > /opt/mapr/hostid')

    for node in cluster:
        configure_command = ('/opt/mapr/server/configure.sh -C {0} -Z {0} -RM {0} -HS {0} '
                             '-u mapr -g mapr -D {1}'.format(
                                 primary_node.fqdn,
                                 ','.join(node_disks.get(node.hostname))
                             ))
        node.execute("bash -c '{}'".format(configure_command))

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

    logger.info('Creating /apps/spark directory on %s ...', primary_node.hostname)
    spark_directory_command = ['sudo -u mapr hadoop fs -mkdir -p /apps/spark',
                               'sudo -u mapr hadoop fs -chmod 777 /apps/spark']
    primary_node.execute("bash -c '{}'".format('; '.join(spark_directory_command)))

    logger.info('Creating MapR sample Stream named /sample-stream on %s ...', primary_node.hostname)
    primary_node.execute('sudo -u mapr maprcli stream create -path /sample-stream '
                         '-produceperm p -consumeperm p -topicperm p')

    if args.mapr_version.startswith('6.0.0') and args.license_url:
        license_commands = ['curl --user {} {} > /tmp/lic'.format(args.license_credentials,
                                                                  args.license_url),
                            '/opt/mapr/bin/maprcli license add -license /tmp/lic -is_file true',
                            'rm -rf /tmp/lic']
        logger.info('Applying license ...')
        primary_node.execute('; '.join(license_commands))

    if not args.dont_register_gateway:
        logger.info('Registering gateway with the cluster ...')
        register_gateway_commands = ["cat /opt/mapr/conf/mapr-clusters.conf | egrep -o '^[^ ]* '"
                                     ' > /tmp/cluster-name',
                                     'maprcli cluster gateway set -dstcluster $(cat '
                                     '/tmp/cluster-name) -gateways {}'.format(primary_node.fqdn),
                                     'rm /tmp/cluster-name']
        primary_node.execute('; '.join(register_gateway_commands))

    logger.info('MapR Control System server is now accessible at https://%s:%s',
                getfqdn(), mcs_server_host_port)
