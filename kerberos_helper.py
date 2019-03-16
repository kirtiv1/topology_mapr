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
import re

from clusterdock.utils import wait_for_condition

KDC_IMAGE_NAME = 'clusterdock/topology_nodebase_kerberos:centos6.6'

KERBEROS_CONFIG_CONTAINER_DIR = '/etc/clusterdock/kerberos'

KDC_ACL_FILENAME = '/var/kerberos/krb5kdc/kadm5.acl'
KDC_CONF_FILEPATH = '/var/kerberos/krb5kdc/kdc.conf'
KDC_HOSTNAME = 'kdc'
KDC_GROUPNAME = 'kdc'
# Following is the location clusterdock places the keytab file of kerberos_principals
# so that client nodes like SDC docker can fetch it.
KDC_KEYTAB_FILEPATH = '{}/clusterdock.keytab'.format(KERBEROS_CONFIG_CONTAINER_DIR)
KRB5_CONF_FILEPATH = '/etc/krb5.conf'
MAPR_CONF_PATH = '/opt/mapr/conf'
MAPR_KEYTAB_FILENAME = 'mapr.keytab'
# Following is the location clusterdock places the mapr.keytab file so that client nodes like SDC docker can fetch it.
MAPR_KEYTAB_FILEPATH = '{}/{}'.format(KERBEROS_CONFIG_CONTAINER_DIR, MAPR_KEYTAB_FILENAME)
# Following is the location expected by MapR for the mapr.keytab file.
MAPR_CONF_KEYTAB_FILEPATH = '{}/{}'.format(MAPR_CONF_PATH, MAPR_KEYTAB_FILENAME)
MAPR_PRINCIPAL = 'mapr/my.cluster.com'
LINUX_USER_ID_START = 1000

logger = logging.getLogger('clusterdock.{}'.format(__name__))


class Kerberos_Helper:
    """Class to deal with kerberization of the cluster.

    Args:
        network (:obj:`str`): Docker network to use.
    """
    def __init__(self, network):
        self.network = network

    @property
    def mapr_principal(self):
        return '{}@{}'.format(MAPR_PRINCIPAL, self.network.upper())

    def configure_kdc(self, kdc_node, nodes, kerberos_principals, kerberos_ticket_lifetime, quiet):
        logger.info('Updating KDC configurations ...')
        realm = self.network.upper()

        logger.debug('Updating krb5.conf ...')
        krb5_conf = kdc_node.get_file(KRB5_CONF_FILEPATH)
        # Here '\g<1>' represents group matched in regex which is the original default value of ticket_lifetime.
        ticket_lifetime_replacement = kerberos_ticket_lifetime if kerberos_ticket_lifetime else '\g<1>'
        krb5_conf_contents = re.sub(r'EXAMPLE.COM', realm,
                                    re.sub(r'example.com', self.network,
                                           re.sub(r'ticket_lifetime = ((.)*)',
                                                  r'ticket_lifetime = {}'.format(ticket_lifetime_replacement),
                                                  re.sub(r'kerberos.example.com',
                                                         kdc_node.fqdn,
                                                         krb5_conf))))
        kdc_node.put_file(KRB5_CONF_FILEPATH, krb5_conf_contents)

        logger.debug('Updating kdc.conf ...')
        kdc_conf = kdc_node.get_file(KDC_CONF_FILEPATH)
        max_time_replacement = kerberos_ticket_lifetime if kerberos_ticket_lifetime else '1d'
        kdc_node.put_file(KDC_CONF_FILEPATH,
                          re.sub(r'EXAMPLE.COM', realm,
                                 re.sub(r'\[kdcdefaults\]',
                                        r'[kdcdefaults]\n max_renewablelife = 7d\n max_life = {}'.format(max_time_replacement),
                                        kdc_conf)))

        logger.debug('Updating kadm5.acl ...')
        kadm5_acl = kdc_node.get_file(KDC_ACL_FILENAME)
        kdc_node.put_file(KDC_ACL_FILENAME,
                          re.sub(r'EXAMPLE.COM', realm, kadm5_acl))

        logger.info('Starting KDC ...')

        kdc_commands = [
            'kdb5_util create -s -r {} -P kdcadmin'.format(realm),
            'kadmin.local -q "addprinc -pw {} admin/admin@{}"'.format('acladmin', realm),
            'kadmin.local -q "addprinc -randkey {}"'.format(self.mapr_principal),
            'kadmin.local -q "ktadd -k {} {}"'.format(MAPR_KEYTAB_FILEPATH, self.mapr_principal)
        ]

        if kerberos_principals:
            principals = ['{}@{}'.format(primary, realm)
                          for primary in kerberos_principals.split(',')]
            if kerberos_ticket_lifetime:
                kdc_commands.extend([('kadmin.local -q "addprinc -maxlife {}sec '
                                      '-maxrenewlife 5day -randkey {}"'.format(kerberos_ticket_lifetime, principal))
                                     for principal in principals])
            else:
                kdc_commands.extend(['kadmin.local -q "addprinc -randkey {}"'.format(principal)
                                     for principal in principals])
            kdc_commands.append('kadmin.local -q '
                                '"xst -norandkey -k {} {}"'.format(KDC_KEYTAB_FILEPATH,
                                                                   ' '.join(principals)))
        kdc_commands.extend(['service krb5kdc start',
                             'service kadmin start',
                             'authconfig --enablekrb5 --update',
                             'cp -f {} {}'.format(KRB5_CONF_FILEPATH,
                                                  KERBEROS_CONFIG_CONTAINER_DIR)])
        if kerberos_principals:
            kdc_commands.append('chmod 644 {}'.format(KDC_KEYTAB_FILEPATH))

        kdc_node.execute(' && '.join(kdc_commands), quiet=quiet)

        _validate_service_health(kdc_node, ['krb5kdc', 'kadmin'], quiet=quiet)

        # nodes are the primary and secondary nodes.
        for node in nodes:
            # Copy mapr.keytab file to location where MapR expects
            commands = ['cp -f {} {}/{}'.format(MAPR_KEYTAB_FILEPATH, MAPR_CONF_PATH, MAPR_KEYTAB_FILENAME),
                        'chown mapr:mapr {}'.format(MAPR_CONF_KEYTAB_FILEPATH)]
            # Copy krb5.conf to each node's /etc/krb5.conf
            commands.append('cp -f {}/{} {}'.format(KERBEROS_CONFIG_CONTAINER_DIR, 'krb5.conf', KRB5_CONF_FILEPATH))
            node.execute(' && '.join(commands), quiet=quiet)

def _validate_service_health(kdc_node, services, quiet=True):
    logger.info('Validating health of Kerberos services ...')

    def condition(node, services, quiet):
        services_with_poor_health = [service
                                     for service in services
                                     if node.execute(command='service {} status'.format(service),
                                                     quiet=quiet).exit_code != 0]
        if services_with_poor_health:
            logger.debug('Services with poor health: %s',
                         ', '.join(services_with_poor_health))
        # Return True if the list of services with poor health is empty.
        return not bool(services_with_poor_health)
    wait_for_condition(condition=condition, condition_args=[kdc_node, services, quiet])

def create_kerberos_cluster_users(nodes, kerberos_principals, quiet):
    commands = ['useradd -u {} -g hadoop {}'.format(uid, primary)
                for uid, primary in enumerate(kerberos_principals.split(','),
                                              start=LINUX_USER_ID_START)]
    for node in nodes:
        node.execute('; '.join(commands), quiet=quiet)
