#! /usr/bin/env python
# This script will replace instance's ports with the same settings.
# It will have a network downtime for the instance.
#
# usage: nova_interface_reset.py [-h] [-k] uuid
# positional arguments:
#   uuid            instance uuid
# optional arguments:
#   -h, --help      show this help message and exit
#   -k, --insecure  allow connections to SSL sites without certs
#
import argparse
from copy import deepcopy
import json
import logging
import os
import time

from novaclient.v1_1.client import Client as nova_client
from neutronclient.v2_0 import client as neutron_client

logging.basicConfig(level=logging.INFO, date_fmt='%m-%d %H:%M')
LOG = logging.getLogger('nova-interface-reset')


class NovaInterfaceResetter(object):
    """NovaInterfaceResetter."""

    def __init__(self, **args):
        """Init NovaInterfaceResetter."""
        self._wait_interval = args.pop('wait_interval', 1)
        self._neutron = neutron_client.Client(**args)
        nova_args = deepcopy(args)
        self._nova = nova_client(nova_args.pop('username'),
                                 nova_args.pop('password'),
                                 nova_args.pop('tenant_name'), **nova_args)

    def _wait_until(self, func, *args, **kwargs):
        """Wait until function returned true."""
        wait_time = 0
        wait_timeout = 20
        wait_interval = 1

        while wait_time <= wait_timeout:
            if not func(*args, **kwargs):
                wait_time += wait_interval
                time.sleep(wait_interval)
            else:
                break
        if wait_time > wait_timeout:
            return False
        else:
            return True

    def _floatingip_port_binding(self, floatingip_id, port_id):
        """Check floatingip and port binding."""
        floatingip = self._neutron.show_floatingip(floatingip_id)['floatingip']
        return floatingip['port_id'] == port_id

    def _port_state(self, query, absent=False):
        """Check port meet query state."""
        ports = self._neutron.list_ports(**query)['ports']
        if absent is True:
            return len(ports) == 0
        else:
            return len(ports) == 1

    def replace_port(self, port_id):
        """Replace a port.

        steps:
            1. disassociate all floating ips from the port
            2. dettach the old port from instance
            3. create new port with the same data of old port
            4. attach the new port back to instance
            5. associate floating ips to new port
        """
        LOG.info("Replace port %s" % port_id)
        # get data of old port
        old_port = self._neutron.show_port(port_id).get('port')
        LOG.info("Old port info: %s " % json.dumps(old_port))

        # disassociate floating ip from the port
        floating_ips = self._neutron.list_floatingips(
            port_id=old_port['id'])['floatingips']
        for floating_ip in floating_ips:
            LOG.info("Disassociate floating ip %s "
                     "from old port %s" % (floating_ip['id'], old_port['id']))
            self._neutron.update_floatingip(floating_ip['id'],
                                            {'floatingip': {'port_id': None}})
            self._wait_until(self._floatingip_port_binding,
                             floating_ip['id'], None)
        time.sleep(self._wait_interval)
        # get server
        server = self._nova.servers.get(old_port['device_id'])
        LOG.info("Servier info: %s " % json.dumps(server.to_dict()))
        # dettach the old port from instance
        LOG.info("Detach old port %s from server %s." % (old_port['id'],
                                                         server.id))
        server.interface_detach(old_port['id'])
        self._wait_until(self._port_state, dict(id=old_port['id']),
                         absent=True)
        # create new port
        new_port = {"port": dict(admin_state_up=old_port['admin_state_up'],
                                 network_id=old_port['network_id'],
                                 mac_address=old_port['mac_address'],
                                 tenant_id=old_port['tenant_id'],
                                 name=old_port['name'],
                                 fixed_ips=old_port['fixed_ips'],
                                 security_groups=old_port['security_groups'])}
        new_port = self._neutron.create_port(new_port).get('port')
        self._wait_until(self._port_state, dict(id=old_port['id']))
        LOG.info("Created new port %s." % json.dumps(new_port))

        # attach the new port back to instance
        LOG.info("Attach new port %s to server %s." % (new_port['id'],
                                                       server.id))
        server.interface_attach(new_port['id'], None, None)
        self._wait_until(self._port_state,
                         dict(id=new_port['id'], device_id=server.id))

        # associate floating ips to new port
        for floating_ip in floating_ips:
            LOG.info("Associate floating ip %s "
                     "to new port %s" % (floating_ip['id'], old_port['id']))
            self._neutron.update_floatingip(floating_ip['id'],
                                            {'floatingip': {'port_id':
                                                            new_port['id']}})
            self._wait_until(self._floatingip_port_binding,
                             floating_ip['id'], new_port['id'])
        LOG.info("Replace port %s with new port %s done" % (old_port['id'],
                                                            new_port['id']))

    def reset_instance(self, uuid):
        """Reset all ports of an instance."""
        ports = self._neutron.list_ports(device_id=uuid).get('ports', [])
        LOG.info("Reset %d ports for instance %s " % (len(ports), uuid))
        for port in ports:
            self.replace_port(port['id'])
        LOG.info("Reset %d ports for instance %s done" % (len(ports), uuid))


if __name__ == '__main__':
    # ensure environment has necessary items to authenticate
    for key in ['OS_TENANT_NAME', 'OS_USERNAME', 'OS_PASSWORD',
                'OS_AUTH_URL']:
        if key not in os.environ.keys():
            LOG.exception("Your environment is missing '%s'")
            exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("uuid", help="instance uuid")
    parser.add_argument('-k', '--insecure', action='store_true',
                        default=False, help='allow connections to SSL sites '
                                            'without certs')
    args = parser.parse_args()

    os_args = dict(auth_url=os.environ.get('OS_AUTH_URL'),
                   username=os.environ.get('OS_USERNAME'),
                   tenant_name=os.environ.get('OS_TENANT_NAME'),
                   password=os.environ.get('OS_PASSWORD'),
                   endpoint_type=os.environ.get('OS_ENDPOINT_TYPE',
                                                'publicURL'),
                   insecure=args.insecure)

    resetter = NovaInterfaceResetter(**os_args)
    resetter.reset_instance(args.uuid)
