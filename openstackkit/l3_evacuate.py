#! /usr/bin/env python
import logging
import os
import time
import itertools
import sys
import ansible.runner
from neutronclient.common.exceptions import NeutronClientException
from neutronclient.v2_0 import client


logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s:%(levelname)s - %(message)s')


def log_info(action, msg):
    logging.info("[%-10s] - %s" % (action.upper(), msg))


def log_warn(action, msg):
    logging.warning("[%-10s] - %s" % (action.upper(), msg))


def log_error(action, msg):
    logging.error("[%-10s] - %s" % (action.upper(), msg))

# RemoteRunners - How to connect to remote server for checking


class RemoteRunner(object):

    def run(self, host, cmd):
        log_info("run cmd", "run remote cmd [%s]: %s" % (host, cmd))
        rc, stdout, stderr = self.remote_exec(host, cmd)
        if rc != 0:
            return (False, stderr)
        else:
            return (True, stdout)


class AnsibleRemoteRunner(RemoteRunner):

    def remote_exec(self, host, cmd):
        results = ansible.runner.Runner(
            run_hosts=[host],
            module_name='shell',
            module_args=" ".join(cmd),
            timeout=12,
        ).run()
        if host in results['contacted']:
            return (results['contacted'][host]['rc'], results['contacted'][host]['stdout'], results['contacted'][host]['stderr'])
        else:
            return (1, None, results['dark'][host][msg])


# Pickers - How to select the destnation for one router
class Picker(object):

    def __init__(self, neutron, src_agent):
        self.client = neutron
        agents = neutron.list_agents(agent_type='L3 agent',
                                     admin_state_up=True, alive=True).get('agents')
        self._src_agent = src_agent
        self.dest = {}
        for agent in agents:
            if agent['alive'] and agent['admin_state_up'] and agent['id'] != self._src_agent['id']:
                self.dest[agent['id']] = {}
                self.dest[agent['id']]['agent'] = agent
                self.dest[agent['id']]['routers'] = []
        self._dest_cycle = itertools.cycle(self.dest.keys())

    def has_next_for_agent(self, agent):
        return len(self.dest[agent['id']]['routers']) > 0

    def get_next_for_agent(self, agent):
        if self.has_next_for_agent(agent):
            return (self.dest[agent['id']]['agent'], self.dest[agent['id']]['routers'].pop())
        else:
            return (None, None)

    def get_next(self):
        candidate = len(self.dest)
        while candidate > 0:
            agent_id = self._dest_cycle.next()
            candidate -= 1
            if len(self.dest[agent_id]['routers']) > 0:
                return (self.dest[agent_id]['agent'], self.dest[agent_id]['routers'].pop())
            else:
                continue
        return (None, None)

    def has_next(self):
        for agent_router in self.dest.values():
            if len(agent_router['routers']) > 0:
                return True
            else:
                continue
        return False


class BalancePicker(Picker):

    def init(self):
        routers = self.client.list_routers_on_l3_agent(
            self._src_agent['id']).get('routers', [])
        totals = {}
        for agent_id in self.dest.keys():
            totals[agent_id] = self.dest[agent_id][
                'agent']['configurations']['routers']

        for router in routers:
            agent_id = min(
                totals.keys(), key=lambda agent_id: totals[agent_id])
            self.dest[agent_id]['routers'].append(router)
            totals[agent_id] += 1


class CyclePicker(Picker):

    def init(self):
        routers = self.client.list_routers_on_l3_agent(
            self._src_agent['id']).get('routers', [])
        for router in routers:
            agent_id = self._dest_cycle.next()
            self.dest[agent_id]['routers'].append(router)


# Evacuator - How to migate routers
class L3AgentEvacuator(object):

    def __init__(self, agent_id, picker, remote_runner, **kwargs):
        if 'stop_agent_after_evacuate' in kwargs and kwargs['stop_agent_after_evacuate'] == True:
            self._stop_agent_after_evacuate = True
        else:
            self._stop_agent_after_evacuate = False
        if "wait_interval" in kwargs:
            self._wait_interval = kwargs['wait_interval']
        else:
            self._wait_interval = 1
        if "wait_timeout" in kwargs:
            self._wait_timeout = kwargs['wait_timeout']
        else:
            self._wait_timeout = 30
        if "least_wait_time" in kwargs:
            self._least_wait_time = kwargs['least_wait_time']
        else:
            self._least_wait_time = 2
        if "insecure" in kwargs and kwargs['insecure'] == True:
            self._insecure_client = True
        else:
            self._insecure_client = False
        self._setup_neutron_client()
        self._setup_remote_runner(remote_runner)
        self._src_agent = self._neutron.show_agent(agent_id).get('agent', {})
        self._setup_picker(picker)
        self._summary = {}

    def _setup_neutron_client(self):
        ca = os.environ.get('OS_CACERT', None)

        self._neutron = client.Client(auth_url=os.environ['OS_AUTH_URL'],
                                      username=os.environ['OS_USERNAME'],
                                      tenant_name=os.environ['OS_TENANT_NAME'],
                                      password=os.environ['OS_PASSWORD'],
                                      endpoint_type='internalURL',
                                      insecure=self._insecure_client,
                                      ca_cert=ca)

    def _setup_picker(self, picker):
        if picker == 'cycle':
            self.picker = CyclePicker(self._neutron, self._src_agent)
        elif picker == 'balance':
            self.picker = BalancePicker(self._neutron, self._src_agent)
        else:
            raise Exception("No picker found for %s" % picker)

    def _setup_remote_runner(self, remote_runner):
        if remote_runner == 'nope':
            self.remote_runner = NopeRemoteRunner()
        elif remote_runner == 'fabric':
            self.remote_runner = FabricRemoteRunner()
        elif remote_runner == 'ansible':
            self.remote_runner = AnsibleRemoteRunner()
        else:
            raise Exception("No remote runner found for %s" % remote_runner)

    def run(self):
        # setup picker
        self.picker.init()
        # do migrate
        self.evacuate()
        if self._stop_agent_after_evacuate:
            log_info(
                "checking start", "checking before stop neutron l3 agent service")
            new_routers = self._list_router_on_l3_agent(self._src_agent)
            if len(new_routers) == 0:
                # no new created routers, stop service
                log_info("checking complete",
                         "No new router scheduled to the agent, stopping...")
                self._stop_agent(self._src_agent['host'])
                log_info("service stop",
                         "Service neutron-l3-agent stopped on %s" % self._src_agent['host'])
            else:
                # run the whole agent evacuate again
                log_info("summary",
                         "Found new scheduled router on agent, retry evacuating")
                self.run()
        else:
            log_info("summary", "-----")
            new_routers = self._list_router_on_l3_agent(self._src_agent)
            log_warn("summary",
                     "[%d] routers are not evacuated" % len(new_routers))
            for router in new_routers:
                log_warn("summary", "router id %s" % router['id'])

    def _list_router_on_l3_agent(self, agent):
        return self._neutron.list_routers_on_l3_agent(agent['id']).get('routers', [])

    def _wait_until(self, func, *args, **kwargs):
        wait_time = 0
        wait_timeout = self._wait_timeout
        wait_interval = self._wait_interval
        least_wait_time = self._least_wait_time
        if 'wait_timeout' in kwargs:
            wait_timeout = kwargs.pop('wait_timeout')
        if 'wait_interval' in kwargs:
            wait_interval = kwargs.pop('wait_interval')
        if 'least_wait_time' in kwargs:
            least_wait_time = kwargs.pop('least_wait_time')

        while wait_time <= wait_timeout:
            if not func(*args, **kwargs):
                wait_time += wait_interval
                time.sleep(wait_interval)
            else:
                break
        if wait_time < least_wait_time:
            time.sleep(least_wait_time - wait_time)
        if wait_time > wait_timeout:
            return False
        else:
            return True

    def _check_api_removed(self, agent, router):
        log_info("api checking", "checking router %s removed from agent %s via api " %
                 (router['id'], agent['id']))
        agents = self._neutron.list_l3_agent_hosting_routers(
            router['id']).get('agents', [])
        if len(agents) == 0 or agent['id'] not in [one_agent['id'] for one_agent in agents]:
            log_info("api checking", "router %s removed from %s successfully via api " % (
                router['id'], agent['id']))
            return True
        else:
            log_info("api checking", "Router %s removed from agent %s failed via api " %
                     (router['id'], agent['id']))
            return False

    def _check_api_added(self, agent, router):
        log_info("api checking", "checking router %s added to agent %s via api " %
                 (router['id'], agent['id']))
        agents = self._neutron.list_l3_agent_hosting_routers(
            router['id']).get('agents', [])
        if agent['id'] in [one_agent['id'] for one_agent in agents]:
            log_info("api checking",
                     "router %s added to %s successfully via api" % (router['id'], agent['id']))
            return True
        else:
            log_info("api checking", "router %s added to agent %s failed via api" %
                     (router['id'], agent['id']))
            return False

    def _ensure_clean_router_on_host(self, agent, router):
        log_info("ensure router clean", "ensure router %s cleaned from agent %s on host %s" %
                 (router['id'], agent['id'], agent['host']))
        host = agent['host']
        namespace = "qrouter-%s" % router['id']
        result = self._list_nics_in_netns_on_remote(host, namespace)
        if len(result) == 0:
            log_info("ensure router clean",
                     "router %s remove verified from agent %s on host %s" % (router['id'], agent['id'], agent['host']))
            return True
        else:
            log_info("port clean", "router %s clean failed from agent %s on host %s - nics %s not deleted" %
                     (router['id'], agent['id'], agent['host'], result))
            self._clean_nics_on_host(host, result)
            log_info("port clean", "router %s cleaned from agent %s on host %s - nics %s force cleaned" %
                     (router['id'], agent['id'], agent['host'], result))
            return True

    def _verify_router_on_host(self, agent, router):
        log_info("router verify", "Verifying router %s added to agent %s on host %s" %
                 (router['id'], agent['id'], agent['host']))
        host = agent['host']
        namespace = "qrouter-%s" % router['id']
        ports = self._neutron.list_ports(
            device_id=router['id']).get('ports', [])
        if len(ports) == 0:
            return True
        state = True
        result = self._list_nics_in_netns_on_remote(host, namespace)
        for one_port in ports:
            if one_port['device_owner'] == 'network:router_interface':
                nic = "qr-%s" % one_port['id'][0:11]
            elif one_port['device_owner'] == 'network:router_gateway':
                nic = "qg-%s" % one_port['id'][0:11]
            else:
                continue
            verfied = nic in result
            log_info("port verify", "verify router %s added to agent %s on host %s - %s : %s" %
                     (router['id'], agent['id'], agent['host'], nic, verfied))
            state = state & verfied
        return state

    def _extra_timeout_for_router(self, router):
        ports = self._neutron.list_ports(
            device_id=router['id']).get('ports', [])
        floating_ips = self._neutron.list_floatingips(
            router_id=router['id']).get('floatingips', [])
        return len(ports) + len(floating_ips)

    def _cmd_list_nic_in_netns(self, netns):
        return ["ip", "netns", "exec", netns, "ls", "-1", "/sys/class/net/"]

    def _list_nics_in_netns_on_remote(self, host, netns):
        rc, output = self.remote_runner.run(
            host, self._cmd_list_nic_in_netns(netns))
        if rc:
            nics = []
            for one_nic in output.split('\n'):
                if one_nic != 'lo':
                    nics.append(one_nic)
            return nics
        else:
            if 'Cannot open network namespace' in output:
                return []
            else:
                raise Exception(
                    "Failed list nics in namespace %s on host [%s]" % (netns, host))

    def _cmd_delete_ovs_port(self, port_name, br_name="br-router", timeout=10):
        return ["ovs-vsctl", "--timeout=%d" % timeout, "--", "--if-exists",
                "del-port", br_name, port_name]

    def _cmd_rm_netns(self, netns):
        return ["ip", "netns", "delete", netns]

    def _clean_nics_on_host(self, host, nics):
        for one_nic in nics:
            log_info(
                "port deleting", "start deleting port %s on host %s" % (one_nic, host))
            succeed, output = self.remote_runner.run(
                host, self._cmd_delete_ovs_port(one_nic))
            if not succeed:
                log_error(
                    "port deleting", "Failed to delete port %s on host %s - %s" % (one_nic, host, output))

    def _stop_agent(self, host):
        cmd = ["service", "neutron-l3-agent", "stop"]
        result = self.remote_runner.run(host, cmd)
        if not result:
            log_error("service stop", "Failed to stop neutron-l3-agent")
        else:
            log_info("service stop", "Failed to stop neutron-l3-agent")


class SequenceEvacuator(L3AgentEvacuator):

    def _remove_router(self, agent, router):

        log_info("remove start", "remove router %s from %s" %
                 (router['id'], agent['id']))
        try:
            self._neutron.remove_router_from_l3_agent(
                agent['id'], router['id'])
        except NeutronClientException as e:
            log_error("neutron error", "error remove router %s from agent %s - %s" %
                      (router['id'], agent['id'], e.message))
            return False

        if not self._wait_until(self._check_api_removed, agent, router):
            # remove again
            log_warn("api remove failed",
                     "remove router %s from agent %s, retry" % (router['id'], agent['id']))
            return self._remove_router(agent, router)

        else:
            try:
                # clean left qg qr devices if they are not cleaned by neutron
                self._ensure_clean_router_on_host(agent, router)
                log_info("remove complete",
                         "remove router %s from agent %s" % (router['id'], agent['id']))
                return True
            except Exception as e:
                log_error("ensure error", "error ensure router %s from agent %s - %s" %
                          (router['id'], agent['id'], e.message))
                # need to make sure removed router need to added to another
                # host
                return True

    def _add_router(self, agent, router):
        log_info("add start", "add router %s to agent %s" %
                 (router['id'], agent['id']))
        try:
            self._neutron.add_router_to_l3_agent(
                agent['id'], dict(router_id=router['id']))
        except NeutronClientException as e:
            log_error("neutron error", "error add router %s to agent %s - %s" %
                      (router['id'], agent['id'], e.message))
            return False

        if not self._wait_until(self._check_api_added, agent, router):
            # add again
            log_warn("api add failed",
                     "add router %s to agent %s failed, retry" % (router['id'], agent['id']))
            return self._add_router(agent, router)
        else:
            try:
                # check the server if the routers setting is correct
                if not self._verify_router_on_host(agent, router):
                    # wait again, since port with mutil floating ip will takes
                    # time to add
                    extra_timeout = self._extra_timeout_for_router(router)
                    log_warn(
                        "verify add failed", "failed to verify router %s on agent %s, wait for another %d seconds" % (router['id'], agent['id'], extra_timeout))
                    added = self._wait_until(
                        self._verify_router_on_host, agent, router, wait_timeout=extra_timeout, least_wait_time=1, wait_interval=1)
                    if not added:
                        # if not, migrate again to the the same node
                        log_warn(
                            "verify add failed", "failed to add router %s on agent %s, rm-add again" % (router['id'], agent['id']))

                        return self.migrate_router(agent, router, src_agent=agent)
                    else:
                        log_info("add complete",
                                 "add router %s to agent %s" % (router['id'], agent['id']))
                        return True
                else:
                    log_info("add complete",
                             "add router %s to agent %s" % (router['id'], agent['id']))
                    return True
            except Exception as e:
                log_error("verify error", "Error - check router %s on agent %s - %s" %
                          (router['id'], agent['id'], e.message))
                return True

    def migrate_router(self, target_agent, router, src_agent=None):
        if not src_agent:
            src_agent = self._src_agent
        log_info("migrate start", "Start migrate router %s from %s to %s" % (
            router['id'], src_agent['id'], target_agent['id']))
        removed = self._remove_router(src_agent, router)
        if removed:
            self._add_router(target_agent, router)
        log_info("migrate end", "End migrate router %s from %s to %s" %
                 (router['id'], self._src_agent['id'], target_agent['id']))

    def evacuate(self):
        while self.picker.has_next():
            agent, router = self.picker.get_next()
            self.migrate_router(agent, router)


class BatchEvacuator(L3AgentEvacuator):
    # improve performance
    pass


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("agent_id", help="l3 agent id to evacuate")
    parser.add_argument("--picker",
                        choices=['cycle', 'balance'],
                        help="method to distribute",
                        default='cycle')
    parser.add_argument("--runner",
                        choices=['ansible'],
                        help="method to run remote command",
                        default="ansible")
    parser.add_argument("--stopl3", action="store_true",
                        help="stop neutron-l3-agent after evacuate",
                        default=False)
    args = parser.parse_args()
    log_info("start", "------ L3 agent evacuate start ------")
    SequenceEvacuator(args.agent_id, args.picker, args.runner,
                      stop_agent_after_evacuate=args.stopl3).run()
    log_info("completed", "------ L3 agent evacuate end ------")