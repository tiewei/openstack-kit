#! /usr/bin/env python

import logging
import os
import time
from neutronclient.v2_0 import client

# RemoteRunners - How to connect to remote server for checking


class RemoteRunner(object):

    def run(self, host, cmd):
        rc, stdout, stderr = self.remote_exec(host, cmd)
        if not rc == 0:
            logging.error("Failed run remote cmd: %s" % stderr)
            return False
        else:
            logging.debug("Successfully run remote cmd: %s" % cmd)
            return stdout if stdout else True


class NopeRemoteRunner(RemoteRunner):

    def remote_exec(self, host, cmd):
        stdout = ""
        stderr = "[%s]:%s" % (host, cmd)
        return (1, stdout, stderr)


class FabricRemoteRunner(RemoteRunner):
    pass


class AnsibleRemoteRunner(RemoteRunner):
    pass


# Pickers - How to select the destnation for one router
class Picker(object):

    def __init__(self, neutron, src_agent):
        self.client = neutron
        agents = neutron.list_agents().get('agents',agent_type='L3 agent', admin_state_up=True, alive=True)
        self.src = src_agent
        self.dest = {}
        for agent in agents:
            if agent['alive'] and agent['id'] != self.src['id']:
                self.dest[agent['id']] = {}
                self.dest[agent['id']]['agent'] = agent
                self.dest[agent['id']]['routers'] = []

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
            agent_id = itertools.cycle(self.dest.keys())
            candidate -= 1
            if len(self.dest[agent_id]['routers']) > 0
                return  (self.dest[agent_id]['agent'], self.dest[agent_id]['routers'].pop())
            else:
                continue
        return (None, None)


    def has_next(self):
        for agent_router in self.dest.values()
            if len(agent_router['routers']) > 0:
                return True
            else:
                continue
        return False


class BalancePicker(Picker):
    def init(self):
        routers = self._list_router_on_l3_agent(self.src_agent['id']).get('routers', [])
        totals = {}
        for agent_id in self.dest.keys():
            totals[agent_id] = self.dest[agent_id]['agent']['routers']
        
        for router in routers:
            agent_id = min(totals.keys(), key=lambda agent_id: totals[agent_id])
            self.dest[agent_id]['routers'].append(router)
            totals[agent_id] += 1

class CyclePicker(Picker):
    def __init__(self, neutron, src_agent):
        import itertools
        super(CyclePicker,self).__init__(neutron, src_agent)

    def init(self):
        routers = self._list_router_on_l3_agent(self.src_agent['id'])
        for router in routers:
            agent_id = itertools.cycle(self.dest.keys())
            self.dest[agent_id]['routers'].append(router) 


# Evacuator - How to migate routers
class L3AgentEvacuator(object):

    def __init__(self, agent_id, picker, remote_runner, **kwargs):
        self._setup_neutron_client()
        self._setup_remote_runner(remote_runner)
        self.picker = picker
        self.src_agent = self._neutron.get_agent(agent_id)
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
        if "least_wait_time"
            self._least_wait_time = kwargs['least_wait_time']
        else:
            self._least_wait_time = 2
        if "insecure" in kwargs and kwargs['insecure'] == True:
            self._insecure_client = True
        else:
            self._insecure_client = False

    def _setup_client(self):
        ca = os.environ.get('OS_CACERT', None)

        self._neutron = client.Client(auth_url=os.environ['OS_AUTH_URL'],
                                      username=os.environ['OS_USERNAME'],
                                      tenant_name=os.environ['OS_TENANT_NAME'],
                                      password=os.environ['OS_PASSWORD'],
                                      endpoint_type='internalURL',
                                      insecure=self._insecure_client,
                                      ca_cert=ca)

    def _setup_remote_runner(self, remote_runner):
        if remote_runner == 'nope':
            self.remote_runner = NopeRemoteRunner()
        elif remote_runner == 'ssh':
            self.remote_runner = FabricRemoteRunner()
        elif remote_runner == 'ansible':
            self.remote_runner = AnsibleRemoteRunner()
        else
            raise Exception("No remote runner found for %s" % remote_runner)

    def _init_picker(self):
        self.picker.init(self._neutron, self.src_agent)

    def run(self):
        # setup picker
        self._init_picker()
        # do migrate
        self.evacuate()
        # verify
        #self._verify_env()
        if self._stop_agent_after_evacuate:
            logging.info("Checking before stop neutron l3 agent service")
            new_routers = self._list_router_on_l3_agent(self.src_agent)
            if len(new_routers) == 0:
                # no new created routers, stop service
                logging.info("No new router scheduled to the agent, stopping...")
                self._stop_agent(self.src_agent['host'])
                logging.info("Service neutron-l3-agent stopped on %s" % self.src_agent['host'])
            else:
                # run the whole agent evaculate again
                logging.info("Found new scheduled router on agent, retry evacuating")
                self.run()
        # summary

    def _list_router_on_l3_agent(agent):
        return self._neutron.list_routers_on_l3_agent(agent['id']).get('routers', [])

    def _wait_until(self, func, *args, **kwargs):
        wait_time = 0
        while wait_time <= self._wait_timeout:
            if not func(*args, **kwargs):
                wait_time += self._wait_interval
                time.sleep(self._wait_interval)
            else:
                break
        if wait_time < self._least_wait_time:
            time.sleep(self._least_wait_time - wait_time)
        if wait_time > self._wait_timeout:
            return False
        else:
            return True

    def _check_api_removed(self, agent, router):
        logging.info("Checking router %s removed from %s via api " % (router['id'], agent['id']))
        agents = self._neutron.list_l3_agent_hosting_routers(
            router['id']).get('agents', [])
        if len(agents) == 0 or router['id'] not in [one_agent['id'] for one_agent in agents]:
            logging.info("Router %s removed from %s successfully via api " % (router['id'], agent['id']))
            return True
        else:
            logging.info("Router %s removed from %s failed via api " % (router['id'], agent['id']))
            return False

    def _check_api_added(self, agent, router):
        logging.info("Checking router %s added to %s via api " % (router['id'], agent['id']))
        agents = self._neutron.list_l3_agent_hosting_routers(
            router['id']).get('agents', [])
        if router['id'] in [one_agent['id'] for one_agent in agents]:
            logging.info("Router %s added to %s successfully via api " % (router['id'], agent['id']))
            return True
        else:
            logging.info("Router %s added to %s failed via api " % (router['id'], agent['id']))
            return False

    def _ensure_clean_router_on_host(self, agent, router):
        logging.info("Ensure router %s cleaned from %s via ssh " % (router['id'], agent['id']))
        host = agent['host']
        namespace = "qrouter-%s" % router['id']
        result = self._list_nics_in_netns_on_remote(host, namespace)
        if len(result) == 0:
            logging.info("Router %s cleaned succeed from %s via ssh " % (router['id'], agent['id']))
            return True
        else:
            logging.info("Router %s cleaned failed from %s via ssh - nics %s not deleted" % (router['id'], agent['id'], result))
            self._clean_nics_in_netns_on_remote(host, namespace)
            logging.info("Router %s cleaned from %s via ssh - nics %s force cleaned" % (router['id'], agent['id'], result))
            return True

    def _check_router_on_host(self, agent, router):
        host = agent['host']
        namespace = "qrouter-%s" % router['id']
        ports = self._neutron.list_ports(device_id=self._id).get('ports', [])
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
            state = state & (nic in result)
        return state

    def _cmd_list_nic_in_netns(self, netns):
        return ["ip", "netns", "exec", netns, "ls", "-1", "/sys/class/net/"]

    def _list_nics_in_netns_on_remote(self, host, netns):
        stdout = self.remote_runner.run(
            host, self._cmd_list_nic_in_netns(netns))
        if stdout:
            nics = []
            for nic in stdout.split('\n'):
                if nic != 'lo':
                    nics.append(nic)
            return nic
        else:
            return []

    def _cmd_delete_ovs_port(self, port_name, br_name="br-router", timeout=10):
        return ["ovs-vsctl", "--timeout=%d" % timeout, "--", "--if-exists",
                "del-port", br_name, port_name]

    def _cmd_rm_netns(self, netns):
        return ["ip", "netns", "delete", netns]

    def _clean_nics_on_remote(self, host, netns):
        nics = self._list_nics_in_netns_on_remote(host, netns)
        for one_nic in nics:
            succeed = self.remote_runner.run(
                host, self._cmd_delete_ovs_port(one_nic))
            if not succeed:
                logging.error("Failed to delete port %s" % one_nic)

    def _stop_agent(self, host):
        cmd = ["service", "neutron-l3-agent", "stop"]
        result = self.remote_runner.run(host, cmd)
        if not result:
            logging.error("Failed to stop neutron-l3-agent")


class SequenceEvacuator(L3AgentEvacuator):

    def _remove_router(self, agent, router):
        try:
            logging.info("Start remove router %s from %s" %
                         (router['id'], agent['id']))
            self._neutron.remove_router_from_l3_agent(
                agent['id'], router['id'])
            if not self._wait_until(self._check_api_removed, agent['id'], router['id']):
                # remove again
                logging.warning(
                    "Remove router %s from agent %s failed, retry" % (router['id'], agent['id']))
                return self._remove_router(agent, router)
            else:
                # clean left qg qr devices if they are not cleaned by neutron
                self._ensure_clean_router_on_host(agent, router)
                logging.info(
                    "Remove router %s from agent %s completed" % (router['id'], agent['id']))
                return True
        except:
            logging.warning()

    def _add_router(self, agent, router):
        try:
            logging.info("Start add router %s to %s" % (router['id'], agent['id']))
            self._neutron.add_router_to_l3_agent(agent['id'], router['id'])
            if not self._wait_until(self._check_api_added, agent=agent, router=router):
                # add again
                logging.warning(
                    "Add router %s from agent %s failed, retry" % (router['id'], agent['id']))
                return self._add_router(agent, router)
            else:
                # check the server if the routers setting is correct
                if not self._check_router_on_host(agent, router):
                    # if not, migrate again to the the same node
                    logging.info()
                    return self.migrate_router(agent, router)
                else:
                    return True
        except:
            logging.warning()

    def migrate_router(self, target_agent, router):
        try:
            logging.info()
            self._remove_router(self._src_agent, router)
            self._add_router(target_agent, router)
        except:
            # ignore
            pass

    def evacuate(self):
        while self.picker.has_next():
            agent, router = self.picker.get_next()
            self.migrate_router(agent, router)


class BatchEvaculator(L3AgentEvacuator):
    pass


if __name__ = '__main__':

    # parse_args
    # run
