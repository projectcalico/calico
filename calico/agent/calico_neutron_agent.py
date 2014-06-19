#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Metaswitch Networks.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
#
# Performs per host Calico configuration for Neutron.
# Based on the structure of the Linux Bridge agent in the
# Linux Bridge ML2 Plugin.
# @author: Metaswitch Networks

import os
import sys
import time

import eventlet
from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as logging_config
from neutron.common import constants
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common.rpc import common as rpc_common
from neutron.openstack.common.rpc import dispatcher
from neutron.plugins.linuxbridge.common import config  # noqa
from neutron.plugins.linuxbridge.common import constants as lconst
from calico import common as calico_common

LOG = logging.getLogger(__name__)

TAP_INTERFACE_PREFIX = "tap"
TAP_FS = "/sys/devices/virtual/net/"


class CalicoManager(object):
    def __init__(self, interface_mappings, root_helper):
        LOG.debug('CalicoManager::__init__')
        self.interface_mappings = interface_mappings
        self.root_helper = root_helper
        self.ip = ip_lib.IPWrapper(self.root_helper)

    def get_tap_device_name(self, interface_id):
        LOG.debug('CalicoManager::get_tap_device_name')
        if not interface_id:
            LOG.warning(_("Invalid Interface ID, will lead to incorrect "
                          "tap device name"))
        tap_device_name = TAP_INTERFACE_PREFIX + interface_id[0:11]
        return tap_device_name

    def add_static_route(self, tap_device_name, fixed_ips, mac_address):
        LOG.warning('CalicoManager::add_static_route')
        result = True
        for ip_data in fixed_ips:
            ip_address = ip_data["ip_address"]
            LOG.info(_("Adding static route for %s via %s"),
                     ip_address, tap_device_name)
            route_out, route_err = utils.execute(
                ['ip', 'route', 'add', ip_address,
                 'dev', tap_device_name,
                 'proto', 'static'],
                root_helper=self.root_helper,
                check_exit_code=False,
                return_stderr=True)
            result &= (route_err == '') or ('File exists' in route_err)
            proxy_arp_out = utils.execute(
                ['neutron-enable-proxy-arp', tap_device_name],
                root_helper=self.root_helper)
            result &= "Enabled proxy arp" in proxy_arp_out
            utils.execute(
                ['arp', '-s', ip_address, mac_address],
                root_helper=self.root_helper)
        return result

    def remove_static_route(self, tap_device_name, fixed_ips, mac_address):
        # We don't use the mac_address parameter right now, but it's kept for
        # symmetry.
        LOG.debug('CalicoManager::remove_static_route')
        for ip_data in fixed_ips:
            ip_address = ip_data['ip_address']
            LOG.info(_("Removing static route for %s via %s"),
                     ip_address, tap_device_name)

            route_out, route_err = utils.execute(
                ['ip', 'route', 'del', ip_address,
                 'dev', tap_device_name, 'proto', 'static'],
                root_helper=self.root_helper,
                check_exit_code=False,
                return_stderr=True,
            )
            if route_err:
                LOG.warning(_("Unable to remove route for %s via %s"),
                          ip_address, tap_device_name)
            utils.execute(['neutron-disable-proxy-arp', tap_device_name],
                          root_helper=self.root_helper)
            arp_out, arp_err = utils.execute(
                ['arp', '-d', ip_address, '-i', tap_device_name],
                root_helper=self.root_helper,
                check_exit_code=False,
                return_stderr=True
            )
            if arp_err:
                LOG.warning(_("ARP entry missing for %s"), ip_address)

        return True

    def add_interface(self, network_id, network_type, physical_network,
                      segmentation_id, port_id, fixed_ips, mac_address):
        LOG.debug('CalicoManager::add_interface')
        LOG.info(_("Add interface: %s, %s, %s, %s, %s, %s"),
                 network_id, network_type, physical_network,
                 segmentation_id, port_id, fixed_ips)

        tap_device_name = self.get_tap_device_name(port_id)

        return self.add_static_route(tap_device_name,
                                     fixed_ips,
                                     mac_address)

    def remove_interface(self, network_id, network_type, physical_network,
                         segmentation_id, port_id, fixed_ips, mac_address):
        LOG.debug('CalicoManager::remove_interface')
        LOG.info(_("Remove interface: %s, %s, %s, %s, %s, %s"),
                 network_id, network_type, physical_network,
                 segmentation_id, port_id, fixed_ips)

        tap_device_name = self.get_tap_device_name(port_id)

        return self.remove_static_route(tap_device_name,
                                        fixed_ips,
                                        mac_address)

    def update_devices(self, registered_devices):
        LOG.debug('CalicoManager::update_devices %s' % registered_devices)
        devices = self.get_tap_devices()
        if devices == registered_devices:
            return
        added = devices - registered_devices
        removed = registered_devices - devices
        return {'current': devices,
                'added': added,
                'removed': removed}

    def get_tap_devices(self):
        LOG.debug('CalicoManager::get_tap_devices')
        devices = set()
        for device in os.listdir(TAP_FS):
            if device.startswith(TAP_INTERFACE_PREFIX):
                devices.add(device)
        return devices


class CalicoRpcCallbacks(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'

    def __init__(self, context, agent):
        LOG.debug('CalicoRpcCallbacks::__init__')
        self.context = context
        self.agent = agent
        self.sg_agent = agent

    def port_update(self, context, **kwargs):
        '''Update the port in response to a port update message from the
        controlling node.
        '''
        LOG.debug(_("port_update received %s, %s"), context, kwargs)
        # Check port exists on node
        port = kwargs.get('port')
        tap_device_name = self.agent.routing_mgr.get_tap_device_name(port['id'])
        devices = self.agent.routing_mgr.get_tap_devices()
        if tap_device_name not in devices:
            return

        if 'security_groups' in port:
            self.sg_agent.refresh_firewall()
        try:
            if port['admin_state_up']:
                network_type = kwargs.get('network_type')
                if network_type:
                    segmentation_id = kwargs.get('segmentation_id')
                else:
                    # compatibility with pre-Havana RPC vlan_id encoding
                    vlan_id = kwargs.get('vlan_id')
                    (network_type,
                     segmentation_id) = lconst.interpret_vlan_id(vlan_id)
                physical_network = kwargs.get('physical_network')
                # create the networking for the port
                if self.agent.routing_mgr.add_interface(port['network_id'],
                                                        network_type,
                                                        physical_network,
                                                        segmentation_id,
                                                        port['id'],
                                                        port['fixed_ips'],
                                                        port['mac_address']):
                    # update plugin about port status
                    self.agent.plugin_rpc.update_device_up(self.context,
                                                           tap_device_name,
                                                           self.agent.agent_id,
                                                           cfg.CONF.host)
                else:
                    self.agent.plugin_rpc.update_device_down(
                        self.context,
                        tap_device_name,
                        self.agent.agent_id,
                        cfg.CONF.host
                    )
            else:
                self.agent.routing_mgr.remove_interface(port['network_id'],
                                                        None,
                                                        None,
                                                        None,
                                                        port['id'],
                                                        port['fixed_ips'],
                                                        port['mac_address'])
                # update plugin about port status
                self.agent.plugin_rpc.update_device_down(self.context,
                                                         tap_device_name,
                                                         self.agent.agent_id,
                                                         cfg.CONF.host)
        except rpc_common.Timeout:
            LOG.error(_("RPC timeout while updating port %s"), port['id'])

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        LOG.debug('CalicoRpcCallbacks::create_rpc_dispatcher')
        return dispatcher.RpcDispatcher([self])


class CalicoPluginApi(agent_rpc.PluginApi,
                      sg_rpc.SecurityGroupServerRpcApiMixin):
    pass


class CalicoNeutronAgentRPC(sg_rpc.SecurityGroupAgentRpcMixin):

    def __init__(self, interface_mappings, polling_interval,
                 root_helper):
        LOG.debug('CalicoNeutronAgentRPC::__init__')
        self.polling_interval = polling_interval
        self.root_helper = root_helper
        self.setup_calico_routing(interface_mappings)

        configurations = {'interface_mappings': interface_mappings}

        self.agent_state = {
            'binary': 'neutron-calico-agent',
            'host': cfg.CONF.host,
            'topic': constants.L2_AGENT_TOPIC,
            'configurations': configurations,
            'agent_type': calico_common.AGENT_TYPE_CALICO,
            'start_flag': True}

        self.setup_rpc(interface_mappings.values())
        self.init_firewall()

    def _report_state(self):
        LOG.debug('CalicoNeutronAgentRPC::_report_state')
        try:
            devices = len(self.routing_mgr.get_tap_devices())
            self.agent_state.get('configurations')['devices'] = devices
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def setup_rpc(self, physical_interfaces):
        LOG.debug('CalicoNeutronAgentRPC::setup_rpc')
        if physical_interfaces:
            mac = utils.get_interface_mac(physical_interfaces[0])
        else:
            devices = ip_lib.IPWrapper(self.root_helper).get_devices(True)
            if devices:
                mac = utils.get_interface_mac(devices[0].name)
            else:
                LOG.error(_("Unable to obtain MAC address for unique ID. "
                            "Agent terminated!"))
                exit(1)
                return
        self.agent_id = '%s%s' % ('lb', (mac.replace(":", "")))
        LOG.info(_("RPC agent_id: %s"), self.agent_id)

        self.topic = topics.AGENT
        self.plugin_rpc = CalicoPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.callbacks = CalicoRpcCallbacks(self.context,
                                            self)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]

        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def setup_calico_routing(self, interface_mappings):
        LOG.debug('CalicoNeutronAgentRPC::setup_calico_routing')
        self.routing_mgr = CalicoManager(interface_mappings, self.root_helper)

    def process_network_devices(self, device_info):
        LOG.info(_("Process network devices %s"), device_info)
        resync_a = False
        resync_b = False
        if 'added' in device_info:
            resync_a = self.treat_devices_added(device_info['added'])
        if 'removed' in device_info:
            resync_b = self.treat_devices_removed(device_info['removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def treat_devices_added(self, devices):
        """
        Called by the polling loop when we discover new devices have appeared.
        Checks if the new devices are known to OpenStack and configures them if
        needed.

        """
        LOG.info(_("treat_devices_added %s"), devices)
        resync = False
        self.prepare_devices_filter(devices)
        for device in devices:
            LOG.debug(_("Port %s added"), device)
            try:
                details = self.plugin_rpc.get_device_details(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue
            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                # If a device has been added but it's not active, don't
                # do anything with it. We'll add it later. Otherwise, configure
                # it.
                if details['admin_state_up']:
                    # create the networking for the port
                    network_type = details.get('network_type')
                    if network_type:
                        segmentation_id = details.get('segmentation_id')
                    else:
                        # compatibility with pre-Havana RPC vlan_id encoding
                        vlan_id = details.get('vlan_id')
                        (network_type,
                         segmentation_id) = lconst.interpret_vlan_id(vlan_id)

                    if self.routing_mgr.add_interface(details['network_id'],
                                                      network_type,
                                                      details['physical_network'],
                                                      segmentation_id,
                                                      details['port_id'],
                                                      details['fixed_ips'],
                                                      details['mac_address']):

                        # update plugin about port status
                        resp = self.plugin_rpc.update_device_up(self.context,
                                                                device,
                                                                self.agent_id,
                                                                cfg.CONF.host)
                    else:
                        resp = self.plugin_rpc.update_device_down(self.context,
                                                                  device,
                                                                  self.agent_id,
                                                                  cfg.CONF.host)
                    LOG.info(_("Update device response: %s"), resp)
            else:
                LOG.info(_("Device %s not defined on plugin"), device)
        return resync

    def treat_devices_removed(self, devices):
        LOG.info(_("treat_devices_removed %s"), devices)
        resync = False
        self.remove_devices_filter(devices)
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id,
                                                             cfg.CONF.host)
            except Exception as e:
                LOG.exception(_("port_removed failed for %(device)s"),
                              {'device': device})
                resync = True
            else:
                if details['exists']:
                    LOG.info(_("Port %s updated."), device)
                else:
                    LOG.debug(_("Device %s not defined on plugin"), device)
        return resync

    def daemon_loop(self):
        sync = True
        devices = set()

        LOG.info(_("Calico Agent RPC Daemon Started!"))

        while True:
            start = time.time()
            if sync:
                LOG.info(_("Agent out of sync with plugin!"))
                devices.clear()
                sync = False
            device_info = {}
            try:
                device_info = self.routing_mgr.update_devices(devices)
            except Exception:
                LOG.exception(_("Update devices failed"))
                sync = True
            try:
                # notify plugin about device deltas
                if device_info:
                    LOG.debug(_("Agent loop has new devices!"))
                    # If treat devices fails - indicates must resync with
                    # plugin
                    sync = self.process_network_devices(device_info)
                    devices = device_info['current']
            except Exception:
                LOG.exception(_("Error in agent loop. Devices info: %s"),
                              device_info)
                sync = True
            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if elapsed < self.polling_interval:
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})


def main():
    eventlet.monkey_patch()
    cfg.CONF(project='neutron')

    logging_config.setup_logging(cfg.CONF)
    try:
        interface_mappings = q_utils.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.physical_interface_mappings)
    except ValueError as e:
        LOG.error(_("Parsing physical_interface_mappings failed: %s."
                    " Agent terminated!"), e)
        sys.exit(1)
    LOG.info(_("Interface mappings: %s"), interface_mappings)

    polling_interval = cfg.CONF.AGENT.polling_interval
    root_helper = cfg.CONF.AGENT.root_helper
    agent = CalicoNeutronAgentRPC(interface_mappings,
                                  polling_interval,
                                  root_helper)
    LOG.info(_("Agent initialized successfully, now running... "))
    agent.daemon_loop()
    sys.exit(0)

def enable_proxy_arp():
    """
    Helper 'main' function, run as root to enable proxy arp on an interface.
    """
    tap_name = sys.argv[1]
    print "Enabling proxy arp on %s" % tap_name
    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % tap_name, 'wb') as f:
        f.write('1')
    print "Enabled proxy arp on %s" % tap_name

def disable_proxy_arp():
    """
    Helper 'main' function to disable proxy arp.
    """
    tap_name = sys.argv[1]
    print "Disabling proxy arp on %s" % tap_name
    with open('/proc/sys/net/ipv4/conf/%s/proxy_arp' % tap_name, 'wb') as f:
        f.write('0')
    print "Disabled proxy arp on %s" % tap_name


if __name__ == "__main__":
    main()
