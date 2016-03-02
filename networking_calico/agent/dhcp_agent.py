# Copyright 2012 OpenStack Foundation
# Copyright 2015 Metaswitch Networks
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

import etcd
import logging
import socket
import sys

import eventlet
eventlet.monkey_patch()

from oslo_config import cfg

from neutron.agent.common import config
from neutron.agent.dhcp.agent import DhcpAgent
from neutron.agent.dhcp.agent import NetworkCache
from neutron.agent.dhcp_agent import register_options
from neutron.agent.linux import dhcp
from neutron.common import config as common_config
from neutron.common import constants

from calico.datamodel_v1 import dir_for_host
from calico.datamodel_v1 import key_for_subnet
from calico.datamodel_v1 import SUBNET_DIR
from calico.etcdutils import EtcdWatcher
from calico.etcdutils import safe_decode_json

from networking_calico.agent.linux.dhcp import DnsmasqRouted

LOG = logging.getLogger(__name__)

NETWORK_ID = 'calico'


class FakePlugin(object):
    """Fake plugin class.

    This class exists to support various calls that
    neutron.agent.linux.dhcp.Dnsmasq makes to what it thinks is the Neutron
    database (aka the plugin).

    The calls are create_dhcp_port, update_dhcp_port and release_dhcp_port, and
    the docstring for each corresponding method below indicates how they are
    called.

    However, update_dhcp_port is never called in the Calico setup, because it
    is only used when there is a change to the set of Neutron-allocated IP
    addresses that are associated with the DHCP port.  In the Calico setup, we
    use gateway IPs on the DHCP port instead of any new Neutron allocations,
    hence the situation just described can never happen.  Therefore we don't
    provide any code for update_dhcp_port.

    Because this class doesn't speak to the real Neutron database, it follows
    that the DHCP interface that we create on each compute host does not show
    up as a port in the Neutron database.  That doesn't matter, because we
    don't allocate a unique IP for each DHCP port, and hence don't consume any
    IPs that the Neutron database ought to know about.

    """

    def create_dhcp_port(self, port):
        """Support the following DHCP DeviceManager calls.

        dhcp_port = self.plugin.create_dhcp_port({'port': port_dict})
        """
        LOG.debug("create_dhcp_port: %s", port)
        port['port']['id'] = 'dhcp'

        # The following MAC address will be assigned to the Linux dummy
        # interface that
        # networking_calico.agent.linux.interface.RoutedInterfaceDriver
        # creates.  Therefore it will never actually be used or involved in the
        # sending or receiving of any real data.  Hence it should not matter
        # that we use a hardcoded value here, and the same value on every
        # networking-calico compute host.  The '2' bit of the first byte means
        # 'locally administered', which makes sense for a hardcoded value like
        # this and distinguishes it from the space of managed MAC addresses.
        port['port']['mac_address'] = '02:00:00:00:00:00'
        port['port']['device_owner'] = constants.DEVICE_OWNER_DHCP
        return dhcp.DictModel(port['port'])

    def release_dhcp_port(self, network_id, device_id):
        """Support the following DHCP DeviceManager calls.

        self.plugin.release_dhcp_port(network.id,
                                      self.get_device_id(network))
        """
        LOG.debug("release_dhcp_port: %s %s", network_id, device_id)


class CalicoEtcdWatcher(EtcdWatcher):

    NETWORK_ID = 'calico'
    """
    Calico network ID.

    Although there can in general be multiple networks and multiple
    subnets per network that need DHCP on a particular compute host,
    there's actually nothing that depends on how the subnets are
    partitioned across networks, and a single instance of Dnsmasq is
    quite capable of providing DHCP for many subnets.

    Therefore we model the DHCP requirement using a single network
    with ID 'calico', and many subnets within that network.
    """

    def _empty_network(self):
        """Construct and return an empty network model."""
        return dhcp.NetModel(False,
                             {"id": NETWORK_ID,
                              "subnets": [],
                              "ports": [],
                              "mtu": constants.DEFAULT_NETWORK_MTU})

    def __init__(self, agent):
        super(CalicoEtcdWatcher, self).__init__(
            '127.0.0.1:4001',
            dir_for_host(socket.gethostname()) + "/workload"
        )
        self.agent = agent
        self.suppress_on_ports_changed = False

        # Create empty Calico network object in the cache.
        self.agent.cache.put(self._empty_network())

        # Register the etcd paths that we need to watch.
        self.register_path(
            "/calico/v1/host/<hostname>/workload/<orchestrator>" +
            "/<workload_id>/endpoint/<endpoint_id>",
            on_set=self.on_endpoint_set,
            on_del=self.on_endpoint_delete
        )
        self.register_path(
            "/calico/v1/host/<hostname>/workload/<orchestrator>" +
            "/<workload_id>/endpoint",
            on_del=self.on_dir_delete
        )
        self.register_path(
            "/calico/v1/host/<hostname>/workload/<orchestrator>" +
            "/<workload_id>",
            on_del=self.on_dir_delete
        )
        self.register_path(
            "/calico/v1/host/<hostname>/workload/<orchestrator>",
            on_del=self.on_dir_delete
        )
        self.register_path(
            "/calico/v1/host/<hostname>/workload",
            on_del=self.on_dir_delete
        )

        # Also watch the etcd subnet tree.  When something in that subtree
        # changes, the subnet watcher will tell _this_ watcher to resync.
        self.subnet_watcher = SubnetWatcher(self)
        eventlet.spawn(self.subnet_watcher.loop)

    def on_endpoint_set(self, response, hostname, orchestrator,
                        workload_id, endpoint_id):
        """Handler for endpoint creations and updates.

        Endpoint data is, for example:

        { 'state': 'active' or 'inactive',
          'name': port['interface_name'],
          'mac': port['mac_address'],
          'profile_ids': port['security_groups'],
          'ipv4_nets': ['10.28.0.2/32'],
          'ipv4_gateway': '10.28.0.1',
          'ipv6_nets': ['2001:db8:1::2/128'],
          'ipv6_gateway': '2001:db8:1::1' }

        Port properties needed by DHCP code are:

        { 'id': <unique ID>,
          'network_id': <network ID>,
          'device_owner': 'calico',
          'device_id': <Linux interface name>,
          'fixed_ips': [ { 'subnet_id': <subnet ID>,
                           'ip_address': '10.28.0.2' } ],
          'mac_address: <MAC address>,
          'extra_dhcp_opts': ... (optional) }

        Network properties are:

        { 'subnets': [ <subnet object> ],
          'id': <network ID>,
          'namespace': None,
          'ports: [ <port object> ],
          'tenant_id': ? }

        Subnet properties are:

        { 'enable_dhcp': True,
          'ip_version': 4 or 6,
          'cidr': '10.28.0.0/24',
          'dns_nameservers': [],
          'id': <subnet ID>,
          'gateway_ip': <gateway IP address>,
          'host_routes': [],
          'ipv6_address_mode': 'dhcpv6-stateful' | 'dhcpv6-stateless',
          'ipv6_ra_mode': 'dhcpv6-stateful' | 'dhcpv6-stateless' }
        """

        # Get the endpoint data.
        endpoint = safe_decode_json(response.value, 'endpoint')
        if not (isinstance(endpoint, dict) and
                'ipv4_nets' in endpoint and
                'ipv4_subnet_ids' in endpoint and
                'ipv6_nets' in endpoint and
                'ipv6_subnet_ids' in endpoint and
                'name' in endpoint and
                'mac' in endpoint):
            # Endpoint data is invalid.
            LOG.warning("Invalid endpoint data: %s => %s",
                        response.value, endpoint)
            return

        # Construct NetModel port equivalent of Calico's endpoint data.
        fixed_ips = []
        dns_assignments = []
        fqdn = endpoint.get('fqdn')
        for ip_version in [4, 6]:
            # Generate the fixed IPs and DNS assignments for the current IP
            # version.
            for addrm, subnet_id in zip(endpoint['ipv%s_nets' % ip_version],
                                        endpoint['ipv%s_subnet_ids' %
                                                 ip_version]):
                ip_addr = addrm.split('/')[0]
                fixed_ips.append({'subnet_id': subnet_id,
                                  'ip_address': ip_addr})
                if fqdn:
                    dns_assignments.append({'hostname': fqdn.split('.')[0],
                                            'ip_address': ip_addr,
                                            'fqdn': fqdn})
        port = {'id': endpoint_id,
                'network_id': NETWORK_ID,
                'device_owner': 'calico',
                'device_id': endpoint['name'],
                'fixed_ips': fixed_ips,
                'mac_address': endpoint['mac'],
                'extra_dhcp_opts': []}
        if fqdn:
            port['dns_assignment'] = dns_assignments

        # Add this port into the NetModel.
        LOG.debug("new port: %s", port)
        self.agent.cache.put_port(dhcp.DictModel(port))

        # Now check for impact on subnets and DHCP driver.
        self.on_ports_changed()

    def on_ports_changed(self):
        # Check whether we should really do the following processing.
        if self.suppress_on_ports_changed:
            LOG.debug("Don't recalculate subnets yet;"
                      " must be processing a snapshot")
            return

        # Get current NetModel description of the Calico network.
        net = self.agent.cache.get_network_by_id(NETWORK_ID)
        LOG.debug("net: %s %s %s", net.id, net.subnets, net.ports)

        # See if we need to update the subnets in the NetModel.
        new_subnets = self.calculate_new_subnets(net.ports, net.subnets)
        if new_subnets is None:
            # No change to subnets, so just need 'reload_allocations' to tell
            # Dnsmasq about the new port.
            self.agent.call_driver('reload_allocations', net)
        else:
            # Subnets changed, so need to 'restart' the DHCP driver.
            net = dhcp.NetModel(False,
                                {"id": net.id,
                                 "subnets": new_subnets,
                                 "ports": net.ports,
                                 "tenant_id": "calico",
                                 "mtu": constants.DEFAULT_NETWORK_MTU})
            LOG.debug("new net: %s %s %s", net.id, net.subnets, net.ports)

            # Next line - i.e. just discarding the existing cache - is to work
            # around Neutron bug that the DHCP port is not entered into the
            # cache's port_lookup dict.
            self.agent.cache = NetworkCache()
            self.agent.cache.put(net)
            self.agent.call_driver('restart', net)

    def on_endpoint_delete(self, response, hostname, orchestrator,
                           workload_id, endpoint_id):
        """Handler for endpoint deletion."""
        # Find the corresponding port in the DHCP agent's cache.
        port = self.agent.cache.get_port_by_id(endpoint_id)
        if port:
            LOG.debug("deleted port: %s", port)
            self.agent.cache.remove_port(port)
            self.on_ports_changed()

    def calculate_new_subnets(self, ports, current_subnets):
        """Calculate and return subnets needed for PORTS.

        Given a current set of PORTS that we need to provide DHCP for,
        calculate all the subnets that we need for those, and get their data
        either from CURRENT_SUBNETS or from reading etcd.

        If the new set of subnets is equivalent to what we already had in
        CURRENT_SUBNETS, return None.  Otherwise return the new set of
        subnets.
        """

        # Gather required subnet IDs.
        subnet_ids = set()
        for port in ports:
            for fixed_ip in port['fixed_ips']:
                subnet_ids.add(fixed_ip['subnet_id'])
        LOG.debug("Needed subnet IDs: %s", subnet_ids)

        # Compare against the existing set of IDs.
        existing_ids = set([s.id for s in current_subnets])
        LOG.debug("Existing subnet IDs: %s", existing_ids)
        if subnet_ids == existing_ids:
            LOG.debug("Subnets unchanged")
            return None

        # Prepare required new subnet data.
        new_subnets = []
        for subnet_id in subnet_ids:
            # Check if we already have this subnet.
            existing = [s for s in current_subnets if s.id == subnet_id]
            if existing:
                # We do.  Assume subnet data hasn't changed.
                new_subnets.extend(existing)
            else:
                LOG.debug("Read subnet %s from etcd", subnet_id)

                # Read the data for this subnet.
                subnet_key = key_for_subnet(subnet_id)
                try:
                    response = self.client.read(subnet_key, consistent=True)
                    data = safe_decode_json(response.value, 'subnet')
                    LOG.debug("Subnet data: %s", data)
                    if not (isinstance(data, dict) and
                            'cidr' in data and
                            'gateway_ip' in data):
                        # Subnet data was invalid.
                        LOG.warning("Invalid subnet data: %s => %s",
                                    response.value, data)
                        raise etcd.EtcdKeyNotFound()

                    # Convert to form expected by NetModel.
                    ip_version = 6 if ':' in data['cidr'] else 4
                    subnet = {'enable_dhcp': True,
                              'ip_version': ip_version,
                              'cidr': data['cidr'],
                              'dns_nameservers': data.get('dns_servers') or [],
                              'id': subnet_id,
                              'gateway_ip': data['gateway_ip'],
                              'host_routes': []}
                    if ip_version == 6:
                        subnet['ipv6_address_mode'] = constants.DHCPV6_STATEFUL
                        subnet['ipv6_ra_mode'] = constants.DHCPV6_STATEFUL

                    # Add this to the set to be returned.
                    new_subnets.append(subnet)
                except etcd.EtcdKeyNotFound:
                    LOG.warning("No data for subnet %s", subnet_id)

        return new_subnets

    def _on_snapshot_loaded(self, etcd_snapshot_response):
        """Called whenever a snapshot is loaded from etcd."""

        # Reset the cache.
        LOG.debug("Reset cache for new snapshot")
        self.agent.cache = NetworkCache()
        self.agent.cache.put(self._empty_network())

        # Suppress the processing inside on_ports_changed, until we've
        # processed the whole snapshot.
        self.suppress_on_ports_changed = True

        # Now pass each snapshot node through the dispatcher, which
        # means that on_endpoint_set will be called for each endpoint.
        for etcd_node in etcd_snapshot_response.leaves:
            etcd_node.action = 'set'
            self.dispatcher.handle_event(etcd_node)

        LOG.debug("End of new snapshot")

        # Now check for impact on subnets and DHCP driver.
        self.suppress_on_ports_changed = False
        self.on_ports_changed()

    def on_dir_delete(self, response, *args, **kwargs):
        """Called if an endpoint parent directory is deleted from etcd."""
        LOG.warning("Unexpected directory deletion from etcd; triggering" +
                    " resync; %s %s %s", response, args, kwargs)

        # Handle by doing a resync.
        self.resync_after_current_poll = True


class SubnetWatcher(EtcdWatcher):

    def __init__(self, endpoint_watcher):
        super(SubnetWatcher, self).__init__('127.0.0.1:4001', SUBNET_DIR)
        self.endpoint_watcher = endpoint_watcher
        self.register_path(
            SUBNET_DIR + "/<subnet_id>",
            on_set=self.on_subnet_set
        )

    def on_subnet_set(self, response, subnet_id):
        """Handler for subnet creations and updates.

        We handle this by telling the main watcher to do a resync.
        """
        LOG.info("Subnet %s created or updated", subnet_id)
        self.endpoint_watcher.resync_after_current_poll = True

    def loop(self):
        # Catch and report any exceptions that escape here.
        try:
            super(SubnetWatcher, self).loop()
        except:                 # noqa
            LOG.exception("Exception in SubnetWatcher.loop()")
            raise
        finally:
            # As this thread is exiting, arrange for the agent as a whole to
            # exit.
            self.endpoint_watcher.stop()

    def _on_snapshot_loaded(self, etcd_snapshot_response):
        """Called whenever a snapshot is loaded from etcd."""
        LOG.info("New subnet snapshot, trigger endpoint watcher to resync")
        self.endpoint_watcher.resync_after_current_poll = True


class CalicoDhcpAgent(DhcpAgent):
    """Calico DHCP agent.

    This DHCP agent subclasses and overrides the standard Neutron DHCP
    agent so as to be driven by etcd endpoint data - instead of by
    Neutron RPC network, subnet and port messages - and so as not to
    provide any agent status reporting back to the Neutron server.
    This is because we have observed that the RPC exchanges between
    DHCP agents and the Neutron server will exhaust the latter once
    there are more than a few hundred agents running.
    """
    def __init__(self):
        super(CalicoDhcpAgent, self).__init__(host=socket.gethostname())

        # Override settings that Calico's DHCP agent use requires.
        self.conf.set_override('enable_isolated_metadata', False)
        self.conf.set_override('use_namespaces', False)
        self.conf.set_override(
            'interface_driver',
            'networking_calico.agent.linux.interface.RoutedInterfaceDriver'
        )

        # Override the DHCP driver class - networking-calico's
        # DnsmasqRouted class.
        self.dhcp_driver_cls = DnsmasqRouted

        # Override the RPC plugin (i.e. proxy to the Neutron database)
        # with a fake plugin.  The DHCP driver code calls when it
        # wants to tell Neutron that it is creating, updating or
        # releasing the DHCP port.
        self.plugin_rpc = FakePlugin()

        # Watch etcd for any endpoint changes for this host.
        self.etcd = CalicoEtcdWatcher(self)

    def run(self):
        """Run the EtcdWatcher loop."""
        self.etcd.loop()


def main():
    register_options(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    agent = CalicoDhcpAgent()
    agent.run()
