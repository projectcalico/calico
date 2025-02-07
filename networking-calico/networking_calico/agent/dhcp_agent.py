# Copyright 2012 OpenStack Foundation
# Copyright 2015 Metaswitch Networks
# Copyright 2016, 2018, 2022 Tigera, Inc.
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

import logging
import netaddr
import os
import re
import socket
import subprocess
import sys
import time

import eventlet
eventlet.monkey_patch()

from neutron.agent.dhcp.agent import DhcpAgent
from neutron.agent.dhcp_agent import register_options
from neutron.agent.linux import dhcp
from neutron.common import config as common_config
try:
    from neutron.common import constants as neutron_constants
except ImportError:
    from neutron_lib import constants as neutron_constants
try:
    from neutron.conf.agent import common as config
except ImportError:
    # Neutron code prior to 7f23ccc (15th March 2017).
    from neutron.agent.common import config

from networking_calico.agent.linux.dhcp import DnsmasqRouted
from networking_calico.common import config as calico_config
from networking_calico.common import mkdir_p
from networking_calico.compat import cfg
from networking_calico.compat import constants
from networking_calico.compat import DHCPV6_STATEFUL
from networking_calico import datamodel_v1
from networking_calico import datamodel_v2
from networking_calico import datamodel_v3
from networking_calico import etcdutils

from etcd3gw.exceptions import Etcd3Exception

from eventlet.event import Event
from eventlet.queue import Empty
from eventlet.queue import LightQueue

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
        port['port']['id'] = port['port']['network_id']

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

    get_networks = None

    # New method required sometime between Yoga and Caracal releases - see
    # https://github.com/projectcalico/calico/issues/9216 for discussion.
    def get_ports(self, port_filters):
        return None


def empty_network(network_id=NETWORK_ID):
    """Construct and return an empty network model."""
    return make_net_model({"id": network_id,
                           "subnets": [],
                           "ports": [],
                           "tenant_id": "calico",
                           "mtu": neutron_constants.DEFAULT_NETWORK_MTU})


def copy_network(source_net):
    """Construct and return a copy of an existing network model."""
    return make_net_model({"id": source_net.id,
                           "subnets": source_net.subnets,
                           "ports": source_net.ports,
                           "tenant_id": source_net.tenant_id,
                           "mtu": source_net.mtu})


def make_net_model(net_spec):
    try:
        net_model = dhcp.NetModel(False, net_spec)
    except TypeError:
        # use_namespace option was removed during Mitaka cycle.
        net_model = dhcp.NetModel(net_spec)
        net_model._ns_name = None

    return net_model


def split_endpoint_name(name):
    parts = name.replace('--', '#').split('-')
    return tuple([p.replace('#', '-') for p in parts])


class MTUWatcher(object):

    # -----------------------------------------------------------------
    # Methods called from DHCP agent's main thread.
    # -----------------------------------------------------------------

    def __init__(self, agent, port_handler):
        self.agent = agent
        self.port_handler = port_handler
        self.mtu_by_if_name = {}
        self.port_id_by_if_name = {}
        self.rx_up = re.compile('^[0-9]+: (tap[a-z0-9-]+).*:.* mtu ([0-9]+)')
        self.rx_del = re.compile('Deleted [0-9]+: (tap[a-z0-9-]+)')

    def get_mtu(self, if_name):
        # Note, returns None if we haven't yet seen an MTU for the given
        # interface name.
        return self.mtu_by_if_name.get(if_name)

    def watch_port(self, id, if_name):
        self.port_id_by_if_name[if_name] = id

    def unwatch_port(self, id, if_name):
        if if_name in self.port_id_by_if_name:
            del self.port_id_by_if_name[if_name]

    def run(self):
        while True:
            # Start 'ip monitor link' running on a separate thread.
            running_event = Event()
            exited_event = Event()
            eventlet.spawn(self.process_command, ['ip', 'monitor', 'link'],
                           running_event=running_event,
                           exited_event=exited_event)

            # Wait until we can be sure that 'ip monitor link' is really
            # running (or has exited), and hence that we will see all
            # further link transitions.
            while not (running_event.ready() or exited_event.ready()):
                # Create and delete a dummy interface.
                os.system("ip link add calico-dhcp-dmy type dummy")
                os.system("ip link del calico-dhcp-dmy type dummy")
                time.sleep(0.5)

            if not exited_event.ready():
                # Now run 'ip link', to find MTU of all preexisting interfaces.
                self.process_command(['ip', 'link'])

            # Wait for the 'ip monitor link' thread to exit, so that we
            # can then restart it.
            exited_event.wait()

    # -----------------------------------------------------------------
    # Methods called from MTU watcher's own thread, or from agent thread.
    # -----------------------------------------------------------------

    def process_command(self, command, running_event=None, exited_event=None):
        process = subprocess.Popen(command, stdout=subprocess.PIPE)
        while True:
            line = process.stdout.readline()
            if not line:
                LOG.info("command %r exited", command)
                break
            if running_event:
                running_event.send()
                running_event = None
            match_data = self.rx_up.match(line.decode('utf-8'))
            if match_data:
                self.record_mtu(match_data.group(1), int(match_data.group(2)))
                continue
            match_data = self.rx_del.match(line.decode('utf-8'))
            if match_data:
                self.if_deleted(match_data.group(1))

        if exited_event:
            exited_event.send()

    def record_mtu(self, if_name, mtu):
        LOG.debug("MTU for %s is now %d", if_name, mtu)
        old_mtu = self.mtu_by_if_name.get(if_name)
        if mtu != old_mtu:
            LOG.info("MTU for %s changed from %s to %s", if_name, old_mtu, mtu)
        self.mtu_by_if_name[if_name] = mtu
        if if_name in self.port_id_by_if_name and mtu != old_mtu:
            # MTU changing for a watched port.
            self.port_handler.on_mtu_change(self.port_id_by_if_name[if_name], mtu)

    def if_deleted(self, if_name):
        LOG.debug("Interface %s deleted", if_name)
        if if_name in self.mtu_by_if_name:
            LOG.info("Discard MTU for deleted interface %s", if_name)
            del self.mtu_by_if_name[if_name]


class DnsmasqUpdater(object):
    def __init__(self, agent):
        self.agent = agent
        self.updates_needed = LightQueue()

        # Cache of the ports that we've asked Dnsmasq to handle, for each
        # network ID.
        self._last_dnsmasq_ports = {}

    def update_network(self, network_id):
        self.updates_needed.put(network_id)

    def start(self):
        while True:
            LOG.debug("DnsmasqUpdater: wait until updates needed")
            dirty_network_ids = set()
            dirty_network_ids.add(self.updates_needed.get())
            try:
                while True:
                    dirty_network_ids.add(self.updates_needed.get_nowait())
            except Empty:
                pass
            LOG.debug("DnsmasqUpdater: updating now for %r", dirty_network_ids)
            for network_id in dirty_network_ids:
                # Handle any exceptions here so that the dnsmasq updater thread
                # doesn't die.  There aren't any expected exception scenarios,
                # but better to be more resilient here.
                try:
                    self.really_update_dnsmasq(network_id)
                except Exception as e:
                    LOG.exception("really_update_dnsmasq")

    def really_update_dnsmasq(self, network_id):
        # Get NetModel for that network ID.
        net = self.agent.cache.get_network_by_id(network_id)
        LOG.debug("Net: %s", net)

        # Compute the set of ports that we need Dnsmasq to handle for this
        # network ID.
        ports_needed = [
            port for port in net.ports if port.device_id.startswith('tap')
        ]
        ports_needed.sort(key=lambda port: port.id)
        for p in ports_needed:
            LOG.debug("Port %s", p)
            for edo in p.extra_dhcp_opts:
                LOG.debug("DHCP option %s", edo)

        # Compare a description of each needed port that includes all the
        # information we care about, instead of just `p` (which is really just
        # a pointer), so that we can spot when DHCP options change within the
        # same port DictModel.
        ports_needed_as_string = ''
        for p in ports_needed:
            ports_needed_as_string += ':' + p.device_id
            for edo in p.extra_dhcp_opts:
                ports_needed_as_string += ";" + edo.opt_name + "," + edo.opt_value + "," + str(edo.ip_version)
            for fip in p.fixed_ips:
                ports_needed_as_string += ";" + fip.ip_address
        LOG.debug("Ports needed: %s", ports_needed_as_string)

        # Compare that against what we've last asked Dnsmasq to handle.
        if ports_needed_as_string != self._last_dnsmasq_ports.get(network_id):
            # Requirements have changed, so start, restart or stop Dnsmasq for
            # that network ID.
            LOG.info("old: %s", self._last_dnsmasq_ports.get(network_id))
            LOG.info("new: %s", ports_needed_as_string)
            if ports_needed:
                LOG.info("Restart dnsmasq for network %s with %d port(s)",
                         network_id, len(ports_needed))
                self.agent.call_driver('restart', net)
            else:
                # No ports left, so also remove this network from the cache.
                _fix_network_cache_port_lookup(self.agent, net.id)
                self.agent.cache.remove(net)
                LOG.info("Disable dnsmasq for network %s", network_id)
                self.agent.call_driver('disable', net)

            # Remember what we've asked Dnsmasq for.
            self._last_dnsmasq_ports[network_id] = ports_needed_as_string
        else:
            LOG.debug("No change")

class CalicoEtcdWatcher(etcdutils.EtcdWatcher):

    def __init__(self, agent, hostname):
        self.region_string = calico_config.get_region_string()
        workload_endpoint_prefix = datamodel_v3._build_key(
            "WorkloadEndpoint",
            datamodel_v3.get_namespace(self.region_string),
            "",
        )
        this_host_prefix = (workload_endpoint_prefix +
                            hostname.replace('-', '--') +
                            "-openstack-")

        super(CalicoEtcdWatcher, self).__init__(this_host_prefix)
        self.agent = agent
        self.hostname = hostname
        self.suppress_dnsmasq_updates = False

        # Register the etcd paths that we need to watch.
        self.register_path(workload_endpoint_prefix + "<name>",
                           on_set=self.on_endpoint_set,
                           on_del=self.on_endpoint_delete)

        # Networks for which Dnsmasq needs updating.
        self.dirty_networks = set()

        # Use a separate thread for dnsmasq updating, so that we can
        # also trigger that for MTU changes.
        self.dnsmasq_updater = DnsmasqUpdater(agent)

        # Create MTU watcher.
        self.mtu_watcher = MTUWatcher(agent, self)

        # Also watch the etcd subnet trees: both the new region-aware
        # one, and the old pre-region one, so as to support a VM
        # renewing its DHCP lease while an upgrade is still in
        # progress.  When something in that subtree changes, the
        # subnet watcher will tell _this_ watcher to resync.
        self.v1_subnet_watcher = SubnetWatcher(self, datamodel_v1.SUBNET_DIR)
        self.subnet_watcher = SubnetWatcher(
            self,
            datamodel_v2.subnet_dir(self.region_string))

        # Cache of current local endpoint IDs.
        self.local_endpoint_ids = set()

    def start(self):
        eventlet.spawn(self.dnsmasq_updater.start)
        eventlet.spawn(self.mtu_watcher.run)
        eventlet.spawn(self.v1_subnet_watcher.start)
        eventlet.spawn(self.subnet_watcher.start)
        super(CalicoEtcdWatcher, self).start()

    def on_endpoint_set(self, response, name):
        """Handler for endpoint creations and updates.

        Endpoint data is, for example:

        { 'interfaceName': port['interface_name'],
          'mac': port['mac_address'],
          'profiles': port['security_groups'],
          'ipNetworks': ['10.28.0.2/32', '2001:db8:1::2/128'],
          'ipv4Gateway': '10.28.0.1',
          'ipv6Gateway': '2001:db8:1::1' }

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

        { 'network_id': <network ID>,
          'enable_dhcp': True,
          'ip_version': 4 or 6,
          'cidr': '10.28.0.0/24',
          'dns_nameservers': [],
          'id': <subnet ID>,
          'gateway_ip': <gateway IP address>,
          'host_routes': [],
          'ipv6_address_mode': 'dhcpv6-stateful' | 'dhcpv6-stateless',
          'ipv6_ra_mode': 'dhcpv6-stateful' | 'dhcpv6-stateless' }
        """
        try:
            hostname, orchestrator, workload_id, endpoint_id = \
                split_endpoint_name(name)
        except ValueError:
            # For some reason this endpoint's name does not have the expected
            # form.  Ignore it.
            LOG.warning("Unexpected form for endpoint name: %s", name)
            return

        if hostname != self.hostname:
            LOG.info("Endpoint not on this node: %s", name)
            return

        # Get the endpoint spec.
        endpoint = etcdutils.safe_decode_json(response.value, 'endpoint')
        if not (isinstance(endpoint, dict) and
                'spec' in endpoint and
                isinstance(endpoint['spec'], dict) and
                'interfaceName' in endpoint['spec'] and
                'ipNetworks' in endpoint['spec'] and
                'mac' in endpoint['spec']):
            # Endpoint data is invalid; treat as deletion.
            LOG.warning("Invalid endpoint data: %s => %s",
                        response.value, endpoint)
            self.on_endpoint_delete(None, name)
            return
        annotations = endpoint.get('metadata', {}).get('annotations', {})
        endpoint = endpoint['spec']

        # If the endpoint has no ipNetworks, treat as deletion.  This happens
        # when a resync from the mechanism driver overlaps with a port/VM being
        # deleted.
        if not endpoint['ipNetworks']:
            LOG.info("Endpoint has no ipNetworks: %s", endpoint)
            self.on_endpoint_delete(None, name)
            return

        # Construct NetModel port equivalent of Calico's endpoint data.
        fixed_ips = []
        dns_assignments = []
        fqdn = annotations.get(datamodel_v3.ANN_KEY_FQDN)
        network_id = annotations.get(datamodel_v3.ANN_KEY_NETWORK_ID)
        allowedIps = [e.split('/')[0] for e in endpoint.get('allowedIps', [])]
        for addrm in endpoint['ipNetworks']:
            ip_addr = addrm.split('/')[0]
            if ip_addr in allowedIps:
                continue
            subnet_id = self.subnet_watcher.get_subnet_id_for_addr(
                ip_addr,
                network_id
            ) or self.v1_subnet_watcher.get_subnet_id_for_addr(
                ip_addr,
                network_id
            )
            if subnet_id is None:
                LOG.warning("Missing subnet data for one of port's IPs")
                continue

            fixed_ips.append({'subnet_id': subnet_id,
                              'ip_address': ip_addr})

            if fqdn:
                dns_assignments.append({'hostname': fqdn.split('.')[0],
                                        'ip_address': ip_addr,
                                        'fqdn': fqdn})
        if not fixed_ips:
            LOG.warning("Endpoint has no DHCP-served IPs: %s", endpoint)
            return

        extra_dhcp_opts = []
        mtu = self.mtu_watcher.get_mtu(endpoint['interfaceName'])
        self.mtu_watcher.watch_port(endpoint_id, endpoint['interfaceName'])
        if mtu:
            extra_dhcp_opts.append(self.get_mtu_option(mtu))

        port = {'id': endpoint_id,
                'device_owner': 'calico',
                'device_id': endpoint['interfaceName'],
                'fixed_ips': fixed_ips,
                'mac_address': endpoint['mac'],
                # FIXME: Calico currently does not handle extra DHCP
                # options, other than MTU, but there might be use cases
                # where it should handle further options.
                # https://bugs.launchpad.net/networking-calico/+bug/1553348
                'extra_dhcp_opts': extra_dhcp_opts}
        if fqdn:
            port['dns_assignment'] = dns_assignments

        # Ensure that the cache includes the network and subnets for this port,
        # and set the port's network ID correctly.
        try:
            port['network_id'] = self._ensure_net_and_subnets(port)
        except SubnetIDNotFound:
            LOG.warning("Missing data for one of port's subnets")
            return

        # Report this at INFO level if it is a new port.  Note, we
        # come through this code periodically for existing ports also,
        # because of how we watch the etcd DB for changes.
        if endpoint_id not in self.local_endpoint_ids:
            LOG.info("New port: %s", port)
            self.local_endpoint_ids.add(endpoint_id)
        else:
            LOG.debug("Refresh already known port: %s", port)

        # Add this port into the NetModel.
        self.agent.cache.put_port(dhcp.DictModel(port))

        # If we have seen the TAP interface, schedule updating Dnsmasq;
        # otherwise wait until we do see the TAP interface, whereupon
        # _update_dnsmasq will be called again.  Dnsmasq updates can
        # take a little time, and they run in series, so it's best to
        # wait if we don't have the information we need yet, to avoid
        # delaying the correct Dnsmasq update that we really want.
        if mtu:
            self._update_dnsmasq(port['network_id'])

    def get_mtu_option(self, mtu):
        return dhcp.DictModel({
            'opt_name': 'mtu',
            'opt_value': str(mtu),
            'ip_version': 4,
        })

    # Note, on_mtu_change is called from MTU watcher's thread.
    def on_mtu_change(self, id, mtu):
        port = self.agent.cache.get_port_by_id(id)
        if port:
            LOG.info("MTU changed to %s for %s (%s)", mtu, port.device_id, id)
            port.extra_dhcp_opts = [self.get_mtu_option(mtu)]
            self.agent.cache.put_port(port)
            self._update_dnsmasq(port.network_id)

    def _ensure_net_and_subnets(self, port):
        """Ensure that the cache has a NetModel and subnets for PORT."""

        # Gather the subnet IDs that we need for this port, and get the
        # NetModel if we already have it in the cache.
        needed_subnet_ids = set()
        net = None
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip.get('subnet_id')
            if subnet_id:
                needed_subnet_ids.add(subnet_id)
                if not net:
                    net = self.agent.cache.get_network_by_subnet_id(subnet_id)
        LOG.debug("Needed subnet IDs: %s", needed_subnet_ids)
        LOG.debug("Existing network model by subnet ID: %s", net)

        # For each subnet that we need, get its data from SubnetWatcher and
        # hold for adding into the cache.
        new_subnets = {}
        for subnet_id in needed_subnet_ids:
            # Get data for this subnet from the SubnetWatchers.
            subnet = (self.subnet_watcher.get_subnet(subnet_id) or
                      self.v1_subnet_watcher.get_subnet(subnet_id))
            if subnet is None:
                LOG.warning("No data for subnet %s", subnet_id)
                raise SubnetIDNotFound()
            new_subnets[subnet_id] = subnet

        if not net:
            # We don't already have a NetModel, so look for a cached NetModel
            # with the right network ID.  (In this case we must have new
            # subnets to add into the cache, and the cached NetModel must have
            # subnets other than the ones that we're adding in this iteration;
            # otherwise we would have already found it when searching by
            # subnet_id above.)
            assert new_subnets
            network_id = list(new_subnets.values())[0]['network_id']
            net = self.agent.cache.get_network_by_id(network_id)
            LOG.debug("Existing network model by network ID: %s", net)

        if not net:
            # We still have no NetModel for the relevant network ID, so create
            # a new one.  In this case we _must_ be adding new subnets.
            assert new_subnets
            net = empty_network(network_id)
            LOG.debug("New network %s", net)
        elif new_subnets:
            # We have a NetModel that was already in the cache and are about to
            # modify it.  Cache replacement only works if the new NetModel is a
            # distinct object from the existing one, so make a copy here.
            net = copy_network(net)
            LOG.debug("Copied network %s", net)

        if new_subnets:
            # Add the new subnets into the NetModel.
            assert net
            net.subnets = [s for s in net.subnets
                           if s.id not in new_subnets]
            net.subnets += list(new_subnets.values())

            # Add (or update) the NetModel in the cache.
            LOG.debug("Net: %s", net)
            _fix_network_cache_port_lookup(self.agent, net.id)
            self.agent.cache.put(net)

        return net.id

    def _update_dnsmasq(self, network_id):
        """Start/stop/restart Dnsmasq for NETWORK_ID."""

        # Check whether we should really do the following processing.
        if self.suppress_dnsmasq_updates:
            LOG.debug("Don't update dnsmasq yet;"
                      " must be processing a snapshot")
            self.dirty_networks.add(network_id)
            return

        self.dnsmasq_updater.update_network(network_id)

    def on_endpoint_delete(self, response_ignored, name):
        """Handler for endpoint deletion."""
        try:
            hostname, orchestrator, workload_id, endpoint_id = \
                split_endpoint_name(name)
        except ValueError:
            # For some reason this endpoint's name does not have the expected
            # form.  Ignore it.
            LOG.warning("Unexpected form for endpoint name: %s", name)
            return

        # Remove endpoint ID from our cache.  Note, it might not be
        # there because we haven't checked whether the endpoint just
        # deleted is a local one; hence 'discard' instead of 'remove'.
        self.local_endpoint_ids.discard(endpoint_id)

        # Find the corresponding port in the DHCP agent's cache.
        port = self.agent.cache.get_port_by_id(endpoint_id)
        if port:
            LOG.debug("deleted port: %s", port)
            self.mtu_watcher.unwatch_port(endpoint_id, port.device_id)
            self.agent.cache.remove_port(port)
            self._update_dnsmasq(port.network_id)

    def _pre_snapshot_hook(self):
        """Called when a new snapshot is about to be read from etcdv3."""

        # Add all current networks to the dirty set, so that we will stop their
        # Dnsmasqs if no longer needed.  Also remove all port and subnet
        # information.
        LOG.debug("Reset cache for new snapshot")
        for network_id in list(self.agent.cache.get_network_ids()):
            self.dirty_networks.add(network_id)
            _fix_network_cache_port_lookup(self.agent, network_id)
            self.agent.cache.put(empty_network(network_id))

        # Suppress Dnsmasq updates until we've processed the whole snapshot.
        self.suppress_dnsmasq_updates = True
        return None

    def _post_snapshot_hook(self, _):
        LOG.debug("End of new snapshot")

        # Now do Dnsmasq updates.
        self.suppress_dnsmasq_updates = False
        for network_id in self.dirty_networks:
            self._update_dnsmasq(network_id)
        self.dirty_networks = set()


def _fix_network_cache_port_lookup(agent, network_id):
    """Fix NetworkCache before removing or replacing a network.

    neutron.agent.dhcp.agent is bugged in that it adds the DHCP port into
    the cache without updating the cache's port_lookup dict, but then
    NetworkCache.remove() barfs if there is a port in network.ports but not
    in that dict...

    NetworkCache.put() implicitly does a remove() first if there is already
    a NetModel in the cache with the same ID.  So a put() to update or
    replace a network also hits this problem.

    This method avoids that problem by ensuring that all of a network's
    ports are in the port_lookup dict.  A caller should call this
    immediately before a remove() or a put().
    """

    # If there is an existing NetModel for this network ID, ensure that all
    # its ports are in the port_lookup dict.
    if network_id in agent.cache.cache:
        for port in agent.cache.cache[network_id].ports:
            agent.cache.port_lookup[port.id] = network_id


class SubnetIDNotFound(Exception):
    pass


class SubnetWatcher(etcdutils.EtcdWatcher):

    def __init__(self, endpoint_watcher, path):
        super(SubnetWatcher, self).__init__(path)
        self.endpoint_watcher = endpoint_watcher
        self.register_path(path + "/<subnet_id>",
                           on_set=self.on_subnet_set,
                           on_del=self.on_subnet_del)
        self.subnets_by_id = {}

    def start(self):
        # Catch and report any exceptions that escape here.
        try:
            super(SubnetWatcher, self).start()
        except Etcd3Exception as e3e:
            LOG.exception("Etcd3Exception in SubnetWatcher.start():\n%s",
                          e3e.detail_text)
            raise
        except:                 # noqa
            LOG.exception("Exception in SubnetWatcher.start()")
            raise
        finally:
            # As this thread is exiting, arrange for the agent as a whole to
            # exit.
            self.endpoint_watcher.stop()

    def on_subnet_set(self, response, subnet_id):
        """Handler for subnet creations and updates."""
        LOG.debug("Subnet %s created or updated", subnet_id)
        subnet_data = etcdutils.safe_decode_json(response.value, 'subnet')

        if subnet_data is None:
            LOG.warning("Invalid subnet data %s", response.value)
            return

        if not (isinstance(subnet_data, dict) and
                'cidr' in subnet_data and
                'gateway_ip' in subnet_data):
            LOG.warning("Invalid subnet data: %s", subnet_data)
            return

        self.subnets_by_id[subnet_id] = subnet_data
        return

    def on_subnet_del(self, response, subnet_id):
        """Handler for subnet deletions."""
        LOG.info("Subnet %s deleted", subnet_id)
        if subnet_id in self.subnets_by_id:
            del self.subnets_by_id[subnet_id]
        return

    def get_subnet_id_for_addr(self, ip_str, network_id):
        ip_addr = netaddr.IPAddress(ip_str)
        for subnet_id, subnet_data in self.subnets_by_id.items():
            # If we know we're looking within a given Neutron network, only
            # consider this subnet if it belongs to that network.
            if network_id and subnet_data['network_id'] != network_id:
                continue
            if ip_addr in netaddr.IPNetwork(subnet_data['cidr']):
                return subnet_id
        return None

    def get_subnet(self, subnet_id):
        """Get data for the specified subnet."""
        LOG.debug("Get subnet %s", subnet_id)

        if subnet_id not in self.subnets_by_id:
            return None

        data = self.subnets_by_id[subnet_id]
        LOG.debug("Subnet data: %s", data)

        # Convert to form expected by NetModel.
        ip_version = 6 if ':' in data['cidr'] else 4
        subnet = {'enable_dhcp': True,
                  'ip_version': ip_version,
                  'cidr': data['cidr'],
                  'dns_nameservers': data.get('dns_servers') or [],
                  'id': subnet_id,
                  'gateway_ip': data['gateway_ip'],
                  'host_routes': data.get('host_routes', []),
                  'network_id': data.get('network_id', NETWORK_ID)}
        if ip_version == 6:
            subnet['ipv6_address_mode'] = DHCPV6_STATEFUL
            subnet['ipv6_ra_mode'] = DHCPV6_STATEFUL

        return dhcp.DictModel(subnet)


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
        try:
            hostname = cfg.CONF.host
        except AttributeError:
            # We get AttributeError (or an exception derived from that) if that
            # config option does not exist, in an old enough Neutron release.
            hostname = socket.gethostname()
        super(CalicoDhcpAgent, self).__init__(host=hostname)

        # Override settings that Calico's DHCP agent use requires.
        self.conf.set_override('enable_isolated_metadata', False)
        try:
            self.conf.set_override('use_namespaces', False)
        except cfg.NoSuchOptError:
            # Option removed in Mitaka, with the behaviour of the reference
            # DHCP agent code being hardcoded to assume that it should always
            # _use_ a namespace - which unfortunately is wrong for Calico
            # usage.  We compensate for this through a combination of the
            # make_net_model code above, and subclassing and overriding
            # particular DHCP agent methods so that they don't do
            # namespace-specific actions.
            pass
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
        self.etcd = CalicoEtcdWatcher(self, hostname)

    def run(self):
        """Run the EtcdWatcher loop."""
        self.etcd.start()


def setup_logging():
    config.setup_logging()

    # logging is set up as it is done for neutron agent, so
    # in order to log additionally to file we simply need to add
    # file handler to root logger
    root_logger = logging.getLogger()

    # FIXME(aroma-x) - move logging settings to configuration
    # file in future
    log_file = '/var/log/neutron/dhcp-agent.log'
    log_format = ('%(asctime)s [%(thread)d] (%(levelname)s) '
                  '%(module)s: %(message)s')
    log_level = logging.DEBUG

    # Ensure that log file directory exists.
    mkdir_p(os.path.dirname(log_file))

    fh = logging.FileHandler(log_file)
    fh.setLevel(log_level)
    fh.setFormatter(logging.Formatter(log_format))

    root_logger.addHandler(fh)


def main():
    register_options(cfg.CONF)
    calico_config.register_options(cfg.CONF)
    common_config.init(sys.argv[1:])
    setup_logging()
    try:
        # Neutron agent code has been migrating from rootwrap to privsep.
        # Initialize the privsep system if it is available.
        config.setup_privsep()
    except Exception as e:
        # But don't worry if it isn't; that means we are running with older
        # Neutron code.
        LOG.info("Couldn't setup_privsep(): %r", e)
    agent = CalicoDhcpAgent()
    agent.run()
