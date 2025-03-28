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

import copy
import netaddr
import os
import re
import sys
import time

from neutron.agent.linux import dhcp
from oslo_log import log as logging

from networking_calico.compat import constants

LOG = logging.getLogger(__name__)


class DnsmasqRouted(dhcp.Dnsmasq):
    """Dnsmasq DHCP driver for routed virtual interfaces."""

    def __init__(self, conf, network, process_monitor,
                 version=None, plugin=None, *args):
        if args:
            super(DnsmasqRouted, self).__init__(conf, network, process_monitor,
                                                version, plugin, *args)
        else:
            super(DnsmasqRouted, self).__init__(conf, network, process_monitor,
                                                version, plugin)
        self.device_manager = CalicoDeviceManager(self.conf, plugin)

    # Frozen copy of Dnsmasq::_build_cmdline_callback from
    # neutron/agent/linux/dhcp.py in Neutron 13.0.2.
    def neutron_13_0_2_build_cmdline_callback(self, pid_file):
        # We ignore local resolv.conf if dns servers are specified
        # or if local resolution is explicitly disabled.
        _no_resolv = (
            '--no-resolv' if self.conf.dnsmasq_dns_servers or
            not self.conf.dnsmasq_local_resolv else '')
        cmd = [
            'dnsmasq',
            '--no-hosts',
            _no_resolv,
            '--except-interface=lo',
            '--pid-file=%s' % pid_file,
            '--dhcp-hostsfile=%s' % self.get_conf_file_name('host'),
            '--addn-hosts=%s' % self.get_conf_file_name('addn_hosts'),
            '--dhcp-optsfile=%s' % self.get_conf_file_name('opts'),
            '--dhcp-leasefile=%s' % self.get_conf_file_name('leases'),
            '--dhcp-match=set:ipxe,175',
        ]
        if self.device_manager.driver.bridged:
            cmd += [
                '--bind-interfaces',
                '--interface=%s' % self.interface_name,
            ]
        else:
            cmd += [
                '--bind-dynamic',
                '--interface=%s' % self.interface_name,
                '--interface=tap*',
                '--bridge-interface=%s,tap*' % self.interface_name,
            ]

        possible_leases = 0
        for i, subnet in enumerate(self._get_all_subnets(self.network)):
            mode = None
            # if a subnet is specified to have dhcp disabled
            if not subnet.enable_dhcp:
                continue
            if subnet.ip_version == 4:
                mode = 'static'
            else:
                # Note(scollins) If the IPv6 attributes are not set, set it as
                # static to preserve previous behavior
                addr_mode = getattr(subnet, 'ipv6_address_mode', None)
                ra_mode = getattr(subnet, 'ipv6_ra_mode', None)
                if (addr_mode in [constants.DHCPV6_STATEFUL,
                                  constants.DHCPV6_STATELESS] or
                        not addr_mode and not ra_mode):
                    mode = 'static'

            cidr = netaddr.IPNetwork(subnet.cidr)

            if self.conf.dhcp_lease_duration == -1:
                lease = 'infinite'
            else:
                lease = '%ss' % self.conf.dhcp_lease_duration

            # mode is optional and is not set - skip it
            if mode:
                if subnet.ip_version == 4:
                    cmd.append('--dhcp-range=%s%s,%s,%s,%s,%s' %
                               ('set:', 'subnet-%s' % subnet.id,
                                cidr.network, mode, cidr.netmask, lease))
                else:
                    if cidr.prefixlen < 64:
                        LOG.debug('Ignoring subnet %(subnet)s, CIDR has '
                                  'prefix length < 64: %(cidr)s',
                                  {'subnet': subnet.id, 'cidr': cidr})
                        continue
                    cmd.append('--dhcp-range=%s%s,%s,%s,%d,%s' %
                               ('set:', 'subnet-%s' % subnet.id,
                                cidr.network, mode,
                                cidr.prefixlen, lease))
                possible_leases += cidr.size

        mtu = getattr(self.network, 'mtu', 0)
        # Do not advertise unknown mtu
        if mtu > 0:
            cmd.append('--dhcp-option-force=option:mtu,%d' % mtu)

        # Cap the limit because creating lots of subnets can inflate
        # this possible lease cap.
        cmd.append('--dhcp-lease-max=%d' %
                   min(possible_leases, self.conf.dnsmasq_lease_max))

        try:
            if self.conf.dhcp_renewal_time > 0:
                cmd.append('--dhcp-option-force=option:T1,%ds' %
                           self.conf.dhcp_renewal_time)
        except AttributeError:
            pass

        try:
            if self.conf.dhcp_rebinding_time > 0:
                cmd.append('--dhcp-option-force=option:T2,%ds' %
                           self.conf.dhcp_rebinding_time)
        except AttributeError:
            pass

        cmd.append('--conf-file=%s' % self.conf.dnsmasq_config_file)
        for server in self.conf.dnsmasq_dns_servers:
            cmd.append('--server=%s' % server)

        try:
            if self.conf.dns_domain:
                cmd.append('--domain=%s' % self.conf.dns_domain)
        except AttributeError:
            try:
                if self.dns_domain:
                    cmd.append('--domain=%s' % self.dns_domain)
            except AttributeError:
                pass

        if self.conf.dhcp_broadcast_reply:
            cmd.append('--dhcp-broadcast')

        if self.conf.dnsmasq_base_log_dir:
            log_dir = os.path.join(
                self.conf.dnsmasq_base_log_dir,
                self.network.id)
            try:
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir)
            except OSError:
                LOG.error('Error while create dnsmasq log dir: %s', log_dir)
            else:
                log_filename = os.path.join(log_dir, 'dhcp_dns_log')
                cmd.append('--log-queries')
                cmd.append('--log-dhcp')
                cmd.append('--log-facility=%s' % log_filename)

        return cmd

    def _build_cmdline_callback(self, pid_file):
        cmd = self.neutron_13_0_2_build_cmdline_callback(pid_file)

        # Replace 'static' by 'static,off-link' in all IPv6
        # --dhcp-range options.
        prog = re.compile('(--dhcp-range=set:[^,]+,[0-9a-f:]+),static,(.*)')
        for option in copy.copy(cmd):
            m = prog.match(option)
            if m:
                cmd.remove(option)
                cmd.append(m.group(1) + ',static,off-link,' + m.group(2))

        # Add '--enable-ra'.
        cmd.append('--enable-ra')

        # Enumerate precisely the TAP interfaces to listen on.
        cmd.remove('--interface=tap*')
        cmd.remove('--bridge-interface=%s,tap*' % self.interface_name)
        bridge_option = '--bridge-interface=%s' % self.interface_name
        bridge_ports_added = False
        for port in self.network.ports:
            if port.device_id.startswith('tap'):
                LOG.debug('Listen on %s', port.device_id)
                cmd.append('--interface=%s' % port.device_id)
                bridge_option = bridge_option + ',' + port.device_id
                bridge_ports_added = True
        if bridge_ports_added:
            cmd.append(bridge_option)

        return cmd

    def _destroy_namespace_and_port(self):
        try:
            self.device_manager.destroy(self.network, self.interface_name)
        except RuntimeError:
            LOG.warning('Failed trying to delete interface: %s',
                        self.interface_name)


class CalicoDeviceManager(dhcp.DeviceManager):
    """Device manager for the default namespace that Calico operates in."""

    def _set_default_route(self, network, device_name):
        pass

    def _cleanup_stale_devices(self, network, dhcp_port):
        pass

    def fill_dhcp_udp_checksums(self, *args, **kwargs):
        # NOTE(tstachecki): Very old versions of isc-dhcp-client broke when
        # UDP packets had a checksum field not properly filled in as part of
        # GSO/checksum offload support being introduced for virtio_net:
        # https://lwn.net/Articles/373209/
        #
        # The missing/incorrect checksum in the UDP header was problematic for
        # isc-dhcp-client (and possibly other DHCP clients) because they use
        # raw sockets, and were unaware of how to handle
        # TP_STATUS_CSUMNOTREADY.
        #
        # OpenStack has historically worked around this by adding an iptables
        # mangle rule to always rewrite the UDP header for DHCP packets. But,
        # isc-dhcp-client has also been patched to account for this since 2014,
        # and likewise has qemu (for virtio_net) since 2009:
        # https://git.qemu.org/?p=qemu.git;a=commit;h=1d41b0c
        #
        # The consequence of patching the mangle rule in iptables is that the
        # underlying OpenStack mechanisms tend to add the rules in an order
        # that upsets Felix. When Felix sees this (often during live-migration,
        # when the VM has no networking), it can spend a fair amount of time
        # resyncing the rules... thus leaving a live-migrating instance with
        # no networking for an appreciable amount of time.
        #
        # As this should not be needed for any Linux distribution in the last
        # decade and it can perturb Felix, simply do not add in an iptables
        # rule to fill in DHCP UDP checksums here with the assumption that it
        # it has been fixed/is being done elsewhere.
        pass
