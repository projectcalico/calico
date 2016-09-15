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
import re

from neutron.agent.linux import dhcp
from neutron.common import constants
from oslo_log import log as logging


LOG = logging.getLogger(__name__)
WIN2k3_STATIC_DNS = 249


class DnsmasqRouted(dhcp.Dnsmasq):
    """Dnsmasq DHCP driver for routed virtual interfaces."""

    def __init__(self, conf, network, process_monitor,
                 version=None, plugin=None):
        super(DnsmasqRouted, self).__init__(conf, network, process_monitor,
                                            version, plugin)
        self.device_manager = CalicoDeviceManager(self.conf, plugin)

    def _build_cmdline_callback(self, pid_file):
        cmd = super(DnsmasqRouted, self)._build_cmdline_callback(pid_file)

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
        for port in self.network.ports:
            if port.device_id.startswith('tap'):
                LOG.debug('Listen on %s', port.device_id)
                cmd.append('--interface=%s' % port.device_id)
                bridge_option = bridge_option + ',' + port.device_id
        cmd.append(bridge_option)

        return cmd

    def _destroy_namespace_and_port(self):
        try:
            self.device_manager.destroy(self.network, self.interface_name)
        except RuntimeError:
            LOG.warning('Failed trying to delete interface: %s',
                        self.interface_name)

    def _generate_opts_per_subnet(self):
        options = []
        subnet_index_map = {}
        for i, subnet in enumerate(self.network.subnets):
            addr_mode = getattr(subnet, 'ipv6_address_mode', None)
            if (not subnet.enable_dhcp or
                (subnet.ip_version == 6 and
                 addr_mode == constants.IPV6_SLAAC)):
                continue
            if subnet.dns_nameservers:
                options.append(
                    self._format_option(
                        subnet.ip_version, i, 'dns-server',
                        ','.join(
                            dhcp.Dnsmasq._convert_to_literal_addrs(
                                subnet.ip_version, subnet.dns_nameservers))))
            else:
                # use the dnsmasq ip as nameservers only if there is no
                # dns-server submitted by the server
                subnet_index_map[subnet.id] = i

            if self.conf.dhcp_domain and subnet.ip_version == 6:
                options.append('tag:tag%s,option6:domain-search,%s' %
                               (i, ''.join(self.conf.dhcp_domain)))

            gateway = subnet.gateway_ip
            host_routes = []
            for hr in subnet.host_routes:
                if hr.destination == constants.IPv4_ANY:
                    if not gateway:
                        gateway = hr.nexthop
                else:
                    host_routes.append("%s,%s" % (hr.destination, hr.nexthop))

            if subnet.ip_version == 4:
                if host_routes:
                    if gateway:
                        host_routes.append("%s,%s" % (constants.IPv4_ANY,
                                                      gateway))
                    options.append(
                        self._format_option(subnet.ip_version, i,
                                            'classless-static-route',
                                            ','.join(host_routes)))
                    options.append(
                        self._format_option(subnet.ip_version, i,
                                            WIN2k3_STATIC_DNS,
                                            ','.join(host_routes)))

                if gateway:
                    options.append(self._format_option(subnet.ip_version,
                                                       i, 'router',
                                                       gateway))
                else:
                    options.append(self._format_option(subnet.ip_version,
                                                       i, 'router'))
        return options, subnet_index_map


class CalicoDeviceManager(dhcp.DeviceManager):
    """Device manager for the default namespace that Calico operates in."""

    def _set_default_route(self, network, device_name):
        pass

    def _cleanup_stale_devices(self, network, dhcp_port):
        pass
