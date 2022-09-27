# Copyright 2015-2016 Metaswitch Networks
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

import netaddr

from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib

from networking_calico.compat import cfg
from networking_calico.compat import log as logging


LOG = logging.getLogger(__name__)


class RoutedInterfaceDriver(interface.LinuxInterfaceDriver):
    """Driver for DHCP service for routed virtual interfaces."""

    DEV_NAME_PREFIX = 'ns-'

    def __init__(self, conf, get_networks_callback=None):
        super(RoutedInterfaceDriver, self).__init__(conf)

    @property
    def use_gateway_ips(self):
        # Routed networking does not bridge across compute hosts or
        # network nodes, so the DHCP port can use the gateway IP
        # address of each subnet for which it is handing out
        # addresses, instead of requiring a fresh Neutron-allocated IP
        # address.
        return True

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None, mtu=None,
                 link_up=True):
        """Plugin the interface."""
        ip = ip_lib.IPWrapper()

        # Create dummy interface (in the default namespace).
        ns_dummy = ip.add_dummy(device_name)
        ns_dummy.link.set_address(mac_address)

        try:
            mtu = self.conf.network_device_mtu or mtu
        except cfg.NoSuchOptError:
            pass
        if mtu:
            ns_dummy.link.set_mtu(mtu)

        ns_dummy.link.set_up()

    def set_mtu(self, device_name, mtu, namespace=None, prefix=None):
        pass

    def init_l3(self, device_name, ip_cidrs, namespace=None,
                preserve_ips=[], gateway=None, extra_subnets=[]):
        """L3 initialization for RoutedInterfaceDriver.

        Extend LinuxInterfaceDriver.init_l3 to remove the subnet
        route(s) that Linux automatically creates.
        """
        super(RoutedInterfaceDriver, self).init_l3(device_name, ip_cidrs)
        device = ip_lib.IPDevice(device_name)
        device.set_log_fail_as_error(False)
        for ip_cidr in ip_cidrs:
            LOG.debug("Remove subnet route for cidr %s" % ip_cidr)
            net = netaddr.IPNetwork(ip_cidr)
            LOG.debug("=> real cidr %s" % net.cidr)
            try:
                device.route.delete_onlink_route(str(net.cidr))
            except Exception:
                # The "does not exist" condition used to be a
                # RuntimeError but is now a pyroute2 NetlinkError,
                # which apparently does not derive from RuntimeError.
                # I don't want to code an explicit pyroute2 dependency
                # here, so fall back to using Exception.
                LOG.debug("Subnet route %s did not exist" % net.cidr)

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        device = ip_lib.IPDevice(device_name, namespace)
        try:
            device.link.delete()
            LOG.debug("Unplugged interface '%s'", device_name)
        except RuntimeError:
            LOG.error("Failed unplugging interface '%s'", device_name)

    @property
    def bridged(self):
        return False
