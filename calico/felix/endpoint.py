# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
#
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
"""
felix.endpoint
~~~~~~~~~~~~~~

Contains Felix logic to manage endpoints and their configuration.
"""

from calico.felix import futils
import logging
import subprocess

log = logging.getLogger(__name__)


class Address(object):
    """
    An address as reported to felix by the plugin
    """
    def __init__(self, fields):
        if fields['gateway'] is None:
            self.gateway = None
        else:
            self.gateway = fields['gateway'].encode('ascii')

        self.ip      = fields['addr'].encode('ascii')
        if ":" in self.ip:
            self.type = futils.IPV6
        else:
            self.type = futils.IPV4

class Endpoint(object):
    """
    Endpoint represents an endpoint in a Calico network, managed by a specific
    instance of Felix.
    """
    def __init__(self, uuid, mac):
        self.uuid           = uuid.encode('ascii')
        self.suffix         = uuid.encode('ascii')[:11]
        self.tap            = "tap" + self.suffix
        self.mac            = mac.encode('ascii')

        # Addresses is a set of addresses.
        self.addresses      = set()

        # pending_resync is set True when we want to resync all data,
        # and this particular endpoint has NOT received an update.
        self.pending_resync = False  # Are we waiting for an EP resync?

        self.need_acls      = True   # Need to get ACL data back?
        self.acl_data       = None   # ACL data structure

    def remove(self):
        # Delete a programmed endpoint. Remove the rules only, since the routes will vanish
        # due course when the tap interface goes.
        futils.del_rules(self.suffix, futils.IPV4)
        futils.del_rules(self.suffix, futils.IPV6)

    def program_endpoint(self):
        # Given an endpoint, make the programmed state match the non-programmed state.
        #
        # Note that if acl_data is none, the ACLs are "do not allow any traffic except
        # DHCP"
        #
        # Returns True if the endpoint needs to be retried.
        if not futils.tap_exists(self.tap):
            # TODO: need to retry at some point, not just give up until next resync
            log.error("Unable to configure non-existent interface %s" % self.tap)
            return True

        ipv4_routes   = futils.list_routes(futils.IPV4, self.tap)
        ipv6_routes   = futils.list_routes(futils.IPV6, self.tap)
        ipv6_intended = set()

        # Configure the tap interface.
        futils.configure_tap(self.tap)

        # Build up list of addresses that should be present
        ipv4_intended = set([addr.ip.encode('ascii') for addr in self.addresses
                             if addr.type is futils.IPV4])
        ipv6_intended = set([addr.ip.encode('ascii') for addr in self.addresses
                             if addr.type is futils.IPV6])

        for ipv4 in ipv4_intended:
            if ipv4 not in ipv4_routes:
                log.info("Add route to IPv4 address %s for tap %s" % (ipv4, self.tap))
                futils.add_route(futils.IPV4, ipv4, self.tap)
            else:
                log.debug("Already got route to address %s for tap %s" % (ipv4, self.tap))

        for ipv6 in ipv6_intended:
            if ipv6 not in ipv6_routes:
                log.info("Add route to IPv6 address %s for tap %s" % (ipv6, self.tap))
                futils.add_route(futils.IPV6, ipv6, self.tap)
            else:
                log.debug("Already got route to address %s for tap %s" % (ipv4, self.tap))

        for ipv4 in ipv4_routes:
            if ipv4 not in ipv4_intended:
                log.info("Remove extra IPv4 route to address %s for tap %s" % (ipv4, self.tap))
                futils.del_route(futils.IPV4, ipv4, self.tap)

        for ipv6 in ipv6_routes:
            if ipv6 not in ipv6_intended:
                log.info("Remove extra IPv6 route to address %s for tap %s" % (ipv6, self.tap))
                futils.del_route(futils.IPV6, ipv6, self.tap)

        futils.set_rules(self.suffix, self.tap, futils.IPV4, ipv4_intended, self.mac)
        futils.set_rules(self.suffix, self.tap, futils.IPV6, ipv6_intended, self.mac)

        return False

    def update_acls(self, acls):
        """
        Updates the ACL state of a machine.
        """
        self.need_acls = False
        self.acl_data = acls

        log.debug("Update ACLs for endpoint %s" % self.suffix)

        log.debug("ACLs for %s are %s" % (self.suffix, acls))

        inbound     = acls['v4']['inbound']
        in_default  = acls['v4']['inbound_default']
        outbound    = acls['v4']['outbound']
        out_default = acls['v4']['outbound_default']

        futils.set_acls(self.suffix, futils.IPV4, inbound, in_default, outbound, out_default)

        inbound     = acls['v6']['inbound']
        in_default  = acls['v6']['inbound_default']
        outbound    = acls['v6']['outbound']
        out_default = acls['v6']['outbound_default']

        futils.set_acls(self.suffix, futils.IPV6, inbound, in_default, outbound, out_default)

