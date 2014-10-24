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
        # Constructor parsed the address fields.
        self.gateway = fields['gateway'].encode('ascii')
        self.ipv4    = fields['addr'].encode('ascii')

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
        self.addresses      = set()

        # pending_resync is set True when we want to resync all data,
        # and this particular endpoint has NOT received an update.
        self.pending_resync = False  # Are we waiting for an EP resync?

        self.need_acls      = True   # Need to get ACL data back?
        self.acl_data       = None   # ACL data structure

    def remove(self):
        # Delete a programmed endpoint. Remove the rules only, since the routes will vanish
        # due course.
        futils.del_rules(self.suffix)

    def program_endpoint(self):
        # Given an endpoint, make the programmed state match the non-programmed state.
        #
        # Note that if acl_data is none, the ACLs are "do not allow any traffic except
        # DHCP"
        if not futils.tap_exists(self.tap):
            # TODO: need to retry at some point, not just give up until next resync
            log.error("Unable to configure non-existent interface %s" % self.tap)
            return

        routes        = futils.list_routes(self.tap)
        ipv4_intended = set()

        futils.configure_tap(self.tap)

        for addr in self.addresses:
            ipv4_intended.add(addr.ipv4)

            if addr.ipv4 not in routes:
                log.info("Add route to address %s for tap %s" % (addr.ipv4, self.tap))
                futils.add_route(addr.ipv4, self.tap)
            else:
                log.debug("Already got route to address %s for tap %s" % (addr.ipv4, self.tap))

        for ipv4 in routes:
            if ipv4 not in ipv4_intended:
                log.info("Remove extra route to address %s for tap %s" % (ipv4, self.tap))
                futils.del_route(ipv4, self.tap)

        localips = { addr.ipv4.encode('ascii') for addr in self.addresses }
        print localips

        futils.set_rules(self.suffix, self.tap, localips, self.mac)

    def update_acls(self, acls):
        """
        Updates the ACL state of a machine.
        """
        self.need_acls = False
        self.acl_data = acls

        log.debug("Update ACLs for endpoint %s" % self.suffix)
        inbound     = acls['v4']['inbound']
        in_default  = acls['v4']['inbound_default']
        outbound    = acls['v4']['outbound']
        out_default = acls['v4']['outbound_default']

        log.debug("ACLs for %s are %s" % (self.suffix, acls))
        log.debug("inbound for %s are %s" % (self.suffix, inbound))

        futils.set_acls(self.suffix,inbound,in_default,outbound,out_default)

