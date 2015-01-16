# -*- coding: utf-8 -*-

# Copyright (c) 2014 Metaswitch Networks
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

"""
felix.endpoint
~~~~~~~~~~~~~~

Contains Felix logic to manage endpoints and their configuration.
"""
from calico.felix import devices
from calico.felix import frules
from calico.felix import futils
import logging

log = logging.getLogger(__name__)


class Address(object):
    """
    An address as reported to Felix by the plugin (ignoring fields that Felix
    does not use). The input *fields* parameter is the fields from the API
    ENDPOINTCREATED (or other ENDPOINT*) request, of which we just need the
    address.
    """
    def __init__(self, fields):
        #*********************************************************************#
        #* An address must have an IP field, and so if we get one that does  *#
        #* not have one we should throw an exception.                        *#
        #*********************************************************************#
        self.ip = fields['addr'].encode('ascii')
        if ":" in self.ip:
            self.type = futils.IPV6
        else:
            self.type = futils.IPV4


class Endpoint(object):
    """
    Endpoint represents an endpoint in a Calico network, managed by a specific
    instance of Felix.
    """
    STATE_ENABLED  = "enabled"
    STATE_DISABLED = "disabled"
    STATES         = [STATE_ENABLED, STATE_DISABLED]

    def __init__(self, uuid, mac):
        self.uuid           = uuid.encode('ascii')
        self.suffix         = uuid.encode('ascii')[:11]
        self.tap            = "tap" + self.suffix
        self.mac            = mac.encode('ascii')

        # Addresses is a set of Address objects.
        self.addresses      = set()

        #*********************************************************************#
        #* pending_resync is set True when we have triggered a resync and    *#
        #* this particular endpoint has NOT received an update for that      *#
        #* resync. This allows us to spot when an endpoint should be removed *#
        #* (because the resync says it no longer exists).                    *#
        #*********************************************************************#
        self.pending_resync = False

        #*********************************************************************#
        #* ACL data structure. This is set to "None" when there are no ACLs  *#
        #* (before the ACL manager has told us about them for a new          *#
        #* endpoint), and is otherwise set to the acls field from the        *#
        #* ACLUPDATE request for the endpoint.                               *#
        #*                                                                   *#
        #* Critically, we do not update ACLs until we have got the first     *#
        #* GETACLUPDATE. If this is a new endpoint, that is fine - no        *#
        #* traffic can enter or leave the endpoint IPs until the ACLs are    *#
        #* first set up. If this is not a new endpoint, then we should leave *#
        #* any ACLs in place from when they were last configured.            *#
        #*********************************************************************#
        self.acl_data       = None   # ACL data structure

        # Assume disabled until we know different
        self.state          = Endpoint.STATE_DISABLED

    def remove(self):
        # Delete a programmed endpoint. Remove the rules only, since the routes
        # will vanish in due course when the tap interface goes.
        frules.del_rules(self.suffix, futils.IPV4)
        frules.del_rules(self.suffix, futils.IPV6)

    def program_endpoint(self):
        """
        Given an endpoint, make the programmed state match the desired state,
        setting up rules and creating chains and ipsets, but not putting
        content into the ipsets (leaving that for frules.update_acls).

        Note that if acl_data is none, we have not received any ACLs, and so
        we just leave the ACLs in place until we do. If there are none because
        this is a new endpoint, then we leave the endpoint with all routing
        disabled until we know better.

        The logic here is that we should create the routes and basic rules, but
        not the ACLs - leaving the ACLs as they were or with no access
        permitted if none. That is because we have the information for the
        former (routes and IP addresses for the endpoint) but not the latter
        (ACLs). However this split only makes sense at the point where the ACLs
        must have a default rule of "deny", so when issue39 is fully resolved
        this method should only be called when the ACLs are available too.

        Returns True if the endpoint needs to be retried (because the tap
        interface does not exist yet).
        """
        if not devices.tap_exists(self.tap):
            if self.state == Endpoint.STATE_ENABLED:
                log.error("Unable to configure non-existent interface %s" %
                          self.tap)
                return True
            else:
                # No tap interface, but disabled. This is not an error, and
                # there is nothing to do.
                log.debug("Tap interface missing when disabling endpoint %s" %
                          self.uuid)
                return False

        # If the interface is down, we can't configure it.
        if not devices.interface_up(self.tap):
            log.error("Unable to configure interface %s: interface is down." %
                      self.tap)
            return True

        # Configure the tap interface.
        if self.state == Endpoint.STATE_ENABLED:
            devices.configure_tap(self.tap)

            # Build up list of addresses that should be present
            ipv4_intended = set([addr.ip.encode('ascii')
                                 for addr in self.addresses
                                 if addr.type is futils.IPV4])
            ipv6_intended = set([addr.ip.encode('ascii')
                                 for addr in self.addresses
                                 if addr.type is futils.IPV6])
        else:
            # Disabled endpoint; we should remove all the routes.
            ipv4_intended = set()
            ipv6_intended = set()

        ipv4_existing   = devices.list_tap_ips(futils.IPV4, self.tap)
        ipv6_existing   = devices.list_tap_ips(futils.IPV6, self.tap)

        # Determine the addresses to add, remove and that won't be changed.
        # These are rapid operations because we're using sets.
        ipv4_add = ipv4_intended - ipv4_existing
        ipv6_add = ipv6_intended - ipv6_existing
        ipv4_remove = ipv4_existing - ipv4_intended
        ipv6_remove = ipv6_existing - ipv6_intended

        unchanged = ((ipv4_intended & ipv4_existing) |
                     (ipv6_intended & ipv6_existing))

        log.debug("Already got routes for %s for tap %s", unchanged, self.tap)

        for ipv4 in ipv4_add:
            log.info("Add route to IPv4 address %s for tap %s" %
                     (ipv4, self.tap))
            devices.add_route(futils.IPV4, ipv4, self.tap, self.mac)

        for ipv6 in ipv6_add:
            log.info("Add route to IPv6 address %s for tap %s" %
                     (ipv6, self.tap))
            devices.add_route(futils.IPV6, ipv6, self.tap, self.mac)

        for ipv4 in ipv4_remove:
            log.info("Remove extra IPv4 route to address %s for tap %s" %
                     (ipv4, self.tap))
            devices.del_route(futils.IPV4, ipv4, self.tap)

        for ipv6 in ipv6_remove:
            log.info("Remove extra IPv6 route to address %s for tap %s" %
                     (ipv6, self.tap))
            devices.del_route(futils.IPV6, ipv6, self.tap)

        #*********************************************************************#
        #* Set up the rules for this endpoint, not including ACLs. Note that *#
        #* if the endpoint is disabled, then it has no permitted addresses,  *#
        #* so it cannot send any data.                                       *#
        #*********************************************************************#
        frules.set_ep_specific_rules(self.suffix, self.tap, futils.IPV4,
                                     ipv4_intended, self.mac)
        frules.set_ep_specific_rules(self.suffix, self.tap, futils.IPV6,
                                     ipv6_intended, self.mac)

        #*********************************************************************#
        #* If we have just disabled / enabled an endpoint, we may need to    *#
        #* enable / disable incoming traffic. update_acls makes this         *#
        #* decision.                                                         *#
        #*********************************************************************#
        self.update_acls()

        return False

    def update_acls(self):
        """
        Updates the ACL state for an endpoint, setting all the rules and IP
        sets appropriately.
        """
        if self.state == Endpoint.STATE_DISABLED:
            # Disabled endpoint - bar all traffic.
            log.debug("Set up empty ACLs for %s" % (self.suffix))
            default = {'inbound_default': 'DENY',
                       'inbound': [],
                       'outbound_default': 'DENY',
                       'outbound': []}
            acls    = {'v4': default, 'v6': default}
        elif self.acl_data is None:
            # No ACLs received; hold off until we get some.
            log.debug("No ACLs available yet for endpoint %s" % self.suffix)
            return
        else:
            log.debug("ACLs for %s are %s" % (self.suffix, self.acl_data))
            acls = self.acl_data

        inbound     = acls['v4']['inbound']
        in_default  = acls['v4']['inbound_default']
        outbound    = acls['v4']['outbound']
        out_default = acls['v4']['outbound_default']

        frules.set_acls(self.suffix, futils.IPV4,
                        inbound, in_default,
                        outbound, out_default)

        inbound     = acls['v6']['inbound']
        in_default  = acls['v6']['inbound_default']
        outbound    = acls['v6']['outbound']
        out_default = acls['v6']['outbound_default']

        frules.set_acls(self.suffix, futils.IPV6,
                        inbound, in_default,
                        outbound, out_default)
