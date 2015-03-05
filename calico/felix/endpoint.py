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
from calico import common
from calico.felix import devices
from calico.felix import frules
from calico.felix import futils
from calico.felix.exceptions import (InvalidRequest,
                                     InconsistentIPVersion,
                                     InvalidAddress)
from netaddr import IPAddress
import logging

log = logging.getLogger(__name__)

class Address(object):
    """
    An address as reported to Felix by the plugin (ignoring fields that Felix
    does not use). The input *fields* parameter is the fields from the API
    ENDPOINTCREATED (or other ENDPOINT*) request, of which we just need the
    address and gateway.

    Raises KeyError if there is a missing "addr" field in the parameters.

    """
    def __init__(self, fields):
        # Two things can go wrong here, addr key doesn't exist, or the IP
        # address is not valid.  In both cases, the caller will deal with the
        # exception thrown.
        try:
            self.ip = IPAddress(fields['addr'])
        except KeyError:
            raise InvalidAddress()

        self.version = self.ip.version

        # The gateway is used by Felix to set up NDP proxy.  It is required
        # for IPv6 addresses unless the deployment has some other mechanism
        # for endpoints to learn the gateway's MAC address, such as Router
        # Advertisements from a DHCP6 service (typical OpenStack mechanism).
        # However, we would always expect the gateway to be provided on the
        # API. If no gateway is provided, log a warning.
        try:
            self.gateway = IPAddress(fields['gateway'])
        except KeyError:
            log.warning("No gateway provided with address")
            self.gateway = None
        else:
            # If, for some reason, the IP version on the address and gateway
            # don't match, we will fail to program the proxy.  So, better to
            # fail the API request now.
            if self.gateway.version != self.ip.version:
                raise InconsistentIPVersion(
                    "IP %s is not the same IP version as gateway %s" %
                    (self.ip, self.gateway))


class Endpoint(object):
    """
    Endpoint represents an endpoint in a Calico network, managed by a specific
    instance of Felix.
    """
    STATE_ENABLED  = "enabled"
    STATE_DISABLED = "disabled"
    STATES         = [STATE_ENABLED, STATE_DISABLED]

    def __init__(self, uuid, mac, interface, prefix):
        self.uuid = uuid.encode('ascii')
        self.mac = mac.encode('ascii')
        self.interface = interface.encode('ascii')
        self.suffix = interface.replace(prefix, "", 1)

        # Dictionary of Address objects, keyed by the IPAddress.
        self.addresses = {}

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
        self.acl_data = None

        # Assume disabled until we know different
        self.state = Endpoint.STATE_DISABLED

    def remove(self, iptables_state):
        """
        Delete a programmed endpoint. Remove the routes, then the rules.
        """
        if devices.interface_exists(self.interface):
            for type in (futils.IPV4, futils.IPV6):
                try:
                    ips = devices.list_interface_ips(type, self.interface)
                    for ip in ips:
                        devices.del_route(type, ip, self.interface)
                except futils.FailedSystemCall:
                    # There is a window where the interface gets deleted under
                    # our feet. If it has gone now, ignore the error, otherwise
                    # rethrow it.
                    if devices.interface_exists(self.interface):
                        raise
                    break

        frules.del_rules(iptables_state, self.suffix, futils.IPV4)
        frules.del_rules(iptables_state, self.suffix, futils.IPV6)

    def program_endpoint(self, iptables_state):
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
        # Declare some utility functions
        def add_routes(routes, type):
            for route in routes:
                log.info("Add route to %s address %s for interface %s",
                         type, route, self.interface)
                devices.add_route(type, route, self.interface, self.mac)

        def remove_routes(routes, type):
            for route in routes:
                log.info("Remove extra %s route to address %s for interface %s",
                         type, route, self.interface)
                devices.del_route(type, route, self.interface)

        if not devices.interface_exists(self.interface):
            if self.state == Endpoint.STATE_ENABLED:
                log.error("Unable to configure non-existent interface %s",
                          self.interface)
                return True
            else:
                # No interface, but disabled. This is not an error, and there
                # is nothing to do.
                log.debug("Interface missing when disabling endpoint %s",
                          self.uuid)
                return False

        # If the interface is down, we can't configure it.
        if not devices.interface_up(self.interface):
            log.error("Unable to configure interface %s: interface is down.",
                      self.interface)
            return True

        # Configure the interface.
        if self.state == Endpoint.STATE_ENABLED:
            devices.configure_interface(self.interface)

            # List the IPv6 gateways to see if we need proxy NDP.
            ipv6_gateways = [addr.gateway for addr in self.addresses.values()
                             if addr.version is 6]
            if ipv6_gateways:
                devices.configure_interface_ipv6(self.interface, ipv6_gateways)

            # Build up list of addresses that should be present
            ipv4_intended = set([str(addr.ip)
                                 for addr in self.addresses.values()
                                 if addr.version is 4])
            ipv6_intended = set([str(addr.ip)
                                 for addr in self.addresses.values()
                                 if addr.version is 6])
        else:
            # Disabled endpoint; we should remove all the routes.
            ipv4_intended = set()
            ipv6_intended = set()

        ipv4_existing = devices.list_interface_ips(futils.IPV4, self.interface)
        ipv6_existing = devices.list_interface_ips(futils.IPV6, self.interface)

        # Determine the addresses that won't be changed.
        unchanged = ((ipv4_intended & ipv4_existing) |
                     (ipv6_intended & ipv6_existing))

        log.debug("Already got routes for %s for interface %s",
                  unchanged, self.interface)

        #*********************************************************************#
        #* Add and remove routes. Add any route we need but don't have, and  *#
        #* remove any route we have but don't need. These operations are     *#
        #* fast because they operate on sets.                                *#
        #*********************************************************************#
        add_routes(ipv4_intended - ipv4_existing, futils.IPV4)
        add_routes(ipv6_intended - ipv6_existing, futils.IPV6)
        remove_routes(ipv4_existing - ipv4_intended, futils.IPV4)
        remove_routes(ipv6_existing - ipv6_intended, futils.IPV6)

        #*********************************************************************#
        #* Set up the rules for this endpoint, not including ACLs. Note that *#
        #* if the endpoint is disabled, then it has no permitted addresses,  *#
        #* so it cannot send any data.                                       *#
        #*********************************************************************#
        frules.set_ep_specific_rules(iptables_state,
                                     self.suffix, self.interface, futils.IPV4,
                                     ipv4_intended, self.mac)
        frules.set_ep_specific_rules(iptables_state,
                                     self.suffix, self.interface, futils.IPV6,
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

    def store_update(self, fields):
        """
        Update an endpoint's MAC, state and addresses with the contents of an
        ENDPOINT* API message.

        :param fields: dictionary of Endpoint Update API fields.
        :return: None.
        :throws: InvalidRequest if unsuccessful.
        """

        try:
            mac = fields['mac']
        except KeyError:
            raise InvalidRequest('Missing "mac" field', fields)

        try:
            state = fields['state']
        except KeyError:
            raise InvalidRequest('Missing "state" field', fields)

        try:
            addrs = fields['addrs']
        except KeyError:
            raise InvalidRequest('Missing "addrs" field', fields)

        addresses = {}

        for addr in addrs:
            try:
                address = Address(addr)
            except InconsistentIPVersion as err:
                # exception has an operator-suitable error message.
                log.error("For endpoint %s, %s", self.uuid, err)
                raise InvalidRequest(str(err),
                                     fields)
            except InvalidAddress:
                log.error("Invalid address for endpoint %s : %s",
                          self.uuid, fields)
                raise InvalidRequest("Invalid address for endpoint",
                                     fields)

            if address.ip in addresses:
                # The IP is listed multiple times in the message.  This is
                # an error.
                log.error("IP %s listed multiple times in message for endpoint"
                          " %s : %s", address.ip, self.uuid, fields)
                raise InvalidRequest("IP %s listed multiple times in message "
                                     "for endpoint %s" %
                                     (address.ip, self.uuid), fields)

            # All error checks passed on this addr.
            addresses[address.ip] = address

        if state not in Endpoint.STATES:
            log.error("Invalid state %s for endpoint %s : %s",
                      state, self.uuid, fields)
            raise InvalidRequest('Invalid state "%s"' % state, fields)

        self.addresses = addresses
        self.mac = mac.encode('ascii')
        self.state = state.encode('ascii')
