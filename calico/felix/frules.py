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
felix.frules
~~~~~~~~~~~~

Felix rule management, including iptables and ipsets.
"""
import logging
import os
import subprocess
import time

from calico import common
from calico.felix import fiptables
from calico.felix import futils
from calico.felix import ipsets
from calico.felix.futils import FailedSystemCall
from calico.felix.futils import IPV4, IPV6

# Logger
log = logging.getLogger(__name__)

# Chain names
CHAIN_PREROUTING         = "felix-PREROUTING"
CHAIN_INPUT              = "felix-INPUT"
CHAIN_FORWARD            = "felix-FORWARD"
CHAIN_TO_ENDPOINT        = "felix-TO-ENDPOINT"
CHAIN_FROM_ENDPOINT      = "felix-FROM-ENDPOINT"
CHAIN_TO_PREFIX          = "felix-to-"
CHAIN_FROM_PREFIX        = "felix-from-"

#*****************************************************************************#
#* ipset names. The "to" ipsets are referenced from the "to" chains, and the *#
#* "from" ipsets from the "from" chains. There are separate ipsets for IPv4  *#
#* and IPv6, and as explained below, three in each of these categories for a *#
#* total of 12 ipsets.                                                       *#
#*                                                                           *#
#* The three types of ipsets are as follows. Note that an ipset can either   *#
#* have a port and protocol or not - it cannot have a mix of members with    *#
#* and without them.                                                         *#
#*                                                                           *#
#* - The "addr" ipsets contain just a CIDR. These are for rules such as      *#
#*   "allow all traffic from this network" (all ports and protocols).        *#
#*                                                                           *#
#* - The "port" ipsets contain a CIDR / protocol / port triple, and allow    *#
#*   matching such as the following examples.                                *#
#*   - outbound UDP to 1.2.3.4/32:0 (port 0, i.e. any port)                  *#
#*   - inbound TCP on port 80 from 0.0.0.0/0                                 *#
#*   - outbound ICMP with type 1, code 2 to 10.0.0.0/8                       *#
#*   - outbound ICMP (neighbor-discover) to 10.0.0.0/8                       *#
#*   - inbound requests of IP protocol type 17 (port 0, i.e. any port)       *#
#*   It does not allow for certain things.                                   *#
#*   - there must be a protocol type                                         *#
#*   - you cannot have a non-zero port except for tcp / udp / sctp           *#
#*   - you cannot have ICMP unless there is either a type plus code or an    *#
#*     ICMP type name (which maps to type plus code)                         *#
#*                                                                           *#
#* - Finally, the "icmp" ipset is to work around the odd final restriction   *#
#*   above, and allows rules such as "allow all ICMP to network X".          *#
#*****************************************************************************#
IPSET_TO_ADDR_PREFIX    = "felix-to-addr-"
IPSET_TO_PORT_PREFIX    = "felix-to-port-"
IPSET_TO_ICMP_PREFIX    = "felix-to-icmp-"
IPSET_FROM_ADDR_PREFIX  = "felix-from-addr-"
IPSET_FROM_PORT_PREFIX  = "felix-from-port-"
IPSET_FROM_ICMP_PREFIX  = "felix-from-icmp-"
IPSET6_TO_ADDR_PREFIX   = "felix-6-to-addr-"
IPSET6_TO_PORT_PREFIX   = "felix-6-to-port-"
IPSET6_TO_ICMP_PREFIX   = "felix-6-to-icmp-"
IPSET6_FROM_ADDR_PREFIX = "felix-6-from-addr-"
IPSET6_FROM_PORT_PREFIX = "felix-6-from-port-"
IPSET6_FROM_ICMP_PREFIX = "felix-6-from-icmp-"
IPSET_TMP_PORT          = "felix-tmp-port"
IPSET_TMP_ADDR          = "felix-tmp-addr"
IPSET_TMP_ICMP          = "felix-tmp-icmp"
IPSET6_TMP_PORT         = "felix-6-tmp-port"
IPSET6_TMP_ADDR         = "felix-6-tmp-addr"
IPSET6_TMP_ICMP         = "felix-6-tmp-icmp"


def set_global_rules(config):
    """
    Set up global iptables rules. These are rules that do not change with
    endpoint, and are expected never to change - but they must be present.
    """
    # The IPV4 nat table first. This must have a felix-PREROUTING chain.
    table = fiptables.get_table(futils.IPV4, "nat")
    chain = fiptables.get_chain(table, CHAIN_PREROUTING)

    if config.METADATA_IP is None:
        # No metadata IP. The chain should be empty - if not, clean it out.
        chain.flush()
    else:
        # Now set the chain to have a single rule by adding it at the start,
        # then truncating. The rule looks like this.
        #  DNAT tcp -- any any anywhere 169.254.169.254 tcp dpt:http to:127.0.0.1:9697
        rule          = fiptables.Rule(futils.IPV4)
        rule.dst      = "169.254.169.254"
        rule.protocol = "tcp"
        rule.create_target("DNAT", {"to_destination": 
                                    "%s:%s" % (config.METADATA_IP,
                                               config.METADATA_PORT)})

        rule.create_tcp_match("80")
        fiptables.insert_rule(rule, chain, 0)
        truncate_rules(chain, 1)

    # Add a rule that forces us through the chain we just created.
    chain = fiptables.get_chain(table, "PREROUTING")
    rule = fiptables.Rule(futils.IPV4, CHAIN_PREROUTING)
    fiptables.insert_rule(rule, chain, force_position=False)

    #*************************************************************************#
    #* Now the filter table. This needs to have calico-filter-FORWARD and    *#
    #* calico-filter-INPUT chains, which we must create before adding any    *#
    #* rules that send to them.                                              *#
    #*************************************************************************#
    for type in (IPV4, IPV6):
        table = fiptables.get_table(type, "filter")
        fiptables.get_chain(table, CHAIN_FROM_ENDPOINT)
        fiptables.get_chain(table, CHAIN_TO_ENDPOINT)
        fiptables.get_chain(table, CHAIN_INPUT)
        fiptables.get_chain(table, CHAIN_FORWARD)

        # Add rules that force us through the main Felix chain.
        chain = fiptables.get_chain(table, "FORWARD")
        rule  = fiptables.Rule(type, CHAIN_FORWARD)
        fiptables.insert_rule(rule, chain, force_position=False)

        chain = fiptables.get_chain(table, "INPUT")
        rule  = fiptables.Rule(type, CHAIN_INPUT)
        fiptables.insert_rule(rule, chain, force_position=False)

        # The felix forward chain tests traffic to and from endpoints
        chain = fiptables.get_chain(table, CHAIN_FORWARD)
        rule  = fiptables.Rule(type, CHAIN_FROM_ENDPOINT)
        rule.in_interface = "tap+"
        fiptables.insert_rule(rule, chain, 0)

        rule  = fiptables.Rule(type, CHAIN_TO_ENDPOINT)
        rule.out_interface = "tap+"
        fiptables.insert_rule(rule, chain, 1)

        rule  = fiptables.Rule(type, "ACCEPT")
        rule.in_interface = "tap+"
        fiptables.insert_rule(rule, chain, 2)

        rule  = fiptables.Rule(type, "ACCEPT")
        rule.out_interface = "tap+"
        fiptables.insert_rule(rule, chain, 3)

        truncate_rules(chain, 4)

        # The felix INPUT chain tests traffic from endpoints
        chain = fiptables.get_chain(table, CHAIN_INPUT)
        rule  = fiptables.Rule(type, CHAIN_FROM_ENDPOINT)
        rule.in_interface = "tap+"
        fiptables.insert_rule(rule, chain, 0)

        rule  = fiptables.Rule(type, "ACCEPT")
        rule.in_interface = "tap+"
        fiptables.insert_rule(rule, chain, 1)

        truncate_rules(chain, 2)


def set_ep_specific_rules(suffix, iface, type, localips, mac):
    """
    Add (or modify) the rules for a particular endpoint, whose suffix is
    supplied. This routine :
    - ensures that the chains specific to this endpoint exist, where there is
      a chain for packets leaving and a chain for packets arriving at the
      endpoint;
    - routes packets to / from the tap interface to the chains created above;
    - fills out the endpoint specific chains with the correct rules;
    - verifies that the ipsets exist.

    The net of all this is that every bit of iptables configuration that is
    specific to this particular endpoint is created (or verified), with the
    exception of ACLs (i.e. the configuration of the list of other addresses
    for which routing is permitted) - this is done in set_acls.
    Note however that this routine handles IPv4 or IPv6 not both; it is
    normally called twice in succession (once for each).
    """
    to_chain_name   = CHAIN_TO_PREFIX + suffix
    from_chain_name = CHAIN_FROM_PREFIX + suffix

    # Set up all the ipsets.
    if type == IPV4:
        to_ipset_port   = IPSET_TO_PORT_PREFIX + suffix
        to_ipset_addr   = IPSET_TO_ADDR_PREFIX + suffix
        to_ipset_icmp   = IPSET_TO_ICMP_PREFIX + suffix
        from_ipset_port = IPSET_FROM_PORT_PREFIX + suffix
        from_ipset_addr = IPSET_FROM_ADDR_PREFIX + suffix
        from_ipset_icmp = IPSET_FROM_ICMP_PREFIX + suffix
        family          = "inet"
    else:
        to_ipset_port   = IPSET6_TO_PORT_PREFIX + suffix
        to_ipset_addr   = IPSET6_TO_ADDR_PREFIX + suffix
        to_ipset_icmp   = IPSET6_TO_ICMP_PREFIX + suffix
        from_ipset_port = IPSET6_FROM_PORT_PREFIX + suffix
        from_ipset_addr = IPSET6_FROM_ADDR_PREFIX + suffix
        from_ipset_icmp = IPSET6_FROM_ICMP_PREFIX + suffix
        family            = "inet6"

    # Create ipsets if they do not already exist.
    ipsets.create(to_ipset_port, "hash:net,port", family)
    ipsets.create(to_ipset_addr, "hash:net", family)
    ipsets.create(to_ipset_icmp, "hash:net", family)
    ipsets.create(from_ipset_port, "hash:net,port", family)
    ipsets.create(from_ipset_addr, "hash:net", family)
    ipsets.create(from_ipset_icmp, "hash:net", family)

    # Get the table.
    table = fiptables.get_table(type, "filter")

    # Create the chains for packets to the interface
    to_chain = fiptables.get_chain(table, to_chain_name)

    #*************************************************************************#
    #* Put rules into that "from" chain, i.e. the chain traversed by         *#
    #* outbound packets. Note that we never ACCEPT, but always RETURN if we  *#
    #* want to accept this packet. This is because the rules here are for    *#
    #* this endpoint only - we cannot (for example) ACCEPT a packet which    *#
    #* would be rejected by the "to" rules for another endpoint to which it  *#
    #* is addressed which happens to exist on the same host.                 *#
    #*************************************************************************#
    index = 0

    if type == IPV6:
        #************************************************************************#
        #* In ipv6 only, there are 6 rules that need to be created first.       *#
        #* RETURN ipv6-icmp anywhere anywhere ipv6-icmptype 130                 *#
        #* RETURN ipv6-icmp anywhere anywhere ipv6-icmptype 131                 *#
        #* RETURN ipv6-icmp anywhere anywhere ipv6-icmptype 132                 *#
        #* RETURN ipv6-icmp anywhere anywhere ipv6-icmp router-advertisement    *#
        #* RETURN ipv6-icmp anywhere anywhere ipv6-icmp neighbour-solicitation  *#
        #* RETURN ipv6-icmp anywhere anywhere ipv6-icmp neighbour-advertisement *#
        #*                                                                      *#
        #* These rules are ICMP types 130, 131, 132, 134, 135 and 136, and can  *#
        #* be created on the command line with something like :                 *#
        #*    ip6tables -A plw -j RETURN --protocol icmpv6 --icmpv6-type 130    *#
        #************************************************************************#
        for icmp in ["130", "131", "132", "134", "135", "136"]:
            rule = fiptables.Rule(futils.IPV6, "RETURN")
            rule.protocol = "icmpv6"
            rule.create_icmp6_match([icmp])
            fiptables.insert_rule(rule, to_chain, index)
            index += 1

    rule = fiptables.Rule(type, "DROP")
    rule.create_conntrack_match(["INVALID"])
    fiptables.insert_rule(rule, to_chain, index)
    index += 1

    # "Return if state RELATED or ESTABLISHED".
    rule = fiptables.Rule(type, "RETURN")
    rule.create_conntrack_match(["RELATED,ESTABLISHED"])
    fiptables.insert_rule(rule, to_chain, index)
    index += 1

    # "Return anything whose source matches this ipset" (for three ipsets)
    rule = fiptables.Rule(type, "RETURN")
    rule.create_set_match([to_ipset_port, "src,dst"])
    fiptables.insert_rule(rule, to_chain, index)
    index += 1

    rule = fiptables.Rule(type, "RETURN")
    rule.create_set_match([to_ipset_addr, "src"])
    fiptables.insert_rule(rule, to_chain, index)
    index += 1

    rule = fiptables.Rule(type, "RETURN")
    if type is IPV4:
        rule.protocol = "icmp"
    else:
        rule.protocol = "icmpv6"
    rule.create_set_match([to_ipset_icmp, "src"])
    fiptables.insert_rule(rule, to_chain, index)
    index += 1

    # If we get here, drop the packet.
    rule = fiptables.Rule(type, "DROP")
    fiptables.insert_rule(rule, to_chain, index)
    index += 1

    #*************************************************************************#
    #* Delete all rules from here to the end of the chain, in case there     *#
    #* were rules present which should not have been.                        *#
    #*************************************************************************#
    truncate_rules(to_chain, index)

    #*************************************************************************#
    #* Now the chain that manages packets from the interface, and the rules  *#
    #* in that chain.                                                        *#
    #*************************************************************************#
    from_chain = fiptables.get_chain(table, from_chain_name)

    index = 0
    if type == IPV6:
        # In ipv6 only, allows all ICMP traffic from this endpoint to anywhere.
        rule = fiptables.Rule(type, "RETURN")
        rule.protocol = "icmpv6"
        fiptables.insert_rule(rule, from_chain, index)
        index += 1

    # "Drop if state INVALID".
    rule = fiptables.Rule(type, "DROP")
    rule.create_conntrack_match(["INVALID"])
    fiptables.insert_rule(rule, from_chain, index)
    index += 1

    # "Return if state RELATED or ESTABLISHED".
    rule = fiptables.Rule(type, "RETURN")
    rule.create_conntrack_match(["RELATED,ESTABLISHED"])
    fiptables.insert_rule(rule, from_chain, index)
    index += 1

    if type == IPV4:
        # Allow outgoing v4 DHCP packets.
        rule = fiptables.Rule(type, "RETURN")
        rule.protocol = "udp"
        rule.create_udp_match("68", "67")
        fiptables.insert_rule(rule, from_chain, index)
        index += 1
    else:
        # Allow outgoing v6 DHCP packets.
        rule = fiptables.Rule(type, "RETURN")
        rule.protocol = "udp"
        rule.create_udp_match("546", "547")
        fiptables.insert_rule(rule, from_chain, index)
        index += 1

    #*************************************************************************#
    #* Now only allow through packets from the correct MAC and IP address.   *#
    #* We do this by first setting a mark if it matches any of the IPs, then *#
    #* dropping the packets if that mark is not set.  There may be rules     *#
    #* here from addresses that this endpoint no longer has - in which case  *#
    #* we insert before them and they get tidied up when we truncate the     *#
    #* chain.                                                                *#
    #*************************************************************************#
    for ip in localips:
        rule = fiptables.Rule(type)
        rule.create_target("MARK", {"set_mark": "1"})
        rule.src = ip
        rule.create_mac_match(mac)
        fiptables.insert_rule(rule, from_chain, index)
        index += 1

    rule = fiptables.Rule(type, "DROP")
    rule.create_mark_match("!1")
    fiptables.insert_rule(rule, from_chain, index)
    index += 1
  
    # "Permit packets whose destination matches the supplied ipsets."
    rule = fiptables.Rule(type, "RETURN")
    rule.create_set_match([from_ipset_port, "dst,dst"])
    fiptables.insert_rule(rule, from_chain, index)
    index += 1

    rule = fiptables.Rule(type, "RETURN")
    rule.create_set_match([from_ipset_addr, "dst"])
    fiptables.insert_rule(rule, from_chain, index)
    index += 1

    rule = fiptables.Rule(type, "RETURN")
    if type is IPV4:
        rule.protocol = "icmp"
    else:
        rule.protocol = "icmpv6"
    rule.create_set_match([from_ipset_icmp, "dst"])
    fiptables.insert_rule(rule, from_chain, index)
    index += 1

    # If we get here, drop the packet.
    rule = fiptables.Rule(type, "DROP")
    fiptables.insert_rule(rule, from_chain, index)
    index += 1

    #*************************************************************************#
    #* Delete all rules from here to the end of the chain, in case there     *#
    #* were rules present which should not have been.                        *#
    #*************************************************************************#
    truncate_rules(from_chain, index)

    #*************************************************************************#
    #* We have created the chains and rules that control input and output    *#
    #* for the interface but not routed traffic through them. First a rule   *#
    #* for traffic arriving to the endpoint.                                 *#
    #*************************************************************************#
    chain = fiptables.get_chain(table, CHAIN_FROM_ENDPOINT)

    rule = fiptables.Rule(type, from_chain_name)
    rule.in_interface = iface
    fiptables.insert_rule(rule,
                          chain,
                          fiptables.RULE_POSN_LAST,
                          force_position=False)

    #*************************************************************************#
    #* Similarly, create the rules that direct packets that are forwarded    *#
    #* either to or from the endpoint, sending them to the "to" or "from"    *#
    #* chains as appropriate.                                                *#
    #*************************************************************************#
    chain = fiptables.get_chain(table, CHAIN_TO_ENDPOINT)

    rule = fiptables.Rule(type, to_chain_name)
    rule.out_interface = iface
    fiptables.insert_rule(rule,
                          chain,
                          fiptables.RULE_POSN_LAST,
                          force_position=False)


def del_rules(suffix, type):
    """
    Remove the rules for an endpoint which is no longer managed.
    """
    log.debug("Delete %s rules for %s" % (type, suffix))
    to_chain   = CHAIN_TO_PREFIX + suffix
    from_chain = CHAIN_FROM_PREFIX + suffix
    table = fiptables.get_table(type, "filter")

    if type == IPV4:
        to_ipset_port   = IPSET_TO_PORT_PREFIX + suffix
        to_ipset_addr   = IPSET_TO_ADDR_PREFIX + suffix
        to_ipset_icmp   = IPSET_TO_ICMP_PREFIX + suffix
        from_ipset_port = IPSET_FROM_PORT_PREFIX + suffix
        from_ipset_addr = IPSET_FROM_ADDR_PREFIX + suffix
        from_ipset_icmp = IPSET_FROM_ICMP_PREFIX + suffix
    else:
        to_ipset_port   = IPSET6_TO_PORT_PREFIX + suffix
        to_ipset_addr   = IPSET6_TO_ADDR_PREFIX + suffix
        to_ipset_icmp   = IPSET6_TO_ICMP_PREFIX + suffix
        from_ipset_port = IPSET6_FROM_PORT_PREFIX + suffix
        from_ipset_addr = IPSET6_FROM_ADDR_PREFIX + suffix
        from_ipset_icmp = IPSET6_FROM_ICMP_PREFIX + suffix

    #*************************************************************************#
    #* Remove the rules routing to the chain we are about to remove. The     *#
    #* baroque structure is caused by the python-iptables interface.         *#
    #* chain.rules returns a list of rules, each of which contains its index *#
    #* (i.e. position). If we get rules 7 and 8 and try to remove them in    *#
    #* that order, then the second fails because rule 8 got renumbered when  *#
    #* rule 7 was deleted, so the rule we have in our hand neither matches   *#
    #* the old rule 8 (now at index 7) or the new rule 8 (with a different   *#
    #* target etc. Hence each time we remove a rule we rebuild the list of   *#
    #* rules to iterate through.                                             *#
    #*                                                                       *#
    #* In principle we could use autocommit to make this much nicer (as the  *#
    #* python-iptables docs suggest), but in practice it seems a bit buggy,  *#
    #* and leads to errors elsewhere. Reversing the list sounds like it      *#
    #* should work too, but in practice does not.                            *#
    #*************************************************************************#
    for name in (CHAIN_TO_ENDPOINT, CHAIN_FROM_ENDPOINT):
        chain = fiptables.get_chain(table, name)
        done  = False
        while not done:
            done = True
            for rule in chain.rules:
                if rule.target.name in (to_chain, from_chain):
                    chain.delete_rule(rule)
                    done = False
                    break

    # Delete the from and to chains for this endpoint.
    for name in (from_chain, to_chain):
        if table.is_chain(name):
            chain = fiptables.get_chain(table, name)
            log.debug("Flush chain %s", name)
            chain.flush()
            log.debug("Delete chain %s", name)
            table.delete_chain(name)

    # Delete the ipsets for this endpoint.
    for ipset in (from_ipset_addr, from_ipset_icmp, from_ipset_port,
                  to_ipset_addr, to_ipset_icmp, to_ipset_port):
        ipsets.destroy(ipset)


def set_acls(suffix, type, inbound, in_default, outbound, out_default):
    """
    Set up the ACLs, making sure that they match.
    """
    if type == IPV4:
        to_ipset_port   = IPSET_TO_PORT_PREFIX + suffix
        to_ipset_addr   = IPSET_TO_ADDR_PREFIX + suffix
        to_ipset_icmp   = IPSET_TO_ICMP_PREFIX + suffix
        from_ipset_port = IPSET_FROM_PORT_PREFIX + suffix
        from_ipset_addr = IPSET_FROM_ADDR_PREFIX + suffix
        from_ipset_icmp = IPSET_FROM_ICMP_PREFIX + suffix
        tmp_ipset_port  = IPSET_TMP_PORT
        tmp_ipset_addr  = IPSET_TMP_ADDR
        tmp_ipset_icmp  = IPSET_TMP_ICMP
        family          = "inet"
    else:
        to_ipset_port   = IPSET6_TO_PORT_PREFIX + suffix
        to_ipset_addr   = IPSET6_TO_ADDR_PREFIX + suffix
        to_ipset_icmp   = IPSET6_TO_ICMP_PREFIX + suffix
        from_ipset_port = IPSET6_FROM_PORT_PREFIX + suffix
        from_ipset_addr = IPSET6_FROM_ADDR_PREFIX + suffix
        from_ipset_icmp = IPSET6_FROM_ICMP_PREFIX + suffix
        tmp_ipset_port  = IPSET6_TMP_PORT
        tmp_ipset_addr  = IPSET6_TMP_ADDR
        tmp_ipset_icmp  = IPSET6_TMP_ICMP
        family          = "inet6"

    if in_default != "deny" or out_default != "deny":
        #*********************************************************************#
        #* Only default deny rules are implemented. When we implement        *#
        #* default accept rules, it will be necessary for                    *#
        #* set_ep_specific_rules to at least know what the default policy    *#
        #* is. That implies that set_ep_specific_rules probably ought to be  *#
        #* moved to be called here rather than where it is now. This issue   *#
        #* is covered by https://github.com/Metaswitch/calico/issues/39      *#
        #*********************************************************************#
        log.critical("Only default deny rules are implemented")

    # Verify that the tmp ipsets exist and are empty.
    ipsets.create(tmp_ipset_port, "hash:net,port", family)
    ipsets.create(tmp_ipset_addr, "hash:net", family)
    ipsets.create(tmp_ipset_icmp, "hash:net", family)

    ipsets.flush(tmp_ipset_port)
    ipsets.flush(tmp_ipset_addr)
    ipsets.flush(tmp_ipset_icmp)

    update_ipsets(type, type + " inbound", suffix,
                  inbound,
                  to_ipset_addr, to_ipset_port, to_ipset_icmp,
                  tmp_ipset_addr, tmp_ipset_port, tmp_ipset_icmp)
    update_ipsets(type, type + " outbound", suffix,
                  outbound,
                  from_ipset_addr, from_ipset_port, from_ipset_icmp,
                  tmp_ipset_addr, tmp_ipset_port, tmp_ipset_icmp)


def update_ipsets(type,
                  descr,
                  suffix,
                  rule_list,
                  ipset_addr,
                  ipset_port,
                  ipset_icmp,
                  tmp_ipset_addr,
                  tmp_ipset_port,
                  tmp_ipset_icmp):
    """
    Update the ipsets with a given set of rules. If a rule is invalid we do
    not throw an exception or give up, but just log an error and continue.
    """
    for rule in rule_list:
        if rule.get('cidr') is None:
            log.error("Invalid %s rule without cidr for %s : %s" %
                      (descr, suffix, rule))
            continue

        #*********************************************************************#
        #* The ipset format is something like "10.11.1.3,udp:0"              *#
        #* Further valid examples include                                    *#
        #*   10.11.1.0/24                                                    *#
        #*   10.11.1.0/24,tcp                                                *#
        #*   10.11.1.0/24,80                                                 *#
        #*                                                                   *#
        #*********************************************************************#
        if rule['cidr'].endswith("/0"):
            #*****************************************************************#
            #* We have to handle any CIDR with a "/0" specially, since we    *#
            #* split it into two ipsets entries; ipsets cannot have zero     *#
            #* CIDR length in bits.                                          *#
            #*****************************************************************#
            if type == IPV4:
                cidrs = ["0.0.0.0/1", "128.0.0.0/1"]
            else:
                cidrs = ["::/1", "8000::/1"]
        else:
            cidrs = [rule['cidr']]

        #*********************************************************************#
        #* Now handle the protocol. There are three types of protocol. tcp / *#
        #* sctp /udp / udplite have an optional port. icmp / icmpv6 have an  *#
        #* optional type and code. Anything else doesn't have ports.         *#
        #*                                                                   *#
        #* We build the value to insert without the CIDR, then prepend the   *#
        #* CIDR later (since we may need to use two CIDRs).                  *#
        #*********************************************************************#
        protocol  = rule.get('protocol')
        port      = rule.get('port')
        icmp_type = rule.get('icmp_type')
        icmp_code = rule.get('icmp_code')

        if protocol is None:
            if rule.get('port') is not None:
                # No protocol, so port is not allowed.
                log.error(
                    "Invalid %s rule with port but no protocol for %s : %s",
                    descr, suffix, rule)
                continue
            ipset_value = ""
            ipset  = tmp_ipset_addr
        elif protocol in ("tcp", "sctp", "udp", "udplite"):
            if port is None:
                # ipsets use port 0 to mean "any port"
                ipset_value = ",%s:0" % (protocol)
                ipset = tmp_ipset_port
            elif isinstance(port, list) and len(port) == 2:
                # List of two ports - port range
                if (not common.validate_port(str(port[0])) or
                    not common.validate_port(str(port[1]))    ):
                    # Port range was not two valid ports.
                    log.error(
                        "Invalid port range in %s rule for %s : %s",
                        descr, suffix, rule)
                    continue
                ipset_value = ",%s:%s-%s" % (protocol, port[0], port[1])
                ipset = tmp_ipset_port
            else:
                if not common.validate_port(str(port)):
                    # Port was supplied but was not an integer or range.
                    log.error(
                        "Invalid port in %s rule for %s : %s",
                        descr, suffix, rule)
                    continue

                # An integer port was specified.
                ipset_value = ",%s:%s" % (protocol, port)
                ipset = tmp_ipset_port
        elif protocol in ("icmp", "icmpv6"):
            if rule.get('port') is not None:
                # No protocol, so port is not allowed.
                log.error(
                    "Invalid %s rule for %s with port for protocol %s : %s",
                    descr, suffix, protocol, rule)
                continue

            if (icmp_type is None and icmp_code is not None):
                # A code but no type - not allowed.
                log.error(
                    "Invalid %s rule with ICMP code but no type for %s : %s",
                    descr, suffix, rule)
                continue
            if icmp_type is None:
                # No type - all ICMP to / from the cidr, so use the ICMP ipset.
                ipset_value = ""
                ipset  = tmp_ipset_icmp
            else:
                try:
                    # Assume integer ICMP type first.
                    int(icmp_type)
                    if icmp_code is None:
                        # Code defaults to 0 if not supplied.
                        icmp_code = 0
                    ipset_value = ",%s:%s/%s" % (protocol, icmp_type, icmp_code)
                    ipset  = tmp_ipset_port
                except ValueError:
                    # Not an integer ICMP type - must be a string code name.
                    ipset_value = ",%s:%s" % (protocol, icmp_type)
                    ipset  = tmp_ipset_port
        else:
            if port is not None:
                # The supplied protocol does not allow ports.
                log.error(
                    "Invalid %s rule with port but no protocol for %s : %s",
                    descr, suffix, rule)
                continue
            # ipsets use port 0 to mean "any port"
            ipset_value = ",%s:0" % (protocol)
            ipset = tmp_ipset_port

        # Now add those values to the ipsets.
        for cidr in cidrs:
            try:
                ipsets.add(ipset, cidr + ipset_value)
            except FailedSystemCall:
                log.exception("Failed to add %s rule (%s) for %s",
                              descr,
                              cidr + ipset_value,
                              suffix)

    # Now that we have filled the tmp ipset, swap it with the real one.
    ipsets.swap(tmp_ipset_addr, ipset_addr)
    ipsets.swap(tmp_ipset_port, ipset_port)
    ipsets.swap(tmp_ipset_icmp, ipset_icmp)

    # Get the temporary ipsets clean again - we leave them existing but empty.
    ipsets.flush(tmp_ipset_port)
    ipsets.flush(tmp_ipset_addr)
    ipsets.flush(tmp_ipset_icmp)


def list_eps_with_rules(type):
    """
    Lists all of the endpoints for which rules exist and are owned by Felix.
    Returns a set of suffices, i.e. the start of the uuid / end of the
    interface name.

    The purpose of this routine is to get a list of endpoints (actually tap
    suffices) for which there is configuration that Felix might need to tidy up
    from a previous iteration.
    """

    #*************************************************************************#
    #* For chains, we check against the "to" chain, while for ipsets we      *#
    #* check against the "to-port" ipset. This isn't random; we absolutely   *#
    #* must check the first one created in the creation code above (and the  *#
    #* last one deleted), to catch the case where (for example) endpoint     *#
    #* creation created one ipset then Felix terminated, where we have to    *#
    #* detect that there is an ipset lying around that needs tidying up.     *#
    #*************************************************************************#
    table = fiptables.get_table(type, "filter")

    eps  = {chain.name.replace(CHAIN_TO_PREFIX, "")
            for chain in table.chains
            if chain.name.startswith(CHAIN_TO_PREFIX)}

    names = ipsets.list_names()
    for name in names:
        if name.startswith(IPSET_TO_PORT_PREFIX):
            eps.add(name.replace(IPSET_TO_PORT_PREFIX, ""))
        elif name.startswith(IPSET6_TO_PORT_PREFIX):
            eps.add(name.replace(IPSET6_TO_PORT_PREFIX, ""))

    log.debug("Current list of managed %s endpoints : %s" % (type, eps))

    return eps

def truncate_rules(chain, count):
    """
    This is a utility function to remove any excess rules from a chain. After
    we have carefully inserted all the rules we want at the start, we want to
    get rid of any legacy rules from the end.

    It takes a chain object, and a count for how many of the rules should be
    left in place.

    Arguably, it should be in fiptables, but we put it here because it's easier
    to test it here.
    """
    while len(chain.rules) > count:
        rule = chain.rules[-1]
        chain.delete_rule(rule)

