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
felix.futils
~~~~~~~~~~~~

Felix utilities.
"""
import iptc
import logging
import os
import subprocess
import time

from calico.felix.config import Config

# Logger
log = logging.getLogger(__name__)

# Special value to mean "put this rule at the end".
RULE_POSN_LAST = -1

# Chain names
CHAIN_PREROUTING         = "felix-PREROUTING"
CHAIN_INPUT              = "felix-INPUT"
CHAIN_FORWARD            = "felix-FORWARD"
CHAIN_TO_PREFIX          = "felix-to-"
CHAIN_FROM_PREFIX        = "felix-from-"

# ipset names. An ipset can either have a port and protocol or not - it cannot
# have a mix of members with and without them.
IPSET_TO_NOPORT_PREFIX    = "felix-to-noport-"
IPSET_TO_PORT_PREFIX      = "felix-to-port-"
IPSET_FROM_NOPORT_PREFIX  = "felix-from-noport-"
IPSET_FROM_PORT_PREFIX    = "felix-from-port-"
IPSET6_TO_NOPORT_PREFIX   = "felix-6-to-noport-"
IPSET6_TO_PORT_PREFIX     = "felix-6-to-port-"
IPSET6_FROM_NOPORT_PREFIX = "felix-6-from-noport-"
IPSET6_FROM_PORT_PREFIX   = "felix-6-from-port-"
IPSET_TMP_PORT            = "felix-tmp-port"
IPSET_TMP_NOPORT          = "felix-tmp-noport"
IPSET6_TMP_PORT           = "felix-6-tmp-port"
IPSET6_TMP_NOPORT         = "felix-6-tmp-noport"

# Flag to indicate "IP v4" or "IP v6"; format that can be printed in logs.
IPV4 = "IPv4"
IPV6 = "IPv6"

# Load the conntrack tables. This is a workaround for this issue
# https://github.com/ldx/python-iptables/issues/112
iptc.Rule().create_match("conntrack")
iptc.Rule6().create_match("conntrack")

def tap_exists(tap):
    """
    Returns True if tap device exists.
    """
    return os.path.exists("/sys/class/net/" + tap)

def list_routes(type, tap):
    """
    List routes for a given tap interface. Returns a set with all addresses for
    which there is a route to the device.
    """
    routes = set()

    if type == IPV4:
        data = subprocess.check_output(["ip", "route", "list", "dev", tap])
    else:
        data = subprocess.check_output(["ip", "-6", "route", "list", "dev", tap])

    lines = data.split("\n")

    for line in lines:
        # Example of the lines we care about is (having specified the device above) :
        # 10.11.2.66 proto static  scope link
        words = line.split()

        if len(words) > 1:
            routes.add(words[0])

    return routes

def add_route(type,ip,tap):
    """
    Add a route to a given tap interface (including arp config).
    Errors lead to exceptions that are not handled here.
    """
    if type == IPV4:
        subprocess.check_call(['arp', '-Ds', ip, tap, '-i', tap])
        subprocess.check_call(["ip", "route", "add", ip, "dev", tap])
    else:
        subprocess.check_call(["ip", "-6", "route", "add", ip, "dev", tap])

def del_route(type, ip,tap):
    """
    Delete a route to a given tap interface (including arp config).
    Errors lead to exceptions that are not handled here.
    """
    if type == IPV4:
        subprocess.check_call(['arp', '-d', ip, '-i', tap])
        subprocess.check_call(["ip", "route", "del", ip, "dev", tap])
    else:
        subprocess.check_call(["ip", "-6", "route", "del", ip, "dev", tap])

def configure_tap(tap):
    """
    Configure the various proc file system parameters for the tap interface.

    Specifically, allow packets from tap interfaces to be directed to localhost,
    and allow proxy ARP.
    """
    with open('/proc/sys/net/ipv4/conf/%s/route_localnet' % tap, 'wb') as f:
        f.write('1')

    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % tap, 'wb') as f:
        f.write('1')

def insert_rule(rule, chain, position=0):
    """
    Add an iptables rule to a chain if it does not already exist. Position
    is the position for the insert as an offset; if set to futils.RULE_POSN_LAST
    then the rule is appended.
    """
    found = False
    rules = chain.rules

    if position == RULE_POSN_LAST:
        position = len(rules)

    if rule not in chain.rules:
        chain.insert_rule(rule, position)

def get_rule(type):
    """
    Gets a new empty rule. This is a simple helper method that returns either
    an IP v4 or an IP v6 rule according to type.
    """
    if type == IPV4:
        rule = iptc.Rule()
    else:
        rule = iptc.Rule6()
    return rule

def set_global_rules():
    """
    Set up global iptables rules. These are rules that do not change with endpoint,
    and are expected never to change - but they must be present.
    """
    # The nat tables first. This must have a felix-PREROUTING chain.
    table = iptc.Table(iptc.Table.NAT)
    
    if not table.is_chain(CHAIN_PREROUTING):
        log.debug("Creating chain %s", CHAIN_PREROUTING)
        chain = table.create_chain(CHAIN_PREROUTING)
    else:
        chain = iptc.Chain(table,CHAIN_PREROUTING)

    # Now add the single rule to that chain. It looks like this.
    #  DNAT       tcp  --  any    any     anywhere             169.254.169.254      tcp dpt:http to:127.0.0.1:9697
    rule          = iptc.Rule()
    rule.dst      = "169.254.169.254"
    rule.protocol = "tcp"
    target        = iptc.Target(rule, "DNAT")
    target.to_destination = "127.0.0.1:9697"
    rule.target   = target
    match = iptc.Match(rule, "tcp")
    match.dport = "80"
    rule.add_match(match)
    insert_rule(rule,chain)

    # TODO: This is a hack, because of a bug in python-iptables where it fails to
    # correctly match some rules; see https://github.com/ldx/python-iptables/issues/111
    # If any of the rules relating to this tap device already exist, assume that
    # they all do so as not to recreate them.
    rules_check = subprocess.call("iptables -L %s | grep %s" % ("INPUT",CHAIN_INPUT),shell=True)

    if rules_check == 0:
        log.debug("Static rules already exist")
    else:
        # Add a rule that forces us through the chain we have just created / verified
        chain = iptc.Chain(table, "PREROUTING")
        rule  = iptc.Rule()
        rule.create_target(CHAIN_PREROUTING)
        insert_rule(rule,chain)

    # Now the filter table. This needs to have calico-filter-FORWARD and calico-filter-INPUT chains
    table = iptc.Table(iptc.Table.FILTER)

    if not table.is_chain(CHAIN_FORWARD):
        table.create_chain(CHAIN_FORWARD)

    if not table.is_chain(CHAIN_INPUT):
        table.create_chain(CHAIN_INPUT)

    if rules_check != 0:
        # Add rules that forces us through the chain we have just created / verified
        chain = iptc.Chain(table,"FORWARD")
        rule  = iptc.Rule()
        rule.create_target(CHAIN_FORWARD)
        insert_rule(rule,chain)

        chain = iptc.Chain(table,"INPUT")
        rule  = iptc.Rule()
        rule.create_target(CHAIN_INPUT)
        insert_rule(rule,chain)

    # Now the IP v6 filter table. This needs to have calico-filter-FORWARD and
    # calico-filter-INPUT chains
    table = iptc.Table6(iptc.Table6.FILTER)
    if not table.is_chain(CHAIN_FORWARD):
        table.create_chain(CHAIN_FORWARD)

    if not table.is_chain(CHAIN_INPUT):
        table.create_chain(CHAIN_INPUT)

    if rules_check != 0:
        # Add rules that forces us through the chain we have just created / verified
        chain = iptc.Chain(table,"FORWARD")
        rule  = iptc.Rule6()
        rule.create_target(CHAIN_FORWARD)
        insert_rule(rule,chain)

        chain = iptc.Chain(table,"INPUT")
        rule  = iptc.Rule6()
        rule.create_target(CHAIN_INPUT)
        insert_rule(rule,chain)

def set_rules(id,iface,type,localips,mac):
    """
    Add (or modify) the rules for a particular endpoint, whose id
    is supplied.
    """
    to_chain_name   = CHAIN_TO_PREFIX + id
    from_chain_name = CHAIN_FROM_PREFIX + id

    # Set up all the ipsets.
    if type == IPV4:
        to_ipset_port     = IPSET_TO_PORT_PREFIX + id
        to_ipset_noport   = IPSET_TO_NOPORT_PREFIX + id
        from_ipset_port   = IPSET_FROM_PORT_PREFIX + id
        from_ipset_noport = IPSET_FROM_NOPORT_PREFIX + id
        family            = "inet"
    else:
        to_ipset_port     = IPSET6_TO_PORT_PREFIX + id
        to_ipset_noport   = IPSET6_TO_NOPORT_PREFIX + id
        from_ipset_port   = IPSET6_FROM_PORT_PREFIX + id
        from_ipset_noport = IPSET6_FROM_NOPORT_PREFIX + id
        family            = "inet6"

    # Create ipsets if they do not already exist.
    if call_silent(["ipset", "list", to_ipset_port]) != 0:
        subprocess.check_call(["ipset", "create", to_ipset_port, "hash:net,port",
                               "family", family],
                              stdout=open('/dev/null', 'w'), stderr=subprocess.STDOUT)

    if call_silent(["ipset", "list", to_ipset_noport]) != 0:
        subprocess.check_call(["ipset", "create", to_ipset_noport, "hash:net",
                               "family", family],
                              stdout=open('/dev/null', 'w'), stderr=subprocess.STDOUT)

    if call_silent(["ipset", "list", from_ipset_port]) != 0:
        subprocess.check_call(["ipset", "create", from_ipset_port, "hash:net,port",
                               "family", family],
                              stdout=open('/dev/null', 'w'), stderr=subprocess.STDOUT)

    if call_silent(["ipset", "list", from_ipset_noport]) != 0:
        subprocess.check_call(["ipset", "create", from_ipset_noport, "hash:net",
                               "family", family],
                              stdout=open('/dev/null', 'w'), stderr=subprocess.STDOUT)

    # Get the table.
    if type == IPV4:
        table  = iptc.Table(iptc.Table.FILTER)
    else:
        table  = iptc.Table6(iptc.Table6.FILTER)

    # Create the chains for packets to the interface
    if not table.is_chain(to_chain_name):
        to_chain = table.create_chain(to_chain_name)
    else:
        to_chain = iptc.Chain(table,to_chain_name)

    # Put rules into that chain.
    index = 0
   
    if type == IPV6:
        # In ipv6 only, there are 6 rules that need to be created first.
        # RETURN     ipv6-icmp    anywhere             anywhere             ipv6-icmptype 130
        # RETURN     ipv6-icmp    anywhere             anywhere             ipv6-icmptype 131
        # RETURN     ipv6-icmp    anywhere             anywhere             ipv6-icmptype 132
        # RETURN     ipv6-icmp    anywhere             anywhere             ipv6-icmp router-advertisement
        # RETURN     ipv6-icmp    anywhere             anywhere             ipv6-icmp neighbour-solicitation
        # RETURN     ipv6-icmp    anywhere             anywhere             ipv6-icmp neighbour-advertisement
        #
        # These rules are ICMP types 130, 131, 132, 134, 135 and 136, and can be
        # created on the command line with something like :
        #         ip6tables -A plw -j RETURN --protocol icmpv6 --icmpv6-type 130
        for icmp in [ "130", "131", "132", "134", "135", "136" ]:
            rule          = iptc.Rule6()
            rule.create_target("RETURN")
            rule.protocol = "icmpv6"
            match = iptc.Match(rule, "icmp6")
            match.icmpv6_type = [ icmp ]
            rule.add_match(match)
            insert_rule(rule,to_chain,index)
            index += 1

    rule = get_rule(type)
    rule.create_target("DROP")
    match = rule.create_match("conntrack")
    match.ctstate = ["INVALID"]
    insert_rule(rule,to_chain,index)
    index += 1

    # "Return if state RELATED or ESTABLISHED".
    rule = get_rule(type)
    rule.create_target("RETURN")
    match = rule.create_match("conntrack")
    match.ctstate = ["RELATED,ESTABLISHED"]
    insert_rule(rule,to_chain,index)
    index += 1

    # "Accept anything whose sources matches this ipset" (for two ipsets)
    rule = get_rule(type)
    rule.create_target("RETURN")
    match = iptc.Match(rule, "set")
    match.match_set = [to_ipset_port, "src"]
    rule.add_match(match)
    insert_rule(rule,to_chain,index)
    index += 1
   
    rule = get_rule(type)
    rule.create_target("RETURN")
    match = iptc.Match(rule, "set")
    match.match_set = [to_ipset_noport, "src"]
    rule.add_match(match)
    insert_rule(rule,to_chain,index)
    index += 1

    # Finally, "DROP unconditionally"
    rule = get_rule(type)
    rule.create_target("DROP")
    insert_rule(rule,to_chain,RULE_POSN_LAST)

    # Now the chain that manages packets from the interface.
    if not table.is_chain(from_chain_name):
        from_chain = table.create_chain(from_chain_name)
    else:
        from_chain = iptc.Chain(table,from_chain_name)

    # Now the rules in that from chain
    index = 0
    if type == IPV6:
        # In ipv6 only, we start with a rule that allows all ICMP traffic from
        # this endpoint to anywhere.
        rule = iptc.Rule6()
        rule.create_target("RETURN")
        rule.protocol = "icmpv6"
        insert_rule(rule,from_chain,index)
        index += 1

    # "Drop if state INVALID".
    rule = get_rule(type)
    rule.create_target("DROP")
    match = rule.create_match("conntrack")
    match.ctstate = ["INVALID"]
    insert_rule(rule,from_chain,index)
    index += 1

    # "Return if state RELATED or ESTABLISHED".
    rule = get_rule(type)
    rule.create_target("RETURN")
    match = rule.create_match("conntrack")
    match.ctstate = ["RELATED,ESTABLISHED"]
    insert_rule(rule, from_chain, index)
    index += 1

    if type == IPV4:
        # Only IP v4 needs rules for DHCP traffic here.
        # "Allow through UDP packets from port 68 to port 67" (client to server)
        # This ensures that DHCP can work before the IP address is known.
        rule          = iptc.Rule()
        rule.protocol = "udp"
        rule.create_target("RETURN")
        match = iptc.Match(rule, "udp")
        match.source_port = "68"
        match.destination_port = "67"
        rule.add_match(match)
        insert_rule(rule, from_chain, index)
        index += 1

        # Drop UDP in the other direction, so that endpoints cannot hijack DHCP
        # traffic by acting as DHCP servers.
        rule          = iptc.Rule()
        rule.protocol = "udp"
        rule.create_target("DROP")
        match = iptc.Match(rule, "udp")
        match.sport = "67"
        match.dport = "68"
        rule.add_match(match)
        insert_rule(rule, from_chain, index)
        index += 1

    # "Drop packets whose destination matches the supplied ipset."
    rule = get_rule(type)
    rule.create_target("DROP")
    match = iptc.Match(rule, "set")
    match.match_set = [from_ipset_port, "dst"]
    rule.add_match(match)
    insert_rule(rule, from_chain, index)
    index += 1

    rule = get_rule(type)
    rule.create_target("DROP")
    match = iptc.Match(rule, "set")
    match.match_set = [from_ipset_noport, "dst"]
    rule.add_match(match)
    insert_rule(rule, from_chain, index)
    index += 1

    # Now allow through packets from the correct MAC and IP address. There may
    # be rules here from addresses that this endpoint no longer has - in which
    # case we must remove them.
    #
    # This code is rather ugly - better to turn off table autocommit, but as
    # commented elsewhere, that appears buggy.
    done  = False
    while not done:
        done = True
        for rule in from_chain.rules:
            if (rule.target.name == "RETURN" and rule.match.name == "mac") and
               (rule.src not in localips or rule.match.mac_source != mac):
                # We have a rule that we should not have; either the MAC or the
                # IP has changed. Toss the rule.
                log.info("Removing old IP %s, MAC %s from endpoint %s" %
                         (rule.src, rule.match.mac_source, id))
                chain.delete_rule(rule)
                done = False
                break

    for ip in localips:
        rule = get_rule(type)
        rule.create_target("RETURN")
        rule.src         = ip
        match            = iptc.Match(rule, "mac")
        match.mac_source = mac
        rule.add_match(match)
        insert_rule(rule,from_chain,index)
        index += 1

    # Last rule (at end) says drop unconditionally.
    rule = get_rule(type)
    rule.create_target("DROP")
    insert_rule(rule,from_chain,RULE_POSN_LAST)

    # TODO: This is a hack, because of a bug in python-iptables where it fails to
    # correctly match some rules; see https://github.com/ldx/python-iptables/issues/111
    # If any of the rules relating to this tap device already exist, assume that
    # they all do so as not to recreate them.
    if type == IPV4:
        rules_check = subprocess.call("iptables -L %s | grep %s > /dev/null" %
                                      (CHAIN_INPUT,iface),shell=True)
    else:
        rules_check = subprocess.call("ip6tables -L %s | grep %s > /dev/null" %
                                      (CHAIN_INPUT,iface),shell=True)

    if rules_check == 0:
        log.debug("%s rules for interface %s already exist" % (type, iface))
    else:
        # We have created the chains and rules that control input and output for
        # the interface but not routed traffic through them. Add the input rule
        # detecting packets arriving for the endpoint.
        log.debug("%s rules for interface %s do not already exist" % (type, iface))
        chain = iptc.Chain(table,CHAIN_INPUT)
        rule  = get_rule(type)
        target        = iptc.Target(rule, from_chain_name)
        rule.target   = target
        match = iptc.Match(rule, "physdev")
        match.physdev_in = iface
        match.physdev_is_bridged = ""
        rule.add_match(match)
        insert_rule(rule,chain,RULE_POSN_LAST)

        # Similarly, create the rules that direct packets that are forwarded either
        # to or from the endpoint, sending them to the "to" or "from" chains as
        # appropriate.
        chain = iptc.Chain(table,CHAIN_FORWARD)
        rule  = get_rule(type)
        target        = iptc.Target(rule, from_chain_name)
        rule.target   = target
        match = iptc.Match(rule, "physdev")
        match.physdev_in = iface
        match.physdev_is_bridged = ""
        rule.add_match(match)
        insert_rule(rule,chain,RULE_POSN_LAST)

        rule          = get_rule(type)
        target        = iptc.Target(rule, to_chain_name)
        rule.target   = target
        match = iptc.Match(rule, "physdev")
        match.physdev_out = iface
        match.physdev_is_bridged = ""
        rule.add_match(match)
        insert_rule(rule,chain,RULE_POSN_LAST)

        rule               = get_rule(type)
        target             = iptc.Target(rule, to_chain_name)
        rule.target        = target
        rule.out_interface = iface
        insert_rule(rule,chain,RULE_POSN_LAST)

def del_rules(id,type):
    """
    Remove the rules for an endpoint which is no longer managed.
    """
    log.debug("Delete %s rules for %s" % (type, id))
    to_chain   = CHAIN_TO_PREFIX + id
    from_chain = CHAIN_FROM_PREFIX + id

    if type == IPV4:
        to_ipset_port     = IPSET_TO_PORT_PREFIX + id
        to_ipset_noport   = IPSET_TO_NOPORT_PREFIX + id
        from_ipset_port   = IPSET_FROM_PORT_PREFIX + id
        from_ipset_noport = IPSET_FROM_NOPORT_PREFIX + id

        table = iptc.Table(iptc.Table.FILTER)
    else:
        to_ipset_port     = IPSET6_TO_PORT_PREFIX + id
        to_ipset_noport   = IPSET6_TO_NOPORT_PREFIX + id
        from_ipset_port   = IPSET6_FROM_PORT_PREFIX + id
        from_ipset_noport = IPSET6_FROM_NOPORT_PREFIX + id

        table = iptc.Table6(iptc.Table6.FILTER)

    # Remove the rules routing to the chain we are about to remove
    # The baroque structure is caused by the python-iptables interface.
    # chain.rules returns a list of rules, each of which contains its
    # index (i.e. position). If we get rules 7 and 8 and try to remove
    # them in that order, then the second fails because rule 8 got renumbered
    # when rule 7 was deleted, so the rule we have in our hand neither matches
    # the old rule 8 (now at index 7) or the new rule 8 (with a different target
    # etc. Hence each time we remove a rule we rebuild the list of rules to
    # iterate through.
    #
    # In principle we could use autocommit to make this much nicer, but 
    # in practice it seems a bit buggy, and leads to errors elsewhere.
    for name in (CHAIN_INPUT, CHAIN_FORWARD):
        chain = iptc.Chain(table, name)
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
            chain = iptc.Chain(table, name)
            log.debug("Flush chain %s", name)
            chain.flush()
            log.debug("Delete chain %s", name)
            table.delete_chain(name)

    # Delete the ipsets for this endpoint.
    for ipset in [ from_ipset_noport, from_ipset_port, to_ipset_noport, to_ipset_port ]:
        if call_silent(["ipset", "list", ipset]) == 0:
            subprocess.check_call(["ipset", "destroy", ipset])

def set_acls(id,type,inbound,in_default,outbound,out_default):
    """
    Set up the ACLs, making sure that they match.
    """
    if type == IPV4:
        to_ipset_port     = IPSET_TO_PORT_PREFIX + id
        to_ipset_noport   = IPSET_TO_NOPORT_PREFIX + id
        from_ipset_port   = IPSET_FROM_PORT_PREFIX + id
        from_ipset_noport = IPSET_FROM_NOPORT_PREFIX + id
        tmp_ipset_port    = IPSET_TMP_PORT
        tmp_ipset_noport  = IPSET_TMP_NOPORT
        family            = "inet"
    else:
        to_ipset_port     = IPSET6_TO_PORT_PREFIX + id
        to_ipset_noport   = IPSET6_TO_NOPORT_PREFIX + id
        from_ipset_port   = IPSET6_FROM_PORT_PREFIX + id
        from_ipset_noport = IPSET6_FROM_NOPORT_PREFIX + id
        tmp_ipset_port    = IPSET6_TMP_PORT
        tmp_ipset_noport  = IPSET6_TMP_NOPORT
        family            = "inet6"

    if call_silent(["ipset", "list", tmp_ipset_port]) != 0:
        subprocess.check_call(["ipset", "create", tmp_ipset_port,
                               "hash:net,port", "family", family])
    if call_silent(["ipset", "list", tmp_ipset_noport]) != 0:
        subprocess.check_call(["ipset", "create", tmp_ipset_noport,
                               "hash:net", "family", family])

    subprocess.check_call(["ipset", "flush", tmp_ipset_port])
    subprocess.check_call(["ipset", "flush", tmp_ipset_noport])

    # The ipset format is something like "10.11.1.3,udp:0"
    # Further valid examples include
    #   10.11.1.0/24
    #   10.11.1.0/24,tcp
    #   10.11.1.0/24,80
    for loop in [ "to", "from" ]:
        if loop == "to":
            rule_list     = inbound
            descr        = "inbound " + type
            ipset_port   = to_ipset_port
            ipset_noport = to_ipset_noport
        else:
            rule_list    = outbound
            descr        = "outbound " + type
            ipset_port   = from_ipset_port
            ipset_noport = from_ipset_noport

        for rule in rule_list:
            if rule['cidr'] is None:
                # No cidr - give up.
                log.error("Invalid %s rule without cidr for %s : %s", (descr, id, rule))
                continue
            if rule['protocol'] is None and rule['port'] is not None:
                # No protocol - must also be no port.
                log.error("Invalid %s rule without port but no protocol for %s : %s",
                          (descr, id, rule))
                continue

            if rule['port'] is not None:
                value = "%s,%s:%s" % (rule['cidr'],rule['protocol'],rule['port'])
                subprocess.check_call(["ipset", "add", tmp_ipset_port, value, "-exist"])
            elif rule['protocol'] is not None:
                value = "%s,%s:0" % (rule['cidr'],rule['protocol'])
                subprocess.check_call(["ipset", "add", tmp_ipset_port, value, "-exist"])
            else:
                value = rule['cidr']
                subprocess.check_call(["ipset", "add", tmp_ipset_noport, value, "-exist"])

        # Now that we have added the rules, swap the tmp ipsets with the proper ones.
        subprocess.check_call(["ipset", "swap", tmp_ipset_noport, ipset_noport])
        subprocess.check_call(["ipset", "swap", tmp_ipset_port, ipset_port])

        # Get the temporary ipsets clean again - we leave them existing but empty.
        subprocess.check_call(["ipset", "flush", tmp_ipset_port])
        subprocess.check_call(["ipset", "flush", tmp_ipset_noport])
          
def list_eps_with_rules(type):
    """
    Lists all of the endpoints for which rules exist and are owned by Felix.
    Returns a set of suffices, i.e. the start of the uuid / end of the interface
    name.
    """
    if type == IPV4:
        table = iptc.Table(iptc.Table.FILTER)
    else:
        table = iptc.Table6(iptc.Table6.FILTER)

    eps  = { chain.name.replace(CHAIN_TO_PREFIX, "")
             for chain in table.chains
             if chain.name.startswith(CHAIN_TO_PREFIX) }

    data  = subprocess.check_output(["ipset", "list"])
    lines = data.split("\n")

    for line in lines:
        # Pull out ipsets that we manage. Note that we are looking for the
        # first one created, and the last one deleted, as with the chains above.
        words = line.split()
        if len(words) > 1 and words[0] == "Name:" and words[1].startswith(IPSET_TO_PORT_PREFIX):
            eps.add(words[1].replace(IPSET_TO_PORT_PREFIX, ""))
        elif len(words) > 1 and words[0] == "Name:" and words[1].startswith(IPSET6_TO_PORT_PREFIX):
            eps.add(words[1].replace(IPSET6_TO_PORT_PREFIX, ""))
            
    return eps

def mkdir_p(path):
    """http://stackoverflow.com/a/600612/190597 (tzot)"""
    try:
        os.makedirs(path, exist_ok=True)  # Python>3.2
    except TypeError:
        try:
            os.makedirs(path)
        except OSError as exc: # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else: raise

def call_silent(args):
    """
    Wrapper round subprocess_call that discards all of the output. *args* must
    be a list.
    """
    retcode = subprocess.call(args,
                              stdout=open('/dev/null', 'w'),
                              stderr=subprocess.STDOUT)
    return retcode
