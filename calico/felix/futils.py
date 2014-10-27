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
IPSET_TO_NOPORT_PREFIX   = "felix-to-noport-"
IPSET_TO_PORT_PREFIX     = "felix-to-port-"
IPSET_FROM_NOPORT_PREFIX = "felix-from-noport-"
IPSET_FROM_PORT_PREFIX   = "felix-from-port-"
IPSET_TMP_PORT           = "felix-tmp-port"
IPSET_TMP_NOPORT         = "felix-tmp-noport"

def tap_exists(tap):
    """
    Returns True if tap device exists.
    """
    return os.path.exists("/sys/class/net/" + tap)

def list_routes(tap):
    """
    List routes for a given tap interface. Returns a set with all addresses for
    which there is a route to the device.
    """
    # TODO: currently IP v4 only
    routes = set()

    data = subprocess.check_output(["ip", "route", "list", "dev", tap])
    lines = data.split("\n")

    for line in lines:
        # Example of the lines we care about is (having specified the device above) :
        # 10.11.2.66 proto static  scope link
        words = line.split()

        if len(words) > 1:
            routes.add(words[0])

    return routes

def add_route(ip,tap):
    """
    Add a route to a given tap interface (including arp config).
    Errors lead to exceptions that are not handled here.
    """
    # TODO: currently IP v4 only
    subprocess.check_call(['arp', '-Ds', ip, tap, '-i', tap])
    subprocess.check_call(["ip", "route", "add", ip, "dev", tap])

def del_route(ip,tap):
    """
    Delete a route to a given tap interface (including arp config).
    Errors lead to exceptions that are not handled here.
    """
    # TODO: currently IP v4 only
    subprocess.check_call(['arp', '-d', ip, '-i', tap])
    subprocess.check_call(["ip", "route", "del", ip, "dev", tap])

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
       

def set_rules(id,iface,localips,mac):
    """
    Add (or modify) the rules for a particular endpoint, whose id
    is supplied.
    """
    to_chain   = CHAIN_TO_PREFIX + id
    from_chain = CHAIN_FROM_PREFIX + id

    to_ipset_port     = IPSET_TO_PORT_PREFIX + id
    to_ipset_noport   = IPSET_TO_NOPORT_PREFIX + id
    from_ipset_port   = IPSET_FROM_PORT_PREFIX + id
    from_ipset_noport = IPSET_FROM_NOPORT_PREFIX + id

    table = iptc.Table(iptc.Table.FILTER)

    # Create ipsets if they do not already exist.
    if subprocess.call(["ipset", "list", to_ipset_port]) != 0:
        subprocess.check_call(["ipset", "create", to_ipset_port, "hash:net,port"])

    if subprocess.call(["ipset", "list", to_ipset_noport]) != 0:
        subprocess.check_call(["ipset", "create", to_ipset_noport, "hash:net"])

    if subprocess.call(["ipset", "list", from_ipset_port]) != 0:
        subprocess.check_call(["ipset", "create", from_ipset_port, "hash:net,port"])

    if subprocess.call(["ipset", "list", from_ipset_noport]) != 0:
        subprocess.check_call(["ipset", "create", from_ipset_noport, "hash:net"])

    # Create the two chains for packets to / from the interface
    if not table.is_chain(to_chain):
        chain = table.create_chain(to_chain)
    else:
        chain = iptc.Chain(table,to_chain)

    # The "to" chain has 3 default rules.
    # Rule 0 says "drop if state INVALID".
    rule          = iptc.Rule()
    rule.create_target("DROP")
    match = iptc.Match(rule, "state")
    match.state = "INVALID"
    rule.add_match(match)
    insert_rule(rule,chain,0)
    
    # Rule 1 says "return if state RELATED or ESTABLISHED".
    rule          = iptc.Rule()
    rule.create_target("RETURN")
    match = iptc.Match(rule, "state")
    match.state = "RELATED,ESTABLISHED"
    rule.add_match(match)
    insert_rule(rule,chain,1)

    # Rules 2 and 3 say "accept anything whose sources matches this ipset".
    rule = iptc.Rule()
    rule.create_target("RETURN")
    match = iptc.Match(rule, "set")
    match.match_set = [to_ipset_port, "src"]
    rule.add_match(match)
    insert_rule(rule,chain,2)
   
    rule = iptc.Rule()
    rule.create_target("RETURN")
    match = iptc.Match(rule, "set")
    match.match_set = [to_ipset_noport, "src"]
    rule.add_match(match)
    insert_rule(rule,chain,3)
   
    # Last rule (at end) says drop unconditionally.
    rule          = iptc.Rule()
    rule.create_target("DROP")
    insert_rule(rule,chain,RULE_POSN_LAST)

    # Now the chain that manages packets from the interface.
    if not table.is_chain(from_chain):
        chain = table.create_chain(from_chain)
    else:
        chain = iptc.Chain(table,from_chain)

    # Rule 0 says "drop if state INVALID".
    rule          = iptc.Rule()
    rule.create_target("DROP")
    match = iptc.Match(rule, "state")
    match.state = "INVALID"
    rule.add_match(match)
    insert_rule(rule,chain,0)
    
    # Rule 1 says "return if state RELATED or ESTABLISHED".
    rule          = iptc.Rule()
    rule.create_target("RETURN")
    match = iptc.Match(rule, "state")
    match.state = "RELATED,ESTABLISHED"
    rule.add_match(match)
    insert_rule(rule,chain,1)

    # Rule 2 says allow through UDP packets from port 68 to port 67
    # This ensures that DHCP can work before the IP address is known.
    rule          = iptc.Rule()
    rule.protocol = "udp"
    rule.create_target("RETURN")
    match = iptc.Match(rule, "udp")
    match.source_port = "68"
    match.destination_port = "67"
    rule.add_match(match)
    insert_rule(rule,chain,2)

    # Rule 3 says drop UDP in the other direction, so that endpoints cannot
    # hijack DHCP traffic by acting as DHCP servers.
    rule          = iptc.Rule()
    rule.protocol = "udp"
    rule.create_target("DROP")
    match = iptc.Match(rule, "udp")
    match.sport = "67"
    match.dport = "68"
    rule.add_match(match)
    insert_rule(rule,chain,3)

    # Rules 4 and 5 say to drop packets whose destination matches the supplied ipset.
    rule = iptc.Rule()
    rule.create_target("DROP")
    match = iptc.Match(rule, "set")
    match.match_set = [from_ipset_port, "dst"]
    rule.add_match(match)
    insert_rule(rule,chain,4)

    rule = iptc.Rule()
    rule.create_target("DROP")
    match = iptc.Match(rule, "set")
    match.match_set = [from_ipset_noport, "dst"]
    rule.add_match(match)
    insert_rule(rule,chain,5)

    # Rule 6 says allow through packets from the correct MAC and IP address.
    for ip in localips:
        rule = iptc.Rule()
        rule.create_target("RETURN")
        rule.src         = ip
        match            = iptc.Match(rule, "mac")
        match.mac_source = mac
        rule.add_match(match)
        insert_rule(rule,chain,6)

    # TODO: If you remove an IP from an instance, we do not tidy it up here.
    # We ought to run through all such rules and tidy them up.
       
    # Last rule (at end) says drop unconditionally; other rules allowing things
    # may be added before this.
    rule          = iptc.Rule()
    rule.create_target("DROP")
    insert_rule(rule,chain,RULE_POSN_LAST)

    # TODO: This is a hack, because of a bug in python-iptables where it fails to
    # correctly match some rules; see https://github.com/ldx/python-iptables/issues/111
    # If any of the rules relating to this tap device already exist, assume that
    # they all do so as not to recreate them.
    rules_check = subprocess.call("iptables -L %s | grep %s" % (CHAIN_INPUT,iface),shell=True)

    if rules_check == 0:
        log.debug("Rules for interface %s already exist" % iface)
    else:
        # We have created the chains and rules that control input and output for
        # the interface but not routed traffic through them. Add the input rule
        # detecting packets arriving for the endpoint.
        log.debug("Rules for interface %s do not already exist" % iface)
        chain = iptc.Chain(table,CHAIN_INPUT)
        rule  = iptc.Rule()
        target        = iptc.Target(rule, from_chain)
        rule.target   = target
        match = iptc.Match(rule, "physdev")
        match.physdev_in = iface
        match.physdev_is_bridged = ""
        rule.add_match(match)
        insert_rule(rule,chain,RULE_POSN_LAST)

        # Similarly, create the rules that direct packets that are forwarded either
        # to or from the endpoint, sending them to the to or from chains as
        # appropriate.
        chain = iptc.Chain(table,CHAIN_FORWARD)
        rule  = iptc.Rule()
        target        = iptc.Target(rule, from_chain)
        rule.target   = target
        match = iptc.Match(rule, "physdev")
        match.physdev_in = iface
        match.physdev_is_bridged = ""
        rule.add_match(match)
        insert_rule(rule,chain,RULE_POSN_LAST)

        rule  = iptc.Rule()
        target        = iptc.Target(rule, to_chain)
        rule.target   = target
        match = iptc.Match(rule, "physdev")
        match.physdev_out = iface
        match.physdev_is_bridged = ""
        rule.add_match(match)
        insert_rule(rule,chain,RULE_POSN_LAST)

        rule  = iptc.Rule()
        target             = iptc.Target(rule, to_chain)
        rule.target        = target
        rule.out_interface = iface
        insert_rule(rule,chain,RULE_POSN_LAST)

def del_rules(id):
    """
    Remove the rules for an endpoint which is no longer managed.
    """
    to_chain   = CHAIN_TO_PREFIX + id
    from_chain = CHAIN_FROM_PREFIX + id

    to_ipset_port     = IPSET_TO_PORT_PREFIX + id
    to_ipset_noport   = IPSET_TO_NOPORT_PREFIX + id
    from_ipset_port   = IPSET_FROM_PORT_PREFIX + id
    from_ipset_noport = IPSET_FROM_NOPORT_PREFIX + id

    table = iptc.Table(iptc.Table.FILTER)

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
    # TODO: Think if there is a good way to tidy this up.
    chain = iptc.Chain(table, CHAIN_INPUT)
    done  = False
    while not done:
        done = True
        for rule in chain.rules:
            if rule.target.name in (to_chain, from_chain):
                log.debug("Delete rule %s from %s" % (rule.target.name, chain.name))
                chain.delete_rule(rule)
                done = False
                break

    chain = iptc.Chain(table, CHAIN_FORWARD)
    done  = False
    while not done:
        done = True
        for rule in chain.rules:
            if rule.target.name in (to_chain, from_chain):
                log.debug("Delete rule %s from %s" % (rule.target.name, chain.name))
                chain.delete_rule(rule)
                done = False
                break

    for rule in chain.rules[:]:
        if rule.target.name in (to_chain, from_chain):
            log.debug("Delete rule %s from %s" % (rule.target.name, chain.name))
            chain.delete_rule(rule)

    if table.is_chain(from_chain):
        chain = iptc.Chain(table, from_chain)
        chain.flush()
        chain = table.delete_chain(from_chain)

    if table.is_chain(to_chain):
        chain = iptc.Chain(table, to_chain)
        chain.flush()
        chain = table.delete_chain(to_chain)

    # Delete the ipsets for this entity.
    if subprocess.call(["ipset", "list", from_ipset_noport]) != 0:
        subprocess.check_call(["ipset", "destroy", from_ipset_noport])

    if subprocess.call(["ipset", "list", from_ipset_port]) != 0:
        subprocess.check_call(["ipset", "destroy", from_ipset_port])

    if subprocess.call(["ipset", "list", to_ipset_noport]) != 0:
        subprocess.check_call(["ipset", "destroy", to_ipset_noport])

    if subprocess.call(["ipset", "list", to_ipset_port]) != 0:
        subprocess.check_call(["ipset", "destroy", to_ipset_port])

def set_acls(id,inbound,in_default,outbound,out_default):
    """
    Set up the ACLs, making sure that they match.
    """
    log.debug("Create ACLs for endpoint %s, with inbound %s" % (id, inbound))

    to_ipset_port     = IPSET_TO_PORT_PREFIX + id
    to_ipset_noport   = IPSET_TO_NOPORT_PREFIX + id
    from_ipset_port   = IPSET_FROM_PORT_PREFIX + id
    from_ipset_noport = IPSET_FROM_NOPORT_PREFIX + id

    if subprocess.call(["ipset", "list", IPSET_TMP_PORT]) != 0:
        subprocess.check_call(["ipset", "create", IPSET_TMP_PORT, "hash:net,port"])

    if subprocess.call(["ipset", "list", IPSET_TMP_NOPORT]) != 0:
        subprocess.check_call(["ipset", "create", IPSET_TMP_NOPORT, "hash:net"])

    subprocess.check_call(["ipset", "flush", IPSET_TMP_PORT])
    subprocess.check_call(["ipset", "flush", IPSET_TMP_NOPORT])

    # The ipset format is something like "10.11.1.3,udp:0"
    # Further valid examples include
    #   10.11.1.0/24
    #   10.11.1.0/24,tcp
    #   10.11.1.0/24,80
    for rule in inbound:
        if rule['cidr'] is None:
            # No cidr - give up.
            log.error("Invalid rule without cidr for %s : %s", id, rule)
            continue
        if rule['protocol'] is None and rule['port'] is not None:
            # No protocol - must also be no port.
            log.error("Invalid rule without port but no protocol for %s : %s", id, rule)
            continue

        if rule['port'] is not None:
            value = "%s,%s:%s" % (rule['cidr'],rule['protocol'],rule['port'])
            subprocess.check_call(["ipset", "add", IPSET_TMP_PORT, value, "-exist"])
        elif rule['protocol'] is not None:
            value = "%s,%s:0" % (rule['cidr'],rule['protocol'])
            subprocess.check_call(["ipset", "add", IPSET_TMP_PORT, value, "-exist"])
        else:
            value = rule['cidr']
            subprocess.check_call(["ipset", "add", IPSET_TMP_NOPORT, value, "-exist"])
          
    # Now that we have added the rules, swap the tmp ipsets with the proper ones.
    subprocess.check_call(["ipset", "swap", IPSET_TMP_NOPORT, to_ipset_noport])
    subprocess.check_call(["ipset", "swap", IPSET_TMP_PORT, to_ipset_port])

    # Get the temporary ipsets clean for outbound rules.
    subprocess.check_call(["ipset", "flush", IPSET_TMP_PORT])
    subprocess.check_call(["ipset", "flush", IPSET_TMP_NOPORT])

    # TODO: This code is block coped from that above. Clearly refactoring would
    #       be a good idea here
    for rule in outbound:
        if rule['cidr'] is None:
            # No cidr - give up.
            log.error("Invalid rule without cidr for %s : %s", id, rule)
            continue
        if rule['protocol'] is None and rule['port'] is not None:
            # No protocol - must also be no port.
            log.error("Invalid rule without port but no protocol for %s : %s", id, rule)
            continue

        if rule['port'] is not None:
            value = "%s,%s:%s" % (rule['cidr'],rule['protocol'],rule['port'])
            subprocess.check_call(["ipset", "add", IPSET_TMP_PORT, value, "-exist"])
        elif rule['protocol'] is not None:
            value = "%s,%s:0" % (rule['cidr'],rule['protocol'])
            subprocess.check_call(["ipset", "add", IPSET_TMP_PORT, value, "-exist"])
        else:
            value = rule['cidr']
            subprocess.check_call(["ipset", "add", IPSET_TMP_NOPORT, value, "-exist"])

    # Now that we have added the rules, swap the tmp ipsets with the proper ones.
    subprocess.check_call(["ipset", "swap", IPSET_TMP_NOPORT, from_ipset_noport])
    subprocess.check_call(["ipset", "swap", IPSET_TMP_PORT, from_ipset_port])

    # Empty the ipsets - we could leave the old data lying around, but tidier
    # to delete it all.
    subprocess.check_call(["ipset", "flush", IPSET_TMP_PORT])
    subprocess.check_call(["ipset", "flush", IPSET_TMP_NOPORT])

          
def list_eps_with_rules():
    """
    Lists all of the endpoints for which rules exist and are owned by Felix.
    Returns a set of suffices, i.e. the start of the uuid / end of the interface
    name.
    """
    table = iptc.Table(iptc.Table.FILTER)
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
            
    return eps

