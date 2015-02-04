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
felix.fiptables
~~~~~~~~~~~~

IP tables management functions. This is a wrapper round python-iptables that
allows us to mock it out for testing.
"""
import logging
import os
import re
import time

from calico.felix import futils
from calico.felix.futils import IPV4, IPV6

# iptables command to use.
IPTABLES_CMD = { IPV4: "iptables",
                 IPV6: "ip6tables" }

# Logger
log = logging.getLogger(__name__)

# Special value to mean "put this rule at the end".
RULE_POSN_LAST = -1

class Chain(object):
    """
    Representation of an iptables chain.
    """
    def __init__(self, table, name):
        self.type = table.type
        self.table = table
        self.name = name
        self.rules = []

    def flush(self):
        log.debug("Flushing chain %s", self.name)
        futils.check_call([IPTABLES_CMD[self.type],
                           "-w",
                           "-t",
                           self.table.name,
                           "-F",
                           self.name])
        del self.rules[:]

    def delete_rule(self, rule):
        # The rule must exist or it is an error.
        self.rules.remove(rule)
        args = [IPTABLES_CMD[self.type],
                "-w",
                "-t",
                self.table.name,
                "-D",
                self.name]
        args.extend(rule.generate_fields())
        log.debug("Removing rule : %s", args)
        futils.check_call(args)

    def truncate_rules(self, count):
        """
        This is a utility function to remove any excess rules from a
        chain. After we have carefully inserted all the rules we want at the
        start, we want to get rid of any legacy rules from the end.

        It takes a chain object, and a count for how many of the rules should
        be left in place.
        """
        log.debug("Truncate chain %s to length %d (length now %d)",
                  self.name,
                  count,
                  len(self.rules))
        while len(self.rules) > count:
            args = [IPTABLES_CMD[self.type],
                    "-w",
                    "-t",
                    self.table.name,
                    "-D",
                    self.name,
                    str(count + 1)]
            futils.check_call(args)
            self.rules.pop(count)

    def insert_rule(self, rule, position):
        """
        Insert the given rule at the supplied position.
        
        position of 0 means "insert at the start", which is what iptables
        considers as position 1.
        """
        args = [IPTABLES_CMD[self.type],
                "-w",
                "-t",
                self.table.name,
                "-I",
                self.name,
                str(position + 1)]
        args.extend(rule.generate_fields())
        futils.check_call(args)
        self.rules.insert(position, rule)

    def __eq__(self, other):
        # Equality deliberately only cares about name.
        if self.name == other.name:
            return True
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(self,other)

class Table(object):
    """
    Representation of an iptables table.
    """
    def __init__(self, type, name):
        self.type = type
        self.name = name
        self.chains = {}

    def is_chain(self, name):
        return (name in self.chains)

    def delete_chain(self, chain_name):
        log.debug("Delete chain %s from table %s", chain_name, self.name)
        futils.check_call([IPTABLES_CMD[self.type],
                           "-w",
                           "-t",
                           self.name,
                           "-X",
                           chain_name])
        del self.chains[chain_name]
                
class Rule(object):
    """
    Rule object. This contains information about rules.
    """
    def __init__(self, type, target=None):
        self.type = type

        # TODO: This whole lot would be improved if src, dst etc. were all just
        # fields in a dictionary. But that is for a later phase (when we either
        # put in a lot of setters or just change the calling code and the
        # tests).
        self.dst = None
        self.src = None
        self.protocol = None
        self.in_interface = None
        self.out_interface = None

        self.target = target
        self.match = None

        # We bundle rule and match parameters together for easier coding.
        self.parameters = {}

    def parse_fields(self, line, fields):
        """
        Parse field retrieved from iptables -S. The -A and the chain name must
        have been removed from the list supplied.

        For example :
        -s 192.168.122.0/24 -d 224.0.0.0/24 -j RETURN
        -m set --match-set felix-from-port-1729ebac-f0 dst,dst -j RETURN

        line is used only for logging.
        """
        #TODO: The big if test on all the fields is a bit ugly.
        while fields:
            negative = False

            if fields[0] == "!":
                negative = True
                fields.pop(0)

            flag = fields.pop(0)

            # TODO: Values can be multiple words, and we just prepend ! for a
            # negative. We could do this more tidily.
            values = []
            while fields and fields[0][0] != "-":
                values.append(fields.pop(0)) 

            value = " ".join(values)

            if negative:
                value = "!" + value

            if flag == "-s":
                #TODO: oh my; this is horrible
                if value.endswith("/32"):
                    value = value[:-3]
                self.src = value
            elif flag == "-d":
                #TODO: oh my; this is horrible
                if value.endswith("/32"):
                    value = value[:-3]
                self.dst = value
            elif flag == "-p":
                self.protocol = value
            elif flag == "-i":
                self.in_interface = value
            elif flag == "-o":
                self.out_interface = value
            elif flag == "-j":
                self.target = value
            elif flag == "-m":
                self.match = value
            elif flag.startswith("--"):
                self.parameters[flag[2:]] = value
            else:
                raise UnrecognisedIptablesField(
                        "Unable to parse iptables rule : %s" % line)

    def generate_fields(self):
        """
        Returns an iptables set of fields from a rule; the inverse of
        parse_fields.
        """
        #TODO: This is ugly and should be tidied up too.
        fields = []
        if self.src is not None:
            if self.src[0] == "!":
                fields.extend(["!", "-s", self.src[1:]])
            else:
                fields.extend(["-s", self.src])

        if self.dst is not None:
            if self.dst[0] == "!":
                fields.extend(["!", "-d", self.dst[1:]])
            else:
                fields.extend(["-d", self.dst])

        if self.protocol is not None:
            if self.protocol[0] == "!":
                fields.extend(["!", "-p", self.protocol[1:]])
            else:
                fields.extend(["-p", self.protocol])

        if self.in_interface is not None:
            if self.in_interface[0] == "!":
                fields.extend(["!", "-i", self.in_interface[1:]])
            else:
                fields.extend(["-i", self.in_interface])

        if self.out_interface is not None:
            if self.out_interface[0] == "!":
                fields.extend(["!", "-o", self.out_interface[1:]])
            else:
                fields.extend(["-o", self.out_interface])

        if self.target is not None:
            if self.target[0] == "!":
                fields.extend(["!", "-j", self.target[1:]])
            else:
                fields.extend(["-j", self.target])

        if self.match is not None:
            if self.match[0] == "!":
                fields.extend(["!", "-m", self.match[1:]])
            else:
                fields.extend(["-m", self.match])

        for key in self.parameters:
            value = self.parameters[key]
            if value[0] == "!":
                fields.append("!")
                value = value[1:]
            fields.append("--" + key)
            fields.extend(value.split())

        return fields
            
    def create_target(self, name, parameters=None):
        self.target = name
        for key in parameters:
            # replace _ (python_iptables) with - (normal iptables)
            self.parameters[key.replace("_", "-")] = parameters[key]

    def create_tcp_match(self, dport):
        self.match = "tcp"
        self.parameters["dport"] = dport

    def create_icmp6_match(self, icmp_type):
        self.match = "icmp6"
        # TODO: bad interface that this is a list, but because of
        # python-iptables
        # And the list must only have one element...
        self.parameters["icmpv6-type"] = icmp_type[0]

    def create_conntrack_match(self, state):
        self.match = "conntrack"
        # TODO: bad interface that this is a list, but because of
        # python-iptables
        self.parameters["ctstate"] = ",".join(state)

    def create_mark_match(self, mark):
        self.match = "mark"
        self.parameters["mark"] = mark

    def create_mac_match(self, mac_source):
        self.match = "mac"
        # Upper case to allow matching with what iptables returns.
        self.parameters["mac-source"] = mac_source.upper()

    def create_set_match(self, match_set):
        self.match = "set"
        # TODO: bad interface that this is a list, but because of
        # python-iptables
        self.parameters["match-set"] = " ".join(match_set)

    def create_udp_match(self, sport, dport):
        self.match = "udp"
        self.parameters["sport"] = sport
        self.parameters["dport"] = dport

    def __str__(self):
        return "%s" % self.generate_fields()

    def __eq__(self, other):
        if (self.type != other.type or
            self.dst != other.dst or
            self.src != other.src or
            self.protocol != other.protocol or
            self.in_interface != other.in_interface or
            self.out_interface != other.out_interface or
            self.target != other.target or
            self.match != other.match or
            self.parameters != other.parameters):
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)


def insert_rule(rule, chain, position=0, force_position=True):
    """
    Add an iptables rule to a chain if it does not already exist. Position is
    the position for the insert as an offset; if set to RULE_POSN_LAST then the
    rule is appended.

    If force_position is True, then the rule is added at the specified point
    unless it already exists there. If force_position is False, then the rule
    is added only if it does not exist anywhere in the list of rules.

    Position starts at offset 0, even though iptables wants it to start at
    offset 1.
    """
    if position == RULE_POSN_LAST:
        position = len(chain.rules)

    if force_position:
        if (len(chain.rules) <= position) or (rule != chain.rules[position]):
            # Either adding after existing rules, or replacing an existing rule.
            chain.insert_rule(rule, position)
    else:
        if rule not in chain.rules:
            chain.insert_rule(rule, position)

    return

class UnrecognisedIptablesField(Exception):
    pass

def get_table(type, name):
    """
    Gets a table, including current state.
    """
    table = Table(type, name)
    data = futils.check_call([IPTABLES_CMD[type],
                              "-w",
                              "-S",
                              "-t",
                              name]).stdout
    lines = data.split("\n")

    for line in lines:
        words = line.split()

        if len(words) > 1:
            if words[0] in ("-P", "-N"):
                # We found a chain; remember and go to next line.
                log.debug("Found chain in table %s : %s", name, line)
                table.chains[words[1]] = Chain(table, words[1])
                continue

            if words[0] != "-A":
                # A line we do not know how to parse. Panic.
                raise UnrecognisedIptablesField(
                    "Unable to parse iptables line : %s" % line)

            log.debug("Found rule in table %s : %s", name, line)
            words.pop(0)
            chain_name = words.pop(0)
            chain = table.chains[chain_name]

            rule = Rule(type)
            rule.parse_fields(line, words)
            chain.rules.append(rule)

    return table

def get_chain(table, name):
    """
    Gets a chain, creating it first if it does not exist.
    """
    chain = table.chains.get(name)

    if chain is None:
        chain = Chain(table, name)
        table.chains[name] = chain
        futils.check_call([IPTABLES_CMD[table.type],
                           "-w",
                           "-t",
                           table.name,
                           "-N",
                           name])

    return chain

