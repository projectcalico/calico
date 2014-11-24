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
import iptc
import logging
import os
import re
import subprocess
import time

from calico.felix import futils
from calico.felix.futils import IPV4, IPV6
from calico.felix.config import Config

# Logger
log = logging.getLogger(__name__)

# Special value to mean "put this rule at the end".
RULE_POSN_LAST = -1

#*****************************************************************************#
#* Load the conntrack tables. This is a workaround for this issue            *#
#* https://github.com/ldx/python-iptables/issues/112                         *#
#*                                                                           *#
#* It forces all extensions to be loaded at start of day then stored so they *#
#* cannot be unloaded (and hence reloaded).                                  *#
#*****************************************************************************#
global_rule  = iptc.Rule()
global_rule6 = iptc.Rule6()
global_rule.create_match("conntrack")
global_rule6.create_match("conntrack")
global_rule.create_match("tcp")
global_rule6.create_match("tcp")
global_rule6.create_match("icmp6")
global_rule.create_match("udp")
global_rule6.create_match("udp")
global_rule.create_match("mac")
global_rule6.create_match("mac")

# Attach some targets.
global_rule.create_target("RETURN")
global_rule6.create_target("RETURN")
global_target = iptc.Target(global_rule, "DNAT")

class Rule(object):
    """
    Rule object. This is just a very simple wrapper round a python-iptables rule.

    It would be nicer if it were a subclass of iptc.Rule, but sometimes it
    would need to be a subclass of iptc.Rule6 (which is not a subclass of
    iptc.Rule).
    """
    def __init__(self, type, target_name=None):
        self.type = type

        if type == IPV4:
            self._rule = iptc.Rule()
        else:
            assert(type == IPV6)
            self._rule = iptc.Rule6()

        if target_name is not None:
            self._rule.create_target(target_name)

    @property
    def protocol(self):
        return self._rule.protocol

    @protocol.setter
    def protocol(self, value):
        self._rule.protocol = value

    @property
    def src(self):
        return self._rule.src

    @src.setter
    def src(self, value):
        self._rule.src = value

    @property
    def in_interface(self):
        return self._rule.in_interface

    @in_interface.setter
    def in_interface(self, value):
        self._rule.in_interface = value

    @property
    def out_interface(self):
        return self._rule.out_interface

    @out_interface.setter
    def out_interface(self, value):
        self._rule.out_interface = value

    def create_target(self, name, parameters=None):
        target = self._rule.create_target(name)
        if parameters is not None:
            for name in parameters:
                value = parameters[name]
                if name == "to_destination":
                    target.to_destination = value
                elif name == "set_mark":
                    target.set_mark = value
                else:
                    assert("Invalid target type : %s" % name)

    def create_tcp_match(self, dport):
        match = self._rule.create_match("tcp")
        match.dport = dport

    def create_icmp6_match(self, icmp_type):
        match = self._rule.create_match("icmp6")
        match.icmpv6_type = icmp_type

    def create_conntrack_match(self, state):
        match = self._rule.create_match("conntrack")
        match.ctstate = state

    def create_mark_match(self, mark):
        match = self._rule.create_match("mark")
        match.mark = mark

    def create_mac_match(self, mac_source):
        match = self._rule.create_match("mac")
        match.mac_source = mac_source

    def create_set_match(self, match_set):
        match = self._rule.create_match("set")
        match.match_set = match_set

    def create_udp_match(self, sport, dport):
        match = self._rule.create_match("udp")
        match.sport = sport
        match.dport = dport


def insert_rule(rule, chain, position=0, force_position=True):
    """
    Add an iptables rule to a chain if it does not already exist. Position is
    the position for the insert as an offset; if set to RULE_POSN_LAST then the
    rule is appended.

    If force_position is True, then the rule is added at the specified point
    unless it already exists there. If force_position is False, then the rule
    is added only if it does not exist anywhere in the list of rules.
    """
    found = False
    rules = chain.rules

    if position == RULE_POSN_LAST:
        position = len(rules)

    if force_position:
        if (len(rules) <= position) or (rule._rule != chain.rules[position]):
            # Either adding after existing rules, or replacing an existing rule.
            chain.insert_rule(rule._rule, position)
    else:
        #*********************************************************************#
        #* The python-iptables code to compare rules does a comparison on    *#
        #* all the relevant rule parameters (target, match, etc.) excluding  *#
        #* the offset into the chain. Hence the test below finds whether     *#
        #* there is a rule with the same parameters anywhere in the chain.   *#
        #*********************************************************************#
        if rule._rule not in chain.rules:
            chain.insert_rule(rule._rule, position)

    return


def get_table(type, name):
    """
    Gets a table. This is a simple helper method that returns either
    an IP v4 or an IP v6 table according to type.
    """
    if type == IPV4:
        table = iptc.Table(name)
    else:
        table = iptc.Table6(name)

    return table


def get_chain(table, name):
    """
    Gets a chain, creating it first if it does not exist.
    """
    if table.is_chain(name):
        chain = iptc.Chain(table, name)
    else:
        table.create_chain(name)
        chain = iptc.Chain(table, name)

    return chain


def truncate_rules(chain, count):
    """
    This is a utility function to remove any excess rules from a chain. After
    we have carefully inserted all the rules we want at the start, we want to
    get rid of any legacy rules from the end.

    It takes a chain object, and a count for how many of the rules should be
    left in place.
    """
    while len(chain.rules) > count:
        rule = chain.rules[-1]
        chain.delete_rule(rule)

