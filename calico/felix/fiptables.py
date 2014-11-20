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
global_rule.create_match("physdev")
global_rule6.create_match("physdev")

# Attach some targets.
global_rule.create_target("RETURN")
global_rule6.create_target("RETURN")
global_target = iptc.Target(global_rule, "DNAT")

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
        if (len(rules) <= position) or (rule != chain.rules[position]):
            # Either adding after existing rules, or replacing an existing rule.
            chain.insert_rule(rule, position)
    else:
        #*********************************************************************#
        #* The python-iptables code to compare rules does a comparison on    *#
        #* all the relevant rule parameters (target, match, etc.) excluding  *#
        #* the offset into the chain. Hence the test below finds whether     *#
        #* there is a rule with the same parameters anywhere in the chain.   *#
        #*********************************************************************#
        if rule not in chain.rules:
            chain.insert_rule(rule, position)

    return

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

