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
felix.test.stub_fiptables
~~~~~~~~~~~~

Stub version of the fiptables module.
"""
from calico.felix.futils import IPV4, IPV6

# Special value to mean "put this rule at the end".
RULE_POSN_LAST = -1

#*****************************************************************************#
#* The range of definitions below mimic fiptables.                           *#
#*****************************************************************************#
class Rule(object):
    """
    Fake rule object.
    """
    def __init__(self, type, target_name=None):
        self.type = type

        self.target_name = target_name
        self.target_args = dict()

        self.match_name = None
        self.match_args = dict()

        self.protocol = None
        self.src = None
        self.in_interface = None
        self.out_interface = None

    def create_target(self, name, parameters=None):
        self.target_name = name
        if parameters is not None:
            for key in parameters:
                self.target_args[key] = parameters[key]

    def create_tcp_match(self, dport):
        self.match_name = "tcp"
        self.match_args["dport"] = dport

    def create_icmp6_match(self, icmp_type):
        self.match_name = "icmp6"
        self.match_args["icmpv6_type"] = icmp_type

    def create_conntrack_match(self, state):
        self.match_name = "conntrack"
        self.match_args["ctstate"] = state

    def create_mark_match(self, mark):
        self.match_name = "mark"
        self.match_args["mark"] = mark

    def create_mac_match(self, mac_source):
        self.match_name = "mac"
        self.match_args["mac_source"] = mac_source

    def create_set_match(self, match_set):
        self.match_name = "set"
        self.match_args["match_set"] = match_set

    def create_udp_match(self, sport, dport):
        self.match_name = "udp"
        self.match_args["sport"] = sport
        self.match_args["dport"] = dport


    def __eq__(self, other):
        if (self.protocol != other.protocol or
            self.src != other.src or
            self.in_interface != other.in_interface or
            self.out_interface != other.out_interface or
            self.target_name != other.target_name or
            self.match_name != other.match_name):
            return False

        if (len(self.match_args) != len(other.match_args) or
            len(self.target_args) != len(other.target_args)):
            return False

        if self.match_args != other.match_args:
            return False

        if self.target_args != other.target_args:
            return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

class Chain(object):
    """
    Mimic of an IPTC chain. Rules must be a list (not a set).
    """
    def __init__(self, name, rules=[]):
        self.name = name
        self.rules = rules

    def flush(self):
        self.rules = []

    def delete_rule(rule):
        # The rule must exist or it is an error.
        self.rules.remove(rule)

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
    Mimic of an IPTC table.
    """
    def __init__(self, type, name):
        self.type = type
        self.name = name
        self.chains = dict()

def get_table(type, name):
    """
    Gets a table. This is a simple helper method that returns either
    an IP v4 or an IP v6 table according to type.
    """
    if type == IPV4:
        table = current_state.tables_v4[name]
    else:
        table = current_state.tables_v6[name]

    return table

def get_chain(table, name):
    """
    Gets a chain, creating it first if it does not exist.
    """
    if name in table.chains:
        chain = table.chains[name]
    else:
        chain = Chain(name)
        table.chains[name] = chain

    return chain


def truncate_rules(chain, count):
    """
    This is a utility function to remove any excess rules from a chain. After
    we have carefully inserted all the rules we want at the start, we want to
    get rid of any legacy rules from the end.

    It takes a chain object, and a count for how many of the rules should be
    left in place.
    """
    # TODO: Function identical to value in production code.
    while len(chain.rules) > count:
        rule = chain.rules[-1]
        chain.delete_rule(rule)


def insert_rule(rule, chain, position=0, force_position=True):
    """
    Add an iptables rule to a chain if it does not already exist. Position is
    the position for the insert as an offset; if set to RULE_POSN_LAST then the
    rule is appended.

    If force_position is True, then the rule is added at the specified point
    unless it already exists there. If force_position is False, then the rule
    is added only if it does not exist anywhere in the list of rules.
    """
    # TODO: Function identical to value in production code.
    found = False
    rules = chain.rules

    if position == RULE_POSN_LAST:
        position = len(rules)

    if force_position:
        if (len(rules) <= position) or (rule != chain.rules[position]):
            # Either adding after existing rules, or replacing an existing rule.
            chain.rules.insert(position, rule)
    else:
        #*********************************************************************#
        #* The python-iptables code to compare rules does a comparison on    *#
        #* all the relevant rule parameters (target, match, etc.) excluding  *#
        #* the offset into the chain. Hence the test below finds whether     *#
        #* there is a rule with the same parameters anywhere in the chain.   *#
        #*********************************************************************#
        if rule not in chain.rules:
            chain.rules.insert(position, rule)

    return

#*****************************************************************************#
#* The next few definitions are not exposed to production code.              *#
#*****************************************************************************#
def reset_current_state():
    current_state.reset()

class UnexpectedStateException(Exception):
    def __init__(self, message, actual, expected):
        super(UnexpectedStateException, self).__init__(message)
        self.actual = actual
        self.expected = expected

    def __str__(self):
        return ("%s\nACTUAL:\n%s\nEXPECTED\n%s" %
                (self.message, self.actual, self.expected))


def check_state(expected_state):
    """
    Checks that the current state matches the expected state. Throws an
    exception if it does not.
    """
    actual = str(current_state)
    expected = str(expected_state)

    if actual != expected:
        raise UnexpectedStateException(actual, expected)

class TableState(object):
    """
    Defines the current state of iptables - which rules exist in which
    tables. Normally there will be two - the state that the test generates, and
    the state that the test expects to have at the end. At the end of the test,
    these are compared.
    """
    def __init__(self):
        self.tables_v4 = dict()
        self.tables_v6 = dict()

        self.reset()


    def reset(self):
        """
        Clear the state of the tables, getting them back to being empty.
        """
        self.tables_v4.clear()
        self.tables = []

        table = Table(IPV4, "filter")
        get_chain(table, "INPUT")
        get_chain(table, "OUTPUT")
        get_chain(table, "FORWARD")
        self.tables_v4["filter"] = table
        self.tables.append(table)

        table = Table(IPV4, "nat")
        get_chain(table, "PREROUTING")
        get_chain(table, "POSTROUTING")
        get_chain(table, "INPUT")
        get_chain(table, "OUTPUT")
        self.tables_v4["nat"] = table
        self.tables.append(table)

        self.tables_v6.clear()
        table = Table(IPV6, "filter")
        get_chain(table, "INPUT")
        get_chain(table, "OUTPUT")
        get_chain(table, "FORWARD")
        self.tables_v6["filter"] = table
        self.tables.append(table)


    def __str__(self):
        """
        Convert a full state to a readable string to use in matches and compare
        for final testing.
        """
        output = ""
        for table in self.tables:
            output += "TABLE %s (%s)\n" % (table.name, table.type)
            for chain_name in sorted(table.chains.keys()):
                output += "  Chain %s\n" % chain.name
                for rule in chain.rules:
                    output += "    %s\n" % rule
                output += "\n"
            output += "\n"

        return output

# Current state.
current_state = TableState()

