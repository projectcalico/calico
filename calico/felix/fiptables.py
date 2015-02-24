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

IP tables management functions.
"""
import logging
import os
import re
import time
import weakref

from calico.felix import futils
from calico.felix.futils import IPV4, IPV6

# iptables command to use.
IPTABLES_CMD = { IPV4: "iptables",
                 IPV6: "ip6tables" }

# Logger
log = logging.getLogger(__name__)

# Special value to mean "put this rule at the end".  This must be "-1" as we
# use it as a python array index!
RULE_POSN_LAST = -1

class Chain(object):
    """
    Representation of an iptables chain.
    """
    def __init__(self, type, name):
        self.type = type
        self.name = name
        self.rules = []

    def flush(self):
        log.debug("Flushing chain %s", self.name)
        self.table.ops.append([IPTABLES_CMD[self.type],
                               "--wait",
                               "--table",
                               self.table.name,
                               "--flush",
                               self.name])
        del self.rules[:]

    def delete_rule(self, rule):
        # The rule must exist.
        args = [IPTABLES_CMD[self.type],
                "--wait",
                "--table",
                self.table.name,
                "--delete",
                self.name]
        args.extend(rule.generate_fields())
        log.debug("Removing rule : %s", args)
        self.rules.remove(rule)
        self.table.ops.append(args)

    def truncate_rules(self, count):
        """
        This is a utility function to remove any excess rules from a
        chain. After we have carefully inserted all the rules we want at the
        start, we want to get rid of any legacy rules from the end.

        It takes a chain object, and a count for how many of the rules should
        be left in place.
        """
        log.debug("Truncate %s chain %s to length %d (length now %d)",
                  self.type,
                  self.name,
                  count,
                  len(self.rules))

        while len(self.rules) > count:
            self.table.ops.append([IPTABLES_CMD[self.type],
                                   "--wait",
                                   "--table",
                                   self.table.name,
                                   "--delete",
                                   self.name,
                                   str(count + 1)])
            self.rules.pop(count)


    def insert_rule(self, rule, position=0, force_position=True):
        """
        Add an iptables rule to a chain if it does not already exist. Position
        is the position for the insert as an offset; if set to RULE_POSN_LAST
        then the rule is appended.

        If force_position is True, then the rule is added at the specified point
        unless it already exists there. If force_position is False, then the
        rule is added only if it does not exist anywhere in the list of rules.

        Position starts at offset 0, even though iptables wants it to start at
        offset 1.
        """
        if force_position:
            try:
                if rule != self.rules[position]:
                    self._insert_rule(rule, position)
            except IndexError:
                # Either appending to empty list (so -1 no good), or list not
                # long enough. Just append the rule.
                self._insert_rule(rule, RULE_POSN_LAST)
        else:
            if rule not in self.rules:
                self._insert_rule(rule, position)
        return

    def _insert_rule(self, rule, position):
        """
        Insert the given rule at the supplied offset.

        position of 0 means "insert at the start", which is what iptables
        considers as position 1.

        This method is private; callers outside this module should call
        insert_rule instead.
        """
        if position == RULE_POSN_LAST:
            args = [IPTABLES_CMD[self.type],
                    "--wait",
                    "--table",
                    self.table.name,
                    "--append",
                    self.name]
            self.rules.append(rule)
        else:
            args = [IPTABLES_CMD[self.type],
                    "--wait",
                    "--table",
                    self.table.name,
                    "--insert",
                    self.name,
                    str(position + 1)]
            self.rules.insert(position, rule)

        args.extend(rule.generate_fields())
        log.debug("Creating rule : %s", args)
        self.table.ops.append(args)

    @property
    def table(self):
        """
        Return the table for this chain.
        """
        return self.table_ref()

    @table.setter
    def table(self, value):
        """
        Set the table for this chain. The weakref is a hint that the table and
        chain reference one another, but when the table goes the chain is no
        longer in use.
        """
        self.table_ref = weakref.ref(value)

    def __str__(self):
        output = "Chain %s\n" % self.name
        if self.rules:
            output += "  " + "\n  ".join(str(rule) for rule in self.rules) + "\n"

        return output

class Table(object):
    """
    Representation of an iptables table.
    """
    def __init__(self, type, name):
        self.type = type
        self.name = name
        self.chains = {}
        self.ops = []

    def is_chain(self, name):
        return name in self.chains

    def get_chain(self, name):
        """
        Gets a chain, creating it first if it does not exist.
        """
        chain = self.chains.get(name)

        if chain is None:
            log.debug("Creating chain %s in table %s (%s)",
                      name,
                      self.name,
                      self.type)

            chain = Chain(self.type, name)
            self.chains[name] = chain
            chain.table = self

            self.ops.append([IPTABLES_CMD[self.type],
                              "--wait",
                              "--table",
                              self.name,
                              "--new-chain",
                              name])

        return chain

    def delete_chain(self, chain_name):
        log.debug("Delete chain %s from table %s (%s)",
                  chain_name,
                  self.name,
                  self.type)
        self.ops.append([IPTABLES_CMD[self.type],
                        "--wait",
                        "--table",
                        self.name,
                        "--delete-chain",
                        chain_name])
        del self.chains[chain_name]

    def __str__(self):
        output = "TABLE %s (%s)\n" % (self.name, self.type)
        for chain_name in sorted(self.chains.keys()):
            output += "  " + "\n  ".join(str(self.chains[chain_name]).split("\n")) + "\n"
        return output

class Rule(object):
    """
    Rule object. This contains information about rules.
    """
    tuples = (("-s", "src"),
              ("-d", "dst"),
              ("-p", "protocol"),
              ("-i", "in_interface"),
              ("-o", "out_interface"),
              ("-m", "match"),
              ("-j", "target"))

    FLAG_TO_FIELD = dict(tuples)
    KNOWN_FIELDS = [ a[1] for a in tuples ]
    FIELD_TO_FLAG = dict((field, flag) for flag, field in tuples)

    def __init__(self, type, target=None):
        self.type = type

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
        Parse fields retrieved from iptables -S. The -A and the chain name must
        have been removed from the list supplied.

        For example :
        -s 192.168.122.0/24 -d 224.0.0.0/24 -j RETURN
        -m set --match-set felix-from-port-1729ebac-f0 dst,dst -j RETURN

        line is used only for logging.
        """
        while fields:
            # For a negative, we just prepend "!" to the value (or the first
            # value if many).
            negative = False

            if fields[0] == "!":
                negative = True
                fields.pop(0)

            flag = fields.pop(0)

            values = []
            while fields and fields[0][0] != "-" and fields[0] != "!":
                values.append(fields.pop(0))

            value = " ".join(values)

            if negative:
                value = "!" + value

            if flag in Rule.FLAG_TO_FIELD:
                setattr(self, Rule.FLAG_TO_FIELD[flag], value)
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
        fields = []

        for field in Rule.KNOWN_FIELDS:
            value = getattr(self, field)
            if value is not None and value[0] == "!":
                fields.extend(["!", Rule.FIELD_TO_FLAG[field], value[1:]])
            elif value is not None:
                fields.extend([Rule.FIELD_TO_FLAG[field], value])

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
        # Note that this adds parameters, rather than replacing existing ones.
        for key in parameters:
            self.parameters[key] = parameters[key]

    def create_tcp_match(self, dport):
        self.match = "tcp"
        self.parameters["dport"] = dport

    def create_icmp6_match(self, icmp_type):
        self.match = "icmp6"
        self.parameters["icmpv6-type"] = icmp_type

    def create_conntrack_match(self, state):
        # State is a comma separated string
        self.match = "conntrack"
        self.parameters["ctstate"] = state

    def create_mark_match(self, mark):
        self.match = "mark"
        self.parameters["mark"] = mark

    def create_mac_match(self, mac_source):
        self.match = "mac"
        # Upper case to allow matching with what iptables returns.
        self.parameters["mac-source"] = mac_source.upper()

    def create_set_match(self, set_name, direction):
        self.match = "set"
        self.parameters["match-set"] = set_name + " " + direction

    def create_udp_match(self, sport, dport):
        self.match = "udp"
        self.parameters["sport"] = sport
        self.parameters["dport"] = dport

    def __str__(self):
        return " ".join(self.generate_fields())

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


class UnrecognisedIptablesField(Exception):
    pass


class TableState(object):
    """
    Defines the current state of iptables - which rules exist in which
    tables.
    """
    def __init__(self):
        self.tables_v4 = {}
        self.tables_v6 = {}

    def get_table(self, type, name):
        """
        Get a table from the current state.
        """
        if type == IPV4:
            hash = self.tables_v4
        else:
            hash = self.tables_v6

        if name in hash:
            table = hash[name]
        else:
            table = self.load_table(type, name)
            hash[name] = table

        return table

    def reset(self):
        """
        Clear the state of the tables.
        """
        self.tables_v4.clear()
        self.tables_v6.clear()

    def apply(self):
        """
        Apply all changes to this table.

        Note that the only way to abort changes is to call
        TableState.reset(); otherwise the changes remain queued up and happen
        the next time TableState.apply() is called.
        """
        ops = []
        for table in self.tables_v4.values() + self.tables_v6.values():
            ops.extend(table.ops)
            table.ops = []

        if ops:
            log.debug("Apply batched changes to tables")
            futils.multi_call(ops)
        else:
            log.debug("No table changes required")

    def load_table(self, type, name):
        """
        Reads a table, building current state.
        """
        table = Table(type, name)
        data = self.read_table(type, name)
        lines = data.split("\n")

        for line in lines:
            words = line.split()

            if len(words) > 1:
                if words[0] in ("-P", "-N"):
                    # We found a chain; remember and go to next line.
                    log.debug("Found chain in table %s : %s", name, line)
                    chain = Chain(type, words[1])
                    chain.table = table
                    table.chains[chain.name] = chain
                    continue

                if words[0] != "-A":
                    # A line we do not know how to parse. Panic.
                    raise UnrecognisedIptablesField(
                        "Unable to parse iptables line : %s" % line)

                log.debug("Found rule in table %s : %s", name, line)
                words.pop(0)
                chain_name = words.pop(0)
                try:
                    chain = table.chains[chain_name]
                except KeyError:
                    # Rule for chain that does not exist
                    raise UnrecognisedIptablesField(
                        "Rule in table %s for chain which does not exist : %s" %
                        (name, line))
                rule = Rule(type)
                rule.parse_fields(line, words)
                chain.rules.append(rule)

        return table

    def read_table(self, type, name):
        """
        Runs the iptables command to load a table and returns it. Separated out
        purely for convenience of testing (since we can trivially mock it out).
        """
        data = futils.check_call([IPTABLES_CMD[type],
                                  "--wait",
                                  "--list-rules",
                                  "--table",
                                  name]).stdout

        return data
