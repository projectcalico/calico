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

Stub versions of functions for the fiptables module.
"""
from calico.felix import fiptables
from calico.felix.futils import IPV4, IPV6
from copy import deepcopy
import difflib
import logging

# Logger
log = logging.getLogger(__name__)

class UnexpectedStateException(Exception):
    def __init__(self, actual, expected):
        super(UnexpectedStateException, self).__init__(
            "iptables state does not match")
        self.diff = "\n".join(difflib.unified_diff(
            expected.split("\n"),
            actual.split("\n")))

        self.actual = actual
        self.expected = expected

    def __str__(self):
        return ("%s\nDIFF:\n%s\nACTUAL:\n%s\nEXPECTED\n%s" %
                (self.message, self.diff, self.actual, self.expected))

class TableState(fiptables.TableState):
    """
    Defines the current state of iptables - which rules exist in which
    tables. Normally there will be two - the state that the test generates, and
    the state that the test expects to have at the end. At the end of the test,
    these can be compared.
    """
    def __init__(self):
        super(TableState, self).__init__()

        # tables_v4 and tables_v6 are the internal state of the tables; real_v4
        # and real_v6 are the tables as written out. Just after "apply" or
        # "reset", the two will match, but if you fail to call "apply" then the
        # two will diverge.
        self.real_v4 = {}
        self.real_v6 = {}

        self.set_empty()

    def apply(self):
        """
        Overriding fiptables.Table.apply().
        """
        log.debug("Overwriting table changes to real state")
        self.real_v4 = deepcopy(self.tables_v4)
        self.real_v6 = deepcopy(self.tables_v4)

    def read_table(self, type, name):
        """
        Overriding fiptables.Table.read_table().
        """
        if type == IPV4:
            table = self.real_v4[name]
        else:
            table = self.real_v6[name]

        data = ""

        for chain in table.chains.values():
            data += ("-N %s\n" % chain.name +
                     "\n".join(str(rule) for rule in chain.rules))

        return data

    def set_empty(self):
        """
        Set up the state of the tables with minimal chains.  After calling
        this, the real (i.e. logically physical) tables and chains are set up,
        and the normal chains are empty.
        """
        log.debug("Set table state to empty")

        self.reset()
        self.real_v4.clear()
        self.real_v6.clear()

        # We must not use get_table, since it assumes that the tables already
        # exist in real_v4.
        table = fiptables.Table(IPV4, "filter")
        table.get_chain("INPUT")
        table.get_chain("OUTPUT")
        table.get_chain("FORWARD")
        table.get_chain("OUTPUT")
        table.get_chain("FORWARD")
        self.real_v4["filter"] = table

        table = fiptables.Table(IPV4, "nat")
        table.get_chain("PREROUTING")
        table.get_chain("POSTROUTING")
        table.get_chain("INPUT")
        table.get_chain("OUTPUT")
        self.real_v4["nat"] = table

        table = fiptables.Table(IPV6, "filter")
        table.get_chain("INPUT")
        table.get_chain("OUTPUT")
        table.get_chain("FORWARD")
        self.real_v6["filter"] = table

    def check_state(self, expected_state):
        """
        Checks that the current state matches the expected state. Throws an
        exception if it does not.
        """
        actual = str(self)
        expected = str(expected_state)

        if actual != expected:
            raise UnexpectedStateException(actual, expected)

    def __str__(self):
        """
        Convert a full state to a readable string to use in matches and compare
        for final testing. Note that we compare only what is actually written,
        not what is just pending writing.
        """
        table_list = ([ self.real_v4[name]
                        for name in sorted(self.real_v4.keys()) ] +
                      [ self.real_v6[name]
                        for name in sorted(self.real_v6.keys()) ] )

        output = "".join([str(table) for table in table_list])

        return output


    def set_expected_global_rules(self, prefix="tap"):
        """
        Sets up the minimal global rules we expect to have.
        """
        self.set_empty()

        match = prefix + "+"

        table = self.get_table(IPV4, "filter")
        table.get_chain("felix-TO-ENDPOINT")
        table.get_chain("felix-FROM-ENDPOINT")
        table.get_chain("felix-FORWARD")
        table.get_chain("felix-INPUT")
        chain = table.chains["FORWARD"]
        chain.rules.append(fiptables.Rule(IPV4, "felix-FORWARD"))
        chain = table.chains["INPUT"]
        chain.rules.append(fiptables.Rule(IPV4, "felix-INPUT"))

        chain = table.chains["felix-FORWARD"]
        rule  = fiptables.Rule(type, "felix-FROM-ENDPOINT")
        rule.in_interface = match
        chain.rules.append(rule)
        rule  = fiptables.Rule(type, "felix-TO-ENDPOINT")
        rule.out_interface = match
        chain.rules.append(rule)
        rule  = fiptables.Rule(type, "ACCEPT")
        rule.in_interface = match
        chain.rules.append(rule)
        rule  = fiptables.Rule(type, "ACCEPT")
        rule.out_interface = match
        chain.rules.append(rule)

        chain = table.chains["felix-INPUT"]
        rule  = fiptables.Rule(type, "felix-FROM-ENDPOINT")
        rule.in_interface = match
        chain.rules.append(rule)
        rule  = fiptables.Rule(type, "ACCEPT")
        rule.in_interface = match
        chain.rules.append(rule)

        table = self.get_table(IPV4, "nat")
        chain = table.chains["PREROUTING"]
        chain.rules.append(fiptables.Rule(IPV4, "felix-PREROUTING"))

        chain = table.get_chain("felix-PREROUTING")
        rule = fiptables.Rule(IPV4)
        rule.dst = "169.254.169.254/32"
        rule.protocol = "tcp"
        rule.create_tcp_match("80")
        rule.create_target("DNAT", {'to-destination': '127.0.0.1:9697'})
        chain.rules.append(rule)

        table = self.get_table(IPV6, "filter")
        table.get_chain("felix-TO-ENDPOINT")
        table.get_chain("felix-FROM-ENDPOINT")
        table.get_chain("felix-FORWARD")
        table.get_chain("felix-INPUT")
        chain = table.chains["FORWARD"]
        chain.rules.append(fiptables.Rule(IPV6, "felix-FORWARD"))
        chain = table.chains["INPUT"]
        chain.rules.append(fiptables.Rule(IPV6, "felix-INPUT"))

        chain = table.chains["felix-FORWARD"]
        rule  = fiptables.Rule(type, "felix-FROM-ENDPOINT")
        rule.in_interface = match
        chain.rules.append(rule)
        rule  = fiptables.Rule(type, "felix-TO-ENDPOINT")
        rule.out_interface = match
        chain.rules.append(rule)
        rule  = fiptables.Rule(type, "ACCEPT")
        rule.in_interface = match
        chain.rules.append(rule)
        rule  = fiptables.Rule(type, "ACCEPT")
        rule.out_interface = match
        chain.rules.append(rule)

        chain = table.chains["felix-INPUT"]
        rule  = fiptables.Rule(type, "felix-FROM-ENDPOINT")
        rule.in_interface = match
        chain.rules.append(rule)
        rule  = fiptables.Rule(type, "ACCEPT")
        rule.in_interface = match
        chain.rules.append(rule)

        self.apply()

    def add_endpoint_rules(self, suffix, interface, ipv4, ipv6, mac):
        """
        This adds the rules for an endpoint, appending to the end. This generates
        a clean state to allow us to test that the state is correct, even after
        it starts with extra rules etc.
        """
        table = self.tables_v4["filter"]
        chain = table.chains["felix-FROM-ENDPOINT"]
        rule = fiptables.Rule(IPV4, "felix-from-%s" % suffix)
        rule.in_interface = interface
        chain.rules.append(rule)

        chain = table.chains["felix-TO-ENDPOINT"]
        rule = fiptables.Rule(IPV4, "felix-to-%s" % suffix)
        rule.out_interface = interface
        chain.rules.append(rule)

        chain = table.get_chain("felix-from-%s" % suffix)
        rule = fiptables.Rule(IPV4, "DROP")
        rule.create_conntrack_match("INVALID")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.create_conntrack_match("RELATED,ESTABLISHED")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.protocol = "udp"
        rule.create_udp_match("68", "67")
        chain.rules.append(rule)

        if ipv4 is not None:
            rule = fiptables.Rule(IPV4)
            rule.create_target("MARK", {"set-mark": "1"})
            rule.src = ipv4 + "/32"
            rule.create_mac_match(mac)
            chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "DROP")
        rule.create_mark_match("!1")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.create_set_match("felix-from-port-%s" % suffix, "dst,dst")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.create_set_match("felix-from-addr-%s" % suffix, "dst")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.protocol = "icmp"
        rule.create_set_match("felix-from-icmp-%s" % suffix, "dst")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "DROP")
        chain.rules.append(rule)

        chain = table.get_chain("felix-to-%s" % suffix)
        rule = fiptables.Rule(IPV4, "DROP")
        rule.create_conntrack_match("INVALID")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.create_conntrack_match("RELATED,ESTABLISHED")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.create_set_match("felix-to-port-%s" % suffix, "src,dst")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.create_set_match("felix-to-addr-%s" % suffix, "src")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "RETURN")
        rule.protocol = "icmp"
        rule.create_set_match("felix-to-icmp-%s" % suffix, "src")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV4, "DROP")
        chain.rules.append(rule)

        table = self.tables_v6["filter"]
        chain = table.chains["felix-FROM-ENDPOINT"]
        rule = fiptables.Rule(IPV6, "felix-from-%s" % suffix)
        rule.in_interface = interface
        chain.rules.append(rule)

        chain = table.chains["felix-TO-ENDPOINT"]
        rule = fiptables.Rule(IPV6, "felix-to-%s" % suffix)
        rule.out_interface = interface
        chain.rules.append(rule)

        chain = table.get_chain("felix-from-%s" % suffix)
        rule = fiptables.Rule(type, "RETURN")
        rule.protocol = "ipv6-icmp"
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "DROP")
        rule.create_conntrack_match("INVALID")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.create_conntrack_match("RELATED,ESTABLISHED")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.protocol = "udp"
        rule.create_udp_match("546", "547")
        chain.rules.append(rule)

        if ipv6 is not None:
            rule = fiptables.Rule(IPV6)
            rule.create_target("MARK", {"set-mark": "1"})
            rule.src = ipv6
            rule.create_mac_match(mac)
            chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "DROP")
        rule.create_mark_match("!1")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.create_set_match("felix-6-from-port-%s" % suffix, "dst,dst")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.create_set_match("felix-6-from-addr-%s" % suffix, "dst")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.protocol = "ipv6-icmp"
        rule.create_set_match("felix-6-from-icmp-%s" % suffix, "dst")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "DROP")
        chain.rules.append(rule)

        chain = table.get_chain("felix-to-%s" % suffix)
        for icmp in ["130", "131", "132", "134", "135", "136"]:
            rule = fiptables.Rule(IPV6, "RETURN")
            rule.protocol = "ipv6-icmp"
            rule.create_icmp6_match(icmp)
            chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "DROP")
        rule.create_conntrack_match("INVALID")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.create_conntrack_match("RELATED,ESTABLISHED")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.create_set_match("felix-6-to-port-%s" % suffix, "src,dst")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.create_set_match("felix-6-to-addr-%s" % suffix, "src")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "RETURN")
        rule.protocol = "ipv6-icmp"
        rule.create_set_match("felix-6-to-icmp-%s" % suffix, "src")
        chain.rules.append(rule)

        rule = fiptables.Rule(IPV6, "DROP")
        chain.rules.append(rule)

        self.apply()
