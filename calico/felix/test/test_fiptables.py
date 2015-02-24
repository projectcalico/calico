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
felix.test.test_fiptables
~~~~~~~~~~~

Tests for fiptables. Most of this module is tested in test_felix, but this covers
some parts that are not.
"""
from copy import copy
import logging
import mock
import unittest

import calico.felix.fiptables as fiptables
import calico.felix.futils as futils
from calico.felix.futils import IPV4, IPV6
import calico.felix.test.stub_fiptables as stub_fiptables

# Logger
log = logging.getLogger(__name__)

class TestFiptables(unittest.TestCase):
    def test_read_table(self):
        state = fiptables.TableState()

        with mock.patch('calico.felix.futils.check_call'):
            state.read_table(IPV4, "blah")
            futils.check_call.assert_called_with(["iptables", "--wait", "--list-rules", "--table", "blah"])

        with mock.patch('calico.felix.futils.check_call'):
            state.read_table(IPV6, "blah")
            futils.check_call.assert_called_with(["ip6tables", "--wait", "--list-rules", "--table", "blah"])

    def test_load_table(self):
        state = fiptables.TableState()

        data = "\n".join(["-P INPUT ACCEPT\n",
                          "-P FORWARD ACCEPT\n",
                          "-P OUTPUT ACCEPT\n",
                          "-N felix-FORWARD\n",
                          "-N felix-FROM-ENDPOINT\n",
                          "-N felix-INPUT\n",
                          "-N felix-TO-ENDPOINT\n",
                          "-N felix-from-19f8308f-81\n",
                          "-N felix-from-e6d6a9a9-37\n",
                          "-N felix-to-19f8308f-81\n",
                          "-N felix-to-e6d6a9a9-37\n",
                          "-A INPUT -j felix-INPUT\n",
                          "-A INPUT -i virbr0 -p udp -m udp --dport 53 -j ACCEPT\n",
                          "-A INPUT -i virbr0 -p tcp -m tcp --dport 53 -j ACCEPT\n",
                          "-A INPUT -i virbr0 -p udp -m udp --dport 67 -j ACCEPT\n",
                          "-A INPUT -i virbr0 -p tcp -m tcp --dport 67 -j ACCEPT\n",
                          "-A INPUT -j nova-api-INPUT\n",
                          "-A FORWARD -j felix-FORWARD\n",
                          "-A FORWARD -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n",
                          "-A FORWARD -s 192.168.122.0/24 -i virbr0 -j ACCEPT\n",
                          "-A FORWARD -i virbr0 -o virbr0 -j ACCEPT\n",
                          "-A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable\n",
                          "-A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable\n",
                          "-A FORWARD -j nova-filter-top\n",
                          "-A FORWARD -j nova-api-FORWARD\n"])
        state.read_table = mock.Mock(return_value = data)
        table = state.load_table(IPV4, "filter")

        # Check that the state contains what we expect.
        self.assertEqual(len(table.chains), 11)

        # Check a rules is present as expected.
        rule = fiptables.Rule(IPV4, "ACCEPT")
        rule.protocol = "udp"
        rule.in_interface = "virbr0"
        rule.match = "udp"
        rule.parameters["dport"] = "53"

        self.assertEqual(str(table.chains["INPUT"].rules[1]),
                         "-p udp -i virbr0 -m udp -j ACCEPT --dport 53")
        self.assertEqual(table.chains["INPUT"].rules[1], rule)

    def test_load_table_no_chain(self):
        """
        Test that loading a rule in a chain which does not exist fails.
        """
        state = fiptables.TableState()
        data = "\n".join(["-P INPUT ACCEPT\n",
                          "-A no-chain -j felix-INPUT\n"])

        state.read_table = mock.Mock(return_value = data)
        with self.assertRaisesRegexp(fiptables.UnrecognisedIptablesField,
                                     "chain which does not exist"):
            state.load_table(IPV4, "filter")

    def test_load_table_bad_flag(self):
        """
        Test that loading a rule with an unknown flag fails.
        """
        state = fiptables.TableState()
        data = "\n".join(["-P INPUT ACCEPT\n",
                          "-A INPUT -x felix-INPUT\n"])

        state.read_table = mock.Mock(return_value = data)
        with self.assertRaisesRegexp(fiptables.UnrecognisedIptablesField,
                                     "Unable to parse"):
            state.load_table(IPV4, "filter")

    def test_load_table_bad_line(self):
        """
        Test that loading an unparseable line fails.
        """
        state = fiptables.TableState()

        data = "\n".join(["-P INPUT ACCEPT\n",
                          "-Z no-chain -j felix-INPUT\n"])

        state.read_table = mock.Mock(return_value = data)
        with self.assertRaisesRegexp(fiptables.UnrecognisedIptablesField,
                                     "Unable to parse"):
            state.load_table(IPV4, "filter")

    def test_load_table_rule_not_known(self):
        """
        Test that loading a rule which we cannot understand is still valid.
        """
        state = fiptables.TableState()

        data = "\n".join(["-P INPUT ACCEPT\n",
                          "-A INPUT -i eth0 -p tcp --some-thing x y -j DROP"])

        state.read_table = mock.Mock(return_value = data)
        table = state.load_table(IPV4, "filter")

        self.assertEqual(str(table.chains["INPUT"].rules[0]),
                         "-p tcp -i eth0 -j DROP --some-thing x y")

        rule = fiptables.Rule(IPV4, "DROP")
        rule.protocol = "tcp"
        rule.in_interface = "eth0"
        rule.parameters["some-thing"] = "x y"

        self.assertEqual(rule, table.chains["INPUT"].rules[0])


    def test_apply(self):
        """
        Test apply method.
        """
        data = "\n".join(["-P INPUT ACCEPT",
                          "-P FORWARD ACCEPT",
                          "-P OUTPUT ACCEPT",
                          "-N felix-FORWARD",
                          "-N felix-FROM-ENDPOINT",
                          "-N felix-INPUT",
                          "-N felix-TO-ENDPOINT",
                          "-N felix-from-19f8308f-81",
                          "-N felix-from-e6d6a9a9-37",
                          "-N felix-to-19f8308f-81",
                          "-N felix-to-e6d6a9a9-37",
                          "-A INPUT -j felix-INPUT",
                          "-A INPUT -i virbr0 -p udp -m udp --dport 53 -j ACCEPT",
                          "-A INPUT -i virbr0 -p tcp -m tcp --dport 53 -j ACCEPT",
                          "-A INPUT -i virbr0 -p udp -m udp --dport 67 -j ACCEPT",
                          "-A INPUT -i virbr0 -p tcp -m tcp --dport 67 -j ACCEPT",
                          "-A INPUT -j nova-api-INPUT",
                          "-A FORWARD -j felix-FORWARD",
                          "-A FORWARD -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                          "-A FORWARD -s 192.168.122.0/24 -i virbr0 -j ACCEPT",
                          "-A FORWARD -i virbr0 -o virbr0 -j ACCEPT",
                          "-A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable",
                          "-A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable",
                          "-A FORWARD -j nova-filter-top",
                          "-A FORWARD -j nova-api-FORWARD"])

        state = fiptables.TableState()
        state.read_table = mock.Mock(return_value = data)
        table = state.get_table(IPV4, "filter")

        # Build up a list of rules as they will be after changes.
        rules = []
        rules.append(fiptables.Rule(IPV4))
        line = "-j felix-FORWARD"
        rules[0].parse_fields(line, line.split())

        # New rule to be added at location 1
        rules.append(fiptables.Rule(IPV4, "somewhere"))
        rules[1].protocol = "udp"
        rules[1].in_interface = "blah"
        rules[1].out_interface = "stuff"
        rules[1].match = "udp"
        rules[1].parameters["dport"] = "53"

        line = "-d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        rules.append(fiptables.Rule(IPV4))
        rules[2].parse_fields(line, line.split())

        chain = table.get_chain("FORWARD")
        self.assertEqual(len(chain.rules), 8)

        chain.insert_rule(rules[1], 1)

        chain.truncate_rules(3)

        # Verify that the rules are as expected.
        self.assertEqual(len(chain.rules), 3)
        self.assertEqual(rules, chain.rules)

        # Now test apply.
        with mock.patch('calico.felix.futils.multi_call') as mock_call:
            state.apply()
        self.assertEqual(mock_call.call_count, 1)

        ops = []
        op = ["iptables", "--wait", "--table", "filter", "--insert", "FORWARD", "2"]
        op.extend(rules[1].generate_fields())
        ops.append(op)

        for loop in range(0,6):
            ops.append(["iptables",
                        "--wait",
                        "--table",
                        "filter",
                        "--delete",
                        "FORWARD",
                        "4"])

        self.assertEqual(mock_call.call_count, 1)
        mock_call.assert_called_with(ops)

        # Apply again - this is a noop, as states match.
        with mock.patch('calico.felix.futils.multi_call') as mock_call:
            state.apply()
        self.assertEqual(mock_call.call_count, 0)

    def test_negative_fields(self):
        """
        Test negative fields
        """
        lines = [ "-N felix-from-blah",
                  "-A felix-from-blah ! -d 1.2.3.4/32 -j DROP",
                  "-A felix-from-blah ! -d 1.2.3.4/32 -p tcp -j DROP",
                  "-A felix-from-blah ! -d 1.2.3.4/32 ! -p udp -j DROP",
                  "-A felix-from-blah -m mark ! --mark 0x1 -j DROP"]

        data = "\n".join(lines)

        state = fiptables.TableState()
        state.read_table = mock.Mock(return_value = data)
        table = state.load_table(IPV4, "filter")
        chain = table.chains["felix-from-blah"]

        # Check that lot got parsed as expected.
        self.assertTrue(len(chain.rules), 4)

        rule = fiptables.Rule(IPV4)
        rule.dst = "!1.2.3.4/32"
        rule.target = "DROP"
        self.assertEqual(chain.rules[0], rule)

        rule.protocol = "tcp"
        self.assertEqual(chain.rules[1], rule)

        rule.protocol = "!udp"
        self.assertEqual(chain.rules[2], rule)

        rule = fiptables.Rule(IPV4)
        rule.match = "mark"
        rule.parameters["mark"] = "!0x1"
        rule.target = "DROP"
        self.assertEqual(chain.rules[3], rule)

        # Now convert back again, and compare. Lines are different here in that
        # we have (a) removed the chain specification; and (b) reordered
        # fields.
        lines = [ "! -d 1.2.3.4/32 -j DROP",
                  "! -d 1.2.3.4/32 -p tcp -j DROP",
                  "! -d 1.2.3.4/32 ! -p udp -j DROP",
                  "-m mark -j DROP ! --mark 0x1"]

        for loop in range(0,4):
            actual = " ".join(chain.rules[loop].generate_fields())
            self.assertEqual(actual, lines[loop])

    def test_insert_rule(self):
        """
        Test insert_rule
        """
        data = "\n".join(["-N blah",
                          "-A blah -j original"])

        state = fiptables.TableState()
        state.read_table = mock.Mock(return_value = data)
        table = state.get_table(IPV4, "filter")
        chain = table.get_chain("blah")
        self.assertTrue(len(chain.rules), 1)

        # Set up a handy list of arguments
        base_args = ["iptables", "--wait", "--table", "filter"]

        # Put a new rule at the start
        rule = fiptables.Rule(IPV4, "rule1")
        chain.insert_rule(rule)
        self.assertTrue(len(chain.rules), 2)
        self.assertTrue(chain.rules[0].target, "rule1")
        self.assertTrue(chain.rules[1].target, "original")
        args = copy(base_args)
        args.extend(["--insert", "blah", "1", "-j", "rule1"])
        self.assertEqual(len(table.ops), 1)
        self.assertEqual(table.ops[0], args)

        # Put in a copy of the original rule, forcing position.
        rule = fiptables.Rule(IPV4, "original")
        chain.insert_rule(rule)
        self.assertTrue(len(chain.rules), 3)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        args = copy(base_args)
        args.extend(["--insert", "blah", "1", "-j", "original"])
        self.assertEqual(len(table.ops), 2)
        self.assertEqual(table.ops[1], args)

        # Now add another copy. Does not get added, as already there.
        rule = fiptables.Rule(IPV4, "original")
        chain.insert_rule(rule)
        self.assertTrue(len(chain.rules), 3)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertEqual(len(table.ops), 2)

        # Add rule1 again - doesn't get added as not forcing position.
        rule = fiptables.Rule(IPV4, "rule1")
        chain.insert_rule(rule, 0, False)
        self.assertTrue(len(chain.rules), 3)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertEqual(len(table.ops), 2)

        chain.insert_rule(rule, 1, False)
        self.assertTrue(len(chain.rules), 3)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertEqual(len(table.ops), 2)

        chain.insert_rule(rule, 2, False)
        self.assertTrue(len(chain.rules), 3)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertEqual(len(table.ops), 2)

        chain.insert_rule(rule, fiptables.RULE_POSN_LAST, False)
        self.assertTrue(len(chain.rules), 3)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertEqual(len(table.ops), 2)

        # Now use POSN_LAST but forcing position
        rule = fiptables.Rule(IPV4, "original")
        chain.insert_rule(rule, fiptables.RULE_POSN_LAST)
        self.assertTrue(len(chain.rules), 3)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertEqual(len(table.ops), 2)

        rule = fiptables.Rule(IPV4, "rule1")
        chain.insert_rule(rule, fiptables.RULE_POSN_LAST)
        self.assertTrue(len(chain.rules), 4)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertTrue(chain.rules[3].target, "rule1")
        args = copy(base_args)
        args.extend(["--append", "blah", "-j", "rule1"])
        self.assertEqual(len(table.ops), 3)
        self.assertEqual(table.ops[2], args)

        rule = fiptables.Rule(IPV4, "rule1")
        chain.insert_rule(rule, fiptables.RULE_POSN_LAST, True)
        self.assertTrue(len(chain.rules), 4)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertTrue(chain.rules[3].target, "rule1")
        self.assertEqual(len(table.ops), 3)

        rule = fiptables.Rule(IPV4, "new")
        chain.insert_rule(rule, fiptables.RULE_POSN_LAST, False)
        self.assertTrue(len(chain.rules), 5)
        self.assertTrue(chain.rules[0].target, "original")
        self.assertTrue(chain.rules[1].target, "rule1")
        self.assertTrue(chain.rules[2].target, "original")
        self.assertTrue(chain.rules[3].target, "rule1")
        self.assertTrue(chain.rules[4].target, "original")
        args = copy(base_args)
        args.extend(["--append", "blah", "-j", "new"])
        self.assertEqual(len(table.ops), 4)
        self.assertEqual(table.ops[3], args)

    def test_rule_match(self):
        """
        Test every possible rule match.
        """
        rule1 = fiptables.Rule(IPV4)
        rule2 = fiptables.Rule(IPV6)
        self.assertNotEqual(rule1, rule2)

        rule1 = fiptables.Rule(IPV4)
        rule2 = fiptables.Rule(IPV4)
        self.assertEqual(rule1, rule2)

        rule1.target = "blah"
        self.assertNotEqual(rule1, rule2)
        rule2.target = "x"
        self.assertNotEqual(rule1, rule2)
        rule2.target = "blah"
        self.assertEqual(rule1, rule2)

        rule1.dst = "dst"
        self.assertNotEqual(rule1, rule2)
        rule2.dst = "x"
        self.assertNotEqual(rule1, rule2)
        rule2.dst = "dst"
        self.assertEqual(rule1, rule2)

        rule1.src = "src"
        self.assertNotEqual(rule1, rule2)
        rule2.src = "x"
        self.assertNotEqual(rule1, rule2)
        rule2.src = "src"
        self.assertEqual(rule1, rule2)

        rule1.match = "match"
        self.assertNotEqual(rule1, rule2)
        rule2.match = "x"
        self.assertNotEqual(rule1, rule2)
        rule2.match = "match"
        self.assertEqual(rule1, rule2)

        rule1.protocol = "protocol"
        self.assertNotEqual(rule1, rule2)
        rule2.protocol = "x"
        self.assertNotEqual(rule1, rule2)
        rule2.protocol = "protocol"
        self.assertEqual(rule1, rule2)

        rule1.in_interface = "in_interface"
        self.assertNotEqual(rule1, rule2)
        rule2.in_interface = "x"
        self.assertNotEqual(rule1, rule2)
        rule2.in_interface = "in_interface"
        self.assertEqual(rule1, rule2)

        rule1.out_interface = "out_interface"
        self.assertNotEqual(rule1, rule2)
        rule2.out_interface = "x"
        self.assertNotEqual(rule1, rule2)
        rule2.out_interface = "out_interface"
        self.assertEqual(rule1, rule2)

        rule1.parameters = { "x": "blah", "y": "other" }
        self.assertNotEqual(rule1, rule2)
        rule2.parameters = { "x": "blah" }
        self.assertNotEqual(rule1, rule2)
        rule2.parameters["y"] = "other"
        self.assertEqual(rule1, rule2)
