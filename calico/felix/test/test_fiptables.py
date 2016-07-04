# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
~~~~~~~~~~~~~~~~~~~~~~~~~

Tests of iptables handling function.
"""
from collections import defaultdict
import copy

import logging
import re
from mock import patch, call, Mock, ANY
from calico.felix import fiptables
from calico.felix.fiptables import IptablesUpdater
from calico.felix.futils import FailedSystemCall
from calico.felix.test.base import BaseTestCase, load_config

_log = logging.getLogger(__name__)

patch.object = getattr(patch, "object")  # Keep PyCharm linter happy.

EXTRACT_UNREF_TESTS = [
("""Chain INPUT (policy DROP)
target     prot opt source               destination
felix-INPUT  all  --  anywhere             anywhere
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:domain

Chain FORWARD (policy DROP)
target     prot opt source               destination
felix-FORWARD  all  --  anywhere             anywhere
ufw-track-forward  all  --  anywhere             anywhere

Chain DOCKER (1 references)
target     prot opt source               destination

Chain felix-FORWARD (1 references)
target     prot opt source               destination
felix-FROM-ENDPOINT  all  --  anywhere             anywhere
felix-TO-ENDPOINT  all  --  anywhere             anywhere
Chain-with-bad-name   all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere

Chain felix-temp (0 references)
target     prot opt source               destination
felix-FROM-ENDPOINT  all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
""",
set(["felix-temp"])),
]

# Define this as a function so that we can override it in plugin tests
def drop_rules(chain_name):
    return [
        '--append %s --jump DROP -m comment --comment "WARNING '
        'Missing '
        'chain"' % chain_name
    ]

STANDARD_ACTIONS = ("MARK", "ACCEPT", "DROP", "RETURN")


class TestIptablesUpdater(BaseTestCase):

    def setUp(self):
        super(TestIptablesUpdater, self).setUp()
        self.stub = IptablesStub("filter")
        env_dict = {"FELIX_REFRESHINTERVAL": "0"}
        self.config = load_config("felix_default.cfg", env_dict=env_dict)
        self.ipt = IptablesUpdater("filter", self.config, 4)
        self.ipt._execute_iptables = self.stub.apply_iptables_restore
        self.check_output_patch = patch("gevent.subprocess.check_output",
                                        autospec=True)
        self.m_check_output = self.check_output_patch.start()
        self.m_check_output.side_effect = self.fake_check_output

    def fake_check_output(self, cmd, *args, **kwargs):
        _log.info("Stubbing out call to %s", cmd)
        if cmd == ["iptables-save", "--table", "filter"]:
            return self.stub.generate_iptables_save()
        elif cmd == ['iptables', '--list', '--numeric',
                     '--table', 'filter']:
            return self.stub.generate_iptables_list()
        else:
            raise AssertionError("Unexpected call %r" % cmd)

    def tearDown(self):
        self.check_output_patch.stop()
        super(TestIptablesUpdater, self).tearDown()

    def test_rewrite_chains_stub(self):
        """
        Tests that referencing a chain causes it to get stubbed out.
        """
        self.ipt.rewrite_chains(
            {"foo": ["--append foo --jump bar"]},
            {"foo": set(["bar"])},
            async=True,
        )
        self.step_actor(self.ipt)
        self.assertEqual(self.stub.chains_contents,
            {"foo": ["--append foo --jump bar"],
             'bar': drop_rules("bar")})

    def test_rewrite_chains_stub_override(self):
        """
        Tests that we can override the contents of a stub chain.
        """
        self.ipt.set_missing_chain_override("bar", ["--append bar --jump RETURN"],
                                            async=True)
        self.ipt.rewrite_chains(
            {"foo": ["--append foo --jump bar"]},
            {"foo": set(["bar"])},
            async=True,
        )
        self.step_actor(self.ipt)
        self.assertEqual(self.stub.chains_contents,
            {"foo": ["--append foo --jump bar"],
             'bar': ["--append bar --jump RETURN"]})

    def test_rewrite_chains_cover(self):
        """
        Hits remaining code paths in rewrite chains.
        """
        cb = Mock()
        self.ipt.rewrite_chains(
            {"foo": ["--append foo --jump bar"]},
            {"foo": set(["bar"])},
            async=True,
            callback=cb,
        )
        self.step_actor(self.ipt)
        cb.assert_called_once_with(None)

    def test_delete_required_chain_stub(self):
        """
        Tests that deleting a required chain stubs it out instead.
        """
        # Exit the graceful restart period, during which we do not stub out
        # chains.
        self.ipt.cleanup(async=True)
        # Install a couple of chains.  foo depends on bar.
        self.ipt.rewrite_chains(
            {"foo": ["--append foo --jump bar"],
             "bar": ["--append bar --jump ACCEPT"]},
            {"foo": set(["bar"]),
             "bar": set()},
            async=True,
        )
        self.step_actor(self.ipt)
        # Both chains should be programmed as normal.
        self.assertEqual(self.stub.chains_contents,
            {"foo": ["--append foo --jump bar"],
             'bar': ["--append bar --jump ACCEPT"] })

        # Deleting bar should stub it out instead.
        self.ipt.delete_chains(["bar"], async=True)
        self.step_actor(self.ipt)
        self.assertEqual(self.stub.chains_contents,
            {"foo": ["--append foo --jump bar"],
             'bar': drop_rules("bar") })

    def test_cleanup_with_dependencies(self):
        # Set up the dataplane with some chains that the IptablesUpdater
        # doesn't know about and some that it will know about.
        self.stub.apply_iptables_restore("""
        *filter
        :INPUT DROP [10:505]
        :FORWARD DROP [0:0]
        :OUTPUT ACCEPT [40:1600]
        # These non-felix chains should be ignored
        :ignore-me -
        :ignore-me-too -
        # These are left-over felix chains.  Some depend on each other.  They
        # can only be cleaned up in the correct order.
        :felix-foo - [0:0]
        :felix-bar -
        :felix-foo -
        :felix-baz -
        :felix-biff -
        --append felix-foo --src 10.0.0.1/32 --jump felix-bar
        # baz depends on biff; cleanup needs to detect that.
        --append felix-baz --src 10.0.0.2/32 --jump felix-biff
        --append felix-biff --src 10.0.0.3/32 --jump DROP
        --append ignore-me --jump ignore-me-too
        --append ignore-me-too --jump DROP
        """.splitlines())

        # IptablesUpdater hears about some chains before the cleanup.  These
        # partially overlap with the ones that are already there.
        self.ipt._load_chain_names_from_iptables(async=True)
        self.ipt.rewrite_chains(
            {"felix-foo": ["--append felix-foo --jump felix-bar",
                           "--append felix-foo --jump felix-baz",
                           "--append felix-foo --jump felix-boff"],
             "felix-bar": ["--append felix-bar --jump ACCEPT"]},
            # felix-foo depends on:
            # * a new chain that's also being programmed
            # * a pre-existing chain that is present at start of day
            # * a new chain that isn't present at all.
            {"felix-foo": set(["felix-bar", "felix-baz", "felix-boff"]),
             "felix-bar": set()},
            async=True,
        )
        self.step_actor(self.ipt)

        # Dataplane should now have all the new chains in place, including
        # a stub for felix-boff.  However, the old chains should not have been
        # cleaned up.
        self.stub.assert_chain_contents({
            "INPUT": [],
            "FORWARD": [],
            "OUTPUT": [],
            "ignore-me": ["--append ignore-me --jump ignore-me-too"],
            "ignore-me-too": ["--append ignore-me-too --jump DROP"],
            "felix-foo": ["--append felix-foo --jump felix-bar",
                          "--append felix-foo --jump felix-baz",
                          "--append felix-foo --jump felix-boff"],
            "felix-bar": ["--append felix-bar --jump ACCEPT"],
            "felix-baz": ["--append felix-baz --src 10.0.0.2/32 "
                          "--jump felix-biff"],
            "felix-boff": drop_rules("felix-boff"),
            "felix-biff": ["--append felix-biff --src 10.0.0.3/32 --jump DROP"],
        })

        # Issue the cleanup.
        self.ipt.cleanup(async=True)
        self.step_actor(self.ipt)

        # Should now have stubbed-out chains for all the ones that are not
        # programmed.
        self.stub.assert_chain_contents({
            # Non felix chains ignored:
            "INPUT": [],
            "FORWARD": [],
            "OUTPUT": [],
            "ignore-me": ["--append ignore-me --jump ignore-me-too"],
            "ignore-me-too": ["--append ignore-me-too --jump DROP"],
            # Explicitly-programmed chains programmed.
            "felix-foo": ["--append felix-foo --jump felix-bar",
                          "--append felix-foo --jump felix-baz",
                          "--append felix-foo --jump felix-boff"],
            "felix-bar": ["--append felix-bar --jump ACCEPT"],
            # All required but unknown chains stubbed.
            "felix-baz": drop_rules("felix-baz"),
            "felix-boff": drop_rules("felix-boff"),
            # felix-biff deleted, even though it was referenced by felix-baz
            # before.
        })

    def test_delete_during_grace_period(self):
        """
        Test explicit deletion of a referenced chain during the grace period.

        The chain _should_ be stubbed out.
        """
        # Simulate a felix restart where the chains we're about to manipulate
        # already exist.
        self.stub.apply_iptables_restore("""
        *filter
        # These are left-over felix chains.  Some depend on each other.  They
        # can only be cleaned up in the correct order.
        :felix-foo - [0:0]
        :felix-bar -
        :felix-baz -
        --append felix-foo --src 10.0.0.1/32 --jump felix-bar
        --append felix-bar --src 10.0.0.2/32 --jump DROP
        --append felix-baz --src 10.0.0.3/32 --jump DROP
        """.splitlines())
        self.ipt._load_chain_names_from_iptables(async=True)

        # IptablesUpdater hears about all the chains before the cleanup.
        # Chains have dependencies.
        self.ipt.rewrite_chains(
            {"felix-foo": ["--append felix-foo --jump felix-bar"],
             "felix-bar": ["--append felix-bar --jump ACCEPT"],
             "felix-baz": ["--append felix-baz --jump ACCEPT"]},
            {"felix-foo": set(["felix-bar"]),
             "felix-bar": set(),
             "felix-baz": set()},
            async=True,
        )
        self.step_actor(self.ipt)

        # Dataplane should now have all the new chains in place.
        self.stub.assert_chain_contents({
            "felix-foo": ["--append felix-foo --jump felix-bar"],
            "felix-bar": ["--append felix-bar --jump ACCEPT"],
            "felix-baz": ["--append felix-baz --jump ACCEPT"],
        })

        # Then delete bar and baz.  The former should be stubbed because it
        # is required by chain foo.  The latter should be deleted.
        self.ipt.delete_chains(["felix-bar", "felix-baz"], async=True)
        self.step_actor(self.ipt)
        self.stub.assert_chain_contents({
            "felix-foo": ["--append felix-foo --jump felix-bar"],
            "felix-bar": drop_rules("felix-bar"),
        })

    def test_cleanup_bad_read_back(self):
        # IptablesUpdater hears about some chains before the cleanup.
        self.ipt.rewrite_chains(
            {"felix-foo": ["--append felix-foo --jump felix-boff"]},
            {"felix-foo": set(["felix-boff"])},
            async=True,
        )
        self.step_actor(self.ipt)
        self.stub.assert_chain_contents({
            "felix-foo": ["--append felix-foo --jump felix-boff"],
            "felix-boff": drop_rules("felix-boff"),
        })

        # Some other process then breaks our chains.
        self.stub.chains_contents = {}
        self.stub.iptables_save_output = [
            None,  # Start of cleanup.
            # End of cleanup.  Out of sync:
            "*filter\n"
            ":INPUT DROP [68:4885]\n"
            ":FORWARD DROP [0:0]\n"
            ":OUTPUT ACCEPT [20:888]\n"
            ":DOCKER - [0:0]\n"
            "-A INPUT -i lxcbr0 -p tcp -m tcp --dport 53 -j ACCEPT\n"
            "-A FORWARD -o lxcbr0 -j ACCEPT\n"
            "COMMIT\n"
        ]
        _log.info("Forcing iptables-save to always return %s",
                  self.stub.iptables_save_output)

        # Issue the cleanup.
        with patch.object(fiptables._log, "error") as m_error:
            self.ipt.cleanup(async=True)
            self.step_actor(self.ipt)
            m_error.assert_called_once_with(
                ANY,
                set([]),
                set([]),
                set(["felix-foo", "felix-boff"])
            )
            self.stub.assert_chain_contents({
                "felix-foo": ["--append felix-foo --jump felix-boff"],
                "felix-boff": drop_rules("felix-boff"),
            })

    def test_ensure_rule_inserted(self):
        fragment = "FOO --jump DROP"
        with patch.object(self.ipt, "_execute_iptables") as m_exec:
            m_exec.side_effect = iter([FailedSystemCall("Message", [], 1, "",
                                                        "line 2 failed"),
                                       None,
                                       None])
            self.ipt.ensure_rule_inserted(fragment, async=True)
            self.step_actor(self.ipt)
            self.assertEqual(
                m_exec.mock_calls,
                [
                    call(["*filter",
                          "--delete FOO --jump DROP",
                          "--insert FOO --jump DROP",
                          "COMMIT"],
                         fail_log_level=logging.DEBUG),
                    call(["*filter",
                          "--insert FOO --jump DROP",
                          "COMMIT"]),
                ])

            self.assertTrue(fragment in self.ipt._inserted_rule_fragments)

    def test_insert_remove_tracking(self):
        fragment = "FOO --jump DROP"
        with patch.object(self.ipt, "_execute_iptables") as m_exec:
            m_exec.side_effect = [
                # Insert.
                None,
                # Remove: requires an exception to terminate loop.
                None,
                FailedSystemCall("Message", [], 1, "", "line 2 failed"),
                # Insert.
                None,
            ]
            self.ipt.ensure_rule_inserted(fragment, async=True)
            self.step_actor(self.ipt)
            self.assertTrue(fragment in self.ipt._inserted_rule_fragments)
            self.assertTrue(fragment not in self.ipt._removed_rule_fragments)

            self.ipt.ensure_rule_removed(fragment, async=True)
            self.step_actor(self.ipt)
            self.assertTrue(fragment not in self.ipt._inserted_rule_fragments)
            self.assertTrue(fragment in self.ipt._removed_rule_fragments)

            self.ipt.ensure_rule_inserted(fragment, async=True)
            self.step_actor(self.ipt)
            self.assertTrue(fragment in self.ipt._inserted_rule_fragments)
            self.assertTrue(fragment not in self.ipt._removed_rule_fragments)

    def test_ensure_rule_removed(self):
        fragment = "FOO --jump DROP"
        with patch.object(self.ipt, "_execute_iptables") as m_exec:
            m_exec.side_effect = iter([None,
                                       FailedSystemCall("Message", [], 1, "",
                                                        "line 2 failed")])
            self.ipt.ensure_rule_removed(fragment, async=True)
            self.step_actor(self.ipt)
            exp_call = call([
                '*filter',
                '--delete FOO --jump DROP',
                'COMMIT',
            ], fail_log_level=logging.DEBUG)
            self.assertEqual(m_exec.mock_calls, [exp_call] * 2)

    def test_ensure_rule_removed_not_present(self):
        with patch.object(self.ipt, "_execute_iptables") as m_exec:
            m_exec.side_effect = iter([FailedSystemCall("Message", [], 1, "",
                                                        "line 2 failed")])
            self.ipt.ensure_rule_removed("FOO --jump DROP", async=True)
            self.step_actor(self.ipt)
            exp_call = call([
                '*filter',
                '--delete FOO --jump DROP',
                'COMMIT',
            ], fail_log_level=logging.DEBUG)
            self.assertEqual(m_exec.mock_calls, [exp_call])

    def test_ensure_rule_removed_missing_dep(self):
        with patch.object(self.ipt, "_execute_iptables") as m_exec:
            m_exec.side_effect = iter([
                FailedSystemCall("Message", [], 1, "",
                                 "at line: 2\n"
                                 "ipset doesn't exist")])
            self.ipt.ensure_rule_removed("FOO --jump DROP", async=True)
            self.step_actor(self.ipt)
            exp_call = call([
                '*filter',
                '--delete FOO --jump DROP',
                'COMMIT',
            ], fail_log_level=logging.DEBUG)
            self.assertEqual(m_exec.mock_calls, [exp_call])

    def test_ensure_rule_removed_error(self):
        with patch.object(self.ipt, "_execute_iptables") as m_exec:
            m_exec.side_effect = iter([FailedSystemCall("Message", [], 1, "",
                                                        "the foo is barred")])
            f = self.ipt.ensure_rule_removed("FOO --jump DROP", async=True)
            self.step_actor(self.ipt)
            self.assertRaises(FailedSystemCall, f.get)
            exp_call = call([
                '*filter',
                '--delete FOO --jump DROP',
                'COMMIT',
            ], fail_log_level=logging.DEBUG)
            self.assertEqual(m_exec.mock_calls, [exp_call])

    def test_refresh_iptables(self):
        self.ipt.ensure_rule_inserted("INPUT -j ACCEPT", async=True)
        self.ipt.ensure_rule_inserted("INPUT -j DROP", async=True)
        self.ipt.ensure_rule_removed("INPUT -j DROP", async=True)
        self.step_actor(self.ipt)

        self.ipt.refresh_iptables(async=True)
        with patch.object(self.ipt, "_insert_rule") as m_insert_rule:
            with patch.object(self.ipt, "_remove_rule") as m_remove_rule:
                self.step_actor(self.ipt)
                m_insert_rule.assert_called_once_with("INPUT -j ACCEPT",
                                                      log_level=logging.DEBUG)
                m_remove_rule.assert_called_once_with("INPUT -j DROP",
                                                      log_level=logging.DEBUG)


class TestIptablesStub(BaseTestCase):
    """
    Tests of our dummy iptables "stub".  It's sufficiently complex
    that giving it a few tests of its own adds a lot of confidence to
    the tests that really rely on it.
    """
    def setUp(self):
        super(TestIptablesStub, self).setUp()
        self.stub = IptablesStub("filter")

    def test_gen_ipt_save(self):
        self.stub.chains_contents = {
            "foo": ["--append foo"]
        }
        self.assertEqual(
            self.stub.generate_iptables_save(),
            "*filter\n"
            ":foo - [0:0]\n"
            "--append foo\n"
            "COMMIT"
        )

    def test_gen_ipt_list(self):
        self.stub.apply_iptables_restore("""
        *filter
        :foo - [0:0]
        :bar -
        --append foo --src 10.0.0.8/32 --jump bar
        --append bar --jump DROP
        """.splitlines())
        self.assertEqual(
            self.stub.generate_iptables_list(),
            "Chain bar (1 references)\n"
            "target     prot opt source               destination\n"
            "DROP dummy -- anywhere anywhere\n"
            "\n"
            "Chain foo (0 references)\n"
            "target     prot opt source               destination\n"
            "bar dummy -- anywhere anywhere\n"
        )


IPT_INPUT = """*filter
:felix-from-09d7e2980bc -
:felix-to-09d7e2980bc -
--flush felix-from-09d7e2980bc
--append felix-from-09d7e2980bc --jump DROP -m comment --comment "WARNING Missing chain"
--flush felix-to-09d7e2980bc
--append felix-to-09d7e2980bc --jump DROP -m comment --comment "WARNING Missing chain"
COMMIT
""".splitlines()


class TestUtilityFunctions(BaseTestCase):

    def test_extract_unreffed_chains(self):
        for inp, exp in EXTRACT_UNREF_TESTS:
            output = fiptables._extract_our_unreffed_chains(inp)
            self.assertEqual(exp, output, "Expected\n\n%s\n\nTo parse as: %s\n"
                                          "but got: %s" % (inp, exp, output))

    def test_parse_commit_failure(self):
        error = "iptables-restore: line 8 failed\n"
        retryable, msg = fiptables._parse_ipt_restore_error(IPT_INPUT, error)
        self.assertTrue(retryable)
        self.assertEqual(msg, "COMMIT failed; likely concurrent access.")

    def test_parse_non_commit_failure_parse(self):
        error = "iptables-restore: line 6 failed\n"
        retryable, msg = fiptables._parse_ipt_restore_error(IPT_INPUT, error)
        self.assertFalse(retryable)
        self.assertEqual(msg, "Line 6 failed: '--flush felix-to-09d7e2980bc'")

    def test_parse_other_failure_parse(self):
        error = "iptables-restore: unknown\n"
        retryable, msg = fiptables._parse_ipt_restore_error(IPT_INPUT, error)
        self.assertFalse(retryable)
        self.assertEqual(msg, "ip(6)tables-restore failed with output: "
                              "iptables-restore: unknown\n")


class IptablesStub(object):
    """
    Fake version of the dataplane, accepts iptables-restore input and
    stores it off.  Can generate dummy versions of the corresponding
    iptables-save and iptables --list output.
    """

    def __init__(self, table):
        self.table = table
        self.chains_contents = defaultdict(list)
        self.chain_dependencies = defaultdict(set)

        self.new_contents = None
        self.new_dependencies = None
        self.declared_chains = None

        self.iptables_save_output = []

    def generate_iptables_save(self):
        if self.iptables_save_output:
            output = self.iptables_save_output.pop(0)
            if output:
                _log.debug("Forcing iptables-save output")
                return output
        lines = ["*" + self.table]
        for chain_name in sorted(self.chains_contents.keys()):
            lines.append(":%s - [0:0]" % chain_name)
        for _, chain_content in sorted(self.chains_contents.items()):
            lines.extend(chain_content)
        lines.append("COMMIT")
        return "\n".join(lines)

    def generate_iptables_list(self):
        _log.debug("Generating iptables --list for chains %s\n%s",
                   self.chains_contents, self.chain_dependencies)
        chunks = []
        for chain, entries in sorted(self.chains_contents.items()):
            num_refs = 0
            for deps in self.chain_dependencies.values():
                if chain in deps:
                    num_refs += 1
            chain_lines = [
                "Chain %s (%s references)" % (chain, num_refs),
                "target     prot opt source               destination"]
            for rule in entries:
                m = re.search(r'(?:--jump|-j|--goto|-g)\s+(\S+)', rule)
                assert m, "Failed to generate listing for %r" % rule
                action = m.group(1)
                chain_lines.append(action + " dummy -- anywhere anywhere")
            chunks.append("\n".join(chain_lines))
        return "\n\n".join(chunks) + "\n"

    def apply_iptables_restore(self, lines, **kwargs):
        _log.debug("iptables-restore input:\n%s", "\n".join(lines))
        table_name = None
        self.new_contents = copy.deepcopy(self.chains_contents)
        self.declared_chains = set()
        self.new_dependencies = copy.deepcopy(self.chain_dependencies)
        for line in lines:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            elif line.startswith("*"):
                table_name = line[1:]
                _log.debug("Processing table %s", table_name)
                assert table_name == self.table
            elif line.startswith(":"):
                assert table_name, "Table should occur before chains."
                splits = line[1:].split(" ")
                _log.debug("Forward declaration %s, flushing chain", splits)
                if len(splits) == 3:
                    chain_name, policy, counts = splits
                    if not re.match(r'\[\d+:\d+\]', counts):
                        raise AssertionError("Bad counts: %r" % line)
                elif len(splits) == 2:
                    chain_name, policy = splits
                else:
                    raise AssertionError(
                        "Invalid chain forward declaration line %r" % line)
                if policy not in ("-", "DROP", "ACCEPT"):
                    raise AssertionError("Unexpected policy %r" % line)
                self.declared_chains.add(chain_name)
                self.new_contents[chain_name] = []
                self.new_dependencies[chain_name] = set()
            elif line.strip() == "COMMIT":
                self._handle_commit()
            else:
                # Should be a rule fragment of some sort
                assert table_name, "Table should occur before rules."
                self._handle_rule(line)
        # Implicit commit at end.
        self._handle_commit()

    def _handle_rule(self, rule):
        splits = rule.split(" ")
        ipt_op = splits[0]
        chain = splits[1]
        _log.debug("Rule op: %s, chain name: %s", ipt_op, chain)
        if ipt_op in ("--append", "-A", "--insert", "-I"):
            self.assert_chain_declared(chain, ipt_op)
            if ipt_op in ("--append", "-A"):
                self.new_contents[chain].append(rule)
            else:
                self.new_contents[chain].insert(0, rule)
            m = re.search(r'(?:--jump|-j|--goto|-g)\s+(\S+)', rule)
            if m:
                action = m.group(1)
                _log.debug("Action %s", action)
                if action not in STANDARD_ACTIONS:
                    # Assume a dependent chain.
                    self.new_dependencies[chain].add(action)
        elif ipt_op in ("--delete-chain", "-X"):
            self.assert_chain_declared(chain, ipt_op)
            del self.new_contents[chain]
            del self.new_dependencies[chain]
        elif ipt_op in ("--flush", "-F"):
            self.assert_chain_declared(chain, ipt_op)
            self.new_contents[chain] = []
            self.new_dependencies[chain] = set()
        elif ipt_op in ("--delete", "-D"):
            self.assert_chain_declared(chain, ipt_op)
            for rule in self.new_contents.get(chain, []):
                rule_fragment = " ".join(splits[1:])
                if rule.endswith(rule_fragment):
                    self.new_contents[chain].remove(rule)
                    break
            else:
                raise FailedSystemCall("Delete for non-existent rule", [], 1,
                                       "", "line 2 failed")
        else:
            raise AssertionError("Unknown operation %s; was expecting "
                                 "'--append|flush|delete|...' " % ipt_op)

    def assert_chain_declared(self, chain, ipt_op):
        kernel_chains = set(["INPUT", "FORWARD", "OUTPUT"])
        if chain not in self.declared_chains and chain not in kernel_chains:
            raise AssertionError("%s to non-existent chain %s" %
                                 (ipt_op, chain))

    def _handle_commit(self):
        for chain, deps in self.chain_dependencies.iteritems():
            for dep in deps:
                if dep not in self.new_contents:
                    raise AssertionError("Chain %s depends on %s but that "
                                         "chain is not present" % (chain, dep))
        self.chains_contents = self.new_contents
        self.chain_dependencies = self.new_dependencies

    def assert_chain_contents(self, expected):
        differences = zip(sorted(self.chains_contents.items()),
                          sorted(expected.items()))
        differences = ["%s != %s" % (p1, p2) for
                       (p1, p2) in differences
                       if p1 != p2]
        if self.chains_contents != expected:
            raise AssertionError("Differences:\n%s" % "\n".join(differences))


class TestTransaction(BaseTestCase):
    def setUp(self):
        super(TestTransaction, self).setUp()
        self.txn = fiptables._Transaction(
            {
                "felix-a": [], "felix-b": [], "felix-c": []
            },
            defaultdict(set, {"felix-a": set(["felix-b", "felix-stub"])}),
            defaultdict(set, {"felix-b": set(["felix-a"]),
                              "felix-stub": set(["felix-a"])}),
        )

    def test_rewrite_existing_chain_remove_stub_dependency(self):
        """
        Test that a no-longer-required stub is deleted.
        """
        self.txn.store_rewrite_chain("felix-a", ["foo"], set(["felix-b"]))
        self.assertEqual(self.txn.affected_chains,
                         set(["felix-a", "felix-stub"]))
        self.assertEqual(self.txn.chains_to_stub_out, set([]))
        self.assertEqual(self.txn.chains_to_delete, set(["felix-stub"]))
        self.assertEqual(self.txn.referenced_chains, set(["felix-b"]))
        self.assertEqual(
            self.txn.prog_chains,
            {
                "felix-a": ["foo"],
                "felix-b": [],
                "felix-c": []
            })
        self.assertEqual(self.txn.required_chns,
                         {"felix-a": set(["felix-b"])})
        self.assertEqual(self.txn.requiring_chns,
                         {"felix-b": set(["felix-a"])})

    def test_rewrite_existing_chain_remove_normal_dependency(self):
        """
        Test that removing a dependency on an explicitly programmed chain
        correctly updates the indices.
        """
        self.txn.store_rewrite_chain("felix-a", ["foo"], set(["felix-stub"]))
        self.assertEqual(self.txn.affected_chains, set(["felix-a"]))
        self.assertEqual(self.txn.chains_to_stub_out, set([]))
        self.assertEqual(self.txn.chains_to_delete, set([]))
        self.assertEqual(self.txn.referenced_chains, set(["felix-stub"]))
        self.assertEqual(
            self.txn.prog_chains,
            {
                "felix-a": ["foo"],
                "felix-b": [],
                "felix-c": [],
            })
        self.assertEqual(self.txn.required_chns,
                         {"felix-a": set(["felix-stub"])})
        self.assertEqual(self.txn.requiring_chns,
                         {"felix-stub": set(["felix-a"])})

    def test_unrequired_chain_delete(self):
        """
        Test that deleting an orphan chain triggers deletion and
        updates the indices.
        """
        self.txn.store_delete("felix-c")
        self.assertEqual(self.txn.affected_chains, set(["felix-c"]))
        self.assertEqual(self.txn.chains_to_stub_out, set([]))
        self.assertEqual(self.txn.chains_to_delete, set(["felix-c"]))
        self.assertEqual(self.txn.referenced_chains,
                         set(["felix-b", "felix-stub"]))
        self.assertEqual(
            self.txn.prog_chains,
            {
                "felix-a": [],
                "felix-b": [],
            })
        self.assertEqual(self.txn.required_chns,
                         {"felix-a": set(["felix-b", "felix-stub"])})
        self.assertEqual(self.txn.requiring_chns,
                         {"felix-b": set(["felix-a"]),
                          "felix-stub": set(["felix-a"])})

    def test_required_deleted_chain_gets_stubbed(self):
        """
        Test that deleting a chain that is still required results in it
        being stubbed out.
        """
        self.txn.store_delete("felix-b")
        self.assertEqual(self.txn.affected_chains, set(["felix-b"]))
        self.assertEqual(self.txn.chains_to_stub_out, set(["felix-b"]))
        self.assertEqual(self.txn.chains_to_delete, set())
        self.assertEqual(self.txn.referenced_chains,
                         set(["felix-b", "felix-stub"]))
        self.assertEqual(
            self.txn.prog_chains,
            {
                "felix-a": [],
                "felix-c": [],
            })
        self.assertEqual(self.txn.required_chns,
                         {"felix-a": set(["felix-b", "felix-stub"])})
        self.assertEqual(self.txn.requiring_chns,
                         {"felix-b": set(["felix-a"]),
                          "felix-stub": set(["felix-a"])})

    def test_cache_invalidation(self):
        self.assert_cache_dropped()
        self.assert_properties_cached()
        self.txn.store_delete("felix-a")
        self.assert_cache_dropped()

    def test_cache_invalidation_2(self):
        self.assert_cache_dropped()
        self.assert_properties_cached()
        self.txn.store_rewrite_chain("felix-a", [], {})
        self.assert_cache_dropped()

    def assert_properties_cached(self):
        self.assertEqual(self.txn.affected_chains, set())
        self.assertEqual(self.txn.chains_to_stub_out, set())
        self.assertEqual(self.txn.chains_to_delete, set())
        self.assertEqual(self.txn._affected_chains, set())
        self.assertEqual(self.txn._chains_to_stub, set())
        self.assertEqual(self.txn._chains_to_delete, set())

    def assert_cache_dropped(self):
        self.assertEqual(self.txn._affected_chains, None)
        self.assertEqual(self.txn._chains_to_stub, None)
        self.assertEqual(self.txn._chains_to_delete, None)
