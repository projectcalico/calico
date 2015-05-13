# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
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

import logging
from calico.felix import fiptables
from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


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


class TestIptablesUpdater(BaseTestCase):

    def test_extract_unreffed_chains(self):
        for inp, exp in EXTRACT_UNREF_TESTS:
            output = fiptables._extract_unreffed_chains(inp)
            self.assertEqual(exp, output, "Expected\n\n%s\n\nTo parse as: %s\n"
                                          "but got: %s" % (inp, exp, output))


class TestTransaction(BaseTestCase):
    def setUp(self):
        super(TestTransaction, self).setUp()
        self.txn = fiptables._Transaction(
            set(["felix-a", "felix-b", "felix-c"]),
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
        self.assertEqual(self.txn.expl_prog_chains,
                         set(["felix-a", "felix-b", "felix-c"]))
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
        self.assertEqual(self.txn.expl_prog_chains,
                         set(["felix-a", "felix-b", "felix-c"]))
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
        self.assertEqual(self.txn.expl_prog_chains,
                         set(["felix-a", "felix-b"]))
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
        self.assertEqual(self.txn.expl_prog_chains,
                         set(["felix-a", "felix-c"]))
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