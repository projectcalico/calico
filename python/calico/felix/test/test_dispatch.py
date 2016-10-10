# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
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
felix.test.test_dispatch
~~~~~~~~~~~~~~~~~~~~~~~~

Tests of the actor that controls the top-level dispatch chain.
"""
from pprint import pformat

import itertools
import mock

from calico.felix.test.base import BaseTestCase, load_config
from calico.felix.dispatch import WorkloadDispatchChains, \
    HostEndpointDispatchChains
from calico.felix.frules import CHAIN_TO_ENDPOINT, CHAIN_FROM_ENDPOINT, \
    CHAIN_TO_IFACE, CHAIN_FROM_IFACE


class TestWorkloadDispatchChains(BaseTestCase):
    """
    Tests for the WorkloadDispatchChains actor.
    """
    def setUp(self):
        super(TestWorkloadDispatchChains, self).setUp()
        self.iptables_updater = mock.MagicMock()
        self.config = load_config("felix_default.cfg", global_dict={
            "MetadataPort": "8775"})

    def dispatch_chain(self):
        return WorkloadDispatchChains(
            config=self.config,
            ip_version=4,
            iptables_updater=self.iptables_updater
        )

    def assert_iptables_update(self,
                               args,
                               to_updates,
                               from_updates,
                               to_chain_names,
                               from_chain_names):
        # We only care about positional arguments
        args = args[0]

        # The WorkloadDispatchChains object stores the endpoints in a set, which means
        # that when it builds the list of goto rules they can be emitted in any
        # order. However, the DROP rule must always appear at the end. To do
        # that, first check that the updates contain the same rules in any
        # order (using assertItemsEqual), and then confirm that the last rule
        # is the DROP rule.
        self.assertItemsEqual(args[0][CHAIN_TO_ENDPOINT], to_updates)
        self.assertItemsEqual(args[0][CHAIN_FROM_ENDPOINT], from_updates)
        self.assertEqual(args[0][CHAIN_TO_ENDPOINT][-1], to_updates[-1])
        self.assertEqual(args[0][CHAIN_FROM_ENDPOINT][-1], from_updates[-1])

        # Confirm that the dependency sets match.
        self.assertEqual(args[1][CHAIN_TO_ENDPOINT], to_chain_names)
        self.assertEqual(args[1][CHAIN_FROM_ENDPOINT], from_chain_names)

    def test_applying_metadata(self):
        """
        Tests that a snapshot with metadata works OK.
        """
        self.config = load_config("felix_default.cfg", global_dict={
            "MetadataPort": "8775",
            "MetadataAddr": "127.0.0.1"})

        d = self.dispatch_chain()

        ifaces = {'tapabcdef', 'tap123456', 'tapb7d849'}
        d.apply_snapshot(ifaces, async=True)
        self.step_actor(d)

        from_updates = [
            '--append felix-FROM-ENDPOINT --in-interface tapabcdef --goto felix-from-abcdef',
            '--append felix-FROM-ENDPOINT --in-interface tap123456 --goto felix-from-123456',
            '--append felix-FROM-ENDPOINT --in-interface tapb7d849 --goto felix-from-b7d849',
            '--append felix-FROM-ENDPOINT --jump DROP -m comment '
            '--comment "From unknown endpoint"',
        ]
        to_updates = [
            '--append felix-TO-ENDPOINT --out-interface tapabcdef --goto felix-to-abcdef',
            '--append felix-TO-ENDPOINT --out-interface tap123456 --goto felix-to-123456',
            '--append felix-TO-ENDPOINT --out-interface tapb7d849 --goto felix-to-b7d849',
            '--append felix-TO-ENDPOINT --jump DROP -m comment --comment "To unknown endpoint"',
        ]
        from_chain_names = set(['felix-from-abcdef', 'felix-from-123456', 'felix-from-b7d849'])
        to_chain_names = set(['felix-to-abcdef', 'felix-to-123456', 'felix-to-b7d849'])
        args = self.iptables_updater.rewrite_chains.call_args
        self.assert_iptables_update(
            args, to_updates, from_updates, to_chain_names,
            from_chain_names
        )

    def test_tree_building(self):
        d = self.dispatch_chain()
        d.programmed_leaf_chains.add("felix-FROM-EP-PFX-a")
        d.programmed_leaf_chains.add("felix-FROM-EP-PFX-z")
        ifaces = {'tapa1', 'tapa2', 'tapa3',
                  'tapb1', 'tapb20123456789012345',
                  'tapc'}
        to_delete, deps, updates, new_leaf_chains = d._calculate_update(ifaces)
        self.assertEqual(to_delete, set(["felix-FROM-EP-PFX-z"]))
        print "Deps", pformat(deps)
        self.assertEqual(deps, {
            'felix-TO-ENDPOINT': set(
                ['felix-FROM-EP-PFX-a', 'felix-FROM-EP-PFX-b', 'felix-to-c']),
            'felix-FROM-ENDPOINT': set(
                ['felix-TO-EP-PFX-a', 'felix-TO-EP-PFX-b', 'felix-from-c']),

            'felix-TO-EP-PFX-a': set(['felix-to-a1',
                                      'felix-to-a2',
                                      'felix-to-a3']),
            'felix-TO-EP-PFX-b': set(['felix-to-b1',
                                      'felix-to-_62629f0db434d57']),

            'felix-FROM-EP-PFX-a': set(['felix-from-a1',
                                        'felix-from-a2',
                                        'felix-from-a3']),
            'felix-FROM-EP-PFX-b': set(['felix-from-b1',
                                        'felix-from-_62629f0db434d57']),
        })
        for chain_name, chain_updates in updates.items():
            chain_updates[:] = sorted(chain_updates[:-1]) + chain_updates[-1:]
        print "Updates:", pformat(updates)
        self.assertEqual(updates, {
            'felix-TO-ENDPOINT': [
                # If there are multiple endpoints with a prefix, we get a
                # prefix match.
                '--append felix-TO-ENDPOINT --out-interface tapa+ --goto felix-TO-EP-PFX-a',
                '--append felix-TO-ENDPOINT --out-interface tapb+ --goto felix-TO-EP-PFX-b',
                # If there's only one, we don't.
                '--append felix-TO-ENDPOINT --out-interface tapc --goto felix-to-c',
                '--append felix-TO-ENDPOINT --jump DROP -m comment --comment "To unknown endpoint"'],
            'felix-FROM-ENDPOINT': [
                '--append felix-FROM-ENDPOINT --in-interface tapa+ --goto felix-FROM-EP-PFX-a',
                '--append felix-FROM-ENDPOINT --in-interface tapb+ --goto felix-FROM-EP-PFX-b',
                '--append felix-FROM-ENDPOINT --in-interface tapc --goto felix-from-c',
                '--append felix-FROM-ENDPOINT --jump DROP -m comment --comment "From unknown endpoint"'],
            'felix-FROM-EP-PFX-a': [
                # Per-prefix chain has one entry per endpoint.
                '--append felix-FROM-EP-PFX-a --in-interface tapa1 --goto felix-from-a1',
                '--append felix-FROM-EP-PFX-a --in-interface tapa2 --goto felix-from-a2',
                '--append felix-FROM-EP-PFX-a --in-interface tapa3 --goto felix-from-a3',
                # And a trailing drop.
                '--append felix-FROM-EP-PFX-a --jump DROP -m comment --comment "From unknown endpoint"'],
            'felix-FROM-EP-PFX-b': [
                '--append felix-FROM-EP-PFX-b --in-interface tapb1 --goto felix-from-b1',
                '--append felix-FROM-EP-PFX-b --in-interface tapb20123456789012345 --goto felix-from-_62629f0db434d57',
                '--append felix-FROM-EP-PFX-b --jump DROP -m comment --comment "From unknown endpoint"'],
            'felix-TO-EP-PFX-a': [
                '--append felix-TO-EP-PFX-a --out-interface tapa1 --goto felix-to-a1',
                '--append felix-TO-EP-PFX-a --out-interface tapa2 --goto felix-to-a2',
                '--append felix-TO-EP-PFX-a --out-interface tapa3 --goto felix-to-a3',
                '--append felix-TO-EP-PFX-a --jump DROP -m comment --comment "To unknown endpoint"'],
            'felix-TO-EP-PFX-b': [
                '--append felix-TO-EP-PFX-b --out-interface tapb1 --goto felix-to-b1',
                '--append felix-TO-EP-PFX-b --out-interface tapb20123456789012345 --goto felix-to-_62629f0db434d57',
                '--append felix-TO-EP-PFX-b --jump DROP -m comment --comment "To unknown endpoint"']
        })

    def test_applying_snapshot_clean(self):
        """
        Tests that a snapshot can be applied to a previously unused actor.
        """
        d = self.dispatch_chain()

        ifaces = {'tapabcdef', 'tap123456', 'tapb7d849'}
        d.apply_snapshot(ifaces, async=True)
        self.step_actor(d)

        from_updates = [
            '--append felix-FROM-ENDPOINT --in-interface tapabcdef --goto felix-from-abcdef',
            '--append felix-FROM-ENDPOINT --in-interface tap123456 --goto felix-from-123456',
            '--append felix-FROM-ENDPOINT --in-interface tapb7d849 --goto felix-from-b7d849',
            '--append felix-FROM-ENDPOINT --jump DROP -m comment --comment "From unknown endpoint"',
        ]
        to_updates = [
            '--append felix-TO-ENDPOINT --out-interface tapabcdef --goto felix-to-abcdef',
            '--append felix-TO-ENDPOINT --out-interface tap123456 --goto felix-to-123456',
            '--append felix-TO-ENDPOINT --out-interface tapb7d849 --goto felix-to-b7d849',
            '--append felix-TO-ENDPOINT --jump DROP -m comment --comment "To unknown endpoint"',
        ]
        from_chain_names = set(['felix-from-abcdef', 'felix-from-123456', 'felix-from-b7d849'])
        to_chain_names = set(['felix-to-abcdef', 'felix-to-123456', 'felix-to-b7d849'])
        args = self.iptables_updater.rewrite_chains.call_args
        self.assert_iptables_update(
            args,
            to_updates,
            from_updates,
            to_chain_names,
            from_chain_names
        )

    def test_applying_snapshot_dirty(self):
        """
        Tests that a snapshot can be applied to an actor that used to have
        state.
        """
        d = self.dispatch_chain()

        # Insert some chains I don't want to see.
        d.apply_snapshot({'tapxyz', 'tap889900', 'tapundefined'}, async=True)
        self.step_actor(d)

        ifaces = {'tapabcdef', 'tap123456', 'tapb7d849'}
        d.apply_snapshot(ifaces, async=True)
        self.step_actor(d)

        from_updates = [
            '--append felix-FROM-ENDPOINT --in-interface tapabcdef --goto felix-from-abcdef',
            '--append felix-FROM-ENDPOINT --in-interface tap123456 --goto felix-from-123456',
            '--append felix-FROM-ENDPOINT --in-interface tapb7d849 --goto felix-from-b7d849',
            '--append felix-FROM-ENDPOINT --jump DROP -m comment --comment "From unknown endpoint"',
        ]
        to_updates = [
            '--append felix-TO-ENDPOINT --out-interface tapabcdef --goto felix-to-abcdef',
            '--append felix-TO-ENDPOINT --out-interface tap123456 --goto felix-to-123456',
            '--append felix-TO-ENDPOINT --out-interface tapb7d849 --goto felix-to-b7d849',
            '--append felix-TO-ENDPOINT --jump DROP -m comment --comment "To unknown endpoint"',
        ]
        from_chain_names = set(['felix-from-abcdef', 'felix-from-123456', 'felix-from-b7d849'])
        to_chain_names = set(['felix-to-abcdef', 'felix-to-123456', 'felix-to-b7d849'])

        self.assertEqual(self.iptables_updater.rewrite_chains.call_count, 2)
        args = self.iptables_updater.rewrite_chains.call_args
        self.assert_iptables_update(
            args,
            to_updates,
            from_updates,
            to_chain_names,
            from_chain_names
        )

    def test_applying_empty_snapshot(self):
        """
        Tests that an empty snapshot can be applied to an actor that used to
        have state.
        """
        d = self.dispatch_chain()

        # Insert some chains I don't want to see.
        d.apply_snapshot({'tapxyz', 'tap889900', 'tapundefined'}, async=True)
        self.step_actor(d)

        # Clear it out
        d.apply_snapshot(set(), async=True)
        self.step_actor(d)

        from_updates = [
            '--append felix-FROM-ENDPOINT --jump DROP -m comment --comment "From unknown endpoint"',
        ]
        to_updates = [
            '--append felix-TO-ENDPOINT --jump DROP -m comment --comment "To unknown endpoint"',
        ]
        from_chain_names = set()
        to_chain_names = set()

        self.assertEqual(self.iptables_updater.rewrite_chains.call_count, 2)
        args = self.iptables_updater.rewrite_chains.call_args
        self.assert_iptables_update(
            args,
            to_updates,
            from_updates,
            to_chain_names,
            from_chain_names
        )

    def test_on_endpoint_added_simple(self):
        """
        Tests that adding an endpoint, adds it to the state.
        """
        d = self.dispatch_chain()

        # Insert some basic chains.
        d.apply_snapshot({'tapabcdef', 'tap123456'}, async=True)
        self.step_actor(d)

        # Add one endpoint.
        d.on_endpoint_added('tapb7d849', async=True)
        self.step_actor(d)

        from_updates = [
            '--append felix-FROM-ENDPOINT --in-interface tapabcdef --goto felix-from-abcdef',
            '--append felix-FROM-ENDPOINT --in-interface tap123456 --goto felix-from-123456',
            '--append felix-FROM-ENDPOINT --in-interface tapb7d849 --goto felix-from-b7d849',
            '--append felix-FROM-ENDPOINT --jump DROP -m comment --comment "From unknown endpoint"',
        ]
        to_updates = [
            '--append felix-TO-ENDPOINT --out-interface tapabcdef --goto felix-to-abcdef',
            '--append felix-TO-ENDPOINT --out-interface tap123456 --goto felix-to-123456',
            '--append felix-TO-ENDPOINT --out-interface tapb7d849 --goto felix-to-b7d849',
            '--append felix-TO-ENDPOINT --jump DROP -m comment --comment "To unknown endpoint"',
        ]
        from_chain_names = set(['felix-from-abcdef', 'felix-from-123456', 'felix-from-b7d849'])
        to_chain_names = set(['felix-to-abcdef', 'felix-to-123456', 'felix-to-b7d849'])

        self.assertEqual(self.iptables_updater.rewrite_chains.call_count, 2)
        args = self.iptables_updater.rewrite_chains.call_args
        self.assert_iptables_update(
            args,
            to_updates,
            from_updates,
            to_chain_names,
            from_chain_names
        )

    def test_on_endpoint_added_idempotent(self):
        """
        Tests that adding an endpoint that's already present does nothing.
        """
        d = self.dispatch_chain()

        # Insert some basic chains.
        d.apply_snapshot({'tapabcdef', 'tap123456', 'tapb7d849'}, async=True)
        self.step_actor(d)

        # Add an endpoint we already have.
        d.on_endpoint_added('tapabcdef', async=True)
        self.step_actor(d)

        # Confirm that we only got called once.
        self.assertEqual(self.iptables_updater.rewrite_chains.call_count, 1)

    def test_on_endpoint_removed_basic(self):
        """
        Tests that we can remove an endpoint.
        """
        d = self.dispatch_chain()

        # Insert some basic chains.
        d.apply_snapshot({'tapabcdef', 'tap123456', 'tapb7d849'}, async=True)
        self.step_actor(d)

        # Remove an endpoint.
        d.on_endpoint_removed('tapabcdef', async=True)
        self.step_actor(d)

        from_updates = [
            '--append felix-FROM-ENDPOINT --in-interface tap123456 --goto felix-from-123456',
            '--append felix-FROM-ENDPOINT --in-interface tapb7d849 --goto felix-from-b7d849',
            '--append felix-FROM-ENDPOINT --jump DROP -m comment --comment "From unknown endpoint"',
        ]
        to_updates = [
            '--append felix-TO-ENDPOINT --out-interface tap123456 --goto felix-to-123456',
            '--append felix-TO-ENDPOINT --out-interface tapb7d849 --goto felix-to-b7d849',
            '--append felix-TO-ENDPOINT --jump DROP -m comment --comment "To unknown endpoint"',
        ]
        from_chain_names = set(['felix-from-123456', 'felix-from-b7d849'])
        to_chain_names = set(['felix-to-123456', 'felix-to-b7d849'])

        # Confirm that we got called twice.
        self.assertEqual(self.iptables_updater.rewrite_chains.call_count, 2)
        args = self.iptables_updater.rewrite_chains.call_args
        self.assert_iptables_update(
            args,
            to_updates,
            from_updates,
            to_chain_names,
            from_chain_names
        )

    def test_on_endpoint_removed_idempotent(self):
        """
        Tests that removing an endpoint multiple times does nothing.
        """
        d = self.dispatch_chain()

        # Insert some basic chains.
        d.apply_snapshot({'tapabcdef', 'tap123456', 'tapb7d849'}, async=True)
        self.step_actor(d)

        # Remove an endpoint.
        d.on_endpoint_removed('tapabcdef', async=True)
        self.step_actor(d)

        # Remove it a few more times for good measure.
        d.on_endpoint_removed('tapabcdef', async=True)
        self.step_actor(d)
        d.on_endpoint_removed('tapabcdef', async=True)
        self.step_actor(d)
        d.on_endpoint_removed('tapabcdef', async=True)
        self.step_actor(d)

        # Confirm that we only got called twice.
        self.assertEqual(self.iptables_updater.rewrite_chains.call_count, 2)


class TestHostDispatchChains(BaseTestCase):
    """
    Tests for the HostEndpointDispatchChains actor.

    We get most of our coverage of the base class from the workload version
    of this test.
    """
    def setUp(self):
        super(TestHostDispatchChains, self).setUp()
        self.iptables_updater = mock.MagicMock()
        self.config = load_config("felix_default.cfg", global_dict={
            "MetadataPort": "8775"})

    def dispatch_chain(self):
        return HostEndpointDispatchChains(
            config=self.config,
            ip_version=4,
            iptables_updater=self.iptables_updater
        )

    def assert_iptables_update(self,
                               args,
                               to_updates,
                               from_updates,
                               to_chain_names,
                               from_chain_names):
        # We only care about positional arguments
        args = args[0]

        # Since the ordering is non-deterministic, use assertItemsEqual to
        # check the contents.
        self.assertItemsEqual(args[0][CHAIN_TO_IFACE], to_updates)
        self.assertItemsEqual(args[0][CHAIN_FROM_IFACE], from_updates)

        # Confirm that the dependency sets match.
        self.assertEqual(args[1][CHAIN_TO_ENDPOINT], to_chain_names)
        self.assertEqual(args[1][CHAIN_FROM_ENDPOINT], from_chain_names)

    def test_mainline_tree_building(self):
        d = self.dispatch_chain()
        d.programmed_leaf_chains.add("felix-FROM-IF-PFX-a")
        d.programmed_leaf_chains.add("felix-FROM-IF-PFX-z")
        ifaces = {'tapa1', 'tapa2', 'tapa3',
                  'tapb1', 'tapb20123456789012345',
                  'tapc'}
        to_delete, deps, updates, new_leaf_chains = d._calculate_update(ifaces)
        self.assertEqual(to_delete, set(["felix-FROM-IF-PFX-z"]))
        print "Deps", pformat(deps)
        self.assertEqual(deps, {
            'felix-TO-HOST-IF': set(
                ['felix-FROM-IF-PFX-a', 'felix-FROM-IF-PFX-b', 'felix-to-c']),
            'felix-FROM-HOST-IF': set(
                ['felix-TO-IF-PFX-a', 'felix-TO-IF-PFX-b', 'felix-from-c']),

            'felix-TO-IF-PFX-a': set(['felix-to-a1',
                                      'felix-to-a2',
                                      'felix-to-a3']),
            'felix-TO-IF-PFX-b': set(['felix-to-b1',
                                      'felix-to-_62629f0db434d57']),

            'felix-FROM-IF-PFX-a': set(['felix-from-a1',
                                        'felix-from-a2',
                                        'felix-from-a3']),
            'felix-FROM-IF-PFX-b': set(['felix-from-b1',
                                        'felix-from-_62629f0db434d57']),
        })
        for chain_name, chain_updates in updates.items():
            chain_updates[:] = sorted(chain_updates[:-1]) + chain_updates[-1:]
        print "Updates:", pformat(dict(updates))
        self.assertEqual(updates, {
            'felix-TO-HOST-IF': [
                # If there are multiple endpoints with a prefix, we get a
                # prefix match.
                '--append felix-TO-HOST-IF --out-interface tapa+ --goto felix-TO-IF-PFX-a',
                '--append felix-TO-HOST-IF --out-interface tapb+ --goto felix-TO-IF-PFX-b',
                # If there's only one, we don't.
                '--append felix-TO-HOST-IF --out-interface tapc --goto felix-to-c',
                '--append felix-TO-HOST-IF --jump RETURN --match comment --comment "Unknown interface, return"'],
            'felix-FROM-HOST-IF': [
                '--append felix-FROM-HOST-IF --in-interface tapa+ --goto felix-FROM-IF-PFX-a',
                '--append felix-FROM-HOST-IF --in-interface tapb+ --goto felix-FROM-IF-PFX-b',
                '--append felix-FROM-HOST-IF --in-interface tapc --goto felix-from-c',
                '--append felix-FROM-HOST-IF --jump RETURN --match comment --comment "Unknown interface, return"'],
            'felix-FROM-IF-PFX-a': [
                # Per-prefix chain has one entry per endpoint.
                '--append felix-FROM-IF-PFX-a --in-interface tapa1 --goto felix-from-a1',
                '--append felix-FROM-IF-PFX-a --in-interface tapa2 --goto felix-from-a2',
                '--append felix-FROM-IF-PFX-a --in-interface tapa3 --goto felix-from-a3',
                '--append felix-FROM-IF-PFX-a --jump RETURN --match comment --comment "Unknown interface, return"'],
            'felix-FROM-IF-PFX-b': [
                '--append felix-FROM-IF-PFX-b --in-interface tapb1 --goto felix-from-b1',
                '--append felix-FROM-IF-PFX-b --in-interface tapb20123456789012345 --goto felix-from-_62629f0db434d57',
                '--append felix-FROM-IF-PFX-b --jump RETURN --match comment --comment "Unknown interface, return"'],
            'felix-TO-IF-PFX-a': [
                '--append felix-TO-IF-PFX-a --out-interface tapa1 --goto felix-to-a1',
                '--append felix-TO-IF-PFX-a --out-interface tapa2 --goto felix-to-a2',
                '--append felix-TO-IF-PFX-a --out-interface tapa3 --goto felix-to-a3',
                '--append felix-TO-IF-PFX-a --jump RETURN --match comment --comment "Unknown interface, return"'],
            'felix-TO-IF-PFX-b': [
                '--append felix-TO-IF-PFX-b --out-interface tapb1 --goto felix-to-b1',
                '--append felix-TO-IF-PFX-b --out-interface tapb20123456789012345 --goto felix-to-_62629f0db434d57',
                '--append felix-TO-IF-PFX-b --jump RETURN --match comment --comment "Unknown interface, return"']
        })

    def test_applying_empty_snapshot(self):
        """
        Tests that an empty snapshot can be applied to an actor that used to
        have state.
        """
        d = self.dispatch_chain()

        # Insert some chains I don't want to see.
        d.apply_snapshot({'tapxyz', 'tap889900', 'tapundefined'}, async=True)
        self.step_actor(d)

        # Clear it out
        d.apply_snapshot(set(), async=True)
        self.step_actor(d)

        from_updates = [
            '--append felix-FROM-HOST-IF --jump RETURN --match comment --comment "Unknown interface, return"'
        ]
        to_updates = [
            '--append felix-TO-HOST-IF --jump RETURN --match comment --comment "Unknown interface, return"'
        ]
        from_chain_names = set()
        to_chain_names = set()

        self.assertEqual(self.iptables_updater.rewrite_chains.call_count, 2)
        args = self.iptables_updater.rewrite_chains.call_args
        self.assert_iptables_update(
            args,
            to_updates,
            from_updates,
            to_chain_names,
            from_chain_names
        )

    def test_config_iptables(self):
        d = self.dispatch_chain()
        d.configure_iptables(async=True)
        self.step_actor(d)
        print self.iptables_updater.set_missing_chain_override.mock_calls
        self.assertEqual(
            self.iptables_updater.set_missing_chain_override.mock_calls,
            [
                mock.call('felix-FROM-HOST-IF',
                          ['--append felix-FROM-HOST-IF --jump RETURN --match comment '
                           '--comment "Not ready yet, allowing host traffic"'],
                          async=True),
                mock.call('felix-TO-HOST-IF',
                          ['--append felix-TO-HOST-IF --jump RETURN --match comment '
                           '--comment "Not ready yet, allowing host traffic"'],
                          async=True)
            ]
        )
