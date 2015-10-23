# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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
felix.test.test_splitter
~~~~~~~~~~~~~~~~~~~~~~~~

Tests of the actor that splits update messages to multiple manager actors.
"""
import collections

import gevent
import mock
from calico.felix.masq import MasqueradeManager

from calico.felix.test.base import BaseTestCase
from calico.felix.splitter import UpdateSplitter


# A mocked config object for use in the UpdateSplitter.
Config = collections.namedtuple('Config', ['STARTUP_CLEANUP_DELAY'])

class TestUpdateSplitter(BaseTestCase):
    """
    Tests for the UpdateSplitter actor.
    """
    def setUp(self):
        super(TestUpdateSplitter, self).setUp()

        # Set the cleanup delay to 0, to force immediate cleanup.
        self.config = Config(0)
        self.ipsets_mgrs = [mock.MagicMock(), mock.MagicMock()]
        self.rules_mgrs = [mock.MagicMock(), mock.MagicMock()]
        self.endpoint_mgrs = [mock.MagicMock(), mock.MagicMock()]
        self.iptables_updaters = [mock.MagicMock(), mock.MagicMock()]
        self.masq_manager = mock.Mock(spec=MasqueradeManager)

    def get_splitter(self):
        return UpdateSplitter(
            self.config,
            self.ipsets_mgrs,
            self.rules_mgrs,
            self.endpoint_mgrs,
            self.iptables_updaters,
            self.masq_manager
        )
    #
    # def test_apply_whole_snapshot_clean(self):
    #     """
    #     Test that a whole snapshot applies cleanly to all managers.
    #     """
    #     # We apply a simple sentinel map. The exact map we use really shouldn't
    #     # matter here. We do, however, use different ones for rules, tags, and
    #     # endpoints.
    #     rules = {'profileA': ['first rule', 'second rule']}
    #     tags = {'profileA': ['first tag', 'second tag']}
    #     endpoints = {'endpointA': 'endpoint object'}
    #     ipv4_pools_by_id = {"10.0.0.1-5": {"cidr": "10.0.0.1/5",
    #                                        "masquerade": True}}
    #     s = self.get_splitter()
    #
    #     # Apply the snapshot and let it run.
    #     s.apply_snapshot(rules, tags, endpoints, ipv4_pools_by_id, async=True)
    #     self.step_actor(s)
    #
    #     # At this point, each of our managers should have been notified (one
    #     # call to apply_snapshot), but cleanup should not have occurred.
    #     for mgr in self.ipsets_mgrs:
    #         mgr.apply_snapshot.assertCalledOnceWith(
    #             tags, endpoints, async=True
    #         )
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.rules_mgrs:
    #         mgr.apply_snapshot.assertCalledOnceWith(rules, async=True)
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.endpoint_mgrs:
    #         mgr.apply_snapshot.assertCalledOnceWith(endpoints, async=True)
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.iptables_updaters:
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     self.masq_manager.apply_snapshot.assert_called_once_with(
    #         ipv4_pools_by_id, async=True)
    #
    #     # If we spin the scheduler again, we should begin cleanup.
    #     # Warning: this might be a bit brittle, we may not be waiting long
    #     # enough here, at least on busy machines.
    #     gevent.sleep(0.1)
    #     self.step_actor(s)
    #
    #     # Confirm that we cleaned up. Cleanup only affects the
    #     # iptables_updaters and the ipsets_managers, so confirm the other
    #     # managers got left alone.
    #     for mgr in self.ipsets_mgrs:
    #         mgr.cleanup.assertCalledOnceWith(async=False)
    #     for mgr in self.rules_mgrs:
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.endpoint_mgrs:
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.iptables_updaters:
    #         mgr.cleanup.assertCalledOnceWith(async=False)
    #
    # def test_repeated_snapshots_clean_up_only_once(self):
    #     """
    #     Test that repeated snapshots only clean up once.
    #     """
    #     # We apply a simple sentinel map. The exact map we use really shouldn't
    #     # matter here. We do, however, use different ones for rules, tags, and
    #     # endpoints.
    #     rules = {'profileA': ['first rule', 'second rule']}
    #     tags = {'profileA': ['first tag', 'second tag']}
    #     endpoints = {'endpointA': 'endpoint object'}
    #     ipv4_pools_by_id = {}
    #     s = self.get_splitter()
    #
    #     # Apply three snapshots and let them run. Because of batching logic,
    #     # we should only need to spin the actor once.
    #     s.apply_snapshot(rules, tags, endpoints, ipv4_pools_by_id, async=True)
    #     s.apply_snapshot(rules, tags, endpoints, ipv4_pools_by_id,  async=True)
    #     s.apply_snapshot(rules, tags, endpoints, ipv4_pools_by_id,  async=True)
    #     self.step_actor(s)
    #
    #     # At this point, each of our managers should have been notified (one
    #     # call to apply_snapshot), but cleanup should not have occurred.
    #     for mgr in self.ipsets_mgrs:
    #         mgr.apply_snapshot.assertCalledWith(
    #             tags, endpoints, async=True
    #         )
    #         self.assertEqual(mgr.apply_snapshot.call_count, 3)
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.rules_mgrs:
    #         mgr.apply_snapshot.assertCalledWith(rules, async=True)
    #         self.assertEqual(mgr.apply_snapshot.call_count, 3)
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.endpoint_mgrs:
    #         mgr.apply_snapshot.assertCalledWith(endpoints, async=True)
    #         self.assertEqual(mgr.apply_snapshot.call_count, 3)
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.iptables_updaters:
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     self.assertEqual(self.masq_manager.apply_snapshot.call_count, 3)
    #
    #     # If we spin the scheduler again, we should begin cleanup.
    #     # Warning: this might be a bit brittle, we may not be waiting long
    #     # enough here, at least on busy machines.
    #     gevent.sleep(0.1)
    #     self.step_actor(s)
    #
    #     # Confirm that we cleaned up. Cleanup only affects the
    #     # iptables_updaters and the ipsets_managagers, so confirm the other
    #     # managers got left alone.
    #     for mgr in self.ipsets_mgrs:
    #         mgr.cleanup.assertCalledOnceWith(async=False)
    #     for mgr in self.rules_mgrs:
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.endpoint_mgrs:
    #         self.assertEqual(mgr.cleanup.call_count, 0)
    #     for mgr in self.iptables_updaters:
    #         mgr.cleanup.assertCalledOnceWith(async=False)

    def test_cleanup_give_up_on_exception(self):
        """
        Test that cleanup is killed by exception.
        """
        # No need to apply any data here.
        s = self.get_splitter()

        # However, make sure that the first ipset manager and the first
        # iptables updater throw exceptions when called.
        self.ipsets_mgrs[0].cleanup.side_effect = RuntimeError('Bang!')
        self.iptables_updaters[0].cleanup.side_effect = RuntimeError('Bang!')

        # Start the cleanup.
        result = s.trigger_cleanup(async=True)
        self.step_actor(s)
        self.assertRaises(RuntimeError, result.get)

    def test_rule_updates_propagate(self):
        """
        Test that the on_rules_update message propagates correctly.
        """
        s = self.get_splitter()
        profile = 'profileA'
        rules = ['first rule', 'second rule']

        # Apply the rules update
        s.on_rules_update(profile, rules, async=True)
        self.step_actor(s)

        # Confirm that the rules update propagates.
        for mgr in self.rules_mgrs:
            mgr.on_rules_update.assertCalledOnceWith(
                profile, rules, async=True
            )

    def test_tags_updates_propagate(self):
        """
        Test that the on_tags_update message propagates correctly.
        """
        s = self.get_splitter()
        profile = 'profileA'
        tags = ['first tag', 'second tag']

        # Apply the tags update
        s.on_tags_update(profile, tags, async=True)
        self.step_actor(s)

        # Confirm that the rules update propagates.
        for mgr in self.ipsets_mgrs:
            mgr.on_tags_update.assertCalledOnceWith(
                profile, tags, async=True
            )

    def test_interface_updates_propagate(self):
        """
        Test that the on_interface_update message propagates correctly.
        """
        s = self.get_splitter()
        interface = 'tapABCDEF'

        # Apply the interface update
        s.on_interface_update(interface, iface_up=True, async=True)
        self.step_actor(s)

        # Confirm that the interface update propagates.
        for mgr in self.endpoint_mgrs:
            mgr.on_interface_update.assertCalledOnceWith(interface, async=True)

    def test_endpoint_updates_propagate(self):
        """
        Test that the on_endpoint_update message propagates correctly.
        """
        s = self.get_splitter()
        endpoint = 'endpointA'
        endpoint_object = 'endpoint'

        # Apply the endpoint update
        s.on_endpoint_update(endpoint, endpoint_object, async=True)
        self.step_actor(s)

        # Confirm that the endpoint update propagates.
        for mgr in self.ipsets_mgrs:
            mgr.on_endpoint_update.assertCalledOnceWith(
                endpoint, endpoint_object, async=True
            )
        for mgr in self.endpoint_mgrs:
            mgr.on_endpoint_update.assertCalledOnceWith(
                endpoint, endpoint_object, async=True
            )

    def test_on_ipam_pool_updated(self):
        """
        Test that the on_ipam_pool_update message propagates correctly
        """
        s = self.get_splitter()
        pool_id = "foo"
        pool = {"cidr": "10/16", "masquerade": False}

        s.ipv4_masq_manager.apply_snapshot({"foo": {"cidr": "10.0.0.0/16",
                                                    "masquerade": True},
                                            "bar": {"cidr": "10.1.0.0/16",
                                                    "masquerade": False}},
                                           async=True)

        # Apply the IPAM pool update
        s.on_ipam_pool_update(pool_id, pool, async=True)
        self.step_actor(s)

        # Confirm that the pool update propagates
        self.masq_manager.on_ipam_pool_updated.assertCalledOnceWith(
            pool_id, pool, async=True
        )
