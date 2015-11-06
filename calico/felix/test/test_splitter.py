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

    def test_on_datamodel_in_sync(self):
        s = self.get_splitter()
        with mock.patch("gevent.spawn_later") as m_spawn:
            s.on_datamodel_in_sync(async=True)
            s.on_datamodel_in_sync(async=True)
            self.step_actor(s)
        self.assertTrue(s._cleanup_scheduled)
        self.assertEqual(m_spawn.mock_calls,
                         [mock.call(0, mock.ANY)])
        for mgr in self.ipsets_mgrs + self.rules_mgrs + self.endpoint_mgrs:
            self.assertEqual(mgr.on_datamodel_in_sync.mock_calls,
                             [mock.call(async=True), mock.call(async=True)])

    def test_cleanup_give_up_on_exception(self):
        """
        Test that cleanup is killed by exception.
        """
        # No need to apply any data here.
        s = self.get_splitter()

        # However, make sure that the first ipset manager and the first
        # iptables updater throw exceptions when called.
        self.ipsets_mgrs[0].cleanup.side_effect = RuntimeError('Bang!')

        # Start the cleanup.
        result = s.trigger_cleanup(async=True)
        self.step_actor(s)
        self.assertRaises(RuntimeError, result.get)

    def test_cleanup_mainline(self):
        # No need to apply any data here.
        s = self.get_splitter()
        # Start the cleanup.
        result = s.trigger_cleanup(async=True)
        self.step_actor(s)
        result.get()

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
