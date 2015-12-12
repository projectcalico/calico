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
import mock
from calico.felix.masq import MasqueradeManager

from calico.felix.test.base import BaseTestCase
from calico.felix.splitter import UpdateSplitter, CleanupManager


class TestUpdateSplitter(BaseTestCase):
    """
    Tests for the UpdateSplitter actor.
    """
    def setUp(self):
        super(TestUpdateSplitter, self).setUp()

        self.ipsets_mgrs = [mock.MagicMock(), mock.MagicMock()]
        self.rules_mgrs = [mock.MagicMock(), mock.MagicMock()]
        self.endpoint_mgrs = [mock.MagicMock(), mock.MagicMock()]
        self.iptables_updaters = [mock.MagicMock(), mock.MagicMock()]
        self.masq_manager = mock.Mock(spec=MasqueradeManager)

    def get_splitter(self):
        return UpdateSplitter(
            self.ipsets_mgrs +
            self.rules_mgrs +
            self.endpoint_mgrs +
            self.iptables_updaters +
            [self.masq_manager]
        )

    def test_on_datamodel_in_sync(self):
        s = self.get_splitter()
        s.on_datamodel_in_sync()
        for mgr in self.ipsets_mgrs + self.rules_mgrs + self.endpoint_mgrs:
            self.assertEqual(mgr.on_datamodel_in_sync.mock_calls,
                             [mock.call(async=True)])

    def test_rule_updates_propagate(self):
        """
        Test that the on_rules_update message propagates correctly.
        """
        s = self.get_splitter()
        profile = 'profileA'
        rules = ['first rule', 'second rule']

        # Apply the rules update
        s.on_rules_update(profile, rules)

        # Confirm that the rules update propagates.
        for mgr in self.rules_mgrs:
            mgr.on_rules_update.assert_called_once_with(
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
        s.on_tags_update(profile, tags)

        # Confirm that the rules update propagates.
        for mgr in self.ipsets_mgrs:
            mgr.on_tags_update.assert_called_once_with(
                profile, tags, async=True
            )

    def test_interface_updates_propagate(self):
        """
        Test that the on_interface_update message propagates correctly.
        """
        s = self.get_splitter()
        interface = 'tapABCDEF'

        # Apply the interface update
        s.on_interface_update(interface, iface_up=True)

        # Confirm that the interface update propagates.
        for mgr in self.endpoint_mgrs:
            mgr.on_interface_update.assert_called_once_with(interface,
                                                            True,
                                                            async=True)

    def test_endpoint_updates_propagate(self):
        """
        Test that the on_endpoint_update message propagates correctly.
        """
        s = self.get_splitter()
        endpoint = 'endpointA'
        endpoint_object = 'endpoint'

        # Apply the endpoint update
        s.on_endpoint_update(endpoint, endpoint_object)

        # Confirm that the endpoint update propagates.
        for mgr in self.ipsets_mgrs:
            mgr.on_endpoint_update.assert_called_once_with(
                endpoint, endpoint_object, async=True
            )
        for mgr in self.endpoint_mgrs:
            mgr.on_endpoint_update.assert_called_once_with(
                endpoint, endpoint_object, async=True
            )

    def test_on_ipam_pool_updated(self):
        """
        Test that the on_ipam_pool_update message propagates correctly
        """
        s = self.get_splitter()
        pool_id = "foo"
        pool = {"cidr": "10/16", "masquerade": False}

        # Apply the IPAM pool update
        s.on_ipam_pool_update(pool_id, pool)

        # Confirm that the pool update propagates
        self.masq_manager.on_ipam_pool_updated.assert_called_once_with(
            pool_id, pool, async=True
        )


class TestCleanupManager(BaseTestCase):
    def setUp(self):
        super(TestCleanupManager, self).setUp()

        self.config = load_config("felix_default.cfg",
                                  host_dict={"StartupCleanupDelay": 12})

        # We need to check the order between the iptables and ipsets cleanup
        # calls so make sure they have a common root mock.
        self.m_root_mock = mock.Mock()
        self.m_ipt_updr = self.m_root_mock.m_ipt_updr
        self.m_ips_mgr = self.m_root_mock.m_ips_mgr

        self.mgr = CleanupManager(self.config,
                                  [self.m_ipt_updr],
                                  [self.m_ips_mgr])

    def test_on_datamodel_in_sync(self):
        with mock.patch("gevent.spawn_later", autospec=True) as m_spawn_later:
            self.mgr.on_datamodel_in_sync(async=True)
            self.step_actor(self.mgr)
        self.assertTrue(self.mgr._cleanup_done)
        # Check we got only the expected call to spawn.
        self.assertEqual(m_spawn_later.mock_calls, [mock.call(12, mock.ANY)])
        # Grab the callable.
        do_cleanup = m_spawn_later.call_args[0][1]
        self.assertTrue(callable(do_cleanup))
        # Check it really invokes the cleanup.
        do_cleanup()
        self.step_actor(self.mgr)
        self.assertEqual(
            self.m_root_mock.mock_calls,
            [
                # iptables call should come first.
                mock.call.m_ipt_updr.cleanup(async=False),
                mock.call.m_ips_mgr.cleanup(async=False),
            ]
        )
        # Finally, check that subsequent in-sync calls are ignored.
        with mock.patch("gevent.spawn_later", autospec=True) as m_spawn_later:
            self.mgr.on_datamodel_in_sync(async=True)
            self.step_actor(self.mgr)
        self.assertEqual(m_spawn_later.mock_calls, [])

    def test_cleanup_failure(self):
        self.m_ips_mgr.cleanup.side_effect = RuntimeError
        with mock.patch("os._exit") as m_exit:
            result = self.mgr._do_cleanup(async=True)
            self.step_actor(self.mgr)
        self.assertEqual(m_exit.mock_calls, [mock.call(1)])
        self.assertRaises(RuntimeError, result.get)
