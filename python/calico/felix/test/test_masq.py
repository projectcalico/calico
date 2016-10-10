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
felix.test.test_masq
~~~~~~~~~~~~~~~~~~~~

Unit tests for the MasqueradeManager.
"""
import logging
from mock import *
from calico.felix.fiptables import IptablesUpdater
from calico.felix.masq import *

# Logger
from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


class TestMasqueradeManager(BaseTestCase):
    def setUp(self):
        super(TestMasqueradeManager, self).setUp()
        self.m_iptables_mgr = Mock(spec=IptablesUpdater)
        self.m_iptables_mgr.table = "nat"
        with patch("calico.felix.masq.Ipset", autospec=True) as m_Ipset:
            self.masq_mgr = MasqueradeManager(IPV4, self.m_iptables_mgr)
            _log.info("Ipset calls: %s", m_Ipset.mock_calls)
            m_Ipset.assert_has_calls([
                call("felix-all-ipam-pools", "felix-all-ipam-pools-tmp",
                     "inet", "hash:net"),
                call("felix-masq-ipam-pools", "felix-masq-ipam-pools-tmp",
                     "inet", "hash:net"),
            ])
        self.m_all_pools = Mock(spec=Ipset)
        self.m_masq_pools = Mock(spec=Ipset)
        self.masq_mgr._all_pools_ipset = self.m_all_pools
        self.masq_mgr._masq_pools_ipset = self.m_masq_pools

    def test_apply_snapshot_empty(self):
        self.m_all_pools.exists.return_value = True
        self.m_masq_pools.exists.return_value = True
        self.masq_mgr.apply_snapshot({}, async=True)
        self.step_actor(self.masq_mgr)
        self.m_iptables_mgr.ensure_rule_removed.assert_called_once_with(
            "POSTROUTING "
            "--match set --match-set felix-masq-ipam-pools src "
            "--match set ! --match-set felix-all-ipam-pools dst "
            "--jump MASQUERADE",
            async=False
        )
        self.m_all_pools.delete.assert_called_once_with()
        self.m_masq_pools.delete.assert_called_once_with()

    def test_apply_snapshot_no_masq_pools(self):
        self.m_all_pools.exists.return_value = True
        self.m_masq_pools.exists.return_value = False
        self.masq_mgr.apply_snapshot({"foo": {"cidr": "10.0.0.0/16"}},
                                     async=True)
        self.step_actor(self.masq_mgr)
        self.m_iptables_mgr.ensure_rule_removed.assert_called_once_with(
            "POSTROUTING "
            "--match set --match-set felix-masq-ipam-pools src "
            "--match set ! --match-set felix-all-ipam-pools dst "
            "--jump MASQUERADE",
            async=False
        )
        self.m_all_pools.delete.assert_called_once_with()
        self.m_masq_pools.delete.assert_called_once_with()

    def test_apply_snapshot_with_masq_pools(self):
        self.masq_mgr.apply_snapshot({"foo": {"cidr": "10.0.0.0/16",
                                              "masquerade": True},
                                      "bar": {"cidr": "10.1.0.0/16",
                                              "masquerade": False}},
                                     async=True)
        self.step_actor(self.masq_mgr)
        self.m_iptables_mgr.ensure_rule_inserted.assert_called_once_with(
            "POSTROUTING "
            "--match set --match-set felix-masq-ipam-pools src "
            "--match set ! --match-set felix-all-ipam-pools dst "
            "--jump MASQUERADE",
            async=True
        )
        self.assertFalse(self.m_iptables_mgr.ensure_rule_removed.called)
        self.m_all_pools.replace_members.assert_called_once_with(set([
            "10.0.0.0/16",
            "10.1.0.0/16",
        ]))
        self.m_masq_pools.replace_members.assert_called_once_with(set([
            "10.0.0.0/16",
        ]))

    def test_update(self):
        self.masq_mgr.apply_snapshot({"foo": {"cidr": "10.0.0.0/16",
                                              "masquerade": True},
                                      "bar": {"cidr": "10.1.0.0/16",
                                              "masquerade": False}},
                                     async=True)
        # Delete
        self.masq_mgr.on_ipam_pool_updated("foo", None, async=True)
        # Update
        self.masq_mgr.on_ipam_pool_updated("bar", {"cidr": "10.1.0.0/16",
                                                   "masquerade": True},
                                           async=True)
        # New
        self.masq_mgr.on_ipam_pool_updated("baz", {"cidr": "10.2.0.0/16",
                                                   "masquerade": False},
                                           async=True)
        self.step_actor(self.masq_mgr)
        self.m_all_pools.replace_members.assert_called_once_with(set([
            "10.1.0.0/16",
            "10.2.0.0/16",
        ]))
        self.m_masq_pools.replace_members.assert_called_once_with(set([
            "10.1.0.0/16",
        ]))
