# -*- coding: utf-8 -*-
# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
Tests for CalicoMechanismDriver initialization and voting behavior.

These tests validate:
  - Only voting=True calls create an Elector.
  - Voting=False (API/RPC workers) never create an elector.
  - @requires_state does NOT cause a worker to become a voter.
  - Invalid election key does not cause non-voting workers to join election.
"""

import mock
import unittest

import networking_calico.plugins.ml2.drivers.calico.test.lib as lib
from networking_calico.plugins.ml2.drivers.calico import mech_calico


# Prevent eventlet.spawn_after from scheduling background threads.
_spawn_after_patch = mock.patch("eventlet.spawn_after", return_value=None)


@_spawn_after_patch
class TestMechanismDriverVoting(lib.Lib, unittest.TestCase):

    @mock.patch.object(mech_calico, "Elector")
    @mock.patch.object(mech_calico, "WorkloadEndpointSyncer")
    @mock.patch.object(mech_calico, "PolicySyncer")
    @mock.patch.object(mech_calico, "SubnetSyncer")
    @mock.patch.object(mech_calico.agent_rpc, "PluginReportStateAPI")
    @mock.patch.object(mech_calico, "KeystoneClient")
    def test_parent_creates_elector(
        self, m_keystone, m_rpc, m_subnet, m_policy, m_endpoint, m_elector
    ):
        driver = mech_calico.CalicoMechanismDriver()

        driver._my_pid = None
        driver._post_fork_init(voting=True)

        m_elector.assert_called_once()
        self.assertIs(driver.elector, m_elector.return_value)

    @mock.patch.object(mech_calico, "Elector")
    @mock.patch.object(mech_calico, "WorkloadEndpointSyncer")
    @mock.patch.object(mech_calico, "PolicySyncer")
    @mock.patch.object(mech_calico, "SubnetSyncer")
    @mock.patch.object(mech_calico.agent_rpc, "PluginReportStateAPI")
    @mock.patch.object(mech_calico, "KeystoneClient")
    def test_worker_does_not_create_elector(
        self, m_keystone, m_rpc, m_subnet, m_policy, m_endpoint, m_elector
    ):
        driver = mech_calico.CalicoMechanismDriver()

        driver._my_pid = None
        driver._post_fork_init(voting=False)

        m_elector.assert_not_called()
        self.assertIsNone(driver.elector)

    @mock.patch.object(mech_calico, "Elector")
    def test_requires_state_does_not_make_worker_voter(self, m_elector):
        driver = mech_calico.CalicoMechanismDriver()

        driver._my_pid = None
        fake_ctx = mock.Mock()

        # No-op DB initialization
        with mock.patch.object(driver, "_get_db", return_value=None):
            driver.bind_port(fake_ctx)

        m_elector.assert_not_called()
        self.assertIsNone(driver.elector)

    @mock.patch.object(mech_calico.etcdv3, "get")
    @mock.patch.object(mech_calico, "Elector")
    @mock.patch.object(mech_calico, "WorkloadEndpointSyncer")
    @mock.patch.object(mech_calico, "PolicySyncer")
    @mock.patch.object(mech_calico, "SubnetSyncer")
    @mock.patch.object(mech_calico.agent_rpc, "PluginReportStateAPI")
    @mock.patch.object(mech_calico, "KeystoneClient")
    def test_worker_ignores_invalid_election_key(
        self,
        m_keystone, m_rpc, m_subnet, m_policy, m_endpoint,
        m_elector, m_etcd_get
    ):
        driver = mech_calico.CalicoMechanismDriver()

        m_etcd_get.side_effect = Exception("invalid election data")

        driver._my_pid = None
        driver._post_fork_init(voting=False)

        m_elector.assert_not_called()
        self.assertIsNone(driver.elector)

    @mock.patch.object(mech_calico, "Elector")
    def test_worker_init_does_not_override_parent_elector(self, m_elector):
        driver = mech_calico.CalicoMechanismDriver()

        driver._my_pid = None
        driver._post_fork_init(voting=True)
        parent_elector = m_elector.return_value

        # Worker init must not replace elector
        with mock.patch.object(driver, "_get_db", return_value=None):
            driver._my_pid = 99999
            driver._post_fork_init(voting=False)

        self.assertIs(driver.elector, parent_elector)
        m_elector.assert_called_once()
