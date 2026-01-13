# -*- coding: utf-8 -*-
# Copyright (c) 2025 Tigera, Inc.
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
  - Only voting=True creates an Elector.
  - Voting=False never creates an Elector.
  - @requires_state does NOT cause a worker to become a voter.
  - A worker initialization does not override the parent elector.
"""

import unittest
import mock

import networking_calico.plugins.ml2.drivers.calico.test.lib as lib
from networking_calico.plugins.ml2.drivers.calico import mech_calico
from networking_calico import etcdv3


class TestMechanismDriverVoting(lib.Lib, unittest.TestCase):

    def setUp(self):
        super(TestMechanismDriverVoting, self).setUp()

        lib.m_oslo_config.cfg.CONF.keystone_authtoken.auth_url = ""
        lib.m_oslo_config.cfg.CONF.calico.openstack_region = "no-region"
        lib.m_oslo_config.cfg.CONF.calico.etcd_compaction_period_mins = 0
        lib.m_oslo_config.cfg.CONF.calico.resync_interval_secs = 0
        lib.m_oslo_config.cfg.CONF.calico.project_name_cache_max = 0

        # Mock etcd3gw client so background threads don't touch real etcd.
        etcdv3._client = self.clientv3 = mock.Mock()

        self.clientv3.status.return_value = {
            "header": {"revision": "123", "cluster_id": "cluster-id"},
        }
        self.clientv3.get_prefix.return_value = []
        self.clientv3.watch_prefix.return_value = (iter(()), mock.Mock())

        # Reset the driver
        mech_calico.mech_driver = None

    def tearDown(self):
        # Reset global etcd client.
        etcdv3._client = None
        mech_calico.mech_driver = None

        super(TestMechanismDriverVoting, self).tearDown()

    def _disable_background_threads(self, driver):
        """Disable background threads that would touch etcd or do unrelated things."""
        driver.periodic_resync_thread = mock.Mock()
        driver._status_updating_thread = mock.Mock()
        driver.resync_monitor_thread = mock.Mock()

    @mock.patch.object(mech_calico, "Elector")
    def test_parent_creates_elector(self, m_elector):
        driver = mech_calico.CalicoMechanismDriver()
        self._disable_background_threads(driver)

        driver._my_pid = None
        driver._post_fork_init(voting=True)

        m_elector.assert_called_once()
        self.assertIs(driver.elector, m_elector.return_value)

    @mock.patch.object(mech_calico, "Elector")
    def test_worker_does_not_create_elector(self, m_elector):
        driver = mech_calico.CalicoMechanismDriver()
        self._disable_background_threads(driver)

        driver._my_pid = None
        driver._post_fork_init(voting=False)

        m_elector.assert_not_called()
        self.assertIsNone(driver.elector)

    @mock.patch.object(mech_calico, "Elector")
    def test_requires_state_does_not_make_worker_voter(self, m_elector):
        driver = mech_calico.CalicoMechanismDriver()
        self._disable_background_threads(driver)

        driver._my_pid = None

        fake_context = mock.Mock()
        fake_context.original = {}
        fake_context.current = {}
        fake_context._plugin_context = mock.Mock()

        # update_network_postcommit is decorated with @requires_state
        driver.update_network_postcommit(fake_context)

        m_elector.assert_not_called()
        self.assertIsNone(driver.elector)

    @mock.patch.object(mech_calico, "Elector")
    def test_worker_init_does_not_override_parent_elector(self, m_elector):
        driver = mech_calico.CalicoMechanismDriver()
        self._disable_background_threads(driver)

        driver._my_pid = None
        driver._post_fork_init(voting=True)
        parent_elector = driver.elector

        # Simulate a worker re-initializing in the same process object
        driver._my_pid = 99999
        driver._post_fork_init(voting=False)

        self.assertIs(driver.elector, parent_elector)
        m_elector.assert_called_once()
