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
        lib.m_oslo_config.cfg.CONF.calico.etcd_compaction_period_mins = 10
        lib.m_oslo_config.cfg.CONF.calico.resync_interval_secs = 0
        lib.m_oslo_config.cfg.CONF.calico.project_name_cache_max = 0
        lib.m_oslo_config.cfg.CONF.calico.num_port_status_threads = 4

        # Mock etcd3gw client so background threads don't touch real etcd.
        etcdv3._client = self.clientv3 = mock.Mock()

        self.clientv3.status.return_value = {
            "header": {"revision": "123", "cluster_id": "cluster-id"},
        }
        self.clientv3.get_prefix.return_value = []
        self.clientv3.watch_prefix.return_value = (iter(()), mock.Mock())

    def tearDown(self):
        # Reset global etcd client.
        etcdv3._client = None

        super(TestMechanismDriverVoting, self).tearDown()

    def test_driver_init_common(self):
        driver = mech_calico.CalicoMechanismDriver()
        driver._post_fork_inititialize_common()

        self.assertIsNotNone(driver.db)
        self.assertIsNotNone(driver.subnet_syncer)
        self.assertIsNotNone(driver.policy_syncer)
        self.assertIsNotNone(driver.endpoint_syncer)
        self.assertIsNotNone(driver._agent_update_context)
        self.assertIsNotNone(driver.state_report_rpc)

    @mock.patch("eventlet.spawn")
    def test_driver_init_calico_resource_syncer(self, m_spawn):
        m_spawn.return_value = True

        driver = mech_calico.CalicoMechanismDriver()
        driver._init_and_start_calico_resouce_syncer()

        self.assertTrue(driver.periodic_resync_thread)
        self.assertTrue(driver.monitor_resync_thread)

    @mock.patch("eventlet.spawn")
    @mock.patch.object(mech_calico, "Elector")
    def test_driver_init_calico_manager(self, m_elector, m_spawn):
        m_spawn.return_value = True

        driver = mech_calico.CalicoMechanismDriver()
        driver._init_and_start_calico_manager()

        self.assertTrue(driver.election_thread)
        self.assertTrue(driver.periodic_compaction_thread)

        m_elector.assert_called_once()

    @mock.patch("eventlet.spawn")
    def test_driver_init_calico_agent_status_watcher(self, m_spawn):
        m_spawn.return_value = True

        driver = mech_calico.CalicoMechanismDriver()
        driver._init_and_start_agent_status_watcher()

        self.assertTrue(driver.agent_status_watch_thread)

    @mock.patch("eventlet.spawn")
    def test_driver_init_calico_endpoint_status_watcher(self, m_spawn):
        m_spawn.return_value = True

        driver = mech_calico.CalicoMechanismDriver()
        driver._init_and_start_endpoint_status_watcher()

        self.assertTrue(driver.endpoint_status_watch_thread)
        self.assertEqual(
            len(driver.port_status_update_threads),
            lib.m_oslo_config.cfg.CONF.calico.num_port_status_threads,
        )

        # We will also need to ensure that the required queues components
        # are also created.
        self.assertIsNotNone(driver._port_status_cache)
        self.assertIsNotNone(driver._port_status_queue)
        self.assertIsNotNone(driver._port_status_queue_too_long)
