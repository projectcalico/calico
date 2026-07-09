# -*- coding: utf-8 -*-
# Copyright (c) 2025-2026 Tigera, Inc.
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
Tests for CalicoMechanismDriver initialization.
"""

import unittest
import mock

import networking_calico.plugins.ml2.drivers.calico.test.lib as lib
from networking_calico.plugins.ml2.drivers.calico import mech_calico
from networking_calico import etcdv3


class TestMechanismDriver(lib.Lib, unittest.TestCase):

    def setUp(self):
        super(TestMechanismDriver, self).setUp()

        lib.m_oslo_config.cfg.CONF.keystone_authtoken.auth_url = ""
        lib.m_oslo_config.cfg.CONF.calico.openstack_region = "no-region"
        lib.m_oslo_config.cfg.CONF.calico.etcd_compaction_period_mins = 10
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

        super(TestMechanismDriver, self).tearDown()

    def test_driver_init_common(self):
        self.driver._post_fork_init()

        self.assertIsNotNone(self.driver.db)
        self.assertIsNotNone(self.driver.subnet_syncer)
        self.assertIsNotNone(self.driver.policy_syncer)
        self.assertIsNotNone(self.driver.endpoint_syncer)

    @mock.patch("eventlet.spawn")
    def test_driver_init_calico_resource_syncer(self, m_spawn):
        m_spawn.return_value = True

        self.driver._init_start_calico_resource_syncer()

        self.assertTrue(self.driver.start_up_resync_thread)

    @mock.patch("eventlet.spawn")
    @mock.patch.object(mech_calico, "Elector")
    def test_driver_init_calico_manager(self, m_elector, m_spawn):
        m_spawn.return_value = True

        self.driver._init_start_calico_manager()

        self.assertTrue(self.driver.election_thread)
        self.assertTrue(self.driver.periodic_compaction_thread)

        m_elector.assert_called_once()

    @mock.patch("time.time")
    def test_is_master(self, m_time):
        m_time.return_value = 5

        self.driver._is_master = mock.MagicMock()
        self.driver._is_master.value = 1

        self.assertTrue(self.driver.is_master())

    @mock.patch("time.time")
    def test_is_not_master(self, m_time):
        m_time.return_value = 5

        self.driver._is_master = mock.MagicMock()
        self.driver._is_master.value = 0

        self.assertFalse(self.driver.is_master())

    @mock.patch("time.time")
    def test_is_not_master_timeout(self, m_time):
        m_time.return_value = mech_calico.MASTER_TIMEOUT + 100

        self.driver._is_master = mock.MagicMock()
        self.driver._is_master.value = 1

        self.assertFalse(self.driver.is_master())

    @mock.patch("eventlet.spawn")
    def test_driver_init_calico_agent_status_watcher(self, m_spawn):
        m_spawn.return_value = True

        self.driver._init_start_agent_status_watcher()

        self.assertTrue(self.driver.agent_status_watch_thread)

    @mock.patch("eventlet.spawn")
    def test_driver_init_calico_endpoint_status_watcher(self, m_spawn):
        m_spawn.return_value = True

        self.driver._init_start_endpoint_status_watcher()

        self.assertTrue(self.driver.endpoint_status_watch_thread)
        self.assertEqual(
            len(self.driver.port_status_update_threads),
            lib.m_oslo_config.cfg.CONF.calico.num_port_status_threads,
        )

        # We will also need to ensure that the required queues components
        # are also created.
        self.assertIsNotNone(self.driver._port_status_cache)
        self.assertIsNotNone(self.driver._port_status_queue)
        self.assertIsNotNone(self.driver._port_status_queue_too_long)
