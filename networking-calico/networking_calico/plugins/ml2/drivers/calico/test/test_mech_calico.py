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
Tests for CalicoMechanismDriver initialization and voting behavior.

These tests validate:
  - Only ``_post_fork_init(voting=True)`` creates an Elector.
  - ``_post_fork_init(voting=False)`` never creates an Elector.
  - ``post_fork_initialize`` (the AFTER_INIT callback) dispatches correctly:
    API workers (``neutron.wsgi.WorkerService``) get ``voting=False`` so they
    never become master (per PR #11580); ``CalicoStartupResyncWorker`` runs
    only the one-shot resync; any other worker (RPC etc.) gets
    ``voting=True``.
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
        lib.m_oslo_config.cfg.CONF.calico.project_name_cache_max = 0

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

    def _disable_background_threads(self, driver):
        """Disable background threads that would touch etcd or do unrelated things."""
        driver._do_startup_resync = mock.Mock()
        driver._status_updating_thread = mock.Mock()

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

    @mock.patch.object(mech_calico, "_trigger_class")
    @mock.patch.object(mech_calico, "Elector")
    def test_api_worker_does_not_become_voter(self, m_elector, m_trigger_class):
        """API forks are triggered by ``neutron.wsgi.WorkerService`` at
        AFTER_INIT.  ``post_fork_initialize`` must dispatch them to
        ``_post_fork_init(voting=False)`` so they never join the master
        election -- preserving PR #11580's intent after the periodic-resync
        rework moved init out of the old ``@requires_state`` decorator."""
        driver = mech_calico.CalicoMechanismDriver()
        self._disable_background_threads(driver)
        driver._my_pid = None

        m_trigger_class.return_value = mech_calico.wsgi.WorkerService
        driver.post_fork_initialize(mock.Mock(), mock.Mock(), mock.Mock())

        m_elector.assert_not_called()
        self.assertIsNone(driver.elector)

    @mock.patch.object(mech_calico, "_trigger_class")
    @mock.patch.object(mech_calico, "Elector")
    def test_resync_worker_runs_resync_only(self, m_elector, m_trigger_class):
        """``CalicoStartupResyncWorker`` triggers run only the one-shot
        resync; they don't join the elector or set up the master-only
        background threads."""
        driver = mech_calico.CalicoMechanismDriver()
        self._disable_background_threads(driver)
        driver._my_pid = None

        m_trigger_class.return_value = mech_calico.CalicoStartupResyncWorker
        driver.post_fork_initialize(mock.Mock(), mock.Mock(), mock.Mock())

        driver._do_startup_resync.assert_called_once()
        m_elector.assert_not_called()
        self.assertIsNone(driver.elector)

    @mock.patch.object(mech_calico, "_trigger_class")
    @mock.patch.object(mech_calico, "Elector")
    def test_other_worker_becomes_voter(self, m_elector, m_trigger_class):
        """Workers that aren't API workers or the resync worker (RPC,
        state-report, etc.) get ``voting=True`` and join the master
        election."""
        driver = mech_calico.CalicoMechanismDriver()
        self._disable_background_threads(driver)
        driver._my_pid = None

        # An arbitrary non-WSGI, non-resync trigger class.
        class _RpcWorker:
            pass

        m_trigger_class.return_value = _RpcWorker
        driver.post_fork_initialize(mock.Mock(), mock.Mock(), mock.Mock())

        m_elector.assert_called_once()
        self.assertIs(driver.elector, m_elector.return_value)

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
