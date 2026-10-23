# -*- coding: utf-8 -*-
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
networking_calico.plugins.ml2.drivers.calico.test.test_monitor_thread

Unit tests for the periodic resync thread and the thread that monitors it.
"""
from datetime import datetime, timedelta
import mock
import unittest

import networking_calico.plugins.ml2.drivers.calico.test.lib as lib
from networking_calico.plugins.ml2.drivers.calico import mech_calico


INITIAL_EPOCH = 0
TEST_MAX_INTERVAL = 30


class TestResyncMonitorThread(lib.Lib, unittest.TestCase):
    """Tests for the driver's resync monitor thread logic."""

    def setUp(self):
        super(TestResyncMonitorThread, self).setUp()

        # thread logic mocks
        self.driver.elector = mock.Mock()
        self.sleep_patcher = mock.patch("eventlet.sleep")
        self.mock_sleep = self.sleep_patcher.start()

        # log mocks
        self.log_error = mock.patch.object(mech_calico.LOG, "error").start()
        self.log_info = mock.patch.object(mech_calico.LOG, "info").start()
        self.log_debug = mock.patch.object(mech_calico.LOG, "debug").start()

        # resync mocks
        scope_patcher = mock.patch.object(mech_calico.resync, "Scope")
        self.m_scope = scope_patcher.start()
        self.addCleanup(scope_patcher.stop)
        self.m_scope.return_value.run.return_value = mock.Mock(ok=True)

    def tearDown(self):
        self.sleep_patcher.stop()
        super(TestResyncMonitorThread, self).tearDown()

    def simulate_epoch_progression(self, expected_sleep_time=None):
        def increment_epoch(actual_sleep_time):
            if expected_sleep_time is not None:
                assert expected_sleep_time == actual_sleep_time
            self.driver._epoch += 1

        return increment_epoch

    def test_monitor_does_nothing_when_not_master(self):
        """Test that a driver that is not master does not monitor."""
        self.driver.elector.master.return_value = False
        self.mock_sleep.side_effect = self.simulate_epoch_progression()

        self.driver.resync_monitor_thread(INITIAL_EPOCH)

        self.log_debug.assert_called_once_with("I am not master")
        self.log_error.assert_not_called()

    def test_monitor_logs_error_when_over_max(self):
        """Test that an error is logged when interval surpasses maximum."""
        lib.m_oslo_config.cfg.CONF.calico.resync_max_interval_secs = TEST_MAX_INTERVAL
        self.driver.elector.master.return_value = True
        fake_resync_time = datetime.now() - timedelta(seconds=TEST_MAX_INTERVAL + 1)
        self.driver.last_resync_time = fake_resync_time
        self.mock_sleep.side_effect = self.simulate_epoch_progression()

        self.driver.resync_monitor_thread(INITIAL_EPOCH)

        self.log_error.assert_called_once()
        self.assertIn(
            "The time since the last resync completion has surpassed",
            self.log_error.call_args[0][0],
        )

    def test_monitor_no_error_if_interval_under_max(self):
        """If interval is below max, no error should be logged."""
        lib.m_oslo_config.cfg.CONF.calico.resync_max_interval_secs = TEST_MAX_INTERVAL
        self.driver.elector.master.return_value = True
        self.mock_sleep.side_effect = self.simulate_epoch_progression()

        self.driver.resync_monitor_thread(INITIAL_EPOCH)

        self.log_error.assert_not_called()

    def test_monitor_exception_stops_elector(self):
        """On unexpected exception, elector.stop() must be called."""
        self.driver.elector.master.return_value = True

        with mock.patch.object(self.driver, "elector") as mock_elector:
            mock_elector.master.side_effect = Exception("Test exception")

            with self.assertRaises(Exception):
                self.driver.resync_monitor_thread(INITIAL_EPOCH)

            mock_elector.stop.assert_called_once()

    def test_resync_resets_time(self):
        """Test that resync resets current interval duration to below max."""
        lib.m_oslo_config.cfg.CONF.calico.resync_max_interval_secs = TEST_MAX_INTERVAL
        self.driver.elector.master.return_value = True
        fake_resync_time = datetime.now() - timedelta(seconds=TEST_MAX_INTERVAL + 1)
        self.driver.last_resync_time = fake_resync_time

        self.mock_sleep.side_effect = self.simulate_epoch_progression()
        self.driver.resync_monitor_thread(INITIAL_EPOCH)

        self.log_error.assert_called_once()
        self.assertIn(
            "The time since the last resync completion has surpassed",
            self.log_error.call_args[0][0],
        )

        # Resync
        self.mock_sleep.side_effect = self.simulate_epoch_progression()
        self.driver.periodic_resync_thread(INITIAL_EPOCH + 1)

        self.mock_sleep.side_effect = self.simulate_epoch_progression()
        self.driver.resync_monitor_thread(INITIAL_EPOCH + 2)

        self.log_error.assert_called_once()

    def test_errors_continue_to_log(self):
        """Test that errors continue logging if resync does not occur."""
        lib.m_oslo_config.cfg.CONF.calico.resync_max_interval_secs = TEST_MAX_INTERVAL
        self.driver.elector.master.return_value = True
        fake_resync_time = datetime.now() - timedelta(seconds=TEST_MAX_INTERVAL + 1)
        self.driver.last_resync_time = fake_resync_time

        self.mock_sleep.side_effect = self.simulate_epoch_progression()
        self.driver.resync_monitor_thread(INITIAL_EPOCH)

        self.log_error.assert_called_once()
        self.assertIn(
            "The time since the last resync completion has surpassed",
            self.log_error.call_args[0][0],
        )

        self.mock_sleep.side_effect = self.simulate_epoch_progression()
        self.driver.resync_monitor_thread(INITIAL_EPOCH + 1)

        self.assertEqual(self.log_error.call_count, 2)
        self.assertIn(
            "The time since the last resync completion has surpassed",
            self.log_error.call_args[0][0],
        )

    @mock.patch("networking_calico.plugins.ml2.drivers.calico.mech_calico.datetime")
    def test_sleep_time_logic_before_deadline(self, mock_datetime):
        """Test that we sleep until deadline if there is time left."""
        lib.m_oslo_config.cfg.CONF.calico.resync_max_interval_secs = TEST_MAX_INTERVAL
        self.driver.elector.master.return_value = True

        curr_time = datetime.now()
        self.driver.last_resync_time = curr_time
        expected_sleep_time = TEST_MAX_INTERVAL
        mock_datetime.now.return_value = curr_time

        self.mock_sleep.side_effect = self.simulate_epoch_progression(
            expected_sleep_time
        )
        self.driver.resync_monitor_thread(INITIAL_EPOCH)

    def test_sleep_time_logic_after_deadline(self):
        """Test that we poll if the deadline has passed."""
        lib.m_oslo_config.cfg.CONF.calico.resync_max_interval_secs = TEST_MAX_INTERVAL
        self.driver.elector.master.return_value = True

        fake_resync_time = datetime.now() - timedelta(seconds=TEST_MAX_INTERVAL + 1)
        self.driver.last_resync_time = fake_resync_time
        expected_sleep_time = TEST_MAX_INTERVAL / 5

        self.mock_sleep.side_effect = self.simulate_epoch_progression(
            expected_sleep_time
        )
        self.driver.resync_monitor_thread(INITIAL_EPOCH)


class TestPeriodicResyncThread(lib.Lib, unittest.TestCase):
    """Tests for the driver's periodic resync thread logic."""

    def setUp(self):
        super(TestPeriodicResyncThread, self).setUp()

        self.driver.elector = mock.Mock()
        self.sleep_patcher = mock.patch("eventlet.sleep")
        self.mock_sleep = self.sleep_patcher.start()

        scope_patcher = mock.patch.object(mech_calico.resync, "Scope")
        self.m_scope = scope_patcher.start()
        self.addCleanup(scope_patcher.stop)
        self.m_scope.return_value.run.return_value = mock.Mock(ok=True)

        self.log_error = mock.patch.object(mech_calico.LOG, "error").start()

        lib.m_oslo_config.cfg.CONF.calico.resync_interval_secs = 60

    def tearDown(self):
        # Before the base class restores the real eventlet.sleep; a cleanup would run
        # after it and so put the base class's simulated sleep back.
        self.sleep_patcher.stop()
        super(TestPeriodicResyncThread, self).tearDown()

    def stop_after_one_sleep(self, actual_sleep_time):
        self.driver._epoch += 1

    def test_master_resyncs_then_sleeps_for_interval(self):
        self.driver.elector.master.return_value = True
        self.mock_sleep.side_effect = self.stop_after_one_sleep

        self.driver.periodic_resync_thread(INITIAL_EPOCH)

        self.m_scope.assert_called_once_with(self.driver.db, driver=self.driver)
        self.m_scope.return_value.run.assert_called_once_with()
        self.mock_sleep.assert_called_once_with(60)

    def test_non_master_does_not_resync(self):
        self.driver.elector.master.return_value = False
        self.mock_sleep.side_effect = self.stop_after_one_sleep

        self.driver.periodic_resync_thread(INITIAL_EPOCH)

        self.m_scope.assert_not_called()
        self.mock_sleep.assert_called_once_with(mech_calico.MASTER_CHECK_INTERVAL_SECS)

    def test_zero_interval_resyncs_once(self):
        """With resync_interval_secs = 0 there is only the initial resync."""
        lib.m_oslo_config.cfg.CONF.calico.resync_interval_secs = 0
        self.driver.elector.master.return_value = True

        self.driver.periodic_resync_thread(INITIAL_EPOCH)

        self.m_scope.return_value.run.assert_called_once_with()
        self.mock_sleep.assert_not_called()

    def test_successful_resync_records_completion_time(self):
        self.driver.elector.master.return_value = True
        self.mock_sleep.side_effect = self.stop_after_one_sleep
        old_time = datetime.now() - timedelta(hours=1)
        self.driver.last_resync_time = old_time

        self.driver.periodic_resync_thread(INITIAL_EPOCH)

        self.assertGreater(self.driver.last_resync_time, old_time)
        self.log_error.assert_not_called()

    def test_failed_resync_logs_and_keeps_going(self):
        """A failed pass is logged, doesn't count as a completion for the resync
        monitor, and doesn't stop the periodic resync."""
        self.driver.elector.master.return_value = True
        self.m_scope.return_value.run.return_value = mock.Mock(ok=False)
        self.mock_sleep.side_effect = self.stop_after_one_sleep
        old_time = datetime.now() - timedelta(hours=1)
        self.driver.last_resync_time = old_time

        self.driver.periodic_resync_thread(INITIAL_EPOCH)

        self.assertEqual(old_time, self.driver.last_resync_time)
        self.log_error.assert_called_once()
        self.mock_sleep.assert_called_once_with(60)
