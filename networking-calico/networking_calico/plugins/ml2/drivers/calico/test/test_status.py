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
Targeted unit tests for StatusWatcher helpers that do not need the full
plugin-etcd test harness.  See test_plugin_etcd.py for end-to-end watcher
tests.
"""
from datetime import datetime, timedelta, timezone
import unittest

import mock

from networking_calico.plugins.ml2.drivers.calico import status


class TestCheckForStaleStatus(unittest.TestCase):
    """Exercise StatusWatcher._check_for_stale_status in isolation.

    The real __init__ pulls in config and an EtcdWatcher; we skip it via
    __new__ and set only the attributes the method reads.
    """

    def setUp(self):
        super(TestCheckForStaleStatus, self).setUp()
        self.watcher = status.StatusWatcher.__new__(status.StatusWatcher)
        self.watcher._last_stale_warn = 0.0
        self.watcher.processing_snapshot = False

    def _fmt(self, dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_fresh_update_does_not_warn(self):
        fresh = self._fmt(datetime.now(tz=timezone.utc))
        with mock.patch.object(status.LOG, "warning") as m_warn:
            self.watcher._check_for_stale_status("host1", {"time": fresh})
        m_warn.assert_not_called()
        self.assertEqual(0.0, self.watcher._last_stale_warn)

    def test_stale_update_warns(self):
        stale = self._fmt(datetime.now(tz=timezone.utc) - timedelta(hours=1))
        with mock.patch.object(status.LOG, "warning") as m_warn:
            self.watcher._check_for_stale_status("host1", {"time": stale})
        m_warn.assert_called_once()
        # First positional arg of the single call is the log format string.
        self.assertIn("stale Felix status update", m_warn.call_args.args[0])
        self.assertGreater(self.watcher._last_stale_warn, 0.0)

    def test_stale_update_is_rate_limited(self):
        stale = self._fmt(datetime.now(tz=timezone.utc) - timedelta(hours=1))
        with mock.patch.object(status.LOG, "warning") as m_warn:
            self.watcher._check_for_stale_status("host1", {"time": stale})
            self.watcher._check_for_stale_status("host2", {"time": stale})
            self.watcher._check_for_stale_status("host3", {"time": stale})
        # Only one warning across several stale updates within the
        # rate-limit window.
        self.assertEqual(1, m_warn.call_count)

    def test_snapshot_processing_skips_check(self):
        self.watcher.processing_snapshot = True
        stale = self._fmt(datetime.now(tz=timezone.utc) - timedelta(hours=1))
        with mock.patch.object(status.LOG, "warning") as m_warn:
            self.watcher._check_for_stale_status("host1", {"time": stale})
        m_warn.assert_not_called()

    def test_missing_time_field_is_silent(self):
        with mock.patch.object(status.LOG, "warning") as m_warn:
            self.watcher._check_for_stale_status(
                "host1", {"uptime": 10, "first_update": False}
            )
        m_warn.assert_not_called()

    def test_stale_naive_timestamp_warns(self):
        """A timezone-less timestamp (no trailing Z) should not crash."""
        stale = (datetime.now(tz=timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        with mock.patch.object(status.LOG, "warning") as m_warn:
            self.watcher._check_for_stale_status("host1", {"time": stale})
        m_warn.assert_called_once()
        self.assertIn("stale Felix status update", m_warn.call_args.args[0])

    def test_unparseable_time_logs_separate_warning(self):
        with mock.patch.object(status.LOG, "warning") as m_warn:
            self.watcher._check_for_stale_status("host1", {"time": "not a date"})
        m_warn.assert_called_once()
        self.assertIn("Could not parse status time", m_warn.call_args.args[0])
        # An unparseable time does not count as a stale-status warning for
        # rate-limiting purposes.
        self.assertEqual(0.0, self.watcher._last_stale_warn)
