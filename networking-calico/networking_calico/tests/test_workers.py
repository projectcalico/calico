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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

"""Unit tests for ``CalicoManagerWorker.stop()``.

The shutdown path is the regression fix in
https://github.com/projectcalico/calico/pull/13069 -- ``stop()`` must ask
the elector to step down so its ``finally: _attempt_step_down()`` clause
runs and the election key is removed from etcd promptly, rather than
lingering for the lease ttl.  These tests verify all branches of that
path: elector present, elector absent, and elector raising.

Lives under ``networking_calico/tests/`` rather than
``networking_calico/plugins/ml2/drivers/calico/test/`` because the
latter's ``lib.py`` replaces ``sys.modules['neutron_lib.worker']`` with
a MagicMock at import time -- which collapses
``CalicoManagerWorker`` itself into a MagicMock and makes its real
shutdown code unreachable.  Running here keeps ``neutron_lib.worker``
real (the two test directories are run in separate subunit processes
per ``.testr.conf``).
"""

import unittest

import mock

from networking_calico.plugins.ml2.drivers.calico import workers


class TestCalicoManagerWorkerStop(unittest.TestCase):
    """Verify ``CalicoManagerWorker.stop()`` shutdown semantics."""

    def setUp(self):
        super(TestCalicoManagerWorkerStop, self).setUp()
        # Patch the parent's stop() so we can assert it gets chained to
        # without dragging in the real oslo_service shutdown plumbing.
        # create=True because BaseWorker doesn't define stop() itself --
        # it inherits the abstract method from oslo_service.ServiceBase.
        self.super_stop_p = mock.patch.object(
            workers.worker.BaseWorker, "stop", create=True
        )
        self.super_stop = self.super_stop_p.start()
        self.addCleanup(self.super_stop_p.stop)

    def _make_worker(self, driver):
        # set_proctitle='off' avoids touching the real process title in
        # the test runner.
        return workers.CalicoManagerWorker(driver=driver, set_proctitle="off")

    def test_stop_steps_down_elector_then_chains_to_super(self):
        # Happy path: driver.elector is set, so stop() must call
        # elector.stop() exactly once, then super().stop().
        driver = mock.Mock()
        driver.elector = mock.Mock()
        worker = self._make_worker(driver)

        worker.stop()

        driver.elector.stop.assert_called_once_with()
        self.super_stop.assert_called_once_with()

    def test_stop_tolerates_elector_attribute_missing(self):
        # post_fork_initialize hasn't run yet -- driver has no `elector`
        # attribute.  stop() must not raise and must still chain to
        # super().
        driver = mock.Mock(spec=[])  # empty spec => no elector attr
        worker = self._make_worker(driver)

        worker.stop()  # must not raise

        self.super_stop.assert_called_once_with()

    def test_stop_tolerates_driver_is_none(self):
        # Defensive case: _driver itself is None (worker was somehow
        # constructed without a driver back-reference).
        worker = self._make_worker(driver=None)

        worker.stop()  # must not raise

        self.super_stop.assert_called_once_with()

    def test_stop_tolerates_elector_being_none(self):
        # post_fork_initialize cleared the elector (or never set it),
        # leaving driver.elector = None.
        driver = mock.Mock()
        driver.elector = None
        worker = self._make_worker(driver)

        worker.stop()  # must not raise

        self.super_stop.assert_called_once_with()

    def test_stop_swallows_elector_stop_exception(self):
        # elector.stop() can fail (e.g. etcd unreachable during shutdown).
        # The exception must be logged but not propagate, and super().stop()
        # must still be called so the worker process exits cleanly.
        driver = mock.Mock()
        driver.elector.stop.side_effect = RuntimeError("etcd unreachable")
        worker = self._make_worker(driver)

        with mock.patch.object(workers.LOG, "exception") as mock_log_exc:
            worker.stop()  # must not raise

        mock_log_exc.assert_called_once()
        self.super_stop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
