# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
Test election code.
"""
import logging
import unittest

from etcd3gw import exceptions as e3e

import eventlet

import mock

from networking_calico import etcdv3
from networking_calico.plugins.ml2.drivers.calico import election
from networking_calico.plugins.ml2.drivers.calico.test import stub_etcd


LOG = logging.getLogger(__name__)


def eventlet_sleep(time):
    pass


class TestElection(unittest.TestCase):
    def setUp(self):
        super(TestElection, self).setUp()
        self._real_sleep = eventlet.sleep
        eventlet.sleep = eventlet_sleep
        # Stop eventlet from printing our expected NoMoreResults exception
        # to stdout directly.
        self.print_exc_patch = mock.patch("traceback.print_exception", autospec=True)
        self.print_exc_patch.start()
        # Mock calls to sys.exit.
        self.sys_exit_p = mock.patch("sys.exit")
        self.sys_exit_p.start()
        # Mock is_master variable
        self.mock_is_master = mock.MagicMock()

    def tearDown(self):
        self.sys_exit_p.stop()
        self.print_exc_patch.stop()
        eventlet.sleep = self._real_sleep
        etcdv3._client = None
        super(TestElection, self).tearDown()

    def test_invalid(self):
        # Test that not elected using defaults.
        with self.assertRaises(ValueError):
            etcdv3._client = stub_etcd.Client()
            elector = election.Elector(
                "test_basic",
                "/bloop",
                self.mock_is_master,
                interval=-1,
                ttl=15,
            )
            elector.start()
            self._wait_and_stop(etcdv3._client, elector)

        with self.assertRaises(ValueError):
            etcdv3._client = stub_etcd.Client()
            elector = election.Elector(
                "test_basic",
                "/bloop",
                self.mock_is_master,
                interval=10,
                ttl=5,
            )
            elector.start()
            self._wait_and_stop(etcdv3._client, elector)

    def _wait_and_stop(self, client, elector):
        # Wait for the client to tell us that all the results have been
        # processed.
        try:
            eventlet.with_timeout(5, client.no_more_results.wait)
        except eventlet.Timeout:
            elector._greenlet.kill(AssertionError("Didn't reach end of results"))
            elector._greenlet.wait()
            raise
        # This should shut down the Elector.
        eventlet.with_timeout(5, elector.stop)
        # The greenlet should be dead already, but just in case, let our
        # client proceed to raise its exception.
        client.stop.send()
        # Double-check there were no failures.
        self.assertIsNone(client.failure, msg=client.failure)
        # Make sure the value is set back to 0
        self.assertEqual(self.mock_is_master.value, 0)

    def test_basic_election(self):
        # Test that not elected using defaults.
        LOG.debug("test_basic_election")
        etcdv3._client = client = stub_etcd.Client()
        client.add_read_result(key="/bloop", value="value")
        elector = election.Elector(
            "test_basic",
            "/bloop",
            self.mock_is_master,
            interval=5,
            ttl=15,
        )
        elector.start()
        self._wait_and_stop(client, elector)

    def test_become_master_first_time(self):
        # Become the master after one round
        LOG.debug("test_become_master_first_time")
        etcdv3._client = client = stub_etcd.Client()
        client.add_read_exception(etcdv3.KeyNotFound())
        client.add_write_exception(None)
        client.add_write_exception(None)
        client.add_write_exception(None)
        elector = election.Elector(
            "test_basic",
            "/bloop",
            self.mock_is_master,
            old_key="/legacy",
            interval=5,
            ttl=15,
        )
        elector.start()
        self._wait_and_stop(client, elector)
        client.assert_key_written("/legacy")

    def test_fail_to_maintain(self):
        # Become the master after one round
        LOG.debug("test_become_master_first_time")
        etcdv3._client = client = stub_etcd.Client()
        client.add_read_exception(etcdv3.KeyNotFound())
        client.add_write_exception(None)
        client.add_write_exception(e3e.ConnectionFailedError())
        elector = election.Elector(
            "test_basic",
            "/bloop",
            self.mock_is_master,
            interval=5,
            ttl=15,
        )
        elector.start()
        self._wait_and_stop(client, elector)

    def test_become_master_multiple_attempts(self):
        # Become the master after one round
        LOG.debug("test_become_master_multiple_circuits")
        for action in ["delete", "expire", "compareAndDelete", "something"]:
            LOG.info("Testing etcd delete event %s", action)
            etcdv3._client = client = stub_etcd.Client()
            client.add_read_result(key="/bloop", value="value")
            client.add_read_result(key="/bloop", value="value")
            client.add_read_result(key="/bloop", value=None, action=action)
            client.add_write_exception(None)
            client.add_write_exception(None)
            elector = election.Elector(
                "test_basic",
                "/bloop",
                self.mock_is_master,
                interval=5,
                ttl=15,
            )
            elector.start()
            self._wait_and_stop(client, elector)

    def test_become_master_implausible(self):
        # Become the master after key vanishes
        LOG.debug("test_become_master_implausible")
        etcdv3._client = client = stub_etcd.Client()
        client.add_read_result(key="/bloop", value="value")
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(etcdv3.KeyNotFound())
        client.add_write_result()
        client.add_write_result()
        elector = election.Elector(
            "test_basic",
            "/bloop",
            self.mock_is_master,
            interval=5,
            ttl=15,
        )
        elector.start()
        self._wait_and_stop(client, elector)

    def test_initial_read_exceptions(self):
        LOG.debug("test_initial_read_exceptions")

        etcdv3._client = client = stub_etcd.Client()
        client.add_read_exception(e3e.Etcd3Exception(detail_text="Unauthorised user"))
        client.add_read_exception(e3e.InternalServerError())
        client.add_read_exception(e3e.ConnectionFailedError())
        client.add_read_exception(e3e.PreconditionFailedError())
        elector = election.Elector(
            "test_basic",
            "/bloop",
            self.mock_is_master,
            interval=5,
            ttl=15,
        )
        elector.start()
        self._wait_and_stop(client, elector)

    def test_exception_detail_logging(self):
        LOG.debug("test_exception_detail_logging")

        with mock.patch.object(election.LOG, "warning") as mock_lw:
            etcdv3._client = client = stub_etcd.Client()
            exc = e3e.Etcd3Exception(detail_text="Unauthorised user")
            client.add_read_exception(exc)
            elector = election.Elector(
                "test_basic",
                "/bloop",
                self.mock_is_master,
                interval=5,
                ttl=15,
            )
            elector.start()
            self._wait_and_stop(client, elector)

            # Check that Etcd3Exception detail was logged.
            mock_lw.assert_called_with(
                "Failed to %s - key %s: %r:\n%s",
                "read current master",
                "/bloop",
                exc,
                "Unauthorised user",
            )

    def test_later_exceptions(self):
        LOG.debug("test_later_read_exceptions")

        etcdv3._client = client = stub_etcd.Client()
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(e3e.Etcd3Exception())
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(e3e.InternalServerError())
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(e3e.ConnectionFailedError())
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(e3e.PreconditionFailedError())
        elector = election.Elector(
            "test_basic",
            "/bloop",
            self.mock_is_master,
            interval=5,
            ttl=15,
        )
        elector.start()
        self._wait_and_stop(client, elector)

    def test_master_failure(self):
        LOG.debug("test_master_failure")

        etcdv3._client = client = stub_etcd.Client()
        client.add_read_exception(etcdv3.KeyNotFound())
        # Now become the master but fail
        client.add_write_exception(e3e.ConnectionFailedError())
        client.add_read_result(key="/bloop", value="value")
        client.add_read_result(key="/bloop", value=None, action="delete")
        # Now become the master but fail again
        client.add_write_exception(e3e.InternalServerError())
        # Go back to the beginning again.
        client.add_read_result(key="/bloop", value="value")
        client.add_read_result(key="/bloop", value=None, action="delete")
        client.add_write_exception(None)
        client.add_write_exception(None)
        elector = election.Elector(
            "test_basic",
            "/bloop",
            self.mock_is_master,
            interval=5,
            ttl=15,
        )
        elector.start()
        self._wait_and_stop(client, elector)


class TestCheckMasterProcess(unittest.TestCase):
    """Direct tests for Elector._check_master_process.

    These tests instantiate the Elector but never start the election greenlet;
    they call _check_master_process synchronously with mocked /proc and
    etcdv3.delete.
    """

    HOST = "this-host"
    OTHER_HOST = "other-host"
    KEY = "/calico/v2/no-region/neutron_election"

    def setUp(self):
        super(TestCheckMasterProcess, self).setUp()
        self.elector = election.Elector(
            self.HOST,
            self.KEY,
            mock.MagicMock(),
            interval=5,
            ttl=15,
        )

    def test_same_host_live_pid_does_nothing(self):
        with mock.patch("os.path.exists", return_value=True) as m_exists, mock.patch(
            "networking_calico.etcdv3.delete"
        ) as m_delete:
            # No RestartElection, no delete call.
            self.elector._check_master_process("%s:12345" % self.HOST)
        m_exists.assert_called_once_with("/proc/12345")
        m_delete.assert_not_called()

    def test_same_host_dead_pid_deletes_then_returns(self):
        # On a successful CAS-delete the method returns normally (the watch
        # in _vote will then see the delete event and we will try to become
        # master through the normal path).
        with mock.patch("os.path.exists", return_value=False), mock.patch(
            "networking_calico.etcdv3.delete", return_value=True
        ) as m_delete:
            self.elector._check_master_process("%s:99999" % self.HOST)
        m_delete.assert_called_once_with(
            self.KEY, existing_value="%s:99999" % self.HOST
        )

    def test_same_host_dead_pid_cas_fail_raises(self):
        # CAS-delete returning False means somebody else has already moved
        # the election on; we restart so the next _vote sees the new state.
        with mock.patch("os.path.exists", return_value=False), mock.patch(
            "networking_calico.etcdv3.delete", return_value=False
        ):
            with self.assertRaises(election.RestartElection):
                self.elector._check_master_process("%s:99999" % self.HOST)

    def test_same_host_dead_pid_etcd_exception_raises(self):
        # etcd-side error during the cleanup delete: log and restart.
        with mock.patch("os.path.exists", return_value=False), mock.patch(
            "networking_calico.etcdv3.delete",
            side_effect=e3e.ConnectionFailedError(),
        ):
            with self.assertRaises(election.RestartElection):
                self.elector._check_master_process("%s:99999" % self.HOST)

    def test_different_host_does_nothing(self):
        # Previous master was on another node -- not our problem; defer to
        # the lease TTL for cleanup if that node has died.
        with mock.patch("os.path.exists") as m_exists, mock.patch(
            "networking_calico.etcdv3.delete"
        ) as m_delete:
            self.elector._check_master_process("%s:12345" % self.OTHER_HOST)
        m_exists.assert_not_called()
        m_delete.assert_not_called()

    def test_unparseable_value_does_nothing(self):
        # A value that doesn't match "<host>:<pid>" is left alone; warn but
        # do not attempt any cleanup.
        with mock.patch("os.path.exists") as m_exists, mock.patch(
            "networking_calico.etcdv3.delete"
        ) as m_delete, mock.patch.object(election.LOG, "warning") as m_warn:
            self.elector._check_master_process("not-a-valid-id")
        m_exists.assert_not_called()
        m_delete.assert_not_called()
        m_warn.assert_called_once()
        self.assertIn("Unable to parse master ID", m_warn.call_args.args[0])
