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

from etcd3gw import exceptions as e3e
import eventlet
import logging
import mock
import unittest

from networking_calico.compat import log
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
        self.print_exc_patch = mock.patch("traceback.print_exception",
                                          autospec=True)
        self.print_exc_patch.start()
        # Mock calls to sys.exit.
        self.sys_exit_p = mock.patch("sys.exit")
        self.sys_exit_p.start()

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
            elector = election.Elector("test_basic", "/bloop",
                                       interval=-1, ttl=15)
            self.assertFalse(elector.master())
            self._wait_and_stop(etcdv3._client, elector)

        with self.assertRaises(ValueError):
            etcdv3._client = stub_etcd.Client()
            elector = election.Elector("test_basic", "/bloop",
                                       interval=10, ttl=5)
            self.assertFalse(elector.master())
            self._wait_and_stop(etcdv3._client, elector)

    def _wait_and_stop(self, client, elector):
        # Wait for the client to tell us that all the results have been
        # processed.
        try:
            eventlet.with_timeout(5, client.no_more_results.wait)
        except eventlet.Timeout:
            elector._greenlet.kill(
                AssertionError("Didn't reach end of results")
            )
            elector._greenlet.wait()
            raise
        # This should shut down the Elector.
        eventlet.with_timeout(5, elector.stop)
        # The greenlet should be dead already, but just in case, let our
        # client proceed to raise its exception.
        client.stop.send()
        # Double-check there were no failures.
        self.assertIsNone(client.failure, msg=client.failure)

    def test_basic_election(self):
        # Test that not elected using defaults.
        LOG.debug("test_basic_election")
        etcdv3._client = client = stub_etcd.Client()
        client.add_read_result(key="/bloop", value="value")
        elector = election.Elector("test_basic", "/bloop",
                                   interval=5, ttl=15)
        self._wait_and_stop(client, elector)
        self.assertFalse(elector.master())

    def test_become_master_first_time(self):
        # Become the master after one round
        LOG.debug("test_become_master_first_time")
        etcdv3._client = client = stub_etcd.Client()
        client.add_read_exception(etcdv3.KeyNotFound())
        client.add_write_exception(None)
        client.add_write_exception(None)
        client.add_write_exception(None)
        elector = election.Elector("test_basic",
                                   "/bloop",
                                   old_key="/legacy",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)
        client.assert_key_written("/legacy")

    def test_fail_to_maintain(self):
        # Become the master after one round
        LOG.debug("test_become_master_first_time")
        etcdv3._client = client = stub_etcd.Client()
        client.add_read_exception(etcdv3.KeyNotFound())
        client.add_write_exception(None)
        client.add_write_exception(e3e.ConnectionFailedError())
        elector = election.Elector("test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
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
            elector = election.Elector("test_basic", "/bloop",
                                       interval=5, ttl=15)
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
        elector = election.Elector("test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)

    def test_initial_read_exceptions(self):
        LOG.debug("test_initial_read_exceptions")

        etcdv3._client = client = stub_etcd.Client()
        client.add_read_exception(e3e.Etcd3Exception(
            detail_text="Unauthorised user")
        )
        client.add_read_exception(e3e.InternalServerError())
        client.add_read_exception(e3e.ConnectionFailedError())
        client.add_read_exception(e3e.PreconditionFailedError())
        elector = election.Elector("test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)

    def test_exception_detail_logging(self):
        LOG.debug("test_exception_detail_logging")

        with mock.patch.object(election.LOG, 'warning') as mock_lw:
            etcdv3._client = client = stub_etcd.Client()
            exc = e3e.Etcd3Exception(detail_text="Unauthorised user")
            client.add_read_exception(exc)
            elector = election.Elector("test_basic",
                                       "/bloop",
                                       interval=5,
                                       ttl=15)
            self._wait_and_stop(client, elector)

            # Check that Etcd3Exception detail was logged.
            mock_lw.assert_called_with(
                'Failed to %s - key %s: %r:\n%s',
                'read current master',
                '/bloop',
                exc,
                'Unauthorised user'
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
        elector = election.Elector("test_basic", "/bloop",
                                   interval=5, ttl=15)
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
        elector = election.Elector("test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)

        # We are no longer the master, after being told to stop.
        self.assertFalse(elector.master())

    @mock.patch("os.path.exists")
    def test_check_master_process_died(self, m_exists):
        m_exists.return_value = False
        etcdv3._client = client = mock.Mock()
        elector = election.Elector("server-id", "/bloop",
                                   interval=5, ttl=15)
        # etcd3 transaction returns False because the key is no longer there.
        client.transaction.return_value = {}
        self.assertRaises(election.RestartElection,
                          elector._check_master_process, "server-id:1234")
        self.assertEqual(
            [
                mock.call({
                    'compare': [{
                        'value': 'c2VydmVyLWlkOjEyMzQ=',
                        'result': 'EQUAL',
                        'key': 'L2Jsb29w',
                        'target': 'VALUE'}],
                    'success': [{
                        'request_delete_range': {'key': 'L2Jsb29w'}}],
                    'failure': []
                })
            ],
            client.transaction.mock_calls
        )
        client.failure = None
        self._wait_and_stop(client, elector)

    @mock.patch("os.path.exists")
    def test_check_master_process_other_server(self, m_exists):
        m_exists.return_value = False
        etcdv3._client = client = mock.Mock()
        elector = election.Elector("server-id", "/bloop",
                                   interval=5, ttl=15)
        elector._check_master_process("other-server:1234")
        self.assertEqual([], client.delete.mock_calls)
        self.assertEqual([], client.transaction.mock_calls)
        client.failure = None
        self._wait_and_stop(client, elector)

    @mock.patch("os.path.exists")
    def test_check_master_process_still_alive(self, m_exists):
        m_exists.return_value = True
        etcdv3._client = client = mock.Mock()
        elector = election.Elector("server-id", "/bloop",
                                   interval=5, ttl=15)
        elector._check_master_process("server-id:1234")
        self.assertEqual([], client.delete.mock_calls)
        self.assertEqual([], client.transaction.mock_calls)
        client.failure = None
        self._wait_and_stop(client, elector)
