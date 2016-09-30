# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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


import eventlet
import logging
import mock
import sys

from networking_calico.plugins.ml2.drivers.calico import election
from networking_calico.plugins.ml2.drivers.calico.test import stub_etcd

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest


LOG = logging.getLogger(__name__)


def eventlet_sleep(time):
    pass


class TestElection(unittest.TestCase):
    def setUp(self):
        super(TestElection, self).setUp()
        self._real_etcd = election.etcd
        self._real_sleep = eventlet.sleep
        election.etcd = stub_etcd
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
        election.etcd = self._real_etcd
        eventlet.sleep = self._real_sleep
        super(TestElection, self).tearDown()

    def test_invalid(self):
        # Test that not elected using defaults.
        with self.assertRaises(ValueError):
            client = stub_etcd.Client()
            elector = election.Elector(client, "test_basic", "/bloop",
                                       interval=-1, ttl=15)
            self.assertFalse(elector.master())

        with self.assertRaises(ValueError):
            client = stub_etcd.Client()
            elector = election.Elector(client, "test_basic", "/bloop",
                                       interval=10, ttl=5)
            self.assertFalse(elector.master())

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
        self.assertEqual(None, client.failure, msg=client.failure)

    def test_basic_election(self):
        # Test that not elected using defaults.
        LOG.debug("test_basic_election")
        client = stub_etcd.Client()
        client.add_read_result(key="/bloop", value="value")
        elector = election.Elector(client, "test_basic", "/bloop",
                                   interval=5, ttl=15)
        self._wait_and_stop(client, elector)
        self.assertFalse(elector.master())

    def test_become_master_first_time(self):
        # Become the master after once round
        LOG.debug("test_become_master_first_time")
        client = stub_etcd.Client()
        client.add_read_exception(stub_etcd.EtcdKeyNotFound())
        client.add_write_exception(None)
        client.add_write_exception(None)
        elector = election.Elector(client,
                                   "test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)

    def test_fail_to_maintain(self):
        # Become the master after once round
        LOG.debug("test_become_master_first_time")
        client = stub_etcd.Client()
        client.add_read_exception(stub_etcd.EtcdKeyNotFound())
        client.add_write_exception(None)
        client.add_write_exception(stub_etcd.EtcdClusterIdChanged())
        elector = election.Elector(client,
                                   "test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)

    def test_become_master_multiple_attempts(self):
        # Become the master after once round
        LOG.debug("test_become_master_multiple_circuits")
        for action in ["delete", "expire", "compareAndDelete", "something"]:
            LOG.info("Testing etcd delete event %s", action)
            client = stub_etcd.Client()
            client.add_read_result(key="/bloop", value="value")
            client.add_read_result(key="/bloop", value="value")
            client.add_read_result(key="/bloop", value=None, action=action)
            client.add_write_exception(None)
            client.add_write_exception(None)
            elector = election.Elector(client, "test_basic", "/bloop",
                                       interval=5, ttl=15)
            self._wait_and_stop(client, elector)

    def test_become_master_implausible(self):
        # Become the master after key vanishes
        LOG.debug("test_become_master_implausible")
        client = stub_etcd.Client()
        client.add_read_result(key="/bloop", value="value")
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(stub_etcd.EtcdKeyNotFound())
        client.add_write_result()
        client.add_write_result()
        elector = election.Elector(client,
                                   "test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)

    def test_initial_read_exceptions(self):
        LOG.debug("test_initial_read_exceptions")

        client = stub_etcd.Client()
        client.add_read_exception(stub_etcd.EtcdException())
        client.add_read_exception(stub_etcd.EtcdConnectionFailed())
        client.add_read_exception(stub_etcd.EtcdClusterIdChanged())
        client.add_read_exception(stub_etcd.EtcdEventIndexCleared())
        elector = election.Elector(client,
                                   "test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)

    def test_later_exceptions(self):
        LOG.debug("test_later_read_exceptions")

        client = stub_etcd.Client()
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(stub_etcd.EtcdException())
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(stub_etcd.EtcdConnectionFailed())
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(stub_etcd.EtcdClusterIdChanged())
        client.add_read_result(key="/bloop", value="value")
        client.add_read_exception(stub_etcd.EtcdEventIndexCleared())
        elector = election.Elector(client, "test_basic", "/bloop",
                                   interval=5, ttl=15)
        self._wait_and_stop(client, elector)

    def test_master_failure(self):
        LOG.debug("test_master_failure")

        client = stub_etcd.Client()
        client.add_read_exception(stub_etcd.EtcdKeyNotFound())
        # Now become the master but fail
        client.add_write_exception(stub_etcd.EtcdException())
        client.add_read_result(key="/bloop", value="value")
        client.add_read_result(key="/bloop", value=None, action="delete")
        # Now become the master but fail again
        client.add_write_exception(stub_etcd.EtcdException())
        # Go back to the beginning again.
        client.add_read_result(key="/bloop", value="value")
        client.add_read_result(key="/bloop", value=None, action="delete")
        client.add_write_exception(None)
        client.add_write_exception(None)
        elector = election.Elector(client,
                                   "test_basic",
                                   "/bloop",
                                   interval=5,
                                   ttl=15)
        self._wait_and_stop(client, elector)

        # We are no longer the master, after error.
        self.assertFalse(elector.master())

    @mock.patch("os.path.exists")
    def test_check_master_process_died(self, m_exists):
        m_exists.return_value = False
        client = mock.Mock()
        elector = election.Elector(client, "server-id", "/bloop",
                                   interval=5, ttl=15)
        client.delete.side_effect = stub_etcd.EtcdKeyNotFound()
        self.assertRaises(election.RestartElection,
                          elector._check_master_process, "server-id:1234")
        self.assertEqual(
            [
                mock.call("/bloop", prevValue="server-id:1234")
            ],
            client.delete.mock_calls
        )

    @mock.patch("os.path.exists")
    def test_check_master_process_other_server(self, m_exists):
        m_exists.return_value = False
        client = mock.Mock()
        elector = election.Elector(client, "server-id", "/bloop",
                                   interval=5, ttl=15)
        elector._check_master_process("other-server:1234")
        self.assertEqual([], client.delete.mock_calls)

    @mock.patch("os.path.exists")
    def test_check_master_process_still_alive(self, m_exists):
        m_exists.return_value = True
        client = mock.Mock()
        elector = election.Elector(client, "server-id", "/bloop",
                                   interval=5, ttl=15)
        elector._check_master_process("server-id:1234")
        self.assertEqual([], client.delete.mock_calls)
