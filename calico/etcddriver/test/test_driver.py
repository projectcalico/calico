# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
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
calico.etcddriver.test.test_driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for the etcd driver module.
"""
from Queue import Empty
from unittest2 import TestCase, SkipTest

from mock import Mock, patch, call
from urllib3 import HTTPConnectionPool
from urllib3.exceptions import TimeoutError

from calico.datamodel_v1 import READY_KEY, CONFIG_DIR, VERSION_DIR
from calico.etcddriver.driver import EtcdDriver, DriverShutdown
from calico.etcddriver.protocol import *
from calico.etcddriver.test.stubs import (
    StubMessageReader, StubMessageWriter, StubEtcd,
    FLUSH)

_log = logging.getLogger(__name__)


class TestEtcdDriverFV(TestCase):
    """
    FV-level tests for the driver.  These tests run a real copy of the driver
    but they stub out the felix socket and requests to etcd.
    """

    def setUp(self):
        sck = Mock()
        self.watcher_etcd = StubEtcd()
        self.resync_etcd = StubEtcd()

        self.driver = EtcdDriver(sck)
        self.msg_reader = StubMessageReader(sck)
        self.msg_writer = StubMessageWriter(sck)
        self.driver._msg_reader = self.msg_reader
        self.driver._msg_writer = self.msg_writer
        self.driver._issue_etcd_request = Mock(
            spec=self.driver._issue_etcd_request,
            side_effect=self.mock_etcd_request
        )

        self._logging_patch = patch("calico.etcddriver.driver."
                                    "complete_logging", autospec=True)
        self._logging_patch.start()

    def test_mainline_resync(self):
        """
        Test of the mainline resync-and-merge processing.

        * Does the initial config handshake with Felix.
        * Interleaves the snapshot response with updates via the watcher.
        * Checks that the result is correctly merged.
        """
        # Initial handshake.
        self.start_driver_and_handshake()
        # Check for etcd request and start the response.
        snap_stream = self.start_snapshot_response()
        # Respond to the watcher, this should get merged into the event
        # stream at some point later.
        self.watcher_etcd.respond_with_value(
            "/calico/v1/adir/bkey",
            "b",
            mod_index=12,
            action="set"
        )
        # Wait until the watcher makes its next request (with revved
        # wait_index) to make sure it has queued its event to the resync
        # thread.
        self.watcher_etcd.assert_request(
            VERSION_DIR, recursive=True, timeout=90, wait_index=13
        )
        # Write some more data to the resync thread, it should process that
        # and the queued watcher event.
        snap_stream.write('''
                     {
                         "key": "/calico/v1/adir/ckey",
                         "value": "c",
                         "modifiedIndex": 8
                     },
        ''')
        self.assert_msg_to_felix(MSG_TYPE_UPDATE, {
            MSG_KEY_KEY: "/calico/v1/adir/ckey",
            MSG_KEY_VALUE: "c",
        })
        self.assert_msg_to_felix(MSG_TYPE_UPDATE, {
            MSG_KEY_KEY: "/calico/v1/adir/bkey",
            MSG_KEY_VALUE: "b",
        })
        # Respond to the watcher with another event.
        self.watcher_etcd.respond_with_value(
            "/calico/v1/adir/dkey",
            "d",
            mod_index=13,
            action="set"
        )
        # Wait until the watcher makes its next request (with revved
        # wait_index) to make sure it has queued its event to the resync
        # thread.
        self.watcher_etcd.assert_request(
            VERSION_DIR, recursive=True, timeout=90, wait_index=14
        )
        # Send the resync thread some data that should be ignored due to the
        # preceding event.
        snap_stream.write('''
                    {
                        "key": "/calico/v1/adir/bkey",
                        "value": "b",
                        "modifiedIndex": 9
                    },
        ''')
        # The resync event would be generated first but we should should only
        # see the watcher event.
        self.assert_msg_to_felix(MSG_TYPE_UPDATE, {
            MSG_KEY_KEY: "/calico/v1/adir/dkey",
            MSG_KEY_VALUE: "d",
        })
        # Finish the snapshot.
        snap_stream.write('''
                    {
                        "key": "/calico/v1/Ready",
                        "value": "true",
                        "modifiedIndex": 10
                    }]
                }]
            }
        }
        ''')
        # Should get the in-sync message.  (No event for Ready flag due to
        # HWM.
        self.assert_status_message(STATUS_IN_SYNC)
        # Now send a watcher event, which should go straight through.
        self.send_watcher_event_and_assert_felix_msg(14)

    def test_second_resync(self):
        try:
            # Start by going through the first resync.
            self.test_mainline_resync()
        except AssertionError:
            _log.exception("Mainline resync test failed")
            raise SkipTest("Mainline resync test failed to initialise driver")

        # Felix sends a resync message.
        self.msg_reader.send_msg(MSG_TYPE_RESYNC, {})

        # Wait for the watcher to make its request.
        self.watcher_etcd.assert_request(
            VERSION_DIR, recursive=True, timeout=90, wait_index=15
        )
        # Then for determinism, force it to die before it polls again.
        self.driver._watcher_stop_event.set()
        # The event from the watcher triggers the resync.
        self.send_watcher_event_and_assert_felix_msg(15)

        # Back into wait-for-ready mode.
        self.assert_status_message(STATUS_WAIT_FOR_READY)
        # Re-do the config handshake.
        self.do_handshake()

        # Check for etcd request and start the response.
        snap_stream = self.start_snapshot_response(etcd_index=100)
        # Respond to the watcher, this should get merged into the event
        # stream at some point later.
        self.watcher_etcd.respond_with_value(
            "/calico/v1/adir/bkey",
            "b",
            mod_index=102,
            action="set"
        )
        # Wait until the watcher makes its next request (with revved
        # wait_index) to make sure it has queued its event to the resync
        # thread.
        self.watcher_etcd.assert_request(
            VERSION_DIR, recursive=True, timeout=90, wait_index=103
        )
        # Write some data for an unchanged key to the resync thread, which
        # should be ignored.
        snap_stream.write('''
                     {
                         "key": "/calico/v1/adir/ckey",
                         "value": "c",
                         "modifiedIndex": 8
                     },
        ''')
        # But we should get the watcher update.
        self.assert_msg_to_felix(MSG_TYPE_UPDATE, {
            MSG_KEY_KEY: "/calico/v1/adir/bkey",
            MSG_KEY_VALUE: "b",
        })
        # Finish the snapshot.
        snap_stream.write('''
                    {
                        "key": "/calico/v1/adir/dkey",
                        "value": "c",
                        "modifiedIndex": 8
                    },
                    {
                        "key": "/calico/v1/Ready",
                        "value": "true",
                        "modifiedIndex": 10
                    }]
                }]
            }
        }
        ''')
        # Should get a deletion for the keys that were missing in this
        # snapshot.
        self.assert_msg_to_felix(MSG_TYPE_UPDATE, {
            MSG_KEY_KEY: "/calico/v1/adir/ekey",
            MSG_KEY_VALUE: None,
        })
        # Should get the in-sync message.  (No event for Ready flag due to
        # HWM.
        self.assert_status_message(STATUS_IN_SYNC)
        # Now send a watcher event, which should go straight through.
        self.send_watcher_event_and_assert_felix_msg(104)

    def send_watcher_event_and_assert_felix_msg(self, etcd_index):
        self.watcher_etcd.respond_with_value(
            "/calico/v1/adir/ekey",
            "e",
            mod_index=etcd_index,
            action="set"
        )
        self.assert_msg_to_felix(MSG_TYPE_UPDATE, {
            MSG_KEY_KEY: "/calico/v1/adir/ekey",
            MSG_KEY_VALUE: "e",
        })
        self.assert_flush_to_felix()

    @patch("time.sleep", autospec=True)
    def test_resync_pipe_write_fail(self, m_sleep):
        """
        Test a read failure on the snapshot.
        """
        # Start the driver, it will wait for a message from Felix.
        self.driver.start()
        # Queue up an error on the driver's next write.
        self.msg_writer.exception = WriteFailed()
        # Send init message from Felix to driver.
        self.send_init_msg()
        # Driver should die.
        for _ in xrange(100):
            # Need to time out the reader thread or it will block shutdown.
            self.msg_reader.send_timeout()
            if self.driver.join(timeout=0.01):
                break
        else:
            self.fail("Driver failed to die.")

    @patch("time.sleep", autospec=True)
    def test_resync_etcd_read_fail(self, m_sleep):
        """
        Test a read failure on the snapshot.
        """
        # Initial handshake.
        self.start_driver_and_handshake()
        # Start streaming some data.
        snap_stream = self.start_snapshot_response()
        # But then the read times out...
        snap_stream.write(TimeoutError())
        # Triggering a restart of the resync loop.
        self.assert_status_message(STATUS_WAIT_FOR_READY)

    @patch("time.sleep")
    def test_bad_ready_key_retry(self, m_sleep):
        self.start_driver_and_init()
        # Respond to etcd request with a bad response
        self.resync_etcd.assert_request(READY_KEY)
        self.resync_etcd.respond_with_data("foobar", 123, 500)
        # Then it should retry.
        self.resync_etcd.assert_request(READY_KEY)
        m_sleep.assert_called_once_with(1)

    def start_driver_and_init(self):
        self.driver.start()
        # First message comes from Felix.
        self.send_init_msg()
        # Should trigger driver to send a status and start polling the ready
        # flag.
        self.assert_status_message(STATUS_WAIT_FOR_READY)

    def start_driver_and_handshake(self):
        self.start_driver_and_init()
        self.do_handshake()

    def do_handshake(self):
        # Respond to etcd request with ready == true.
        self.resync_etcd.assert_request(READY_KEY)
        self.resync_etcd.respond_with_value(READY_KEY, "true", mod_index=10)
        # Then etcd should get the global config request.
        self.resync_etcd.assert_request(CONFIG_DIR, recursive=True)
        self.resync_etcd.respond_with_dir(CONFIG_DIR, {
            CONFIG_DIR + "/InterfacePrefix": "tap"
        })
        # Followed by the per-host one...
        self.resync_etcd.assert_request("/calico/v1/host/thehostname/config",
                                        recursive=True)
        self.resync_etcd.respond_with_dir(CONFIG_DIR, {
            "/calico/v1/host/thehostname/config/LogSeverityFile": "DEBUG"
        })
        # Then the driver should send the config to Felix.
        self.assert_msg_to_felix(
            MSG_TYPE_CONFIG_LOADED,
            {
                MSG_KEY_GLOBAL_CONFIG: {"InterfacePrefix": "tap"},
                MSG_KEY_HOST_CONFIG: {"LogSeverityFile": "DEBUG"},
            }
        )
        self.assert_flush_to_felix()
        # We respond with the config message to trigger the start of the
        # resync.
        self.msg_reader.send_msg(
            MSG_TYPE_CONFIG,
            {
                MSG_KEY_LOG_FILE: "/tmp/driver.log",
                MSG_KEY_SEV_FILE: "DEBUG",
                MSG_KEY_SEV_SCREEN: "DEBUG",
                MSG_KEY_SEV_SYSLOG: "DEBUG",
            }
        )
        self.assert_status_message(STATUS_RESYNC)

    def start_snapshot_response(self, etcd_index=10):
        # We should get a request to load the full snapshot.
        self.resync_etcd.assert_request(
            VERSION_DIR, recursive=True, timeout=120, preload_content=False
        )
        snap_stream = self.resync_etcd.respond_with_stream(
            etcd_index=etcd_index
        )
        # And then the headers should trigger a request from the watcher
        # including the etcd_index we sent even though we haven't sent a
        # response body to the resync thread.
        self.watcher_etcd.assert_request(
            VERSION_DIR, recursive=True, timeout=90, wait_index=etcd_index+1
        )
        # Start sending the snapshot response:
        snap_stream.write('''{
            "action": "get",
            "node": {
                "key": "/calico/v1",
                "dir": true,
                "nodes": [
                {
                    "key": "/calico/v1/adir",
                    "dir": true,
                    "nodes": [
                    {
                        "key": "/calico/v1/adir/akey",
                        "value": "akey's value",
                        "modifiedIndex": %d
                    },
        ''' % (etcd_index - 2))
        # Should generate a message to felix even though it's only seen part
        # of the response...
        self.assert_msg_to_felix(MSG_TYPE_UPDATE, {
            MSG_KEY_KEY: "/calico/v1/adir/akey",
            MSG_KEY_VALUE: "akey's value",
        })
        return snap_stream

    def assert_status_message(self, status):
        self.assert_msg_to_felix(
            MSG_TYPE_STATUS,
            {MSG_KEY_STATUS: status}
        )
        self.assert_flush_to_felix()

    def send_init_msg(self):
        self.msg_reader.send_msg(
            MSG_TYPE_INIT,
            {
                MSG_KEY_ETCD_URL: "http://localhost:4001",
                MSG_KEY_HOSTNAME: "thehostname",
            }
        )

    def assert_msg_to_felix(self, msg_type, fields=None):
        try:
            mt, fs = self.msg_writer.queue.get(timeout=2)
        except Empty:
            self.fail("Expected %s message to felix but no message was sent" %
                      msg_type)
        self.assertEqual(msg_type, mt, msg="Unexpected message: %s" % fs)
        self.assertEqual(fields, fs, msg="Unexpected message: %s" % fs)

    def assert_flush_to_felix(self):
        self.assertEqual(self.msg_writer.queue.get(timeout=10),
                         FLUSH)

    def assert_no_msgs(self):
        try:
            msg = self.msg_writer.queue.get(timeout=1)
        except Empty:
            pass
        else:
            self.fail("Message unexpectedly received: %s" % msg)

    def mock_etcd_request(self, http_pool, key, timeout=5, wait_index=None,
                          recursive=False, preload_content=None):
        """
        Called from another thread when the driver makes an etcd request,
        we queue the request via the correct stub, then block, waiting
        for the main thread to tell us what to do.
        """
        if http_pool is self.driver._resync_http_pool:
            _log.info("Resync thread issuing request for %s timeout=%s, "
                      "wait_index=%s, recursive=%s, preload=%s", key, timeout,
                      wait_index, recursive, preload_content)
            etcd_stub = self.resync_etcd
        else:
            _log.info("Watcher thread issuing request for %s timeout=%s, "
                      "wait_index=%s, recursive=%s, preload=%s", key, timeout,
                      wait_index, recursive, preload_content)
            etcd_stub = self.watcher_etcd

        return etcd_stub.request(key,
                                 timeout=timeout,
                                 wait_index=wait_index,
                                 recursive=recursive,
                                 preload_content=preload_content)

    def tearDown(self):
        try:
            # Request that the driver stops.
            self.driver.stop()
            # Make sure we don't block the driver from stopping.
            self.msg_reader.send_timeout()
            # SystemExit kills (only) the thread silently.
            self.resync_etcd.respond_with_exception(SystemExit())
            self.watcher_etcd.respond_with_exception(SystemExit())
            # Wait for it to stop.
            self.assertTrue(self.driver.join(1), "Driver failed to stop")
        finally:
            # Now the driver is stopped, it's safe to remove our patch of
            # complete_logging()
            self._logging_patch.stop()


class TestDriver(TestCase):
    """
    Unit-test tests of the Driver.
    """
    def setUp(self):
        self.m_sck = Mock(spec=socket.socket)
        self.driver = EtcdDriver(self.m_sck)
        self.msg_reader = StubMessageReader(self.m_sck)
        self.msg_writer = StubMessageWriter(self.m_sck)
        self.driver._msg_reader = self.msg_reader
        self.driver._msg_writer = self.msg_writer

    def test_read_bad_message(self):
        self.msg_reader.send_msg("unknown", {})
        self.assertRaises(RuntimeError, self.driver._read_from_socket)

    def test_shutdown_before_config(self):
        self.driver._stop_event.set()
        self.assertRaises(DriverShutdown, self.driver._wait_for_config)

    def test_issue_etcd_request_basic_get(self):
        # Initialise the etcd URL.
        self.driver._handle_init({
            MSG_KEY_ETCD_URL: "http://localhost:4001/",
            MSG_KEY_HOSTNAME: "ourhost",
        })
        m_pool = Mock(spec=HTTPConnectionPool)
        self.driver._issue_etcd_request(m_pool, "calico/v1/Ready")
        self.assertEqual(
            m_pool.request.mock_calls,
            [call("GET",
                  "http://localhost:4001/v2/keys/calico/v1/Ready",
                  fields=None,
                  timeout=5,
                  preload_content=True)]
        )

    def test_issue_etcd_request_recursive_watch(self):
        # Initialise the etcd URL.
        self.driver._handle_init({
            MSG_KEY_ETCD_URL: "http://localhost:4001/",
            MSG_KEY_HOSTNAME: "ourhost",
        })
        m_pool = Mock(spec=HTTPConnectionPool)
        self.driver._issue_etcd_request(m_pool, "calico/v1", timeout=10,
                                        wait_index=11, recursive=True)
        self.assertEqual(
            m_pool.request.mock_calls,
            [call("GET",
                  "http://localhost:4001/v2/keys/calico/v1",
                  fields={"recursive": "true",
                          "wait": "true",
                          "waitIndex": 11},
                  timeout=10,
                  preload_content=False)]
        )

    def test_cluster_id_check(self):
        m_resp = Mock()
        m_resp.getheader.return_value = "abcdef"
        self.driver._check_cluster_id(m_resp)
        m_resp = Mock()
        m_resp.getheader.return_value = "ghijkl"
        self.assertRaises(DriverShutdown, self.driver._check_cluster_id,
                          m_resp)
        self.assertTrue(self.driver._stop_event.is_set())

