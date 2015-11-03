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

import logging
from Queue import Queue, Empty
from unittest import TestCase

from mock import Mock, call, patch

from calico.etcddriver.driver import EtcdDriver
from calico.etcddriver.protocol import *

_log = logging.getLogger(__name__)


FLUSH = object()


class StubMessageReader(MessageReader):
    def __init__(self, sck):
        super(StubMessageReader, self).__init__(sck)
        self.queue = Queue()

    def send_msg(self, msg_type, fields=None):
        msg = {
            MSG_KEY_TYPE: msg_type
        }
        msg.update(fields or {})
        self.queue.put((msg_type, msg))

    def send_timeout(self):
        self.queue.put(None)

    def send_exception(self, exc):
        self.queue.put(exc)

    def new_messages(self, timeout=None):
        while True:
            item = self.queue.get()
            if item is None:
                return  # timeout
            if isinstance(item, Exception):
                raise item
            else:
                yield item


class StubMessageWriter(MessageWriter):
    def __init__(self, sck):
        super(StubMessageWriter, self).__init__(sck)
        self.queue = Queue()

    def send_message(self, msg_type, fields=None, flush=True):
        self.queue.put((msg_type, fields))
        if flush:
            self.flush()

    def flush(self):
        self.queue.put(FLUSH)


class TestEtcdDriverFV(TestCase):
    """
    FV-level tests for the driver.  These tests run a real copy of the driver
    but they stub out the felix socket and requests to etcd.
    """

    def setUp(self):
        sck = Mock()
        self.msg_reader = StubMessageReader(sck)
        self.msg_writer = StubMessageWriter(sck)

        self.driver = EtcdDriver(sck)
        self.driver._msg_reader = self.msg_reader
        self.driver._msg_writer = self.msg_writer
        self.driver._etcd_request = Mock(spec=self.driver._etcd_request,
                                         side_effect=self.mock_etcd_request)

    def mock_etcd_request(self, http_pool, key, timeout=5, wait_index=None,
                          recursive=False, preload_content=None):
        if http_pool is self.driver._resync_http_pool:
            _log.info("Resync thread issuing request for %s timeout=%s, "
                      "wait_index=%s, recursive=%s, preload=%s", key, timeout,
                      wait_index, recursive, preload_content)
        else:
            _log.info("Watcher thread issuing request for %s timeout=%s, "
                      "wait_index=%s, recursive=%s, preload=%s", key, timeout,
                      wait_index, recursive, preload_content)
        return NotImplemented

    def test_start(self):
        self.driver.start()
        self.assert_no_msgs()
        self.msg_reader.send_msg(
            MSG_TYPE_INIT,
            {
                MSG_KEY_ETCD_URL: "http://localhost:4001",
                MSG_KEY_HOSTNAME: "thehostname",
            }
        )
        self.assert_next_msg(
            MSG_TYPE_STATUS,
            {MSG_KEY_STATUS: STATUS_WAIT_FOR_READY}
        )

    def assert_next_msg(self, msg_type, fields=None):
        mt, fs = self.msg_writer.queue.get(timeout=10)
        self.assertEqual(msg_type, mt)
        self.assertEqual(fields, fs)

    def assert_no_msgs(self):
        try:
            msg = self.msg_writer.queue.get(timeout=1)
        except Empty:
            pass
        else:
            self.fail("Message unexpectedly received: %s" % msg)

    def tearDown(self):
        self.driver.stop()
        self.msg_reader.send_timeout()
        self.driver._reader_thread.join(2)
        self.driver._resync_thread.join(2)
        try:
            self.driver._watcher_thread.join(2)
            self.assertFalse(self.driver._watcher_thread.is_alive())
        except AttributeError:
            pass
        self.assertFalse(self.driver._reader_thread.is_alive())
        self.assertFalse(self.driver._resync_thread.is_alive())
