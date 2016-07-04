# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
calico.etcddriver.test_protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for Felix/etcddriver protocol read/write function.
"""

import logging
import socket
from unittest import TestCase
import errno
from mock import Mock, call, patch
import msgpack
from calico.etcddriver.protocol import (
    MessageWriter, STATUS_RESYNC, MSG_KEY_STATUS, MSG_TYPE_STATUS,
    MSG_KEY_TYPE, STATUS_IN_SYNC, MessageReader,
    SocketClosed, WriteFailed)

_log = logging.getLogger(__name__)


class StubWriterSocket(object):
    def __init__(self):
        self.chunks = []
        self.unpacker = msgpack.Unpacker()
        self.exception = None

    def sendall(self, data):
        if self.exception:
            raise self.exception
        self.chunks.append(data)
        self.unpacker.feed(data)

    def next_msg(self):
        return next(self.unpacker)


class TestMessageWriter(TestCase):
    def setUp(self):
        self.sck = StubWriterSocket()
        self.writer = MessageWriter(self.sck)
        self.unpacker = msgpack.Unpacker()

    def test_send_message(self):
        self.writer.send_message(MSG_TYPE_STATUS,
                                 {
                                     MSG_KEY_STATUS: STATUS_RESYNC
                                 })
        self.assert_message_sent({
            MSG_KEY_TYPE: MSG_TYPE_STATUS,
            MSG_KEY_STATUS: STATUS_RESYNC
        })
        self.assert_no_more_messages()

    def test_send_message_error(self):
        self.sck.exception = socket.error()
        self.assertRaises(WriteFailed, self.writer.send_message,
                          MSG_TYPE_STATUS,
                          {
                              MSG_KEY_STATUS: STATUS_RESYNC
                          })

    def test_send_message_buffered(self):
        # First message gets buffered.
        self.writer.send_message(MSG_TYPE_STATUS,
                                 flush=False)
        self.assert_no_more_messages()

        # Second message triggers a flush of both messages, in order.
        self.writer.send_message(MSG_TYPE_STATUS,
                                 {
                                     MSG_KEY_STATUS: STATUS_IN_SYNC
                                 })
        self.assert_message_sent({
            MSG_KEY_TYPE: MSG_TYPE_STATUS
        })
        self.assert_message_sent({
            MSG_KEY_TYPE: MSG_TYPE_STATUS,
            MSG_KEY_STATUS: STATUS_IN_SYNC
        })
        self.assert_no_more_messages()

    def test_eventual_flush(self):
        # First 200 messages should be buffered.
        for _ in xrange(200):
            self.writer.send_message(MSG_TYPE_STATUS,
                                     {
                                         MSG_KEY_STATUS: STATUS_RESYNC
                                     },
                                     flush=False)
        self.assert_no_more_messages()

        # 201st message triggers them all to be sent.
        self.writer.send_message(MSG_TYPE_STATUS,
                                 {
                                     MSG_KEY_STATUS: STATUS_RESYNC
                                 },
                                 flush=False)
        for _ in xrange(201):
            self.assert_message_sent({
                MSG_KEY_TYPE: MSG_TYPE_STATUS,
                MSG_KEY_STATUS: STATUS_RESYNC
            })
        self.assert_no_more_messages()

    def test_flush_no_content(self):
        self.writer.flush()
        self.assertFalse(self.sck.chunks)

    def assert_message_sent(self, msg):
        try:
            received_msg = self.sck.next_msg()
        except StopIteration:
            self.fail("No messages received")
        self.assertEqual(received_msg, msg,
                         "Received incorrect message: %s "
                         "while expecting: %s" % (received_msg, msg))

    def assert_no_more_messages(self):
        try:
            msg = self.sck.next_msg()
        except StopIteration:
            return
        else:
            self.fail("Unexpected message: %s" % msg)


class TestMessageReader(TestCase):
    def setUp(self):
        self.sck = Mock(spec=socket.socket)
        self.reader = MessageReader(self.sck)

    @patch("select.select", autospec=True)
    def test_mainline(self, m_select):
        m_select.side_effect = iter([
            ([self.sck], [], []),
            ([self.sck], [], []),
        ])
        exp_msg = {MSG_KEY_TYPE: MSG_TYPE_STATUS,
                   MSG_KEY_STATUS: STATUS_RESYNC}
        self.sck.recv.return_value = msgpack.dumps(exp_msg)
        for _ in xrange(2):
            msg_gen = self.reader.new_messages(timeout=1)
            msg_type, msg = next(msg_gen)
            self.assertEqual(msg_type, MSG_TYPE_STATUS)
            self.assertEqual(msg, exp_msg)
        self.assertEqual(
            self.sck.recv.mock_calls,
            [
                call(16384),
                call(16384),
            ]
        )

    @patch("select.select", autospec=True)
    def test_partial_read(self, m_select):
        m_select.side_effect = iter([
            ([self.sck], [], []),
            ([self.sck], [], []),
        ])
        exp_msg = {MSG_KEY_TYPE: MSG_TYPE_STATUS}
        msg_bytes = msgpack.dumps(exp_msg)
        self.sck.recv.side_effect = iter([
            msg_bytes[:len(msg_bytes)/2],
            msg_bytes[len(msg_bytes)/2:],
        ])
        self.assertRaises(StopIteration, next,
                          self.reader.new_messages(timeout=None))
        self.assertEqual(next(self.reader.new_messages(timeout=None)),
                         (MSG_TYPE_STATUS, exp_msg))

    @patch("select.select", autospec=True)
    def test_retryable_error(self, m_select):
        m_select.side_effect = iter([
            ([self.sck], [], []),
            ([self.sck], [], []),
            ([self.sck], [], []),
            ([self.sck], [], []),
        ])
        errors = []
        for no in [errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR]:
            err = socket.error()
            err.errno = no
            errors.append(err)
        exp_msg = {MSG_KEY_TYPE: MSG_TYPE_STATUS,
                   MSG_KEY_STATUS: STATUS_RESYNC}
        self.sck.recv.side_effect = iter(errors + [msgpack.dumps(exp_msg)])
        for _ in errors:
            msg_gen = self.reader.new_messages(timeout=1)
            self.assertRaises(StopIteration, next, msg_gen)
        msg_gen = self.reader.new_messages(timeout=1)
        msg_type, msg = next(msg_gen)
        self.assertEqual(msg_type, MSG_TYPE_STATUS)
        self.assertEqual(msg, exp_msg)

    @patch("select.select", autospec=True)
    def test_non_retryable_error(self, m_select):
        m_select.side_effect = iter([
            ([self.sck], [], []),
        ])
        err = socket.error()
        err.errno = errno.E2BIG
        self.sck.recv.side_effect = err
        msg_gen = self.reader.new_messages(timeout=1)
        self.assertRaises(socket.error, next, msg_gen)

    @patch("select.select", autospec=True)
    def test_timeout(self, m_select):
        m_select.side_effect = iter([
            ([], [], []),
        ])
        msg_gen = self.reader.new_messages(timeout=1)
        self.assertRaises(StopIteration, next, msg_gen)
        self.assertFalse(self.sck.recv.called)

    @patch("select.select", autospec=True)
    def test_shutdown(self, m_select):
        self.sck.recv.return_value = ""
        msg_gen = self.reader.new_messages(timeout=None)
        self.assertRaises(SocketClosed, next, msg_gen)
