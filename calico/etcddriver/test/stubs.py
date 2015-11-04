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
calico.etcddriver.test.stubs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stub objects used for testing driver/protocol code.
"""
import json

import logging
from Queue import Queue, Empty

from calico.etcddriver.protocol import (
    MessageReader, MessageWriter, MSG_KEY_TYPE
)

_log = logging.getLogger(__name__)


# Singleton representing a flush in the stream of writes.
FLUSH = object()


class StubMessageReader(MessageReader):
    """
    Replacement for the Driver's MessageReader, which is how it reads
    from Felix.

    Allows us to send messages as if we were Felix.
    """
    def __init__(self, sck):
        super(StubMessageReader, self).__init__(sck)
        self.queue = Queue()

    def send_msg(self, msg_type, fields=None):
        """Called by the test to send the driver a message."""
        msg = {
            MSG_KEY_TYPE: msg_type
        }
        msg.update(fields or {})
        self.queue.put((msg_type, msg))

    def send_timeout(self):
        """Called by the test to send the driver a timeout."""
        self.queue.put(None)

    def send_exception(self, exc):
        """Called by the test to raise an exception from the driver's read."""
        self.queue.put(exc)

    def new_messages(self, timeout=None):
        """Called by the driver to receive new messages."""
        while True:
            item = self.queue.get()
            if item is None:
                return  # timeout
            if isinstance(item, BaseException):
                raise item
            else:
                yield item


class StubMessageWriter(MessageWriter):
    """
    Replacement for the driver's MessageWriter, which it uses to send messages
    to Felix.

    Buffers the messages and flush calls in a queue for the test to
    interrogate.
    """
    def __init__(self, sck):
        super(StubMessageWriter, self).__init__(sck)
        self.queue = Queue()
        self.exception = None

    def send_message(self, msg_type, fields=None, flush=True):
        if self.exception:
            raise self.exception
        self.queue.put((msg_type, fields))
        if flush:
            self.flush()

    def flush(self):
        self.queue.put(FLUSH)


class PipeFile(object):
    def __init__(self):
        self.queue = Queue()
        self.buf = None

    def read(self, length):
        data = ""
        if not self.buf:
            self.buf = self.queue.get()
        while len(data) < length:
            if isinstance(self.buf, BaseException):
                raise self.buf
            data += self.buf[:length - len(data)]
            self.buf = self.buf[length - len(data):]
            if not self.buf:
                try:
                    self.buf = self.queue.get_nowait()
                except Empty:
                    break
        return data

    def write(self, data):
        self.queue.put(data)

    def __del__(self):
        self.queue.put("")


class StubEtcd(object):
    """
    A fake connection to etcd.  We hook the driver's _issue_etcd_request
    method and block the relevant thread until the test calls one of the
    respond_... methods.
    """
    def __init__(self):
        self.request_queue = Queue()
        self.response_queue = Queue()
        self.headers = {
            "x-etcd-cluster-id": "abcdefg"
        }

    def request(self, key, **kwargs):
        """
        Called from the driver to make a request.  Blocks until the
        test thread sends a response.
        """
        self.request_queue.put((key, kwargs))
        response = self.response_queue.get(30)
        if isinstance(response, BaseException):
            raise response
        else:
            return response

    def get_next_request(self):
        """
        Called from the test to get the next request from the driver.
        """
        return self.request_queue.get(timeout=10)

    def assert_request(self, expected_key, **expected_args):
        """
        Asserts the properies of the next request.
        """
        key, args = self.get_next_request()
        default_args = {'wait_index': None,
                        'preload_content': None,
                        'recursive': False,
                        'timeout': 5}
        for k, v in default_args.iteritems():
            if k in args and args[k] == v:
                del args[k]
        if expected_key != key:
            raise AssertionError("Expected request for %s but got %s" %
                                 (expected_key, key))
        if expected_args != args:
            raise AssertionError("Expected request args %s for %s but got %s" %
                                 (expected_args, key, args))

    def respond_with_exception(self, exc):
        """
        Called from the test to raise an exception from the current/next
        request.
        """
        self.response_queue.put(exc)

    def respond_with_value(self, key, value, mod_index=None,
                           etcd_index=None, status=200, action="get"):
        """
        Called from the test to return a simple single-key value to the
        driver.
        """
        data = json.dumps({
            "action": action,
            "node": {
                "key": key,
                "value": value,
                "modifiedIndex": mod_index,
            }
        })
        self.respond_with_data(data, etcd_index, status)

    def respond_with_dir(self, key, children, mod_index=None,
                         etcd_index=None, status=200):
        """
        Called from the test to return a directory of key/values (from a
        recursive request).
        """
        nodes = [{"key": k, "value": v, "modifiedIndex": mod_index}
                 for (k, v) in children.iteritems()]
        data = json.dumps({
            "action": "get",
            "node": {
                "key": key,
                "dir": True,
                "modifiedIndex": mod_index,
                "nodes": nodes
            }
        })
        self.respond_with_data(data, etcd_index, status)

    def respond_with_data(self, data, etcd_index, status):
        """
        Called from the test to return a raw response (e.g. to send
        malformed JSON).
        """
        headers = self.headers.copy()
        if etcd_index is not None:
            headers["x-etcd-index"] = str(etcd_index)
        resp = MockResponse(status, data, headers)
        self.response_queue.put(resp)

    def respond_with_stream(self, etcd_index, status=200):
        """
        Called from the test to respond with a stream, allowing the test to
        send chunks of data in response.
        """
        headers = self.headers.copy()
        if etcd_index is not None:
            headers["x-etcd-index"] = str(etcd_index)
        f = PipeFile()
        resp = MockResponse(status, f, headers)
        self.response_queue.put(resp)
        return f


class MockResponse(object):
    def __init__(self, status, data_or_exc, headers=None):
        self.status = status
        self._data_or_exc = data_or_exc
        self.headers = headers or {}

    @property
    def data(self):
        if isinstance(self._data_or_exc, Exception):
            raise self._data_or_exc
        elif hasattr(self._data_or_exc, "read"):
            return self._data_or_exc.read()
        else:
            return self._data_or_exc

    def read(self, *args):
        return self._data_or_exc.read(*args)

    def getheader(self, header, default=None):
        _log.debug("Asked for header %s", header)
        return self.headers.get(header.lower(), default)