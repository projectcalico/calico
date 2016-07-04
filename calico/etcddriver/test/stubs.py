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
calico.etcddriver.test.stubs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stub objects used for testing driver/protocol code.
"""
import json
import threading

import logging
from Queue import Queue, Empty

import time

from calico.etcddriver.protocol import (
    MessageReader, MessageWriter, MSG_KEY_TYPE
)

_log = logging.getLogger(__name__)


# Singleton representing a flush in the stream of writes.
class Sigil(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "<%s>" % self.name


FLUSH = Sigil("FLUSH")


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

    def next_msg(self):
        return self.queue.get(timeout=1)

    def flush(self):
        self.queue.put(FLUSH)


class PipeFile(object):
    def __init__(self):
        self.queue = Queue()
        self.buf = None
        self._finished = False
        self.read_in_progress = False

    def read(self, length):
        try:
            self.read_in_progress = True
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
        finally:
            self.read_in_progress = False

    def wait_for_read(self):
        """Waits until a read is in progress."""
        start_time = time.time()
        while not self.read_in_progress:
            time.sleep(0.01)
            if time.time() > start_time + 1:
                raise AssertionError("No read before timeout")

    def write(self, data):
        self.queue.put(data)
        if data == "" or isinstance(data, Exception):
            self._finished = True

    def __del__(self):
        assert self._finished, "PipeFile wasn't correctly finished."


class StubRequest(object):
    def __init__(self, stub_etcd, key, kwargs):
        self.stub_etcd = stub_etcd
        self.thread = threading.current_thread()
        self.key = key
        self.kwargs = kwargs
        self.response = None
        self.response_available = threading.Event()
        self.pipe_file = None

    def __str__(self):
        return "Request<key=%s,args=%s,thread=%s>" % (self.key,
                                                      self.kwargs,
                                                      self.thread)

    def respond_with_exception(self, exc):
        """
        Called from the test to raise an exception from the current/next
        request.
        """
        self.response = exc
        self.on_response_avail()

    def on_response_avail(self):
        self.response_available.set()
        self.stub_etcd.on_req_closed(self)

    def respond_with_value(self, key, value, dir=False, mod_index=None,
                           etcd_index=None, status=200, action="get"):
        """
        Called from the test to return a simple single-key value to the
        driver.
        """
        node = {"key": key, "value": value, "modifiedIndex": mod_index}
        if dir:
            node["dir"] = True
        data = json.dumps({
            "action": action,
            "node": node
        })
        self.respond_with_data(data, etcd_index, status)

    def respond_with_dir(self, key, children, mod_index=None,
                         etcd_index=None, status=200):
        """
        Called from the test to return a directory of key/values (from a
        recursive request).
        """
        nodes = []
        for k, v in children.iteritems():
            if v is not None:
                nodes.append({"key": k, "value": v,
                              "modifiedIndex": mod_index})
            else:
                nodes.append({"key": k, "dir": True,
                              "modifiedIndex": mod_index,
                              "nodes": []})
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
        headers = self.stub_etcd.headers.copy()
        if etcd_index is not None:
            headers["x-etcd-index"] = str(etcd_index)
        resp = MockResponse(status, data, headers)
        self.response = resp
        self.on_response_avail()

    def respond_with_stream(self, etcd_index, status=200):
        """
        Called from the test to respond with a stream, allowing the test to
        send chunks of data in response.
        """
        headers = self.stub_etcd.headers.copy()
        if etcd_index is not None:
            headers["x-etcd-index"] = str(etcd_index)
        self.pipe_file = PipeFile()
        resp = MockResponse(status, self.pipe_file, headers)
        self.response = resp
        self.response_available.set()  # We leave the req open in StubEtcd.
        return self.pipe_file

    def get_response(self):
        self.response_available.wait(timeout=30)  # returns None in Python 2.6
        if self.response_available.is_set():
            return self.response
        else:
            raise AssertionError("No response")

    def assert_request(self, expected_key, **expected_args):
        """
        Asserts the properies of the next request.
        """
        default_args = {'wait_index': None,
                        'preload_content': None,
                        'recursive': False,
                        'timeout': 5}
        key = self.key
        args = self.kwargs
        for k, v in default_args.iteritems():
            if k in args and args[k] == v:
                del args[k]
        if expected_key != key:
            raise AssertionError("Expected request for %s but got %s" %
                                 (expected_key, key))
        if expected_args != args:
            raise AssertionError("Expected request args %s for %s but got %s" %
                                 (expected_args, key, args))

    def stop(self):
        if self.response_available.is_set():
            if self.pipe_file:
                self.pipe_file.write(SystemExit())
        else:
            self.respond_with_exception(SystemExit())


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
        self.lock = threading.Lock()
        self.open_reqs = set()

    def request(self, key, **kwargs):
        """
        Called from the driver to make a request.  Blocks until the
        test thread sends a response.
        """
        _log.info("New request on thread %s: %s, %s",
                  threading.current_thread(),
                  key, kwargs)
        request = StubRequest(self, key, kwargs)
        with self.lock:
            self.open_reqs.add(request)
            rq = self.request_queue
            if rq is None:
                _log.warn("Request after shutdown: %s, %s", key, kwargs)
                raise SystemExit()
            else:
                rq.put(request)
        response = request.get_response()
        if isinstance(response, BaseException):
            raise response
        else:
            return response

    def get_next_request(self):
        """
        Called from the test to get the next request from the driver.
        """
        _log.info("Waiting for next request")
        req = self.request_queue.get(timeout=1)
        _log.info("Got request %s", req)
        return req

    def assert_request(self, expected_key, **expected_args):
        """
        Asserts the properies of the next request.
        """
        req = self.request_queue.get(timeout=1)
        req.assert_request(expected_key, **expected_args)
        return req

    def on_req_closed(self, req):
        with self.lock:
            self.open_reqs.remove(req)

    def stop(self):
        _log.info("Stopping stub etcd")
        with self.lock:
            _log.info("stop() got rq_lock")
            while True:
                try:
                    req = self.request_queue.get_nowait()
                except Empty:
                    break
                else:
                    self.open_reqs.add(req)
            self.request_queue = None
        for req in list(self.open_reqs):
            _log.info("Aborting request %s", req)
            req.stop()
        _log.info("Stub etcd stopped; future requests should self-abort")


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
