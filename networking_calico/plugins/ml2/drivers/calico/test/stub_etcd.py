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
Stub version of the etcd interface.
"""
from etcd3gw.utils import _decode
import eventlet
from eventlet.event import Event
import logging

from networking_calico import etcdv3


# Logger
log = logging.getLogger(__name__)


class NoMoreResults(Exception):
    pass


class UnexpectedResultType(Exception):
    pass

READ = "read"
WRITE = "write"


class Client(object):
    def __init__(self):
        self.results = []
        self.stop = Event()
        self.no_more_results = Event()
        self.failure = None
        self.next_lease_id = 100000
        self.keys_written = set()

    def get(self, key, metadata=False):
        assert metadata, "Always expect get() call with metadata=True"
        try:
            result = self.read(key)
            mod_revision = 10
            if result.etcd_index != 0:
                mod_revision = result.etcd_index
            return [(result.value, {'mod_revision': str(mod_revision)})]
        except etcdv3.KeyNotFound:
            return []

    def watch_once(self, key, timeout=None, **kwargs):
        result = self.read(key)
        mod_revision = 10
        if result.etcd_index != 0:
            mod_revision = result.etcd_index
        return {'kv': {
            'value': result.value,
            'mod_revision': mod_revision
        }}

    def read(self, path, **kwargs):
        try:
            result = self.results.pop(0)
        except IndexError:
            if not self.no_more_results.ready():
                self.no_more_results.send()
            eventlet.with_timeout(5, self.stop.wait)
            raise NoMoreResults()
        if result.op != READ:
            self.failure = "Unexpected result type for read(): %s" % result.op
            raise UnexpectedResultType()
        if result.exception is not None:
            log.debug("Raise read exception %s",
                      type(result.exception).__name__)
            raise result.exception
        log.debug("Return read result %s", result)
        return result

    def put(self, key, value, lease=None):
        self.write(key, value)
        return True

    def transaction(self, txn):
        put_request = txn['success'][0]['request_put']
        succeeded = self.put(_decode(put_request['key']),
                             _decode(put_request['value']))
        return {'succeeded': succeeded}

    def lease(self, ttl):
        l = Lease(self.next_lease_id, self)
        self.next_lease_id += 1
        return l

    def write(self, path, value, **kwargs):
        log.debug("Write of %s to %s", value, path)
        try:
            result = self.results.pop(0)
        except IndexError:
            if not self.no_more_results.ready():
                self.no_more_results.send()
            eventlet.with_timeout(5, self.stop.wait)
            raise NoMoreResults()
        if result.op != WRITE:
            self.failure = "Unexpected result type for write(): %s" % result.op
            raise UnexpectedResultType()
        if result.exception is not None:
            log.debug("Raise write exception %s", result.exception)
            raise result.exception
        log.debug("Return write result")
        self.keys_written.add(path)
        return result

    def assert_key_written(self, key):
        assert(key in self.keys_written)

    def add_read_exception(self, exception):
        assert(isinstance(exception, Exception))
        self.results.append(EtcdResult(exception=exception))

    def add_read_result(self, **kwargs):
        self.results.append(EtcdResult(**kwargs))

    def add_write_result(self):
        # Write results have no useful content.
        self.results.append(EtcdResult(op=WRITE))

    def add_write_exception(self, exception):
        self.results.append(EtcdResult(op=WRITE, exception=exception))


class EtcdResult(object):
    def __init__(self, op=READ, exception=None, key=None,
                 value=None, action=None, index=0):
        self.op = op
        self.key = key
        self.value = value
        self.action = action
        self.exception = exception
        self.etcd_index = index
        if self.key is not None:
            self.key = self.key.encode()
        if self.value is not None:
            self.value = self.value.encode()

    def __str__(self):
        return ("key=%s, value=%s, action=%s,index=%d" %
                (self.key, self.value, self.action, self.etcd_index))


class Lease(object):
    def __init__(self, id, stub):
        self.id = id
        self.stub = stub

    def refresh(self):
        # Use up a write result or write exception - because with etcdv2 this
        # refresh operation used to be done by writing the key/value pair
        # again.
        self.stub.write("lease", "refresh")
