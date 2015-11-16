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
Stub version of the etcd interface.
"""
import eventlet
from eventlet.event import Event
import logging

# Logger
log = logging.getLogger(__name__)


class EtcdException(Exception):
    pass


class EtcdKeyNotFound(EtcdException):
    pass


class EtcdClusterIdChanged(EtcdException):
    pass


class EtcdConnectionFailed(EtcdException):
    pass


class EtcdEventIndexCleared(EtcdException):
    pass


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
        return result

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

    def __str__(self):
        return ("key=%s, value=%s, action=%s,index=%d" %
                (self.key, self.value, self.action, self.etcd_index))
