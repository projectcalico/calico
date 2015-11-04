# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
test_etcdutils
~~~~~~~~~~~~~~

Tests for etcd utility function.
"""

import logging
import types
from mock import Mock, patch, call
from calico.etcdutils import (
    PathDispatcher, EtcdWatcher, delete_empty_parents
)
# Since other tests patch the module table, make sure we have the same etcd
# module as the module under test.
from calico.etcdutils import etcd

from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


SAME_AS_KEY = object()


class TestEtcdutils(BaseTestCase):
    def test_delete_empty_parents_mainline(self):
        m_client = Mock()
        m_client.delete = Mock()
        delete_empty_parents(m_client, "/foo/bar/baz/biff", "/foo")
        self.assertEqual(
            m_client.delete.mock_calls,
            [
                call("foo/bar/baz/biff", dir=True, timeout=5),
                call("foo/bar/baz", dir=True, timeout=5),
                call("foo/bar", dir=True, timeout=5),
            ]
        )

    def test_delete_empty_parents_not_empty(self):
        m_client = Mock()
        m_client.delete = Mock()
        m_client.delete.side_effect = [
            None,
            etcd.EtcdDirNotEmpty(),
        ]
        delete_empty_parents(m_client, "/foo/bar/baz/biff", "/foo")
        self.assertEqual(
            m_client.delete.mock_calls,
            [
                call("foo/bar/baz/biff", dir=True, timeout=5),
                call("foo/bar/baz", dir=True, timeout=5),
            ]
        )

    def test_delete_empty_parents_not_found(self):
        m_client = Mock()
        m_client.delete = Mock()
        m_client.delete.side_effect = [
            None,
            etcd.EtcdKeyNotFound(),
            None
        ]
        delete_empty_parents(m_client, "/foo/bar/baz/biff", "/foo")
        self.assertEqual(
            m_client.delete.mock_calls,
            [
                call("foo/bar/baz/biff", dir=True, timeout=5),
                call("foo/bar/baz", dir=True, timeout=5),
                call("foo/bar", dir=True, timeout=5),
            ]
        )

    def test_delete_empty_parents_other_exception(self):
        m_client = Mock()
        m_client.delete = Mock()
        m_client.delete.side_effect = etcd.EtcdValueError()
        delete_empty_parents(m_client, "/foo/bar/baz/biff", "/foo")
        self.assertEqual(
            m_client.delete.mock_calls,
            [
                call("foo/bar/baz/biff", dir=True, timeout=5),
            ]
        )


class _TestPathDispatcherBase(BaseTestCase):
    """
    Abstract base class for Dispatcher tests.
    """
    # Etcd action that this class tests.
    action = None
    # Expected handler type, "set" or "delete".
    expected_handlers = None

    def setUp(self):
        super(_TestPathDispatcherBase, self).setUp()
        self.dispatcher = PathDispatcher()
        self.handlers = {
            "delete": {},
            "set": {},
        }
        self.register("/")
        self.register("/a")
        self.register("/a/<b>")
        self.register("/a/<b>/c")
        self.register("/a/<b>/d")
        self.register("/a/<b>/d/<e>")

    def register(self, key):
        m_on_set = Mock()
        m_on_del = Mock()
        self.dispatcher.register(key, on_set=m_on_set, on_del=m_on_del)
        self.handlers["set"][key.strip("/")] = m_on_set
        self.handlers["delete"][key.strip("/")] = m_on_del

    def assert_handled(self, key, exp_handler=SAME_AS_KEY, **exp_captures):
        if exp_handler is SAME_AS_KEY:
            exp_handler = key
        if isinstance(exp_handler, types.StringTypes):
            exp_handler = exp_handler.strip("/")
        m_response = Mock(spec=etcd.EtcdResult)
        m_response.key = key
        m_response.action = self.action
        self.dispatcher.handle_event(m_response)
        exp_handlers = self.handlers[self.expected_handlers]
        for handler_key, handler in exp_handlers.iteritems():
            assert isinstance(handler, Mock)
            if handler_key == exp_handler:
                continue
            self.assertFalse(handler.called,
                             "Unexpected set handler %s was called for "
                             "key %s" % (handler_key, key))
        unexp_handlers = self.handlers[self.unexpected_handlers]
        for handler_key, handler in unexp_handlers.iteritems():
            assert isinstance(handler, Mock)
            self.assertFalse(handler.called,
                             "Unexpected del handler %s was called for "
                             "key %s" % (handler_key, key))
        if exp_handler is not None:
            exp_handlers[exp_handler].assert_called_once_with(
                m_response, **exp_captures)

    @property
    def unexpected_handlers(self):
        if self.expected_handlers == "set":
            return "delete"
        else:
            return "set"

    def test_dispatch_root(self):
        self.assert_handled("/")

    def test_dispatch_no_captures(self):
        self.assert_handled("/a")

    def test_dispatch_capture(self):
        self.assert_handled("/a/bval", exp_handler="/a/<b>", b="bval")

    def test_dispatch_after_capture(self):
        self.assert_handled("/a/bval/c", exp_handler="/a/<b>/c", b="bval")

    def test_dispatch_after_capture_2(self):
        self.assert_handled("/a/bval/d", exp_handler="/a/<b>/d", b="bval")

    def test_multi_capture(self):
        self.assert_handled("/a/bval/d/eval",
                            exp_handler="/a/<b>/d/<e>",
                            b="bval", e="eval")

    def test_non_match(self):
        self.assert_handled("/a/bval/c/eval", exp_handler=None)
        self.assert_handled("/foo", exp_handler=None)

    def test_cover_no_match(self):
        m_result = Mock(spec=etcd.EtcdResult)
        m_result.key = "/a"
        m_result.action = "unknown"
        self.dispatcher.handle_event(m_result)
        for handlers in self.handlers.itervalues():
            for key, handler in handlers.iteritems():
                self.assertFalse(handler.called,
                                 msg="Unexpected handler called: %s" % key)


class TestDispatcherSet(_TestPathDispatcherBase):
    action = "set"
    expected_handlers = "set"


class TestDispatcherCaS(_TestPathDispatcherBase):
    action = "compareAndSwap"
    expected_handlers = "set"


class TestDispatcherCreate(_TestPathDispatcherBase):
    action = "create"
    expected_handlers = "set"


class TestDispatcherUpdate(_TestPathDispatcherBase):
    action = "update"
    expected_handlers = "set"


class TestDispatcherDel(_TestPathDispatcherBase):
    action = "delete"
    expected_handlers = "delete"


class TestDispatcherCaD(_TestPathDispatcherBase):
    action = "compareAndDelete"
    expected_handlers = "delete"


class TestDispatcherExpire(_TestPathDispatcherBase):
    action = "expire"
    expected_handlers = "delete"


class TestEtcdWatcher(BaseTestCase):
    def setUp(self):
        super(TestEtcdWatcher, self).setUp()
        with patch("calico.etcdutils.EtcdWatcher.reconnect") as m_reconnect:
            self.watcher = EtcdWatcher("foobar:4001", "/calico")
        self.m_client = Mock()
        self.watcher.client = self.m_client

    def test_load_initial_dump(self):
        m_response = Mock(spec=etcd.EtcdResult)
        m_response.etcd_index = 10000
        self.m_client.read.side_effect = [
            etcd.EtcdKeyNotFound(),
            m_response
        ]
        with patch("time.sleep") as m_sleep:
            self.assertEqual(self.watcher.load_initial_dump(), m_response)

        m_sleep.assert_called_once_with(1)
        self.m_client.read.assert_has_calls([
            call("/calico", recursive=True),
            call("/calico", recursive=True),
        ])
        self.assertEqual(self.watcher.next_etcd_index, 10001)
