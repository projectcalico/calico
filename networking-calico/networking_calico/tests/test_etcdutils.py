# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
import unittest

from mock import call
from mock import Mock
from mock import patch

from networking_calico.etcdutils import _is_string_instance
from networking_calico.etcdutils import EtcdWatcher
from networking_calico.etcdutils import PathDispatcher
from networking_calico.etcdutils import Response
from networking_calico import etcdv3

_log = logging.getLogger(__name__)

patch.object = getattr(patch, "object")  # Keep PyCharm linter happy.

SAME_AS_KEY = object()


class _TestPathDispatcherBase(unittest.TestCase):
    """Abstract base class for Dispatcher tests."""
    # Etcd action that this class tests.
    action = None
    # Expected handler type, "set" or "delete".
    expected_handlers = None

    def setUp(self):
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
        if _is_string_instance(exp_handler):
            exp_handler = exp_handler.strip("/")
        m_response = Mock(spec=Response)
        m_response.key = key
        m_response.action = self.action
        self.dispatcher.handle_event(m_response)
        exp_handlers = self.handlers[self.expected_handlers]
        for handler_key, handler in exp_handlers.items():
            assert isinstance(handler, Mock)
            if handler_key == exp_handler:
                continue
            self.assertFalse(handler.called,
                             "Unexpected set handler %s was called for "
                             "key %s" % (handler_key, key))
        unexp_handlers = self.handlers[self.unexpected_handlers]
        for handler_key, handler in unexp_handlers.items():
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
        m_result = Mock(spec=Response)
        m_result.key = "/a"
        m_result.action = "unknown"
        self.dispatcher.handle_event(m_result)
        for handlers in self.handlers.values():
            for key, handler in handlers.items():
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


# Prevent test infrastructure from thinking that it should run the
# _TestPathDispatcherBase class in its own right.
del _TestPathDispatcherBase


class ExpectedException(Exception):
    pass


def _rsp_to_tuple(rsp):
    item = {'key': rsp.key.encode(), 'mod_revision': rsp.mod_revision}
    return (rsp.value.encode(), item)


class TestEtcdWatcher(unittest.TestCase):
    def setUp(self):
        super(TestEtcdWatcher, self).setUp()
        self.m_client = Mock()
        etcdv3._client = self.m_client
        self.watcher = EtcdWatcher("/calico")
        self.m_dispatcher = Mock(spec=PathDispatcher)
        self.watcher.dispatcher = self.m_dispatcher

    def tearDown(self):
        etcdv3._client = None
        super(TestEtcdWatcher, self).tearDown()

    def test_mainline(self):
        # Set up 3 iterations through the watcher's main loop.
        #
        # 1. No data for snapshot.  Watch throws exception.
        #
        # 2. Data for snapshot.  Watch throws exception.
        #
        # 3. Throw ExpectedException(), to exit.
        status = {'header': {'cluster_id': '1234', 'revision': '10'}}
        self.m_client.status.side_effect = iter([
            # Iteration 1.
            status,
            # Iteration 2.
            status,
            # Iteration 3.
            status,
        ])
        rsp1 = Response(action='set',
                        key='foo',
                        value='bar',
                        mod_revision='12')
        self.m_client.get.side_effect = iter([
            [],
            [_rsp_to_tuple(rsp1)],
            ExpectedException()
        ])
        self.m_client.watch_prefix.side_effect = etcdv3.KeyNotFound()

        with patch.object(self.watcher, "_pre_snapshot_hook",
                          autospec=True) as m_pre:
            m_pre.return_value = None
            with patch.object(self.watcher, "_post_snapshot_hook",
                              autospec=True) as m_post:
                self.assertRaises(ExpectedException, self.watcher.start)

        # _pre_snapshot_hook() called 3 times.
        self.assertEqual(m_pre.mock_calls, [call(), call(), call()])

        # _post_snapshot_hook() called twice.
        self.assertEqual(m_post.mock_calls, [call(None), call(None)])

        # watch_prefix called twice.
        self.assertEqual(self.m_client.watch_prefix.mock_calls, [
            call('/calico', start_revision='11'),
            call('/calico', start_revision='11')
        ])

        # Snapshot event dispatched once.
        self.assertEqual(self.m_dispatcher.handle_event.mock_calls,
                         [call(rsp1)])

    def test_register(self):
        self.watcher.register_path("key", foo="bar")
        self.assertEqual(self.m_dispatcher.register.mock_calls,
                         [call("key", foo="bar")])
