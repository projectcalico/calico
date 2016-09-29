# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
import unittest

from etcd import EtcdException
from mock import ANY
from mock import call
from mock import Mock
from mock import patch
from urllib3.exceptions import ReadTimeoutError

from networking_calico.etcdutils import EtcdClientOwner
from networking_calico.etcdutils import EtcdWatcher
from networking_calico.etcdutils import PathDispatcher
from networking_calico.etcdutils import ResyncRequired

# Since other tests patch the module table, make sure we have the same etcd
# module as the module under test.
from networking_calico.etcdutils import etcd

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


# Prevent test infrastructure from thinking that it should run the
# _TestPathDispatcherBase class in its own right.
del _TestPathDispatcherBase


class TestEtcdClientOwner(unittest.TestCase):
    @patch("etcd.Client", autospec=True)
    def test_create(self, m_client_cls):
        # Check creation with a single string, which is required for
        # back-compatibility.
        self._test_create_internal("localhost:1234", m_client_cls)

    @patch("etcd.Client", autospec=True)
    def test_create_list(self, m_client_cls):
        # Check creation with a list of servers.
        self._test_create_internal(["localhost:1234"], m_client_cls)

    def _test_create_internal(self, etcd_addrs, m_client_cls):
        owner = EtcdClientOwner(etcd_addrs,
                                etcd_scheme="https",
                                etcd_key="/path/to/key",
                                etcd_cert="/path/to/cert",
                                etcd_ca="/path/to/ca")
        m_client = m_client_cls.return_value
        m_client.expected_cluster_id = "abcdef"
        owner.reconnect()
        self.assertEqual(m_client_cls.mock_calls,
                         [call(host="localhost", port=1234,
                               expected_cluster_id=None,
                               cert=("/path/to/cert", "/path/to/key"),
                               ca_cert="/path/to/ca", protocol="https"),
                          call(host="localhost", port=1234,
                               expected_cluster_id="abcdef",
                               cert=("/path/to/cert", "/path/to/key"),
                               ca_cert="/path/to/ca", protocol="https")])

    @patch("etcd.Client", autospec=True)
    def test_create_default(self, m_client):
        owner = EtcdClientOwner(["localhost"])
        assert owner
        self.assertEqual(m_client.mock_calls,
                         [call(host="localhost", port=4001,
                               expected_cluster_id=None,
                               cert=None, ca_cert=None, protocol="http")])

    @patch("etcd.Client", autospec=True)
    def test_create_multiple(self, m_client):
        owner = EtcdClientOwner(["etcd1:1234", "etcd2:2345"])
        assert owner
        self.assertEqual(m_client.mock_calls,
                         [call(host=ANY,
                               expected_cluster_id=None,
                               allow_reconnect=True,
                               cert=None, ca_cert=None, protocol="http")])
        # We shuffle the hosts so we need to check them by hand.
        _, _, kwargs = m_client.mock_calls[0]
        hosts = kwargs["host"]
        self.assertIsInstance(hosts, tuple)
        self.assertEqual(sorted(hosts), [("etcd1", 1234), ("etcd2", 2345)])


class ExpectedException(Exception):
    pass


class TestEtcdWatcher(unittest.TestCase):
    def setUp(self):
        super(TestEtcdWatcher, self).setUp()
        self.reconnect_patch = patch(
            "networking_calico.etcdutils.EtcdWatcher.reconnect"
        )
        self.m_reconnect = self.reconnect_patch.start()
        self.watcher = EtcdWatcher(["foobar:4001"], "/calico")
        self.m_client = Mock()
        self.watcher.client = self.m_client
        self.m_dispatcher = Mock(spec=PathDispatcher)
        self.watcher.dispatcher = self.m_dispatcher

    @patch("time.sleep", autospec=True)
    def test_mainline(self, m_sleep):
        m_snap_response = Mock()
        m_snap_response.etcd_index = 1
        m_poll_response = Mock()
        m_poll_response.modifiedIndex = 2
        responses = [
            m_snap_response, m_poll_response, ResyncRequired(),  # Loop 1
            EtcdException(),  # Loop 2
            ExpectedException(),  # Loop 3, Break out of loop.
        ]
        self.m_client.read.side_effect = iter(responses)
        with patch.object(self.watcher, "_on_pre_resync",
                          autospec=True) as m_pre_r:
            with patch.object(self.watcher, "_on_snapshot_loaded",
                              autospec=True) as m_snap_load:
                self.assertRaises(ExpectedException, self.watcher.loop)
        # _on_pre_resync() called once per loop.
        self.assertEqual(m_pre_r.mock_calls, [call(), call(), call()])
        # The snapshot only loads successfully the first time.
        self.assertEqual(m_snap_load.mock_calls, [call(m_snap_response)])
        self.assertEqual(self.m_dispatcher.handle_event.mock_calls,
                         [call(m_poll_response)])
        # Should sleep after exception.
        m_sleep.assert_called_once_with(1)

    def test_loop_stopped(self):
        self.watcher._stopped = True

        with patch.object(self.watcher, "_on_pre_resync",
                          autospec=True) as m_pre_r:
            self.watcher.loop()
        self.assertFalse(m_pre_r.called)

    def test_register(self):
        self.watcher.register_path("key", foo="bar")
        self.assertEqual(self.m_dispatcher.register.mock_calls,
                         [call("key", foo="bar")])

    @patch("time.sleep", autospec=True)
    def test_wait_for_ready(self, m_sleep):
        m_resp_1 = Mock()
        m_resp_1.value = "false"
        m_resp_2 = Mock()
        m_resp_2.value = "true"
        responses = [
            etcd.EtcdException(),
            etcd.EtcdKeyNotFound(),
            m_resp_1,
            m_resp_2,
        ]
        self.m_client.read.side_effect = iter(responses)
        self.watcher.wait_for_ready(1)
        self.assertEqual(m_sleep.mock_calls, [call(1)] * 3)

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

    def test_load_initial_dump_stopped(self):
        self.watcher.stop()
        self.m_client.read.side_effect = etcd.EtcdKeyNotFound()
        self.assertRaises(etcd.EtcdKeyNotFound, self.watcher.load_initial_dump)

    def test_resync_set(self):
        self.watcher.next_etcd_index = 1
        self.watcher.resync_after_current_poll = True
        self.assertRaises(ResyncRequired, self.watcher.wait_for_etcd_event)
        self.assertFalse(self.watcher.resync_after_current_poll)

    @patch("time.sleep", autospec=True)
    def test_wait_for_etcd_event_conn_failed(self, m_sleep):
        self.watcher.next_etcd_index = 1
        m_resp = Mock()
        m_resp.modifiedIndex = 123
        read_timeout = etcd.EtcdConnectionFailed()
        read_timeout.cause = ReadTimeoutError(Mock(), "", "")
        other_error = etcd.EtcdConnectionFailed()
        other_error.cause = ExpectedException()
        responses = [
            read_timeout,
            other_error,
            m_resp,
        ]
        self.m_client.read.side_effect = iter(responses)
        event = self.watcher.wait_for_etcd_event()
        self.assertEqual(event, m_resp)
        self.assertEqual(m_sleep.mock_calls, [call(1)])

    def test_wait_for_etcd_event_cluster_id_changed(self):
        self.watcher.next_etcd_index = 1
        responses = [
            etcd.EtcdClusterIdChanged(),
        ]
        self.m_client.read.side_effect = iter(responses)
        self.assertRaises(ResyncRequired, self.watcher.wait_for_etcd_event)

    def test_wait_for_etcd_event_index_cleared(self):
        self.watcher.next_etcd_index = 1
        responses = [
            etcd.EtcdEventIndexCleared(),
        ]
        self.m_client.read.side_effect = iter(responses)
        self.assertRaises(ResyncRequired, self.watcher.wait_for_etcd_event)

    @patch("time.sleep", autospec=True)
    def test_wait_for_etcd_event_unexpected_error(self, m_sleep):
        self.watcher.next_etcd_index = 1
        responses = [
            etcd.EtcdException(),
        ]
        self.m_client.read.side_effect = iter(responses)
        self.assertRaises(ResyncRequired, self.watcher.wait_for_etcd_event)
        self.assertEqual(m_sleep.mock_calls, [call(1)])

    def test_coverage(self):
        # These methods are no-ops.
        self.watcher._on_pre_resync()
        self.watcher._on_snapshot_loaded(Mock())

    def tearDown(self):
        self.reconnect_patch.stop()
        super(TestEtcdWatcher, self).tearDown()
