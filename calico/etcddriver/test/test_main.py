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
calico.etcddriver.test.test_main
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Test __main__ module.
"""

import logging
import socket
from unittest import TestCase

from mock import Mock, call, patch

from calico.etcddriver.__main__ import main

_log = logging.getLogger(__name__)


class TestMain(TestCase):
    @patch("os.getppid", autospec=True)
    @patch("socket.socket", spec=socket.socket)  # mock bug prevents autospec
    @patch("calico.common.default_logging", autospec=True)
    @patch("calico.etcddriver.driver.EtcdDriver", autospec=True)
    def test_mainline(self, m_driver_cls, m_logging, m_socket, m_ppid):
        m_ppid.return_value = 123
        m_driver = m_driver_cls.return_value
        m_driver.join.side_effect = iter([
            False,
            True
        ])
        main()
        self.assertEqual(m_driver.mock_calls,
                         [call.start(),
                          call.join(timeout=1),
                          call.join(timeout=1)])
        self.assertEqual(m_logging.mock_calls,
                         [call(gevent_in_use=False,
                               syslog_executable_name="calico-felix-etcd")])

    @patch("os.getppid", autospec=True)
    @patch("socket.socket", spec=socket.socket)  # mock bug prevents autospec
    @patch("calico.common.default_logging", autospec=True)
    @patch("calico.etcddriver.driver.EtcdDriver", autospec=True)
    def test_reparent(self, m_driver_cls, m_logging, m_socket, m_ppid):
        m_ppid.side_effect = iter([123, 123, 1])
        m_driver = m_driver_cls.return_value
        m_driver.join.return_value = False
        main()
        self.assertEqual(m_driver.mock_calls,
                         [call.start(),
                          call.join(timeout=1),
                          call.join(timeout=1),
                          call.stop()])

    @patch("os.getppid", autospec=True)
    @patch("socket.socket", spec=socket.socket)  # mock bug prevents autospec
    @patch("calico.common.default_logging", autospec=True)
    @patch("calico.etcddriver.driver.EtcdDriver", autospec=True)
    def test_connection_failure(self, m_driver_cls, m_logging, m_socket,
                                m_ppid):
        m_ppid.side_effect = iter([123, 123, 1])
        m_sck = m_socket.return_value
        m_sck.connect.side_effect = RuntimeError()
        self.assertRaises(RuntimeError, main)
