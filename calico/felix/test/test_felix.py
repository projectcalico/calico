# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
felix.test.test_felix
~~~~~~~~~~~

Top level tests for Felix.
"""
import logging
import gevent
from calico.felix import config
import mock
import sys
import time

import calico.felix.test.stub_etcd as stub_etcd
sys.modules['etcd'] = stub_etcd

import calico.felix.futils as futils
import calico.felix.felix as felix
from calico.felix.test.base import BaseTestCase

# Logger
log = logging.getLogger(__name__)


class TestException(Exception):
    pass


class TestBasic(BaseTestCase):

    @mock.patch("calico.felix.fetcd.EtcdWatcher.load_config_and_wait_for_ready")
    @mock.patch("gevent.Greenlet.start", autospec=True)
    @mock.patch("calico.felix.felix.IptablesUpdater", autospec=True)
    @mock.patch("gevent.iwait", autospec=True, side_effect=TestException())
    def test_main_greenlet(self, m_iwait, m_IptablesUpdater, m_start, m_load):
        m_IptablesUpdater.return_value.greenlet = mock.Mock()
        m_config = mock.Mock(spec=config.Config)
        m_config.IFACE_PREFIX = "tap"
        m_config.METADATA_IP = None
        self.assertRaises(TestException,
                          felix._main_greenlet, m_config)
        m_load.assert_called_once_with(async=False)
