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
import calico.felix.futils as futils
import calico.felix.felix as felix
from calico.felix.test.base import BaseTestCase

# Logger
log = logging.getLogger(__name__)


class TestException(Exception):
    pass

class TestBasic(BaseTestCase):
    def setUp(self):
        super(TestBasic, self).setUp()
        self._real_etcd = sys.modules.get('etcd', None)
        sys.modules['etcd'] = stub_etcd

    def tearDown(self):
        super(TestBasic, self).tearDown()
        if self._real_etcd is None:
            sys.modules.pop('etcd')
        else:
            sys.modules['etcd'] = self._real_etcd

    @mock.patch("calico.felix.devices.check_kernel_config", autospec=True)
    @mock.patch("calico.felix.devices.interface_up",
                return_value=False, autospec=True)
    @mock.patch("calico.felix.devices.interface_exists",
                return_value=False, autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.frules.HOSTS_IPSET_V4", autospec=True)
    @mock.patch("calico.felix.fetcd.EtcdAPI.load_config")
    @mock.patch("gevent.Greenlet.start", autospec=True)
    @mock.patch("calico.felix.felix.UpdateSplitter", autospec=True)
    @mock.patch("calico.felix.felix.IptablesUpdater", autospec=True)
    @mock.patch("calico.felix.felix.MasqueradeManager", autospec=True)
    @mock.patch("gevent.iwait", autospec=True, side_effect=TestException())
    def test_main_greenlet(self, m_iwait, m_MasqueradeManager,
                           m_IptablesUpdater, m_UpdateSplitter,
                           m_start, m_load,
                           m_ipset_4, m_check_call, m_iface_exists,
                           m_iface_up, m_check_kernel_config):
        m_IptablesUpdater.return_value.greenlet = mock.Mock()
        m_MasqueradeManager.return_value.greenlet = mock.Mock()
        m_UpdateSplitter.return_value.greenlet = mock.Mock()
        m_config = mock.Mock(spec=config.Config)
        m_config.HOSTNAME = "myhost"
        m_config.IFACE_PREFIX = "tap"
        m_config.METADATA_IP = "10.0.0.1"
        m_config.METADATA_PORT = 1234
        m_config.IP_IN_IP_ENABLED = True
        m_config.IP_IN_IP_MTU = 1480
        m_config.DEFAULT_INPUT_CHAIN_ACTION = "RETURN"
        with gevent.Timeout(5):
            self.assertRaises(TestException,
                              felix._main_greenlet, m_config)
        m_load.assert_called_once_with(async=False)
        m_iface_exists.assert_called_once_with("tunl0")
        m_iface_up.assert_called_once_with("tunl0")
        m_check_kernel_config.assert_called_once_with()

        # Check all IptablesUpdaters get passed to the splitter, which handles
        # cleanup.
        _, args, _ = m_UpdateSplitter.mock_calls[0]
        updaters = args[4]  # List of IptablesUpdaters should be the 5th arg.
        # But check that it contains what we expect.
        self.assertEqual(updaters[0], m_IptablesUpdater.return_value)
        num_ipt_upds = len([c for c in m_IptablesUpdater.mock_calls
                            if c[0] == ""])
        self.assertEqual(len(updaters), num_ipt_upds,
                         "Number of IptablesUpdaters passed to UpdateSplitter"
                         "not the same as number that were created.")
