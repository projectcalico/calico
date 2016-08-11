# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
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
import mock
import sys

import calico.felix.test.stub_etcd as stub_etcd
import calico.felix.felix as felix
from calico.felix import futils
from calico.felix.test.base import BaseTestCase, load_config

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

    @mock.patch("calico.felix.felix.HTTPServer", autospec=True)
    @mock.patch("calico.felix.felix.load_nf_conntrack", autospec=True)
    @mock.patch("os.path.exists", autospec=True, return_value=True)
    @mock.patch("calico.felix.devices.list_interface_ips", autospec=True)
    @mock.patch("calico.felix.devices.configure_global_kernel_config",
                autospec=True)
    @mock.patch("calico.felix.devices.interface_up",
                return_value=False, autospec=True)
    @mock.patch("calico.felix.devices.interface_exists",
                return_value=False, autospec=True)
    @mock.patch("calico.felix.futils.Popen", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.check_output", autospec=True)
    @mock.patch("calico.felix.frules.HOSTS_IPSET_V4", autospec=True)
    @mock.patch("calico.felix.fetcd.EtcdAPI.load_config")
    @mock.patch("gevent.Greenlet.start", autospec=True)
    @mock.patch("calico.felix.felix.WorkloadDispatchChains", autospec=True)
    @mock.patch("calico.felix.felix.HostEndpointDispatchChains", autospec=True)
    @mock.patch("calico.felix.felix.UpdateSplitter", autospec=True)
    @mock.patch("calico.felix.felix.IptablesUpdater", autospec=True)
    @mock.patch("calico.felix.felix.MasqueradeManager", autospec=True)
    @mock.patch("gevent.iwait", autospec=True, side_effect=TestException())
    def test_main_greenlet(self, m_iwait, m_MasqueradeManager,
                           m_IptablesUpdater, m_UpdateSplitter,
                           m_host_chains, m_wl_chains,
                           m_start, m_load,
                           m_ipset_4,
                           m_check_output, m_check_call, m_popen,
                           m_iface_exists, m_iface_up,
                           m_configure_global_kernel_config,
                           m_list_interface_ips, m_path_exists, m_conntrack,
                           m_http_server):
        m_popen.return_value.communicate.return_value = "", ""
        m_IptablesUpdater.return_value.greenlet = mock.Mock()
        m_MasqueradeManager.return_value.greenlet = mock.Mock()
        m_UpdateSplitter.return_value.greenlet = mock.Mock()
        m_host_chains.return_value.greenlet = mock.Mock()
        m_wl_chains.return_value.greenlet = mock.Mock()
        m_list_interface_ips.return_value = set()
        env_dict = {
            "FELIX_ETCDADDR": "localhost:4001",
            "FELIX_ETCDSCHEME": "http",
            "FELIX_ETCDKEYFILE": "none",
            "FELIX_ETCDCERTFILE": "none",
            "FELIX_ETCDCAFILE": "none",
            "FELIX_FELIXHOSTNAME": "myhost",
            "FELIX_INTERFACEPREFIX": "tap",
            "FELIX_METADATAIP": "10.0.0.1",
            "FELIX_METADATAPORT": "1234",
            "FELIX_IPINIPENABLED": "True",
            "FELIX_IPINIPMTU": "1480",
            "FELIX_DEFAULTINPUTCHAINACTION": "RETURN",
            "FELIX_PROMETHEUSMETRICSENABLED": "True",
        }
        config = load_config("felix_missing.cfg", env_dict=env_dict)

        with gevent.Timeout(5):
            self.assertRaises(TestException,
                              felix._main_greenlet, config)
        m_load.assert_called_once_with(async=False)
        m_iface_exists.assert_called_once_with("tunl0")
        m_iface_up.assert_called_once_with("tunl0")
        m_configure_global_kernel_config.assert_called_once_with(config)
        m_conntrack.assert_called_once_with()
        m_http_server.assert_called_once_with(("0.0.0.0", 9091),
                                              felix.MetricsHandler)

    @mock.patch("calico.felix.felix.load_nf_conntrack", autospec=True)
    @mock.patch("calico.felix.felix.install_global_rules", autospec=True)
    @mock.patch("os.path.exists", autospec=True, return_value=False)
    @mock.patch("calico.felix.devices.list_interface_ips", autospec=True)
    @mock.patch("calico.felix.devices.configure_global_kernel_config",
                autospec=True)
    @mock.patch("calico.felix.futils.Popen", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.check_output", autospec=True)
    @mock.patch("calico.felix.frules.HOSTS_IPSET_V4", autospec=True)
    @mock.patch("calico.felix.fetcd.EtcdAPI.load_config")
    @mock.patch("gevent.Greenlet.start", autospec=True)
    @mock.patch("calico.felix.felix.WorkloadDispatchChains", autospec=True)
    @mock.patch("calico.felix.felix.HostEndpointDispatchChains", autospec=True)
    @mock.patch("calico.felix.felix.UpdateSplitter", autospec=True)
    @mock.patch("calico.felix.felix.IptablesUpdater", autospec=True)
    @mock.patch("calico.felix.felix.MasqueradeManager", autospec=True)
    @mock.patch("gevent.iwait", autospec=True, side_effect=TestException())
    def test_main_greenlet_no_ipv6(self, m_iwait, m_MasqueradeManager,
                                   m_IptablesUpdater, m_UpdateSplitter,
                                   m_host_chains, m_wl_chains,
                                   m_start, m_load,
                                   m_ipset_4,
                                   m_check_output, m_check_call, m_popen,
                                   m_configure_global_kernel_config,
                                   m_list_interface_ips, m_path_exists,
                                   m_install_globals, m_conntrack):
        m_popen.return_value.communicate.return_value = "", ""
        m_IptablesUpdater.return_value.greenlet = mock.Mock()
        m_MasqueradeManager.return_value.greenlet = mock.Mock()
        m_UpdateSplitter.return_value.greenlet = mock.Mock()
        m_host_chains.return_value.greenlet = mock.Mock()
        m_wl_chains.return_value.greenlet = mock.Mock()
        m_list_interface_ips.return_value = set()
        env_dict = {
            "FELIX_ETCDADDR": "localhost:4001",
            "FELIX_ETCDSCHEME": "http",
            "FELIX_ETCDKEYFILE": "none",
            "FELIX_ETCDCERTFILE": "none",
            "FELIX_ETCDCAFILE": "none",
            "FELIX_FELIXHOSTNAME": "myhost",
            "FELIX_INTERFACEPREFIX": "tap",
            "FELIX_METADATAIP": "10.0.0.1",
            "FELIX_METADATAPORT": "1234",
            "FELIX_IPINIPENABLED": "True",
            "FELIX_IPINIPMTU": "1480",
            "FELIX_DEFAULTINPUTCHAINACTION": "RETURN"
        }
        config = load_config("felix_missing.cfg", env_dict=env_dict)

        with gevent.Timeout(5):
            self.assertRaises(TestException,
                              felix._main_greenlet, config)
        m_load.assert_called_once_with(async=False)
        m_configure_global_kernel_config.assert_called_once_with(config)
        m_install_globals.assert_called_once_with(mock.ANY, mock.ANY, mock.ANY,
                                                  ip_version=4)
        m_conntrack.assert_called_once_with()

        # Cover the diags dump function.
        futils.dump_diags()
