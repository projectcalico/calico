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

from mock import patch, Mock, call
from netaddr import IPAddress
from nose.tools import *
from pycalico.datastore_datatypes import IPPool
import unittest

import startup

class TestStartup(unittest.TestCase):

    @patch("startup.client", autospec=True)
    @patch("sys.exit", autospec=True)
    def test_error_if_bgp_ipv4_conflict_no_conflict(self, m_exit, m_client):
        """
        Test check that node IP is not already in use by another node, no error.
        """
        m_client.get_hostnames_from_ips = Mock()
        m_client.get_hostnames_from_ips.return_value = {}
        startup.error_if_bgp_ip_conflict("10.0.0.1", "abcd::beef")
        self.assertFalse(m_exit.called)

    @patch("startup.client", autospec=True)
    @patch("sys.exit", autospec=True)
    def test_error_if_ip_conflict_ipv6_key_error(self, m_exit,
                                                 m_client):
        """
        Test that function accepts IP being owned by same host.
        """
        startup.hostname = "host"
        m_client.get_hostnames_from_ips = Mock()
        m_client.get_hostnames_from_ips.return_value = {"10.0.0.1":"host"}
        startup.error_if_bgp_ip_conflict("10.0.0.1", "abcd::beef")
        self.assertFalse(m_exit.called)

    @patch("startup.client", autospec=True)
    def test_error_when_bgp_ipv4_conflict(self, m_client):
        """
        Test that function exits when another node already uses ipv4 addr.
        """
        startup.hostname = "not_host"
        m_client.get_hostnames_from_ips = Mock()
        m_client.get_hostnames_from_ips.return_value = {"10.0.0.1":"host"}
        self.assertRaises(SystemExit, startup.error_if_bgp_ip_conflict,
                          "10.0.0.1", None)

    @patch("startup.client", autospec=True)
    def test_error_when_bgp_ipv6_conflict(self, m_client):
        """
        Test that function exits when another node already uses ipv6 addr.
        """
        startup.hostname = "not_host"
        m_client.get_hostnames_from_ips = Mock()
        m_client.get_hostnames_from_ips.return_value = {"abcd::beef":"host"}
        self.assertRaises(SystemExit, startup.error_if_bgp_ip_conflict,
                          None, "abcd::beef")

    @patch("startup._get_host_tunnel_ip", autospec=True)
    @patch("startup._assign_host_tunnel_addr", autospec=True)
    @patch("startup.client", autospec=True)
    def test_ensure_host_tunnel_addr_no_ip(self, m_client,
                                           m_assign_host_tunnel_addr,
                                           m_get_tunnel_host_ip):
        m_get_tunnel_host_ip.return_value = None
        ipv4_pools = [IPPool("10.0.0.0/16"),
                      IPPool("10.1.0.0/16", ipip=True)]
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True)]
        startup._ensure_host_tunnel_addr(ipv4_pools, ipip_pools)
        assert_equal(m_assign_host_tunnel_addr.mock_calls, [call(ipip_pools)])

    @patch("startup._get_host_tunnel_ip", autospec=True)
    @patch("startup._assign_host_tunnel_addr", autospec=True)
    @patch("startup.client", autospec=True)
    def test_ensure_host_tunnel_addr_non_ipip(self, m_client,
                                              m_assign_host_tunnel_addr,
                                              m_get_tunnel_host_ip):
        m_get_tunnel_host_ip.return_value = IPAddress("10.0.0.1")
        ipv4_pools = [IPPool("10.0.0.0/16"),
                      IPPool("10.1.0.0/16", ipip=True)]
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True)]
        startup._ensure_host_tunnel_addr(ipv4_pools, ipip_pools)
        assert_equal(m_client.release_ips.mock_calls,
                     [call({IPAddress("10.0.0.1")})])
        assert_equal(m_assign_host_tunnel_addr.mock_calls, [call(ipip_pools)])

    @patch("startup._get_host_tunnel_ip", autospec=True)
    @patch("startup._assign_host_tunnel_addr", autospec=True)
    @patch("startup.client", autospec=True)
    def test_ensure_host_tunnel_addr_bad_ip(self, m_client,
                                            m_assign_host_tunnel_addr,
                                            m_get_tunnel_host_ip):
        m_get_tunnel_host_ip.return_value = IPAddress("11.0.0.1")
        ipv4_pools = [IPPool("10.0.0.0/16"),
                      IPPool("10.1.0.0/16", ipip=True)]
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True)]
        startup._ensure_host_tunnel_addr(ipv4_pools, ipip_pools)
        assert_equal(m_assign_host_tunnel_addr.mock_calls, [call(ipip_pools)])

    @patch("startup.client", autospec=True)
    def test_assign_host_tunnel_addr(self, m_client):
        startup.hostname = "host"
        # First pool full, IP allocated from second pool.
        m_client.auto_assign_ips.side_effect = iter([
            ([], []),
            ([IPAddress("10.0.0.1")], [])
        ])
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True),
                      IPPool("10.0.0.0/16", ipip=True)]
        startup._assign_host_tunnel_addr(ipip_pools)
        assert_equal(
            m_client.set_per_host_config.mock_calls,
            [call("host", "IpInIpTunnelAddr", "10.0.0.1")]
        )

    @patch("sys.exit", autospec=True)
    @patch("startup.client", autospec=True)
    def test_assign_host_tunnel_addr_none_available(self,
                                                    m_client, m_exit):
        # First pool full, IP allocated from second pool.
        m_client.auto_assign_ips.side_effect = iter([
            ([], []),
            ([], [])
        ])
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True),
                      IPPool("10.0.0.0/16", ipip=True)]
        m_exit.side_effect = Exception
        assert_raises(Exception, startup._assign_host_tunnel_addr,
                      ipip_pools)
        assert_equal(m_exit.mock_calls, [call(1)])

    @patch("startup._get_host_tunnel_ip", autospec=True)
    @patch("startup.client", autospec=True)
    def test_remove_host_tunnel_addr(self, m_client, m_get_ip):
        startup.hostname = "host"
        ip_address = IPAddress("10.0.0.1")
        m_get_ip.return_value = ip_address
        startup._remove_host_tunnel_addr()
        assert_equal(m_client.release_ips.mock_calls, [call({ip_address})])
        assert_equal(m_client.remove_per_host_config.mock_calls,
                     [call("host", "IpInIpTunnelAddr")])
