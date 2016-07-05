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

import unittest

from mock import patch, Mock
from nose_parameterized import parameterized
from netaddr import IPNetwork
from pycalico.datastore_datatypes import IPPool
from pycalico.datastore_errors import InvalidBlockSizeError
from pycalico.ipam import HostAffinityClaimedError

from calico_ctl import pool


class TestPool(unittest.TestCase):

    @parameterized.expand([
        ({'add':1, '<CIDRS>':['127.a.0.1']}, True),
        ({'add':1, '<CIDRS>':['aa:bb::zz']}, True),
        ({'add':1, '<CIDRS>':['1.2.3.4']}, False),
        ({'add':1, '<CIDRS>':['1.2.3.0/24', '8.8.0.0/16']}, False),
        ({'add':1, '<CIDRS>':['aa:bb::ff']}, False),
        ({'range':1, 'add':1, '<START_IP>':'1.2.3.0',
          '<END_IP>':'1.2.3.255'}, False),
        ({'range':1, 'add':1, '<START_IP>':'1.2.3.255',
          '<END_IP>':'1.2.3.1'}, True),
        ({'range':1, 'add':1, '<START_IP>':'1.2.3.0',
          '<END_IP>':'bad'}, True),
        ({'range':1, 'add':1, '<START_IP>':'bad',
          '<END_IP>':'1.2.3.1'}, True),
        ({'range':1, 'add':1, '<START_IP>':'1.2.3.255',
          '<END_IP>':'aaaa::'}, True),
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl pool command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            pool.validate_arguments(case)

            # Call method under test for each test case
            self.assertEqual(m_sys_exit.called, sys_exit_called)

    @patch("calico_ctl.pool.client", autospec=True)
    @patch("calico_ctl.pool.IPPool", autospec=True)
    def test_add_bad_pool_size(self, m_IPPool, m_client):
        """
        Test ip_pool_add exits when pool with bad prefix is passed in.
        """
        m_IPPool.side_effect = InvalidBlockSizeError
        self.assertRaises(SystemExit, pool.ip_pool_add, cidrs=["10.10.10.10/32"],
                          version=4, ipip=False, masquerade=False)

    @patch("calico_ctl.pool.client", autospec=True)
    @patch("calico_ctl.pool.IPPool", autospec=True)
    def test_add_bad_pool_range(self, m_IPPool, m_client):
        """
        Test ip_pool_range_add exits when range with bad prefix is passed in.
        """
        m_client.get_ip_pools.return_value = []
        m_IPPool.side_effect = InvalidBlockSizeError
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            pool.ip_pool_range_add("10.10.10.10", "10.10.11.10", 4, False, False)

            self.assertTrue(m_sys_exit.called)

    @patch("time.sleep")
    @patch("calico_ctl.pool.client", autospec=True)
    def test_ip_pool_remove(self, m_client, m_sleep):
        """
        Test mainline function of ip_pool_remove.
        """
        net1 = IPNetwork("1.2.3.0/24")
        m_client.remove_ip_pool.side_effect = HostAffinityClaimedError

        m_pool = IPPool(net1)
        m_pool.cidr = net1.ip
        m_client.get_ip_pool_config.return_value = m_pool

        self.assertRaises(SystemExit, pool.ip_pool_remove, [str(net1)], 4)
        m_client.get_ip_pool_config.assert_called_once_with(4, net1)
        m_client.set_ip_pool_config.assert_called_once_with(4, m_pool)
        self.assertEqual(m_pool.disabled, True)
        m_client.release_pool_affinities.assert_called_once_with(m_pool)
        m_client.remove_ip_pool.assert_called_once_with(4, net1.ip)

    @patch("calico_ctl.pool.client", autospec=True)
    def test_add_overlapping_existing_pool(self, m_client):
        """
        Test ip_pool_add exits when a pool is added that falls within an
        existing pool.
        """
        m_client.get_ip_pools.return_value = [IPPool("10.10.10.0/24")]
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            pool.ip_pool_add(cidrs=["10.10.10.0/25"], version=4,
                             ipip=False, masquerade=False)

            self.assertTrue(m_sys_exit.called)

    @patch("calico_ctl.pool.client", autospec=True)
    def test_add_overlapping_existing_pool_2(self, m_client):
        """
        Test ip_pool_add exits when a pool is added that fully encompasses an
        existing pool.
        """
        m_client.get_ip_pools.return_value = [IPPool("10.10.10.0/26")]
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            pool.ip_pool_add(cidrs=["10.10.10.0/24"], version=4,
                             ipip=False, masquerade=False)

            self.assertTrue(m_sys_exit.called)

    @patch("calico_ctl.pool.client", autospec=True)
    def test_add_overlapping_new_pools(self, m_client):
        """
        Test ip_pool_add exits when two new pools overlap with
        each other.
        """
        m_client.get_ip_pools.return_value = []
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            pool.ip_pool_add(cidrs=["10.10.10.0/25", "10.10.10.0/26"],
                             version=4, ipip=False, masquerade=False)

            self.assertTrue(m_sys_exit.called)
