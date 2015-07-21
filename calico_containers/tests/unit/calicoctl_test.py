# Copyright 2015 Metaswitch Networks
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
from StringIO import StringIO
from mock import patch, Mock
from nose_parameterized import parameterized
from netaddr import IPAddress, IPNetwork
from calico_ctl.bgp import *
from calico_ctl.bgp import validate_arguments as bgp_validate_arguments
from calico_ctl.endpoint import validate_arguments as ep_validate_arguments
from calico_ctl.node import validate_arguments as node_validate_arguments
from calico_ctl.pool import validate_arguments as pool_validate_arguments
from calico_ctl.profile import validate_arguments as profile_validate_arguments
from calico_ctl.container import validate_arguments as container_validate_arguments
from calico_ctl.utils import validate_cidr, validate_ip, validate_characters
from pycalico.datastore_datatypes import BGPPeer


class TestBgp(unittest.TestCase):

    @parameterized.expand([
        ({'<PEER_IP>':'127.a.0.1'}, True),
        ({'<PEER_IP>':'aa:bb::zz'}, True),
        ({'<AS_NUM>':9}, False),
        ({'<AS_NUM>':'9'}, False),
        ({'<AS_NUM>':'nine'}, True),
        ({'show':1, '--ipv4':1}, False)
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl bgp command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            bgp_validate_arguments(case)

            # Assert that method exits on bad input
            self.assertEqual(m_sys_exit.called, sys_exit_called)

    @patch('calico_ctl.bgp.BGPPeer', autospec=True)
    @patch('calico_ctl.bgp.client', autospec=True)
    def test_bgp_peer_add(self, m_client, m_BGPPeer):
        """
        Test bgp_peer_add function for calico_ctl bgp
        """
        # Set up mock objects
        peer = Mock(spec=BGPPeer)
        m_BGPPeer.return_value = peer

        # Set up arguments
        address = '1.2.3.4'

        # Call method under test
        bgp_peer_add(address, 4, 1)

        # Assert
        m_BGPPeer.assert_called_once_with(IPAddress(address), 1)
        m_client.add_bgp_peer.assert_called_once_with(4, peer)

    @patch('calico_ctl.bgp.client', autospec=True)
    def test_bgp_peer_remove(self, m_client):
        """
        Test bgp_peer_remove function for calicoctl bgp
        """
        # Set up arguments
        address = '1.2.3.4'

        # Call method under test
        bgp_peer_remove(address, 4)

        # Assert
        m_client.remove_bgp_peer.assert_called_once_with(4, IPAddress(address))

    @patch('calico_ctl.bgp.client', autospec=True)
    def test_set_default_node_as(self, m_client):
        """
        Test set_default_node_as function for calicoctl bgp
        """
        # Call method under test
        set_default_node_as(1)

        # Assert
        m_client.set_default_node_as.assert_called_once_with(1)

    @patch('calico_ctl.bgp.client', autospec=True)
    @patch('sys.stdout', new_callable=StringIO)
    def test_show_default_node_as(self, m_stdout, m_client):
        """
        Test for show_default_node_as() for calicoctl bgp
        """
        # Set up mock objects
        expected_return = '15'
        m_client.get_default_node_as.return_value = expected_return

        # Call method under test
        show_default_node_as()

        # Assert
        m_client.get_default_node_as.assert_called_once_with()
        self.assertEqual(m_stdout.getvalue().strip(), expected_return)

    @patch('calico_ctl.bgp.client', autospec=True)
    @patch('sys.stdout', new_callable=StringIO)
    def test_show_bgp_node_mesh(self, m_stdout, m_client):
        """
        Test for show_bgp_node_mesh() for calicoctl bgp
        """
        # Set up mock objects
        expected_return = '15'
        m_client.get_bgp_node_mesh.return_value = expected_return

        # Call method under test
        show_bgp_node_mesh()

        # Assert
        m_client.get_bgp_node_mesh.assert_called_once_with()
        self.assertEqual(m_stdout.getvalue().strip(), 'on')

    @patch('calico_ctl.bgp.client', autospec=True)
    @patch('sys.stdout', new_callable=StringIO)
    def test_show_bgp_node_mesh_fail(self, m_stdout, m_client):
        """
        Test for show_bgp_node_mesh() for calicoctl bgp
        """
        # Set up mock objects
        expected_return = ''
        m_client.get_bgp_node_mesh.return_value = expected_return

        # Call method under test
        show_bgp_node_mesh()

        # Assert
        m_client.get_bgp_node_mesh.assert_called_once_with()
        self.assertEqual(m_stdout.getvalue().strip(), 'off')

    @patch('calico_ctl.bgp.client', autospec=True)
    def test_set_bgp_node_mesh(self, m_client):
        """
        Test for set_bgp_node_mesh for calicoctl bgp
        """
        # Call method under test
        set_bgp_node_mesh(True)

        # Assert
        m_client.set_bgp_node_mesh.assert_called_once_with(True)


class TestContainer(unittest.TestCase):

    @parameterized.expand([
        ({'<CONTAINER>':'node1', 'ip':1, 'add':1, '<IP>':'127.a.0.1'}, True),
        ({'<CONTAINER>':'node1', 'ip':1, 'add':1, '<IP>':'aa:bb::zz'}, True),
        ({'add':1, '<CONTAINER>':'node1', '<IP>':'127.a.0.1'}, True),
        ({'add':1, '<CONTAINER>':'node1', '<IP>':'aa:bb::zz'}, True)
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl container command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            container_validate_arguments(case)

            # Assert method exits if bad input
            self.assertEqual(m_sys_exit.called, sys_exit_called)


class TestEndpoint(unittest.TestCase):

    @parameterized.expand([
        ({'<PROFILES>':['profile-1', 'profile-2', 'profile-3']}, False),
        ({'<PROFILES>':['Profile1', 'Profile!']}, True),
        ({}, False)
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl endpoint command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            ep_validate_arguments(case)

            # Assert method exits if bad input
            self.assertEqual(m_sys_exit.called, sys_exit_called)


class TestNode(unittest.TestCase):

    @parameterized.expand([
        ({'--ip':'127.a.0.1'}, True),
        ({'--ip':'aa:bb::cc'}, True),
        ({'--ip':'127.0.0.1', '--ip6':'127.0.0.1'}, True),
        ({'--ip':'127.0.0.1', '--ip6':'aa:bb::zz'}, True)
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl node command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            node_validate_arguments(case)

            # Assert that method exits on bad input
            self.assertEqual(m_sys_exit.called, sys_exit_called)


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
            pool_validate_arguments(case)

            # Call method under test for each test case
            self.assertEqual(m_sys_exit.called, sys_exit_called)


class TestProfile(unittest.TestCase):

    @parameterized.expand([
        ({'<PROFILE>':'profile-1'}, False),
        ({'<PROFILE>':'Profile!'}, True),
        ({'<SRCTAG>':'Tag-1', '<DSTTAG>':'Tag-2'}, False),
        ({'<SRCTAG>':'Tag~1', '<DSTTAG>':'Tag~2'}, True),
        ({'<SRCCIDR>':'127.a.0.1'}, True),
        ({'<DSTCIDR>':'aa:bb::zz'}, True),
        ({'<SRCCIDR>':'1.2.3.4', '<DSTCIDR>':'1.2.3.4'}, False),
        ({'<ICMPCODE>':'5'}, False),
        ({'<ICMPTYPE>':'16'}, False),
        ({'<ICMPCODE>':100, '<ICMPTYPE>':100}, False),
        ({'<ICMPCODE>':4, '<ICMPTYPE>':255}, True),
        ({}, False)
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl profile command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            profile_validate_arguments(case)

            # Assert that method exits on bad input
            self.assertEqual(m_sys_exit.called, sys_exit_called)


class TestUtils(unittest.TestCase):

    @parameterized.expand([
        ('127.a.0.1', False),
        ('aa:bb::zz', False),
        ('1.2.3.4', True),
        ('1.2.3.0/24', True),
        ('aa:bb::ff', True),
        ('1111:2222:3333:4444:5555:6666:7777:8888', True),
        ('4294967295', False)
    ])
    def test_validate_cidr(self, cidr, expected_result):
        """
        Test validate_cidr function in calico_ctl utils
        """
        # Call method under test
        test_result = validate_cidr(cidr)

        # Assert
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('1.2.3.4', 4, True),
        ('1.2.3.4', 6, False),
        ('1.2.3.4', 4, True),
        ('1.2.3.0/24', 4, False),
        ('aa:bb::ff', 4, False),
        ('aa:bb::ff', 6, True),
        ('1111:2222:3333:4444:5555:6666:7777:8888', 6, True),
        ('4294967295', 4, True),
        ('5000000000', 4, False)
    ])
    def test_validate_ip(self, ip, version, expected_result):
        """
        Test validate_ip function in calico_ctl utils
        """
        # Call method under test
        test_result = validate_ip(ip, version)

        # Assert
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('abcdefghijklmnopqrstuvwxyz', True),
        ('0123456789', True),
        ('profile_1', True),
        ('profile-1', True),
        ('profile 1', False),
        ('profile.1', True),
        ('!', False),
        ('@', False),
        ('#', False),
        ('$', False),
        ('%', False),
        ('^', False),
        ('&', False),
        ('*', False),
        ('()', False)
    ])
    def test_validate_characters(self, input_string, expected_result):
        """
        Test validate_characters function in calico_ctl utils
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            test_result = validate_characters(input_string)

            # Assert expected result
            self.assertEqual(expected_result, test_result)
