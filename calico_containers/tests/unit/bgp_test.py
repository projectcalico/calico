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
from netaddr import IPAddress

from calico_ctl import bgp
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
            bgp.validate_arguments(case)

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
        bgp.bgp_peer_add(address, 4, 1)

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
        bgp.bgp_peer_remove(address, 4)

        # Assert
        m_client.remove_bgp_peer.assert_called_once_with(4, IPAddress(address))

    @patch('calico_ctl.bgp.client', autospec=True)
    def test_set_default_node_as(self, m_client):
        """
        Test set_default_node_as function for calicoctl bgp
        """
        # Call method under test
        bgp.set_default_node_as(1)

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
        bgp.show_default_node_as()

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
        bgp.show_bgp_node_mesh()

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
        bgp.show_bgp_node_mesh()

        # Assert
        m_client.get_bgp_node_mesh.assert_called_once_with()
        self.assertEqual(m_stdout.getvalue().strip(), 'off')

    @patch('calico_ctl.bgp.client', autospec=True)
    def test_set_bgp_node_mesh(self, m_client):
        """
        Test for set_bgp_node_mesh for calicoctl bgp
        """
        # Call method under test
        bgp.set_bgp_node_mesh(True)

        # Assert
        m_client.set_bgp_node_mesh.assert_called_once_with(True)

