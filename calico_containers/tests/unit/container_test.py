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

from mock import patch, Mock, call
from nose_parameterized import parameterized
from netaddr import IPAddress, IPNetwork
from subprocess import CalledProcessError

from calico_ctl.bgp import *
from calico_ctl import container
from calico_ctl import utils
from pycalico.datastore_datatypes import Endpoint, IPPool


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
            container.validate_arguments(case)

            # Assert method exits if bad input
            self.assertEqual(m_sys_exit.called, sys_exit_called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_add(self, m_netns, m_get_pool_or_exit, m_client,
                           m_get_container_info_or_exit, m_enforce_root):
        """
        Test container_add method of calicoctl container command
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'},
            'HostConfig': {'NetworkMode': "not host"}
        }
        m_client.get_endpoint.side_effect = KeyError
        m_client.get_default_next_hops.return_value = 'next_hops'

        # Call method under test
        test_return = container.container_add('container1', '1.1.1.1', 'interface')

        # Assert
        m_enforce_root.assert_called_once_with()
        m_get_container_info_or_exit.assert_called_once_with('container1')
        m_client.get_endpoint.assert_called_once_with(
            hostname=utils.hostname,
            orchestrator_id=utils.ORCHESTRATOR_ID,
            workload_id=666
        )
        m_get_pool_or_exit.assert_called_once_with(IPAddress('1.1.1.1'))
        m_client.get_default_next_hops.assert_called_once_with(utils.hostname)

        # Check an enpoint object was returned
        self.assertTrue(isinstance(test_return, Endpoint))

        self.assertTrue(m_netns.create_veth.called)
        self.assertTrue(m_netns.move_veth_into_ns.called)
        self.assertTrue(m_netns.add_ip_to_ns_veth.called)
        self.assertTrue(m_netns.add_ns_default_route.called)
        self.assertTrue(m_netns.get_ns_veth_mac.called)
        self.assertTrue(m_client.set_endpoint.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    def test_container_add_container_host_ns(self, m_client,
                         m_get_container_info_or_exit, m_enforce_root):
        """
        Test container_add method of calicoctl container command when the
        container shares the host namespace.
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'},
            'HostConfig': {'NetworkMode': 'host'}
        }
        m_client.get_endpoint.side_effect = KeyError

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_add,
                          'container1', '1.1.1.1', 'interface')
        m_enforce_root.assert_called_once_with()

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    def test_container_add_existing_container(
            self, m_get_pool_or_exit, m_client, m_get_container_info_or_exit,
            m_enforce_root):
        """
        Test container_add when a container already exists.

        Do not raise an exception when the client tries 'get_endpoint'
        Assert that the system then exits and all expected calls are made
        """
        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_add,
                          'container1', '1.1.1.1', 'interface')

        # Assert only expected calls were made
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertFalse(m_get_pool_or_exit.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    def test_container_add_container_not_running(
            self, m_get_pool_or_exit, m_client,
            m_get_container_info_or_exit, m_enforce_root):
        """
        Test container_add when a container is not running

        get_container_info_or_exit returns a running state of value 0
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock object
        m_client.get_endpoint.side_effect = KeyError
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 0, 'Pid': 'Pid_info'}
        }

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_add,
                          'container1', '1.1.1.1', 'interface')

        # Assert only expected calls were made
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertFalse(m_get_pool_or_exit.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    def test_container_add_not_ipv4_configured(
            self, m_get_pool_or_exit, m_client, m_get_container_info_or_exit,
            m_enforce_root):
        """
        Test container_add when the client cannot obtain next hop IPs

        client.get_default_next_hops returns an empty dictionary, which produces
        a KeyError when trying to determine the IP.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_client.get_endpoint.side_effect = KeyError
        m_client.get_default_next_hops.return_value = {}

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_add,
                          'container1', '1.1.1.1', 'interface')

        # Assert only expected calls were made
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_client.get_default_next_hops.called)
        self.assertFalse(m_client.assign_address.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_add_ip_previously_assigned(
            self, m_netns, m_get_pool_or_exit, m_client,
            m_get_container_info_or_exit, m_enforce_root):
        """
        Test container_add when an ip address is already assigned in pool

        client.assign_address returns an empty list.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock object
        m_client.get_endpoint.side_effect = KeyError
        m_client.assign_address.return_value = []

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_add,
                          'container1', '1.1.1.1', 'interface')

        # Assert only expected calls were made
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_client.get_default_next_hops.called)
        self.assertTrue(m_client.assign_address.called)
        self.assertFalse(m_netns.create_veth.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_container_id', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_remove(self, m_netns, m_client,  m_get_container_id,
                              m_enforce_root):
        """
        Test for container_remove of calicoctl container command
        """
        # Set up mock objects
        m_get_container_id.return_value = 666
        ipv4_nets = set()
        ipv4_nets.add(IPNetwork(IPAddress('1.1.1.1')))
        ipv6_nets = set()
        m_endpoint = Mock(spec=Endpoint)
        m_endpoint.ipv4_nets = ipv4_nets
        m_endpoint.ipv6_nets = ipv6_nets
        m_endpoint.endpoint_id = 12
        m_endpoint.name = "eth1234"
        ippool = IPPool('1.1.1.1/24')
        m_client.get_endpoint.return_value = m_endpoint
        m_client.get_ip_pools.return_value = [ippool]

        # Call method under test
        container.container_remove('container1')

        # Assert
        m_enforce_root.assert_called_once_with()
        m_get_container_id.assert_called_once_with('container1')
        m_client.get_endpoint.assert_called_once_with(
            hostname=utils.hostname,
            orchestrator_id=utils.ORCHESTRATOR_ID,
            workload_id=666
        )
        self.assertEqual(m_client.unassign_address.call_count, 1)
        m_netns.remove_veth.assert_called_once_with("eth1234")
        m_client.remove_workload.assert_called_once_with(
            utils.hostname, utils.ORCHESTRATOR_ID, 666)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_container_id', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    def test_container_remove_no_endpoint(
            self, m_client, m_get_container_id, m_enforce_root):
        """
        Test for container_remove when the client cannot obtain an endpoint

        client.get_endpoint raises a KeyError.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_client.get_endpoint.side_effect = KeyError

        # Call function under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_remove, 'container1')

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_container_id.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertFalse(m_client.get_ip_pools.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_ip_add_ipv4(
            self, m_netns, m_client, m_get_container_info_or_exit,
            m_get_pool_or_exit, m_enforce_root):
        """
        Test for container_ip_add with an ipv4 ip argument

        Assert that the correct calls associated with an ipv4 address are made
        """
        # Set up mock objects
        pool_return = 'pool'
        m_get_pool_or_exit.return_value = pool_return
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        m_endpoint = Mock()
        m_client.get_endpoint.return_value = m_endpoint

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1.1.1.1'
        ip_addr = IPAddress(ip)
        interface = 'interface'

        # Call method under test
        container.container_ip_add(container_name, ip, interface)

        # Assert
        m_enforce_root.assert_called_once_with()
        m_get_pool_or_exit.assert_called_once_with(ip_addr)
        m_get_container_info_or_exit.assert_called_once_with(container_name)
        m_client.get_endpoint.assert_called_once_with(
            hostname=utils.hostname,
            orchestrator_id=utils.ORCHESTRATOR_ID,
            workload_id=666
        )
        m_client.assign_address.assert_called_once_with(pool_return, ip_addr)
        m_endpoint.ipv4_nets.add.assert_called_once_with(IPNetwork(ip_addr))
        m_client.update_endpoint.assert_called_once_with(m_endpoint)
        m_netns.add_ip_to_ns_veth.assert_called_once_with(
            'Pid_info', ip_addr, interface
        )

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_ip_add_ipv6(
            self, m_netns, m_client, m_get_container_info_or_exit,
            m_get_pool_or_exit, m_enforce_root):
        """
        Test for container_ip_add with an ipv6 ip argument

        Assert that the correct calls associated with an ipv6 address are made
        """
        # Set up mock objects
        pool_return = 'pool'
        m_get_pool_or_exit.return_value = pool_return
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        m_endpoint = Mock()
        m_client.get_endpoint.return_value = m_endpoint

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1::1'
        ip_addr = IPAddress(ip)
        interface = 'interface'

        # Call method under test
        container.container_ip_add(container_name, ip, interface)

        # Assert
        m_enforce_root.assert_called_once_with()
        m_get_pool_or_exit.assert_called_once_with(ip_addr)
        m_get_container_info_or_exit.assert_called_once_with(container_name)
        m_client.get_endpoint.assert_called_once_with(
            hostname=utils.hostname,
            orchestrator_id=utils.ORCHESTRATOR_ID,
            workload_id=666
        )
        m_client.assign_address.assert_called_once_with(pool_return, ip_addr)
        m_endpoint.ipv6_nets.add.assert_called_once_with(IPNetwork(ip_addr))
        m_client.update_endpoint.assert_called_once_with(m_endpoint)
        m_netns.add_ip_to_ns_veth.assert_called_once_with(
            'Pid_info', ip_addr, interface
        )

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client.get_endpoint', autospec=True)
    def test_container_ip_add_container_not_running(
            self, m_client_get_endpoint, m_get_container_info_or_exit,
            m_get_pool_or_exit, m_enforce_root):
        """
        Test for container_ip_add when the container is not running

        get_container_info_or_exit returns a running state of value 0.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 0, 'Pid': 'Pid_info'}
        }

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1.1.1.1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_add,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertFalse(m_client_get_endpoint.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.print_container_not_in_calico_msg', autospec=True)
    def test_container_ip_add_container_not_in_calico(
            self, m_print_container_not_in_calico_msg, m_client,
            m_get_container_info_or_exit,  m_get_pool_or_exit, m_enforce_root):
        """
        Test for container_ip_add when the container is not networked into calico

        client.get_endpoint raises a KeyError.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        m_client.get_endpoint.return_value = Mock()
        m_client.get_endpoint.side_effect = KeyError

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1.1.1.1'
        interface = 'interface'

        # Call method under test expecting a System Exit
        self.assertRaises(SystemExit, container.container_ip_add,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        m_print_container_not_in_calico_msg.assert_called_once_with(container_name)
        self.assertFalse(m_client.assign_address.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_ip_add_fail_assign_address(
            self, m_netns, m_client, m_get_container_info_or_exit,
            m_get_pool_or_exit, m_enforce_root):
        """
        Test for container_ip_add when the client cannot assign an IP

        client.assign_address returns an empty list.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        m_client.assign_address.return_value = []

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1.1.1.1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_add,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertFalse(m_netns.add_ip_to_ns_veth.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns.add_ip_to_ns_veth', autospec=True)
    def test_container_ip_add_error_updating_datastore(
            self, m_netns_add_ip_to_ns_veth, m_client,
            m_get_container_info_or_exit, m_get_pool_or_exit, m_enforce_root):
        """
        Test for container_ip_add when the client fails to update endpoint

        client.update_endpoint raises a KeyError.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_pool_or_exit.return_value = 'pool'
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        m_client.update_endpoint.side_effect = KeyError

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1.1.1.1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_add,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertTrue(m_client.assign_address.called)
        m_client.unassign_address.assert_called_once_with('pool', ip)
        self.assertFalse(m_netns_add_ip_to_ns_veth.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns.add_ip_to_ns_veth', autospec=True)
    def test_container_ip_add_netns_error_ipv4(
            self, m_netns_add_ip_to_ns_veth, m_client,
            m_get_container_info_or_exit,  m_get_pool_or_exit, m_enforce_root):
        """
        Test container_ip_add when netns cannot add an ipv4 to interface

        netns.add_ip_to_ns_veth throws a CalledProcessError.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        m_get_pool_or_exit.return_value = 'pool'
        m_endpoint = Mock()
        m_client.get_endpoint.return_value = m_endpoint
        err = CalledProcessError(
            1, m_netns_add_ip_to_ns_veth, "Error updating container")
        m_netns_add_ip_to_ns_veth.side_effect = err

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1.1.1.1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_add,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertTrue(m_client.assign_address.called)
        self.assertTrue(m_netns_add_ip_to_ns_veth.called)
        m_endpoint.ipv4_nets.remove.assert_called_once_with(
            IPNetwork(IPAddress(ip))
        )
        m_client.update_endpoint.assert_has_calls([
            call(m_endpoint), call(m_endpoint)])
        m_client.unassign_address.assert_called_once_with('pool', ip)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.print_container_not_in_calico_msg', autospec=True)
    @patch('calico_ctl.container.netns.add_ip_to_ns_veth', autospec=True)
    def test_container_ip_add_netns_error_ipv6(
            self, m_netns, m_print_container_not_in_calico_msg, m_client,
            m_get_container_info_or_exit,  m_get_pool_or_exit, m_enforce_root):
        """
        Test container_ip_add when netns cannot add an ipv6 to interface

        netns.add_ip_to_ns_veth throws a CalledProcessError.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        m_get_pool_or_exit.return_value = 'pool'
        m_endpoint = Mock()
        m_client.get_endpoint.return_value = m_endpoint
        err = CalledProcessError(1, m_netns, "Error updating container")
        m_netns.side_effect = err

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1::1'
        interface = 'interface'

        # Call method under test
        self.assertRaises(SystemExit, container.container_ip_add,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertTrue(m_client.assign_address.called)
        self.assertTrue(m_netns.called)
        m_endpoint.ipv6_nets.remove.assert_called_once_with(
            IPNetwork(IPAddress(ip))
        )
        m_client.update_endpoint.assert_has_calls([
            call(m_endpoint), call(m_endpoint)])
        m_client.unassign_address.assert_called_once_with('pool', ip)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_ip_remove_ipv4(self, m_netns, m_client,
            m_get_container_info_or_exit, m_get_pool_or_exit, m_enforce_root):
        """
        Test container_ip_remove with an ipv4 ip argument
        """
        # Set up mock objects
        m_get_pool_or_exit.return_value = 'pool'
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        ipv4_nets = set()
        ipv4_nets.add(IPNetwork(IPAddress('1.1.1.1')))
        m_endpoint = Mock(spec=Endpoint)
        m_endpoint.ipv4_nets = ipv4_nets
        m_client.get_endpoint.return_value = m_endpoint

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1.1.1.1'
        interface = 'interface'

        # Call method under test
        container.container_ip_remove(container_name, ip, interface)

        # Assert
        m_enforce_root.assert_called_once_with()
        m_get_pool_or_exit.assert_called_once_with(IPAddress(ip))
        m_get_container_info_or_exit.assert_called_once_with(container_name)
        m_client.get_endpoint.assert_called_once_with(
            hostname=utils.hostname,
            orchestrator_id=utils.ORCHESTRATOR_ID,
            workload_id=666
        )
        m_client.update_endpoint.assert_called_once_with(m_endpoint)
        m_netns.remove_ip_from_ns_veth.assert_called_once_with(
            'Pid_info',
            IPAddress(ip),
            interface
        )
        m_client.unassign_address.assert_called_once_with('pool', ip)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_ip_remove_ipv6(self, m_netns, m_client,
            m_get_container_info_or_exit, m_get_pool_or_exit, m_enforce_root):
        """
        Test for container_ip_remove with an ipv6 ip argument
        """
        # Set up mock objects
        m_get_pool_or_exit.return_value = 'pool'
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        ipv6_nets = set()
        ipv6_nets.add(IPNetwork(IPAddress('1::1')))
        m_endpoint = Mock(spec=Endpoint)
        m_endpoint.ipv6_nets = ipv6_nets
        m_client.get_endpoint.return_value = m_endpoint

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1::1'
        interface = 'interface'

        # Call method under test
        container.container_ip_remove(container_name, ip, interface)

        # Assert
        m_enforce_root.assert_called_once_with()
        m_get_pool_or_exit.assert_called_once_with(IPAddress(ip))
        m_get_container_info_or_exit.assert_called_once_with(container_name)
        m_client.get_endpoint.assert_called_once_with(
            hostname=utils.hostname,
            orchestrator_id=utils.ORCHESTRATOR_ID,
            workload_id=666
        )
        m_client.update_endpoint.assert_called_once_with(m_endpoint)
        m_netns.remove_ip_from_ns_veth.assert_called_once_with(
            'Pid_info',
            IPAddress(ip),
            interface
        )
        m_client.unassign_address.assert_called_once_with('pool', ip)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    def test_container_ip_remove_not_running(
            self, m_client, m_get_container_info_or_exit,
            m_get_pool_or_exit, m_enforce_root):
        """
        Test for container_ip_remove when the container is not running

        get_container_info_or_exit returns a running state of value 0.
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 0, 'Pid': 'Pid_info'}
        }

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1::1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_remove,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertFalse(m_client.get_endpoint.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    def test_container_ip_remove_ip_not_assigned(
            self, m_client, m_get_container_info_or_exit, m_get_pool_or_exit,
            m_enforce_root):
        """
        Test container_ip_remove when an IP address is not assigned to a container

        client.get_endpoint returns an endpoint with no ip nets
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        ipv6_nets = set()
        m_endpoint = Mock(spec=Endpoint)
        m_endpoint.ipv6_nets = ipv6_nets
        m_client.get_endpoint.return_value = m_endpoint

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1::1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_remove,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertFalse(m_client.update_endpoint.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    def test_container_ip_remove_container_not_on_calico(
            self, m_client, m_get_container_info_or_exit, m_get_pool_or_exit,
            m_enforce_root):
        """
        Test for container_ip_remove when container is not networked into Calico

        client.get_endpoint raises a KeyError
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        m_client.get_endpoint.side_effect = KeyError

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1::1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_remove,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertFalse(m_client.update_endpoint.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_ip_remove_fail_updating_datastore(
            self, m_netns, m_client, m_get_container_info_or_exit,
            m_get_pool_or_exit, m_enforce_root):
        """
        Test container_ip_remove when client fails to update endpoint in datastore

        client.update_endpoint throws a KeyError
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        ipv6_nets = set()
        ipv6_nets.add(IPNetwork(IPAddress('1::1')))
        m_endpoint = Mock(spec=Endpoint)
        m_endpoint.ipv6_nets = ipv6_nets
        m_client.get_endpoint.return_value = m_endpoint
        m_client.update_endpoint.side_effect = KeyError

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1::1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_remove,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertTrue(m_client.update_endpoint.called)
        self.assertFalse(m_netns.remove_ip_from_ns_veth.called)

    @patch('calico_ctl.container.enforce_root', autospec=True)
    @patch('calico_ctl.container.get_pool_or_exit', autospec=True)
    @patch('calico_ctl.container.get_container_info_or_exit', autospec=True)
    @patch('calico_ctl.container.client', autospec=True)
    @patch('calico_ctl.container.netns', autospec=True)
    def test_container_ip_remove_netns_error(
            self, m_netns, m_client, m_get_container_info_or_exit,
            m_get_pool_or_exit, m_enforce_root):
        """
        Test container_ip_remove when client fails on removing ip from interface

        netns.remove_ip_from_ns_veth raises a CalledProcessError
        Assert that the system then exits and all expected calls are made
        """
        # Set up mock objects
        m_get_container_info_or_exit.return_value = {
            'Id': 666,
            'State': {'Running': 1, 'Pid': 'Pid_info'}
        }
        ipv6_nets = set()
        ipv6_nets.add(IPNetwork(IPAddress('1::1')))
        m_endpoint = Mock(spec=Endpoint)
        m_endpoint.ipv6_nets = ipv6_nets
        m_client.get_endpoint.return_value = m_endpoint
        err = CalledProcessError(1, m_netns, "Error removing ip")
        m_netns.remove_ip_from_ns_veth.side_effect = err

        # Set up arguments to pass to method under test
        container_name = 'container1'
        ip = '1::1'
        interface = 'interface'

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, container.container_ip_remove,
                          container_name, ip, interface)

        # Assert
        self.assertTrue(m_enforce_root.called)
        self.assertTrue(m_get_pool_or_exit.called)
        self.assertTrue(m_get_container_info_or_exit.called)
        self.assertTrue(m_client.get_endpoint.called)
        self.assertTrue(m_client.update_endpoint.called)
        self.assertTrue(m_netns.remove_ip_from_ns_veth.called)
        self.assertFalse(m_client.unassign_address.called)

