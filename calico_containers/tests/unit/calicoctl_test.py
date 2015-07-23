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
from requests import Response
from StringIO import StringIO
from mock import patch, Mock, call
from nose_parameterized import parameterized
from netaddr import IPAddress
from docker.errors import APIError
from calico_ctl.bgp import *
from calico_ctl.bgp import validate_arguments as bgp_validate_arguments
from calico_ctl.endpoint import validate_arguments as ep_validate_arguments
from calico_ctl import node
from calico_ctl.node import validate_arguments as node_validate_arguments
from calico_ctl.pool import validate_arguments as pool_validate_arguments
from calico_ctl.profile import validate_arguments as profile_validate_arguments
from calico_ctl.container import validate_arguments as container_validate_arguments
from calico_ctl.container import container_add
from calico_ctl.utils import validate_cidr, validate_ip, validate_characters
from pycalico.datastore_datatypes import BGPPeer
from pycalico.datastore import (ETCD_AUTHORITY_ENV,
                                ETCD_AUTHORITY_DEFAULT)


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

    @patch("calico_ctl.container.get_container_info_or_exit", autospec=True)
    @patch("calico_ctl.container.enforce_root", autospec=True)
    @patch("calico_ctl.container.sys", autospec=True)
    @patch("calico_ctl.container.client", autospec=True)
    def test_container_add_host_network(self, m_client, m_sys,m_root, m_info):
        """
        Test container_add exits if the container has host networking.
        """

        info = {"Id": "TEST_ID",
                "State": {"Running": True},
                "HostConfig": {"NetworkMode": "host"}}
        m_info.return_value = info
        m_client.get_endpoint.side_effect = KeyError()
        m_sys.exit.side_effect = SysExitMock()

        # Run function under test.
        name = "TEST_NAME"
        ip = "10.1.2.3"
        interface = "eth1"
        self.assertRaises(SysExitMock, container_add, name, ip, interface)

        m_root.assert_called_once_with()
        m_info.assert_called_once_with(name)
        m_sys.exit.assert_called_once_with(1)

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


    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('os.getenv', autospec= True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.install_kubernetes', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    @patch('calico_ctl.node._find_or_pull_node_image', autospec=True)
    @patch('calico_ctl.node._attach_and_stream', autospec=True)
    def test_node_start(self, m_attach_and_stream,
                        m_find_or_pull_node_image, m_docker,
                        m_docker_client, m_client, m_install_kube,
                        m_warn_if_hostname_conflict, m_warn_if_unknown_ip,
                        m_get_host_ips, m_check_system, m_os_getenv,
                        m_os_makedirs, m_os_path_exists):
        """
        Test that the node_start function behaves as expected by mocking
        function returns
        """
        # Set up mock objects
        m_os_path_exists.return_value = False
        ip_1 = '1.1.1.1'
        ip_2 = '2.2.2.2'
        m_get_host_ips.return_value = [ip_1, ip_2]
        m_os_getenv.return_value = '1.1.1.1:80'
        m_docker.utils.create_host_config.return_value = 'host_config'
        container = {'Id':666}
        m_docker_client.create_container.return_value = container

        # Set up arguments
        node_image = 'node_image'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        kubernetes = True

        # Call method under test
        node.node_start(
            node_image, log_dir, ip, ip6, as_num, detach, kubernetes
        )

        # Set up variables used in assertion statements
        environment = [
            "HOSTNAME=%s" % node.hostname,
            "IP=%s" % ip_2,
            "IP6=%s" % ip6,
            "ETCD_AUTHORITY=1.1.1.1:80",  # etcd host:port
            "FELIX_ETCDADDR=1.1.1.1:80",  # etcd host:port
        ]
        binds = {
            "/proc":
                {
                    "bind": "/proc_host",
                    "ro": False
                },
            log_dir:
                {
                    "bind": "/var/log/calico",
                    "ro": False
                },
            "/run/docker/plugins":
                {
                    "bind": "/usr/share/docker/plugins",
                    "ro": False
                }
        }

        # Assert
        m_os_path_exists.assert_called_once_with(log_dir)
        m_os_makedirs.assert_called_once_with(log_dir)
        m_check_system.assert_called_once_with(fix=False, quit_if_error=False)
        m_get_host_ips.assert_called_once_with(4)
        m_warn_if_unknown_ip.assert_called_once_with(ip_2, ip6)
        m_warn_if_hostname_conflict.assert_called_once_with(ip_2)
        m_install_kube.assert_called_once_with(node.KUBERNETES_PLUGIN_DIR)
        m_client.get_ip_pools.assert_has_calls([call(4), call(6)])
        m_client.ensure_global_config.assert_called_once_with()
        m_client.create_host.assert_called_once_with(
            node.hostname, ip_2, ip6, as_num
        )
        m_docker_client.remove_container.assert_called_once_with(
            'calico-node', force=True
        )
        m_os_getenv.assert_called_once_with(
            ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT
        )
        m_docker.utils.create_host_config.assert_called_once_with(
            privileged=True,
            restart_policy={"Name":"Always"},
            network_mode="host",
            binds=binds
        )
        m_find_or_pull_node_image.assert_called_once_with(
            'node_image', m_docker_client
        )
        m_docker_client.create_container.assert_called_once_with(
            node_image,
            name='calico-node',
            detach=True,
            environment=environment,
            host_config='host_config',
            volumes=['/proc_host',
                     '/var/log/calico',
                     '/usr/share/docker/plugins']
        )
        m_docker_client.start.assert_called_once_with(container)
        m_attach_and_stream.assert_called_once_with(container)

    @patch('sys.exit', autospec=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('os.getenv', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.install_kubernetes', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_start_invalid_etcd_authority(
            self, m_docker_client, m_client, m_install_kube, m_warn_if_hostname_conflict,
            m_warn_if_unknown_ip, m_get_host_ips, m_check_system,
            m_os_getenv, m_os_makedirs, m_os_path_exists, m_sys_exit):
        """
        Test that node_start exits when given a bad etcd authority ip:port
        """
        # Set up mock objects
        m_os_getenv.return_value = '1.1.1.1:80:100'

        # Set up arguments
        node_image = 'node_image'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        kubernetes = True

        # Call method under test
        node.node_start(
            node_image, log_dir, ip, ip6, as_num, detach, kubernetes
        )

        m_sys_exit.assert_called_once_with(1)

    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.install_kubernetes', autospec=True)
    def test_node_start_call_backup_kube_directory(
            self, m_install_kube, m_warn_if_hostname_conflict,
            m_warn_if_unknown_ip, m_get_host_ips, m_check_system,
            m_os_makedirs, m_os_path_exists):
        """
        Test that node_start calls the backup kuberentes plugin directory
        when install_kubernetes cannot access the default kubernetes directory
        """
        # Set up mock objects
        m_os_path_exists.return_value = True
        m_get_host_ips.return_value = ['1.1.1.1']
        m_install_kube.side_effect = OSError

        # Set up arguments
        node_image = 'node_image'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        kubernetes = True

        # Test expecting OSError exception
        self.assertRaises(OSError, node.node_start,
                          node_image, log_dir, ip, ip6, as_num, detach, kubernetes)
        m_install_kube.assert_has_calls([
            call(node.KUBERNETES_PLUGIN_DIR),
            call(node.KUBERNETES_PLUGIN_DIR_BACKUP)
        ])

    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.install_kubernetes', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_start_remove_container_error(
            self, m_docker_client, m_client, m_install_kube,
            m_warn_if_hostname_conflict, m_warn_if_unknown_ip,
            m_get_host_ips, m_check_system, m_os_makedirs, m_os_path_exists):
        """
        Test that the docker client raises an APIError when it fails to
        remove a container.
        """
        # Set up mock objects
        err = APIError("Test error message", Response())
        m_docker_client.remove_container.side_effect = err

        # Set up arguments
        node_image = 'node_image'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        kubernetes = True

        # Testing expecting APIError exception
        self.assertRaises(APIError, node.node_start,
                          node_image, log_dir, ip, ip6, as_num, detach, kubernetes)

    @patch('sys.exit', autospec=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.install_kubernetes', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_start_no_detected_ips(
            self, m_docker_client, m_client, m_install_kube,
            m_warn_if_hostname_conflict, m_warn_if_unknown_ip,
            m_get_host_ips, m_check_system, m_os_makedirs, m_os_path_exists,
            m_sys_exit):
        """
        Test that system exits when no ip is provided and host ips cannot be
        obtained
        """
        # Set up mock objects
        m_get_host_ips.return_value = []

        # Set up arguments
        node_image = 'node_image'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        kubernetes = True

        # Call method under test
        node.node_start(
            node_image, log_dir, ip, ip6, as_num, detach, kubernetes
        )

        # Assert
        m_sys_exit.assert_called_once_with(1)

    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.install_kubernetes', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_start_create_default_ip_pools(
            self, m_docker_client, m_client, m_install_kube,
            m_warn_if_hostname_conflict, m_warn_if_unknown_ip,
            m_get_host_ips, m_check_system, m_os_makedirs, m_os_path_exists):
        """
        Test that the client creates default ipv4 and ipv6 pools when the
        client returns an empty ip_pool on etcd setup
        """
        # Set up mock objects
        m_client.get_ip_pools.return_value = []

        # Set up arguments
        node_image = 'node_image'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        kubernetes = True

        # Call method under test
        node.node_start(
            node_image, log_dir, ip, ip6, as_num, detach, kubernetes
        )

        # Assert
        m_client.add_ip_pool.assert_has_calls([
            call(4, node.DEFAULT_IPV4_POOL),
            call(6, node.DEFAULT_IPV6_POOL)
        ])

    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_stop(self, m_docker_client, m_client):
        """
        Test the client removes the host and stops the node when node_stop
        called
        """
        # Call method under test
        node.node_stop(True)

        # Assert
        m_client.remove_host.assert_called_once_with(node.hostname)
        m_docker_client.stop.assert_called_once_with('calico-node')

    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_stop_error(self, m_docker_client, m_client):
        """
        Test node_stop raises an exception when the docker client cannot not
        stop the node
        """
        # Set up mock objects
        err = APIError("Test error message", Response())
        m_docker_client.stop.side_effect = err

        # Call method under test expecting an exception
        self.assertRaises(APIError, node.node_stop, True)


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


class SysExitMock(Exception):
    """
    Used to mock the behaviour of sys.exit(), that is, ending execution of the
    code under test, without exiting the test framework.
    """
    pass
