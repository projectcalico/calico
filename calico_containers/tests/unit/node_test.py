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
import signal
import os
import sys

from docker.errors import APIError
from docker import Client as DockerClient
from mock import patch, Mock, call
from nose_parameterized import parameterized
from pycalico.datastore import (ETCD_AUTHORITY_ENV,
                                ETCD_AUTHORITY_DEFAULT)

from calico_ctl import node


class TestAttachAndStream(unittest.TestCase):

    @patch("calico_ctl.node.docker_client", spec=DockerClient)
    @patch("calico_ctl.node.sys", spec=sys)
    def test_container_stops_normally(self, m_sys, m_docker_client):
        """
        Test _attach_and_stream when the container stops normally.

        :return: None
        """

        # attach(..., stream=True) returns a generator.
        def container_output_gen():
            yield ("Some output\n")
            yield ("from the container.")

        m_docker_client.attach.return_value = container_output_gen()
        m_stdout = Mock(spec=sys.stdout)
        m_sys.stdout = m_stdout
        m_container = Mock()
        node._attach_and_stream(m_container)

        m_docker_client.attach.assert_called_once_with(m_container,
                                                       stream=True)
        self.assertFalse(m_container.called)
        m_stdout.write.assert_has_calls([call("Some output\n"),
                                         call("from the container.")])
        m_docker_client.stop.assert_called_once_with(m_container)

    @patch("calico_ctl.node.docker_client", spec=DockerClient)
    @patch("calico_ctl.node.sys", spec=sys)
    def test_ctrl_c(self, m_sys, m_docker_client):
        """
        Test _attach_and_stream when a Keyboard interrupt is generated.

        :return: None
        """
        # attach(..., stream=True) returns a generator.
        def container_output_gen():
            yield ("Some output\n")
            yield ("from the container.")
            raise KeyboardInterrupt()
            yield ("This output is not printed.")

        m_docker_client.attach.return_value = container_output_gen()
        m_stdout = Mock(spec=sys.stdout)
        m_sys.stdout = m_stdout
        m_container = Mock()
        node._attach_and_stream(m_container)

        m_docker_client.attach.assert_called_once_with(m_container,
                                                       stream=True)
        self.assertFalse(m_container.called)
        m_stdout.write.assert_has_calls([call("Some output\n"),
                                         call("from the container.")])
        self.assertEqual(m_stdout.write.call_count, 2)
        m_docker_client.stop.assert_called_once_with(m_container)

    @patch("calico_ctl.node.docker_client", spec=DockerClient)
    @patch("calico_ctl.node.sys", spec=sys)
    def test_killed(self, m_sys, m_docker_client):
        """
        Test _attach_and_stream when killed by another process.

        :return: None
        """
        # attach(..., stream=True) returns a generator.
        def container_output_gen():
            yield ("Some output\n")
            yield ("from the container.")
            # Commit suicide, simulating being killed from another terminal.
            os.kill(os.getpid(), signal.SIGTERM)
            yield ("\nThis output is printed, but only because we nerf'd "
                   "sys.exit()")

        m_docker_client.attach.return_value = container_output_gen()
        m_stdout = Mock(spec=sys.stdout)
        m_sys.stdout = m_stdout
        m_container = Mock()
        node._attach_and_stream(m_container)

        m_docker_client.attach.assert_called_once_with(m_container,
                                                       stream=True)
        self.assertFalse(m_container.called)
        m_sys.exit.assert_called_once_with(0)
        m_stdout.write.assert_has_calls([call("Some output\n"),
                                         call("from the container."),
                                         call("\nThis output is printed, but "
                                              "only because we nerf'd "
                                              "sys.exit()")])

        # Stop gets called twice, once for SIGTERM, and because sys.exit() gets
        # mocked, the function continues and we get another call when the
        # generator ends normally.
        m_docker_client.stop.assert_has_calls([call(m_container),
                                               call(m_container)])
        self.assertEqual(m_docker_client.stop.call_count, 2)


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
            node.validate_arguments(case)

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
        m_os_getenv.side_effect = iter(['1.1.1.1:80', ""])
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
            "POLICY_ONLY_CALICO=",
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
        m_get_host_ips.assert_called_once_with(exclude=["docker0"])
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

        getenv_calls = [call(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT),
                        call(node.POLICY_ONLY_ENV, "")]
        m_os_getenv.assert_has_calls(getenv_calls)

        m_docker.utils.create_host_config.assert_called_once_with(
            privileged=True,
            restart_policy={"Name":"Always"},
            network_mode="host",
            binds=binds
        )
        m_find_or_pull_node_image.assert_called_once_with(
            'node_image'
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


