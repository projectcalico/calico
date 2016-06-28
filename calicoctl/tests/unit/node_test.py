# Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

from netaddr import IPNetwork, IPAddress
from requests import Response
import signal
import os
import sys

from docker.errors import APIError
from docker import Client as DockerClient
from mock import patch, Mock, call
from nose.tools import *
from nose_parameterized import parameterized
from pycalico.datastore import (ETCD_AUTHORITY_DEFAULT, ETCD_SCHEME_DEFAULT,
                                ETCD_KEY_FILE_ENV, ETCD_CERT_FILE_ENV,
                                ETCD_CA_CERT_FILE_ENV, ETCD_SCHEME_ENV,
                                ETCD_AUTHORITY_ENV, ETCD_ENDPOINTS_ENV)

from calico_ctl import node
from calico_ctl.node import (ETCD_CA_CERT_NODE_FILE, ETCD_CERT_NODE_FILE,
                             ETCD_KEY_NODE_FILE, CALICO_NETWORKING_DEFAULT)
import calico_ctl
from pycalico.datastore_datatypes import IPPool


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
        node._attach_and_stream(m_container, False)

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
        node._attach_and_stream(m_container, False)

        m_docker_client.attach.assert_called_once_with(m_container,
                                                       stream=True)
        self.assertFalse(m_container.called)
        m_stdout.write.assert_has_calls([call("Some output\n"),
                                         call("from the container.")])
        self.assertEqual(m_stdout.write.call_count, 2)
        m_docker_client.stop.assert_called_once_with(m_container)
        m_sys.exit.assertcalled_once_with(130)

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
        node._attach_and_stream(m_container, False)

        m_docker_client.attach.assert_called_once_with(m_container,
                                                       stream=True)
        self.assertFalse(m_container.called)
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
        # sys.exit gets called twice: once when handling the SIGTERM and once
        # when stopping the container for an unknown reason
        m_sys.exit.assert_has_calls([call(0), call(1)])


class TestNode(unittest.TestCase):

    @parameterized.expand([
        ({'--ip': '127.a.0.1'}, True),
        ({'--ip': 'aa:bb::cc'}, True),
        ({'--ip': '127.0.0.1', '--ip6': '127.0.0.1'}, True),
        ({'--ip': '127.0.0.1', '--ip6': 'aa:bb::zz'}, True),
        ({'--ip': ''}, False),
        ({'--ip6': ''}, False),
        ({'--ip': None, '--ip6': ''}, False),
        ({'--ip': '10.10.10.10', '--ip6': None}, False),
        ({'--ip': '', '--ip6': 'dadd::beef'}, False),
        ({'--ip': '10.10.10.10'}, False),
        ({'--ip': '10.10.10.10', '--ip6': 'dead::beef'}, False),
        ({'<IP>': '10.10.10.10', '<IP6>': 'dead::beef'}, False),
        ({'<AS_NUM>': None}, False),
        ({'<AS_NUM>': '65535.65535'}, False),
        ({'<AS_NUM>': '0.65535'}, False),
        ({'<AS_NUM>': '1000000'}, False),
        ({'<AS_NUM>': '65535'}, False),
        ({'<AS_NUM>': '65536.0'}, True),
        ({'<AS_NUM>': '65535.65536'}, True),
        ({'<AS_NUM>': '65535.'}, True)
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

    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node._set_nf_conntrack_max', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node._find_or_pull_node_image', autospec=True)
    @patch('calico_ctl.node._attach_and_stream', autospec=True)
    @patch('calico_ctl.node.running_in_container', autospec=True)
    @patch('calico_ctl.node.enforce_root', autospec=True)
    def test_node_dockerless_start(self, m_enforce_root, m_container, m_attach_and_stream,
                                   m_find_or_pull_node_image, m_call, m_docker,
                                   m_docker_client, m_client,
                                   m_conntrack,
                                   m_setup_ip, m_check_system, m_os_makedirs,
                                   m_os_path_exists, m_ipv6_enabled):
        """
        Test that the node_start function performs all necessary configurations
        without making Docker calls when runtime=none.
        """
        # Set up mock objects
        m_enforce_root.return_value = False
        m_container.return_value = False
        m_os_path_exists.return_value = False
        m_docker_client.create_host_config.return_value = 'host_config'
        container = {'Id': 666}
        m_docker_client.create_container.return_value = container
        m_check_system.return_value = [True, True, True]

        # Set up arguments
        node_image = 'node_image'
        runtime = 'none'
        log_dir = './log_dir'
        ip = '2.2.2.2'
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = True
        libnetwork = False
        no_pull = False

        # Call method under test
        node.node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
                        libnetwork, no_pull)

        # Assert
        m_os_path_exists.assert_called_once_with(log_dir)
        m_os_makedirs.assert_called_once_with(log_dir)
        m_check_system.assert_called_once_with(quit_if_error=False,
                                               libnetwork=libnetwork,
                                               check_docker=False,
                                               check_modules=True
                                               )
        m_setup_ip.assert_called_once_with()

        self.assertFalse(m_docker_client.remove_container.called)
        self.assertFalse(m_docker_client.create_host_config.called)
        self.assertFalse(m_find_or_pull_node_image.called)
        self.assertFalse(m_docker_client.create_container.called)
        self.assertFalse(m_docker_client.start.called)
        self.assertFalse(m_attach_and_stream.called)

    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.running_in_container', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node._set_nf_conntrack_max', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    @patch('calico_ctl.node._find_or_pull_node_image', autospec=True)
    @patch('calico_ctl.node._attach_and_stream', autospec=True)
    @patch('calico_ctl.node.enforce_root', autospec=True)
    def test_node_start(self, m_root, m_attach_and_stream,
                        m_find_or_pull_node_image, m_docker,
                        m_docker_client, m_client,
                        m_conntrack, m_setup_ip,
                        m_check_system, m_container, m_call,
                        m_os_makedirs, m_os_path_exists, m_ipv6_enabled):
        """
        Test that the node_Start function does not make Docker calls
        function returns
        """
        # Set up mock objects
        m_container.return_value = False
        m_root.return_value = False
        m_os_path_exists.return_value = False
        ip_2 = '2.2.2.2'
        m_docker_client.create_host_config.return_value = 'host_config'
        container = {'Id': 666}
        m_docker_client.create_container.return_value = container
        m_check_system.return_value = [True, True, True]
        ipv4_pools = [IPPool(IPNetwork("10.0.0.0/16")),
                      IPPool(IPNetwork("10.1.0.0/16"), ipip=True)]
        ipip_pools = [IPPool(IPNetwork("10.1.0.0/16"), ipip=True)]
        m_client.get_ip_pools.return_value = ipv4_pools

        # Set up arguments
        node_image = 'node_image'
        runtime = 'docker'
        log_dir = './log_dir'
        ip = '2.2.2.2'
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        libnetwork = False
        # Don't pull the node image
        no_pull = True

        # Call method under test
        node.node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
                        libnetwork, no_pull)

        # Set up variables used in assertion statements
        environment = [
            "HOSTNAME=%s" % node.hostname,
            "IP=%s" % ip_2,
            "IP6=%s" % ip6,
            "CALICO_NETWORKING=%s" % node.CALICO_NETWORKING_DEFAULT,
            "AS=",
            "NO_DEFAULT_POOLS=",
            "ETCD_AUTHORITY=%s" % ETCD_AUTHORITY_DEFAULT,  # etcd host:port
            "ETCD_SCHEME=%s" % ETCD_SCHEME_DEFAULT,
        ]
        binds = {
            log_dir:
                {
                    "bind": "/var/log/calico",
                    "ro": False
                },
            "/var/run/calico":
                {
                    "bind": "/var/run/calico",
                    "ro": False
                },
            "/lib/modules":
                {
                    "bind": "/lib/modules",
                    "ro": False
                }
        }

        # Assert
        m_os_path_exists.assert_called_once_with(log_dir)
        m_os_makedirs.assert_called_once_with(log_dir)
        m_check_system.assert_called_once_with(quit_if_error=False,
                                               libnetwork=libnetwork,
                                               check_docker=True,
                                               check_modules=True)
        m_setup_ip.assert_called_once_with()

        m_docker_client.remove_container.assert_called_once_with(
            'calico-node', force=True
        )
        m_docker_client.create_host_config.assert_called_once_with(
            privileged=True,
            restart_policy={"Name": "always"},
            network_mode="host",
            binds=binds
        )
        self.assertFalse(m_find_or_pull_node_image.called)
        m_docker_client.create_container.assert_called_once_with(
            node_image,
            name='calico-node',
            detach=True,
            environment=environment,
            host_config='host_config',
            volumes=['/var/log/calico', "/var/run/calico", "/lib/modules"]
        )
        m_docker_client.start.assert_called_once_with(container)
        m_attach_and_stream.assert_called_once_with(container, False)

    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('os.getenv', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node._set_nf_conntrack_max', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    @patch('calico_ctl.node._find_or_pull_node_image', autospec=True)
    @patch('calico_ctl.node._attach_and_stream', autospec=True)
    @patch('calico_ctl.node.running_in_container', autospec=True)
    @patch('calico_ctl.node.enforce_root', autospec=True)
    def test_node_start_secure(self, m_root, m_container, m_attach_and_stream,
                               m_find_or_pull_node_image, m_docker, m_call,
                               m_docker_client, m_client,
                               m_conntrack, m_setup_ip, m_check_system,
                               m_os_getenv, m_os_makedirs, m_os_path_exists,
                               m_ipv6_enabled):
        """
        Test that the node_start function passes in correct values when
        secure etcd environment variables are present.
        """
        # Set up mock objects
        m_root.return_value = False
        m_container.return_value = False
        ip_2 = '2.2.2.2'
        container1 = {'Id': 111}
        container2 = {'Id': 222}
        m_docker_client.create_container.side_effect = iter([container1,
                                                             container2])
        m_docker_client.create_host_config.return_value = 'host_config'
        m_os_path_exists.return_value = True
        m_check_system.return_value = [True, True, True]

        etcd_ca_path = "/path/to/ca.crt"
        etcd_cert_path = "/path/to/cert.crt"
        etcd_key_path = "/path/to/key.pem"
        etcd_endpoints = "https://1.2.3.4:2379"
        env = {"NO_DEFAULT_POOLS": "",
               "CALICO_NETWORKING": CALICO_NETWORKING_DEFAULT,
               ETCD_AUTHORITY_ENV: ETCD_AUTHORITY_DEFAULT,
               ETCD_ENDPOINTS_ENV: etcd_endpoints,
               ETCD_SCHEME_ENV: "https",
               ETCD_CA_CERT_FILE_ENV: etcd_ca_path,
               ETCD_CERT_FILE_ENV: etcd_cert_path,
               ETCD_KEY_FILE_ENV: etcd_key_path}
        def m_getenv(env_var, *args, **kwargs):
            return env[env_var]
        m_os_getenv.side_effect = m_getenv

        # Set up arguments
        node_image = 'node_image'
        runtime = 'docker'
        log_dir = './log_dir'
        docker_plugin = "/run/docker/plugins"
        ip = '2.2.2.2'
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        libnetwork_image = 'libnetwork_image'
        no_pull = False

        # Call method under test
        node.node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
                        libnetwork_image, no_pull)

        # Set up variables used in assertion statements
        environment_node = [
            "HOSTNAME=%s" % node.hostname,
            "IP=%s" % ip_2,
            "IP6=%s" % ip6,
            "CALICO_NETWORKING=%s" % CALICO_NETWORKING_DEFAULT,
            "AS=",
            "NO_DEFAULT_POOLS=",
            "ETCD_AUTHORITY=%s" % ETCD_AUTHORITY_DEFAULT,  # etcd host:port
            "ETCD_SCHEME=%s" % "https",
            "ETCD_ENDPOINTS=%s" % etcd_endpoints,  # https://host:port
            "ETCD_CA_CERT_FILE=%s" % ETCD_CA_CERT_NODE_FILE,
            "ETCD_KEY_FILE=%s" % ETCD_KEY_NODE_FILE,
            "ETCD_CERT_FILE=%s" % ETCD_CERT_NODE_FILE,
        ]
        environment_libnetwork = [
            "HOSTNAME=%s" % node.hostname,
            "ETCD_AUTHORITY=%s" % ETCD_AUTHORITY_DEFAULT,  # etcd host:port
            "ETCD_SCHEME=%s" % "https",
            "ETCD_ENDPOINTS=%s" % etcd_endpoints,  # https://host:port
            "ETCD_CA_CERT_FILE=%s" % ETCD_CA_CERT_NODE_FILE,
            "ETCD_KEY_FILE=%s" % ETCD_KEY_NODE_FILE,
            "ETCD_CERT_FILE=%s" % ETCD_CERT_NODE_FILE,
        ]
        binds_node = {
            log_dir: {"bind": "/var/log/calico", "ro": False},
            "/var/run/calico": {"bind": "/var/run/calico", "ro": False},
            "/lib/modules": {"bind": "/lib/modules", "ro": False},
            etcd_ca_path: {"bind": ETCD_CA_CERT_NODE_FILE, "ro": True},
            etcd_cert_path: {"bind": ETCD_CERT_NODE_FILE, "ro": True},
            etcd_key_path: {"bind": ETCD_KEY_NODE_FILE, "ro": True}
        }
        binds_libnetwork = {
            etcd_ca_path: {"bind": ETCD_CA_CERT_NODE_FILE, "ro": True},
            etcd_cert_path: {"bind": ETCD_CERT_NODE_FILE, "ro": True},
            etcd_key_path: {"bind": ETCD_KEY_NODE_FILE, "ro": True},
            docker_plugin: {'bind': docker_plugin, 'ro': False}
        }
        volumes_node = ['/var/log/calico', "/var/run/calico", "/lib/modules",
                        ETCD_CA_CERT_NODE_FILE, ETCD_KEY_NODE_FILE,
                        ETCD_CERT_NODE_FILE]
        volumes_libnetwork= [docker_plugin, ETCD_CA_CERT_NODE_FILE,
                             ETCD_KEY_NODE_FILE, ETCD_CERT_NODE_FILE]

        # Assert
        m_os_path_exists.assert_called_once_with(log_dir)
        m_check_system.assert_called_once_with(quit_if_error=False,
                                               libnetwork=libnetwork_image,
                                               check_docker=True,
                                               check_modules=True)
        m_setup_ip.assert_called_once_with()

        m_docker_client.remove_container.assert_has_calls([
            call('calico-node', force=True),
            call('calico-libnetwork', force=True)
        ])
        m_docker_client.create_host_config.assert_has_calls([
            call(privileged=True,
                 restart_policy={"Name": "always"},
                 network_mode="host",
                 binds=binds_node),
            call(privileged=True,
                 restart_policy={"Name": "always"},
                 network_mode="host",
                 binds=binds_libnetwork)
        ])
        m_find_or_pull_node_image.assert_has_calls([call('node_image'),
                                                    call('libnetwork_image')])
        m_docker_client.create_container.assert_has_calls([
            call(node_image,
                 name='calico-node',
                 detach=True,
                 environment=environment_node,
                 host_config='host_config',
                 volumes=volumes_node),
            call(libnetwork_image,
                 name='calico-libnetwork',
                 detach=True,
                 environment=environment_libnetwork,
                 host_config='host_config',
                 volumes=volumes_libnetwork)
        ])
        m_docker_client.start.assert_has_calls([call(container1),
                                                call(container2)])
        m_attach_and_stream.assert_called_once_with(container1, False)


    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node._set_nf_conntrack_max', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    @patch('calico_ctl.node.enforce_root', autospec=True)
    def test_node_start_remove_container_error(
            self, m_root, m_docker, m_docker_client, m_client, m_call,
            m_conntrack, m_setup_ip, m_check_system,
            m_os_makedirs, m_os_path_exists, m_ipv6_enabled):
        """
        Test that the docker client raises an APIError when it fails to
        remove a container.
        """
        # Set up mock objects
        m_root.return_value = False
        err = APIError("Test error message", Response())
        m_docker_client.remove_container.side_effect = err
        m_check_system.return_value = [True, True, True]

        # Set up arguments
        node_image = 'node_image'
        runtime = 'docker'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        libnetwork = False
        no_pull = False

        # Testing expecting APIError exception
        self.assertRaises(APIError, node.node_start,
                          node_image, runtime, log_dir, ip, ip6, as_num, detach,
                          libnetwork, no_pull)

    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    def test_node_start_etcd_docker_error(
            self, m_docker, m_docker_client, m_client, m_call,
            m_setup_ip, m_check_system,
            m_os_makedirs, m_os_path_exists, m_ipv6_enabled):
        """
        Test that the node command fails if etcd or docker are not functional
        """
        # Set up mock objects
        # Set up arguments
        node_image = 'node_image'
        runtime = 'docker'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        libnetwork = False
        no_pull = False

        # Return False for etcd status (failure)
        m_check_system.return_value = [True, True, False]
        self.assertRaises(SystemExit, node.node_start,
                          node_image, runtime, log_dir, ip, ip6, as_num, detach,
                          libnetwork, no_pull)

        # Return False for Docker status (failure)
        m_check_system.return_value = [True, False, True]

        # Testing expecting APIError exception
        self.assertRaises(SystemExit, node.node_start,
                          node_image, runtime, log_dir, ip, ip6, as_num, detach,
                          libnetwork, no_pull)

    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.enforce_root', autospec=True)
    def test_node_stop(self, m_root, m_docker_client, m_client):
        """
        Test the client stops the node when node_stop called when there are
        endpoints and the force flag is set.
        """
        # Call method under test
        m_root.return_value = False
        m_client.get_endpoints.return_value = [Mock()]
        node.node_stop(True)

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname=node.hostname)
        m_docker_client.stop.assert_has_calls([call('calico-node'),
                                               call('calico-libnetwork')])

    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.enforce_root', autospec=True)
    def test_node_stop_endpoints(self, m_root, m_docker_client, m_client):
        """
        Test the client does not stops the node when node_stop is called and
        there are endpoints and the force flag is not set.
        """
        # Call method under test
        m_root.return_value = False
        m_client.get_endpoints.return_value = [Mock()]
        self.assertRaises(SystemExit, node.node_stop, False)

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname=node.hostname)
        self.assertEquals(m_docker_client.stop.call_count, 0)

    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.enforce_root', autospec=True)
    def test_node_stop_error(self, m_root, m_docker_client, m_client):
        """
        Test node_stop raises an exception when the docker client cannot not
        stop the node
        """
        # Set up mock objects
        m_root.return_value = False
        m_client.get_endpoints.return_value = [Mock()]
        err = APIError("Test error message", Response())

        for sidee in ([None, err], [err, None]):
            m_docker_client.stop.side_effect = sidee

            # Call method under test expecting an exception
            self.assertRaises(APIError, node.node_stop, True)

    @patch('calico_ctl.node.remove_veth', autospec=True)
    @patch('calico_ctl.node._container_running', autospec=True, return_value=False)
    @patch('calico_ctl.node.client', autospec=True)
    def test_node_remove(self, m_client, m_cont_running, m_veth):
        """
        Test the client removes the host when node_remove called, and that
        endpoints are removed when remove_endpoints flag is set.
        """
        # Call method under test
        endpoint1 = Mock()
        endpoint1.name = "vethname1"
        endpoint1.ipv4_nets = {IPNetwork("1.2.3.4/32")}
        endpoint1.ipv6_nets = set()
        endpoint2 = Mock()
        endpoint2.name = "vethname2"
        endpoint2.ipv4_nets = set()
        endpoint2.ipv6_nets = {IPNetwork("aa:bb::cc/128")}
        m_client.get_endpoints.return_value = [endpoint1, endpoint2]
        node.node_remove(True, False)

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname=node.hostname)
        m_client.release_ips.assert_called_once_with({IPAddress("1.2.3.4"),
                                                      IPAddress("aa:bb::cc")})
        m_client.remove_ipam_host.assert_called_once_with(node.hostname)
        m_veth.assert_has_calls([call("vethname1"), call("vethname2")])
        m_cont_running.assert_has_calls([call("calico-node"), call("calico-libnetwork")])
        m_client.remove_host.assert_called_once_with(node.hostname)

    @patch('calico_ctl.node.remove_veth', autospec=True)
    @patch('calico_ctl.node._container_running', autospec=True, return_value=True)
    @patch('calico_ctl.node.client', autospec=True)
    def test_node_remove_node_running(self, m_client, m_cont_running, m_veth):
        """
        Test the client does not remove host when containers are running and
        node_remove is invoked.
        """
        # Assert
        self.assertRaises(SystemExit, node.node_remove, True, False)
        self.assertEquals(m_client.get_endpoints.call_count, 0)
        self.assertEquals(m_client.remove_host.call_count, 0)
        self.assertEquals(m_veth.call_count, 0)

    @patch('calico_ctl.node.remove_veth', autospec=True)
    @patch('calico_ctl.node._container_running', autospec=True, return_value=False)
    @patch('calico_ctl.node.client', autospec=True)
    def test_node_remove_endpoints_exist(self, m_client, m_cont_running, m_veth):
        """
        Test the client does not remove host when endpoints exist and
        node_remove is invoked without remove_endpoints flag.
        """
        # Call method under test
        m_client.get_endpoints.return_value = [Mock()]
        self.assertRaises(SystemExit, node.node_remove, False, False)

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname=node.hostname)
        self.assertEquals(m_client.remove_host.call_count, 0)
        self.assertEquals(m_veth.call_count, 0)

    @patch('calico_ctl.node.remove_veth', autospec=True)
    @patch('calico_ctl.node._container_running', autospec=True, return_value=False)
    @patch('calico_ctl.node.client', autospec=True)
    def test_node_remove_specific_host(self, m_client, m_cont_running, m_veth):
        """
        Test the client removes the specific host when node_remove called, and
        that endpoints are removed when remove_endpoints flag is set.
        """
        # Call method under test
        endpoint1 = Mock()
        endpoint1.name = "vethname1"
        endpoint1.ipv4_nets = {IPNetwork("1.2.3.4/32")}
        endpoint1.ipv6_nets = set()
        endpoint2 = Mock()
        endpoint2.name = "vethname2"
        endpoint2.ipv4_nets = set()
        endpoint2.ipv6_nets = set()
        m_client.get_endpoints.return_value = [endpoint1, endpoint2]
        # This should not cause a failure with specific host
        m_cont_running.return_value = True
        node.node_remove(True, "other-host")

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname="other-host")
        m_client.release_ips.assert_called_once_with({IPAddress("1.2.3.4")})
        m_client.remove_ipam_host.assert_called_once_with("other-host")
        m_client.remove_host.assert_called_once_with("other-host")
        m_veth.assert_has_calls([call("vethname1"), call("vethname2")])

    @patch('calico_ctl.node.client')
    def test_node_show(self, m_client):
        """
        Test that correct client methods are called with node_show.
        """
        host_dict = {"host1": {"as_num": "22",
                               "ip_addr_v4": "1.2.3.4",
                               "ip_addr_v6": "a:b:c::d",
                               "peer_v4": [{"ip":"1.1.1.1", "as_num": "22"},
                                           {"ip":"2.2.2.2", "as_num": "22"}],
                               "peer_v6": [{"ip":"a::b", "as_num": "22"}]}}
        m_client.get_hosts_data_dict.return_value = host_dict
        node.node_show()
        m_client.get_hosts_data_dict.assert_called_once_with()
        self.assertFalse(m_client.get_default_node_as.called)

    @patch('calico_ctl.node.client')
    def test_node_show_default_as(self, m_client):
        """
        Test node_show gets default AS for host with no specific AS num.
        """
        host_dict = {"host":{"as_num": "",
                             "ip_addr_v4": "1.2.3.4",
                             "ip_addr_v6": "a:b:c::d",
                             "peer_v4": [],
                             "peer_v6": []}}
        m_client.get_hosts_data_dict.return_value = host_dict

        node.node_show()
        m_client.get_hosts_data_dict.assert_called_once_with()
        m_client.get_default_node_as.assert_called_once_with()

    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_container_running_no_cont(self, m_docker_client):
        """
        Test the _container_running command when no container exists.
        """
        response = Response()
        response.status_code = 404
        m_docker_client.inspect_container.side_effect = APIError("Test error message", response)

        self.assertEquals(node._container_running("container1"), False)
        m_docker_client.inspect_container.assert_called_once_with("container1")

    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_container_running_err(self, m_docker_client):
        """
        Test the _container_running command when the inspect command errors.
        """
        response = Response()
        response.status_code = 400
        m_docker_client.inspect_container.side_effect = APIError("Test error message", response)

        self.assertRaises(APIError, node._container_running, "container1")
        m_docker_client.inspect_container.assert_called_once_with("container1")

    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_container_running_cont_running(self, m_docker_client):
        """
        Test the _container_running command when the container is running
        """
        for test in (True, False):
            m_docker_client.inspect_container.return_value = {"State": {"Running": test}}
            self.assertEquals(node._container_running("container1"), test)
