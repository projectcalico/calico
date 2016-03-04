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
                                ETCD_AUTHORITY_ENV)

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
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.error_if_bgp_ip_conflict', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node._find_or_pull_node_image', autospec=True)
    @patch('calico_ctl.node._attach_and_stream', autospec=True)
    @patch('calico_ctl.node.running_in_container', autospec=True)
    def test_node_dockerless_start(self, m_container, m_attach_and_stream,
                                   m_find_or_pull_node_image, m_call, m_docker,
                                   m_docker_client, m_client,
                                   m_error_if_bgp_ip_conflict,
                                   m_warn_if_hostname_conflict,
                                   m_warn_if_unknown_ip, m_get_host_ips,
                                   m_setup_ip, m_check_system, m_os_makedirs,
                                   m_os_path_exists, m_ipv6_enabled):
        """
        Test that the node_start function performs all necessary configurations
        without making Docker calls when runtime=none.
        """
        # Set up mock objects
        m_container.return_value = False
        m_os_path_exists.return_value = False
        ip_1 = '1.1.1.1'
        ip_2 = '2.2.2.2'
        m_get_host_ips.return_value = [ip_1, ip_2]
        m_docker.utils.create_host_config.return_value = 'host_config'
        container = {'Id': 666}
        m_docker_client.create_container.return_value = container
        m_check_system.return_value = [True, True, True]

        # Set up arguments
        node_image = 'node_image'
        runtime = 'none'
        log_dir = './log_dir'
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = True
        libnetwork = False

        # Call method under test
        node.node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
                        libnetwork)

        # Assert
        m_os_path_exists.assert_called_once_with(log_dir)
        m_os_makedirs.assert_called_once_with(log_dir)
        m_check_system.assert_called_once_with(quit_if_error=False,
                                               libnetwork=libnetwork,
                                               check_docker=False,
                                               check_modules=True
                                               )
        m_setup_ip.assert_called_once_with()
        m_get_host_ips.assert_called_once_with(exclude=["^docker.*", "^cbr.*",
                                                        "virbr.*", "lxcbr.*",
                                                        "veth.*", "cali.*",
                                                        "tunl.*"])
        m_warn_if_unknown_ip.assert_called_once_with(ip_2, ip6)
        m_warn_if_hostname_conflict.assert_called_once_with(ip_2)
        m_error_if_bgp_ip_conflict.assert_called_once_with(ip_2, ip6)
        m_client.get_ip_pools.assert_has_calls([call(4), call(6)])
        m_client.ensure_global_config.assert_called_once_with()
        m_client.create_host.assert_called_once_with(
            node.hostname, ip_2, ip6, as_num
        )

        self.assertFalse(m_docker_client.remove_container.called)
        self.assertFalse(m_docker.utils.create_host_config.called)
        self.assertFalse(m_find_or_pull_node_image.called)
        self.assertFalse(m_docker_client.create_container.called)
        self.assertFalse(m_docker_client.start.called)
        self.assertFalse(m_attach_and_stream.called)

    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.running_in_container', autospec=True)
    @patch('calico_ctl.node._remove_host_tunnel_addr', autospec=True)
    @patch('calico_ctl.node._ensure_host_tunnel_addr', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.error_if_bgp_ip_conflict', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    @patch('calico_ctl.node._find_or_pull_node_image', autospec=True)
    @patch('calico_ctl.node._attach_and_stream', autospec=True)
    def test_node_start(self, m_attach_and_stream,
                        m_find_or_pull_node_image, m_docker,
                        m_docker_client, m_client,
                        m_error_if_bgp_ip_conflict, m_warn_if_hostname_conflict,
                        m_warn_if_unknown_ip, m_get_host_ips, m_setup_ip,
                        m_check_system, m_ensure_host_tunnel_addr,
                        m_remove_host_tunnel_addr, m_container, m_call,
                        m_os_makedirs, m_os_path_exists, m_ipv6_enabled):
        """
        Test that the node_Start function does not make Docker calls
        function returns
        """
        # Set up mock objects
        m_container.return_value = False
        m_os_path_exists.return_value = False
        ip_1 = '1.1.1.1'
        ip_2 = '2.2.2.2'
        m_get_host_ips.return_value = [ip_1, ip_2]
        m_docker.utils.create_host_config.return_value = 'host_config'
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
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        libnetwork = False

        # Call method under test
        node.node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
                        libnetwork)

        # Set up variables used in assertion statements
        environment = [
            "HOSTNAME=%s" % node.hostname,
            "IP=%s" % ip_2,
            "IP6=%s" % ip6,
            "CALICO_NETWORKING=%s" % node.CALICO_NETWORKING_DEFAULT,
            "ETCD_AUTHORITY=%s" % ETCD_AUTHORITY_DEFAULT,  # etcd host:port
            "ETCD_SCHEME=%s" % ETCD_SCHEME_DEFAULT,
            "FELIX_ETCDADDR=%s" % ETCD_AUTHORITY_DEFAULT,  # etcd host:port
            "FELIX_ETCDSCHEME=%s" % ETCD_SCHEME_DEFAULT
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
        m_get_host_ips.assert_called_once_with(exclude=["^docker.*", "^cbr.*",
                                                        "virbr.*", "lxcbr.*",
                                                        "veth.*", "cali.*",
                                                        "tunl.*"])
        m_warn_if_unknown_ip.assert_called_once_with(ip_2, ip6)
        m_warn_if_hostname_conflict.assert_called_once_with(ip_2)
        m_error_if_bgp_ip_conflict.assert_called_once_with(ip_2, ip6)
        m_client.get_ip_pools.assert_has_calls([call(4), call(6)])
        m_client.ensure_global_config.assert_called_once_with()
        m_client.create_host.assert_called_once_with(
            node.hostname, ip_2, ip6, as_num
        )
        m_ensure_host_tunnel_addr.assert_called_once_with(ipv4_pools,
                                                          ipip_pools)
        assert_false(m_remove_host_tunnel_addr.called)

        m_docker_client.remove_container.assert_called_once_with(
            'calico-node', force=True
        )
        m_docker.utils.create_host_config.assert_called_once_with(
            privileged=True,
            restart_policy={"Name": "always"},
            network_mode="host",
            binds=binds
        )
        m_find_or_pull_node_image.assert_called_once_with('node_image')
        m_docker_client.create_container.assert_called_once_with(
            node_image,
            name='calico-node',
            detach=True,
            environment=environment,
            host_config='host_config',
            volumes=['/var/log/calico', "/var/run/calico"]
        )
        m_docker_client.start.assert_called_once_with(container)
        m_attach_and_stream.assert_called_once_with(container)

    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('os.getenv', autospec=True)
    @patch('calico_ctl.node._remove_host_tunnel_addr', autospec=True)
    @patch('calico_ctl.node._ensure_host_tunnel_addr', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.error_if_bgp_ip_conflict', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    @patch('calico_ctl.node._find_or_pull_node_image', autospec=True)
    @patch('calico_ctl.node._attach_and_stream', autospec=True)
    @patch('calico_ctl.node.running_in_container', autospec=True)
    def test_node_start_secure(self, m_container, m_attach_and_stream,
                               m_find_or_pull_node_image, m_docker, m_call,
                               m_docker_client, m_client,
                               m_error_if_bgp_ip_conflict,
                               m_warn_if_hostname_conflict, m_warn_if_unknown_ip,
                               m_get_host_ips, m_setup_ip, m_check_system,
                               m_ensure_host_tunnel_addr,
                               m_remove_host_tunnel_addr, m_os_getenv,
                               m_os_makedirs, m_os_path_exists, m_ipv6_enabled):
        """
        Test that the node_start function passes in correct values when
        secure etcd environment variables are present.
        """
        # Set up mock objects
        m_container.return_value = False
        ip_1 = '1.1.1.1'
        ip_2 = '2.2.2.2'
        m_get_host_ips.return_value = [ip_1, ip_2]
        container1 = {'Id': 111}
        container2 = {'Id': 222}
        m_docker_client.create_container.side_effect = iter([container1,
                                                             container2])
        m_docker.utils.create_host_config.return_value = 'host_config'
        m_os_path_exists.return_value = True
        m_check_system.return_value = [True, True, True]
        m_client.get_ip_pools.return_value = []

        etcd_ca_path = "/path/to/ca.crt"
        etcd_cert_path = "/path/to/cert.crt"
        etcd_key_path = "/path/to/key.pem"
        env = {"CALICO_NETWORKING": CALICO_NETWORKING_DEFAULT,
               ETCD_AUTHORITY_ENV: ETCD_AUTHORITY_DEFAULT,
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
        ip = ''
        ip6 = 'aa:bb::zz'
        as_num = ''
        detach = False
        libnetwork_image = 'libnetwork_image'

        # Call method under test
        node.node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
                        libnetwork_image)

        # Set up variables used in assertion statements
        environment_node = [
            "HOSTNAME=%s" % node.hostname,
            "IP=%s" % ip_2,
            "IP6=%s" % ip6,
            "CALICO_NETWORKING=%s" % CALICO_NETWORKING_DEFAULT,
            "ETCD_AUTHORITY=%s" % ETCD_AUTHORITY_DEFAULT,  # etcd host:port
            "ETCD_SCHEME=%s" % "https",
            "ETCD_CA_CERT_FILE=%s" % ETCD_CA_CERT_NODE_FILE,
            "ETCD_KEY_FILE=%s" % ETCD_KEY_NODE_FILE,
            "ETCD_CERT_FILE=%s" % ETCD_CERT_NODE_FILE,
            "FELIX_ETCDADDR=%s" % ETCD_AUTHORITY_DEFAULT,  # etcd host:port
            "FELIX_ETCDSCHEME=https",
            "FELIX_ETCDCAFILE=%s" % ETCD_CA_CERT_NODE_FILE,
            "FELIX_ETCDKEYFILE=%s" % ETCD_KEY_NODE_FILE,
            "FELIX_ETCDCERTFILE=%s" % ETCD_CERT_NODE_FILE
        ]
        environment_libnetwork = [
            "HOSTNAME=%s" % node.hostname,
            "ETCD_AUTHORITY=%s" % ETCD_AUTHORITY_DEFAULT,  # etcd host:port
            "ETCD_SCHEME=%s" % "https",
            "ETCD_CA_CERT_FILE=%s" % ETCD_CA_CERT_NODE_FILE,
            "ETCD_KEY_FILE=%s" % ETCD_KEY_NODE_FILE,
            "ETCD_CERT_FILE=%s" % ETCD_CERT_NODE_FILE,
        ]
        binds_node = {
            log_dir: {"bind": "/var/log/calico", "ro": False},
            "/var/run/calico": {"bind": "/var/run/calico", "ro": False},
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
        volumes_node = ['/var/log/calico', "/var/run/calico", ETCD_CA_CERT_NODE_FILE,
                        ETCD_KEY_NODE_FILE, ETCD_CERT_NODE_FILE]
        volumes_libnetwork= [docker_plugin, ETCD_CA_CERT_NODE_FILE,
                             ETCD_KEY_NODE_FILE, ETCD_CERT_NODE_FILE]

        # Assert
        m_os_path_exists.assert_called_once_with(log_dir)
        m_check_system.assert_called_once_with(quit_if_error=False,
                                               libnetwork=libnetwork_image,
                                               check_docker=True,
                                               check_modules=True)
        m_setup_ip.assert_called_once_with()
        m_get_host_ips.assert_called_once_with(exclude=["^docker.*", "^cbr.*",
                                                        "virbr.*", "lxcbr.*",
                                                        "veth.*", "cali.*",
                                                        "tunl.*"])
        m_warn_if_unknown_ip.assert_called_once_with(ip_2, ip6)
        m_warn_if_hostname_conflict.assert_called_once_with(ip_2)
        m_error_if_bgp_ip_conflict.assert_called_once_with(ip_2, ip6)
        m_client.get_ip_pools.assert_has_calls([call(4), call(6)])
        m_client.ensure_global_config.assert_called_once_with()
        m_client.create_host.assert_called_once_with(node.hostname, ip_2, ip6,
                                                     as_num)
        assert_true(m_remove_host_tunnel_addr.called)

        m_docker_client.remove_container.assert_has_calls([
            call('calico-node', force=True),
            call('calico-libnetwork', force=True)
        ])
        m_docker.utils.create_host_config.assert_has_calls([
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
        m_attach_and_stream.assert_called_once_with(container1)


    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.error_if_bgp_ip_conflict', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    def test_node_start_remove_container_error(
            self, m_docker, m_docker_client, m_client, m_call,
            m_error_if_bgp_ip_conflict, m_warn_if_hostname_conflict,
            m_warn_if_unknown_ip, m_get_host_ips, m_setup_ip, m_check_system,
            m_os_makedirs, m_os_path_exists, m_ipv6_enabled):
        """
        Test that the docker client raises an APIError when it fails to
        remove a container.
        """
        # Set up mock objects
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

        # Testing expecting APIError exception
        self.assertRaises(APIError, node.node_start,
                          node_image, runtime, log_dir, ip, ip6, as_num, detach,
                          libnetwork)

    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('sys.exit', autospec=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.error_if_bgp_ip_conflict', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    def test_node_start_no_detected_ips(
            self, m_docker, m_docker_client, m_client, m_call,
            m_error_if_bgp_ip_conflict, m_warn_if_hostname_conflict,
            m_warn_if_unknown_ip, m_get_host_ips, m_setup_ip, m_check_system,
            m_os_makedirs, m_os_path_exists, m_sys_exit, m_ipv6_enabled):
        """
        Test that system exits when no ip is provided and host ips cannot be
        obtained
        """
        # Set up mock objects
        m_get_host_ips.return_value = []
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

        # Call method under test
        node.node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
                        libnetwork)

        # Assert
        m_sys_exit.assert_called_once_with(1)

    @patch('calico_ctl.node.ipv6_enabled', autospec=True, return_value=True)
    @patch('os.path.exists', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_ctl.node.check_system', autospec=True)
    @patch('calico_ctl.node._setup_ip_forwarding', autospec=True)
    @patch('calico_ctl.node.get_host_ips', autospec=True)
    @patch('calico_ctl.node.warn_if_unknown_ip', autospec=True)
    @patch('calico_ctl.node.warn_if_hostname_conflict', autospec=True)
    @patch('calico_ctl.node.error_if_bgp_ip_conflict', autospec=True)
    @patch('calico_ctl.node.call', autospec=True)
    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    @patch('calico_ctl.node.docker', autospec=True)
    def test_node_start_create_default_ip_pools(
            self, m_docker, m_docker_client, m_client, m_call,
            m_error_if_bgp_ip_conflict, m_warn_if_hostname_conflict,
            m_warn_if_unknown_ip, m_get_host_ips, m_setup_ip, m_check_system,
            m_os_makedirs, m_os_path_exists, m_ipv6_enabled):
        """
        Test that the client creates default ipv4 and ipv6 pools when the
        client returns an empty ip_pool on etcd setup
        """
        # Set up mock objects
        m_client.get_ip_pools.return_value = []
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

        # Call method under test
        node.node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
                        libnetwork)

        # Assert
        m_client.add_ip_pool.assert_has_calls([
            call(4, node.DEFAULT_IPV4_POOL),
            call(6, node.DEFAULT_IPV6_POOL)
        ])

    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_stop(self, m_docker_client, m_client):
        """
        Test the client stops the node when node_stop called when there are
        endpoints and the force flag is set.
        """
        # Call method under test
        m_client.get_endpoints.return_value = [Mock()]
        node.node_stop(True)

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname=node.hostname)
        m_docker_client.stop.assert_has_calls([call('calico-node'),
                                               call('calico-libnetwork')])

    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_stop_endpoints(self, m_docker_client, m_client):
        """
        Test the client does not stops the node when node_stop is called and
        there are endpoints and the force flag is not set.
        """
        # Call method under test
        m_client.get_endpoints.return_value = [Mock()]
        self.assertRaises(SystemExit, node.node_stop, False)

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname=node.hostname)
        self.assertEquals(m_docker_client.stop.call_count, 0)

    @patch('calico_ctl.node.client', autospec=True)
    @patch('calico_ctl.node.docker_client', autospec=True)
    def test_node_stop_error(self, m_docker_client, m_client):
        """
        Test node_stop raises an exception when the docker client cannot not
        stop the node
        """
        # Set up mock objects
        m_client.get_endpoints.return_value = [Mock()]
        err = APIError("Test error message", Response())

        for sidee in ([None, err], [err, None]):
            m_docker_client.stop.side_effect = sidee

            # Call method under test expecting an exception
            self.assertRaises(APIError, node.node_stop, True)

    @patch('calico_ctl.node._remove_host_tunnel_addr', autospec=True)
    @patch('calico_ctl.node.remove_veth', autospec=True)
    @patch('calico_ctl.node._container_running', autospec=True, return_value=False)
    @patch('calico_ctl.node.client', autospec=True)
    def test_node_remove(self, m_client, m_cont_running, m_veth,
                         m_remove_tunnel_addr):
        """
        Test the client removes the host when node_remove called, and that
        endpoints are removed when remove_endpoints flag is set.
        """
        # Call method under test
        endpoint1 = Mock()
        endpoint1.name = "vethname1"
        endpoint2 = Mock()
        endpoint2.name = "vethname2"
        m_client.get_endpoints.return_value = [endpoint1, endpoint2]
        node.node_remove(True)

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname=node.hostname)
        m_client.remove_host.assert_called_once_with(node.hostname)
        m_veth.assert_has_calls([call("vethname1"), call("vethname2")])
        m_cont_running.assert_has_calls([call("calico-node"), call("calico-libnetwork")])
        assert_equal(m_remove_tunnel_addr.mock_calls, [call()])

    @patch('calico_ctl.node.remove_veth', autospec=True)
    @patch('calico_ctl.node._container_running', autospec=True, return_value=True)
    @patch('calico_ctl.node.client', autospec=True)
    def test_node_remove_node_running(self, m_client, m_cont_running, m_veth):
        """
        Test the client does not remove host when containers are running and
        node_remove is invoked.
        """
        # Assert
        self.assertRaises(SystemExit, node.node_remove, True)
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
        self.assertRaises(SystemExit, node.node_remove, False)

        # Assert
        m_client.get_endpoints.assert_called_once_with(hostname=node.hostname)
        self.assertEquals(m_client.remove_host.call_count, 0)
        self.assertEquals(m_veth.call_count, 0)

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


    @patch("calico_ctl.node.client", autospec=True)
    @patch("sys.exit", autospec=True)
    def test_error_if_bgp_ipv4_conflict_no_conflict(self, m_exit, m_client):
        """
        Test check that node IP is not already in use by another node, no error.
        """
        m_client.get_hostnames_from_ips = Mock()
        m_client.get_hostnames_from_ips.return_value = {}
        node.error_if_bgp_ip_conflict("10.0.0.1", "abcd::beef")
        self.assertFalse(m_exit.called)

    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.utils.get_hostname", autospec=True)
    @patch("sys.exit", autospec=True)
    def test_error_if_ip_conflict_ipv6_key_error(self, m_exit, m_hostname,
                                                 m_client):
        """
        Test that function accepts IP being owned by same host.
        """
        calico_ctl.node.hostname = "host"
        m_client.get_hostnames_from_ips = Mock()
        m_client.get_hostnames_from_ips.return_value = {"10.0.0.1":"host"}
        node.error_if_bgp_ip_conflict("10.0.0.1", "abcd::beef")
        self.assertFalse(m_exit.called)

    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.utils.get_hostname", autospec=True)
    def test_error_when_bgp_ipv4_conflict(self, m_hostname, m_client):
        """
        Test that function exits when another node already uses ipv4 addr.
        """
        calico_ctl.node.hostname = "not_host"
        m_client.get_hostnames_from_ips = Mock()
        m_client.get_hostnames_from_ips.return_value = {"10.0.0.1":"host"}
        self.assertRaises(SystemExit, node.error_if_bgp_ip_conflict,
                          "10.0.0.1", None)

    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.utils.get_hostname", autospec=True)
    def test_error_when_bgp_ipv6_conflict(self, m_hostname, m_client):
        """
        Test that function exits when another node already uses ipv6 addr.
        """
        calico_ctl.node.hostname = "not_host"
        m_client.get_hostnames_from_ips = Mock()
        m_client.get_hostnames_from_ips.return_value = {"abcd::beef":"host"}
        self.assertRaises(SystemExit, node.error_if_bgp_ip_conflict,
                          None, "abcd::beef")

    @patch("calico_ctl.node._get_host_tunnel_ip", autospec=True)
    @patch("calico_ctl.node._assign_host_tunnel_addr", autospec=True)
    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.utils.get_hostname", autospec=True)
    def test_ensure_host_tunnel_addr_no_ip(self, m_hostname, m_client,
                                           m_assign_host_tunnel_addr,
                                           m_get_tunnel_host_ip):
        m_get_tunnel_host_ip.return_value = None
        ipv4_pools = [IPPool("10.0.0.0/16"),
                      IPPool("10.1.0.0/16", ipip=True)]
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True)]
        calico_ctl.node._ensure_host_tunnel_addr(ipv4_pools, ipip_pools)
        assert_equal(m_assign_host_tunnel_addr.mock_calls, [call(ipip_pools)])

    @patch("calico_ctl.node._get_host_tunnel_ip", autospec=True)
    @patch("calico_ctl.node._assign_host_tunnel_addr", autospec=True)
    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.utils.get_hostname", autospec=True)
    def test_ensure_host_tunnel_addr_non_ipip(self, m_hostname, m_client,
                                              m_assign_host_tunnel_addr,
                                              m_get_tunnel_host_ip):
        m_get_tunnel_host_ip.return_value = IPAddress("10.0.0.1")
        ipv4_pools = [IPPool("10.0.0.0/16"),
                      IPPool("10.1.0.0/16", ipip=True)]
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True)]
        calico_ctl.node._ensure_host_tunnel_addr(ipv4_pools, ipip_pools)
        assert_equal(m_client.release_ips.mock_calls,
                     [call({IPAddress("10.0.0.1")})])
        assert_equal(m_assign_host_tunnel_addr.mock_calls, [call(ipip_pools)])

    @patch("calico_ctl.node._get_host_tunnel_ip", autospec=True)
    @patch("calico_ctl.node._assign_host_tunnel_addr", autospec=True)
    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.utils.get_hostname", autospec=True)
    def test_ensure_host_tunnel_addr_bad_ip(self, m_hostname, m_client,
                                            m_assign_host_tunnel_addr,
                                            m_get_tunnel_host_ip):
        m_get_tunnel_host_ip.return_value = IPAddress("11.0.0.1")
        ipv4_pools = [IPPool("10.0.0.0/16"),
                      IPPool("10.1.0.0/16", ipip=True)]
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True)]
        calico_ctl.node._ensure_host_tunnel_addr(ipv4_pools, ipip_pools)
        assert_equal(m_assign_host_tunnel_addr.mock_calls, [call(ipip_pools)])

    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.node.hostname", autospec=True)
    def test_assign_host_tunnel_addr(self, m_hostname, m_client):
        # First pool full, IP allocated from second pool.
        m_client.auto_assign_ips.side_effect = iter([
            ([], []),
            ([IPAddress("10.0.0.1")], [])
        ])
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True),
                      IPPool("10.0.0.0/16", ipip=True)]
        calico_ctl.node._assign_host_tunnel_addr(ipip_pools)
        assert_equal(
            m_client.set_per_host_config.mock_calls,
            [call(m_hostname, "IpInIpTunnelAddr", "10.0.0.1")]
        )

    @patch("sys.exit", autospec=True)
    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.node.hostname", autospec=True)
    def test_assign_host_tunnel_addr_none_available(self, m_hostname,
                                                    m_client, m_exit):
        # First pool full, IP allocated from second pool.
        m_client.auto_assign_ips.side_effect = iter([
            ([], []),
            ([], [])
        ])
        ipip_pools = [IPPool("10.1.0.0/16", ipip=True),
                      IPPool("10.0.0.0/16", ipip=True)]
        m_exit.side_effect = Exception
        assert_raises(Exception, calico_ctl.node._assign_host_tunnel_addr,
                      ipip_pools)
        assert_equal(m_exit.mock_calls, [call(1)])

    @patch("calico_ctl.node._get_host_tunnel_ip", autospec=True)
    @patch("calico_ctl.node.client", autospec=True)
    @patch("calico_ctl.node.hostname", autospec=True)
    def test_remove_host_tunnel_addr(self, m_hostname, m_client, m_get_ip):
        ip_address = IPAddress("10.0.0.1")
        m_get_ip.return_value = ip_address
        calico_ctl.node._remove_host_tunnel_addr()
        assert_equal(m_client.release_ips.mock_calls, [call({ip_address})])
        assert_equal(m_client.remove_per_host_config.mock_calls,
                     [call(m_hostname, "IpInIpTunnelAddr")])