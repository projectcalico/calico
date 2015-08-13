# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os

import unittest
from mock import patch, Mock
import sys
from calico_rkt import plugin

POD_ID = 'ff3afbd1-17ad-499d-b514-72438c009e81'
NETNS_PATH = '/var/lib/rkt/pods/run/%s/netns' % POD_ID
STDIN_JSON = '{"ipam": {"routes": [{"dst": "0.0.0.0/0"}], ' \
             '"subnet": "10.22.0.0/16", "type": "host-local"}, ' \
             '"type": "calico", "name": "test"}'

class RktPluginTest(unittest.TestCase):

    @patch('calico_rkt.tests.test_rkt_plugin.plugin.create', autospec=True)
    @patch.object(sys, 'argv', ['/usr/lib/rkt/plugins/net/calico'],
                  autospec=True)
    @patch.object(os, 'environ', {
        'CNI_IFNAME': 'eth0',
        'CNI_ARGS': '',
        'CNI_COMMAND': 'ADD',
        'CNI_PATH': '/usr/lib/rkt/plugins/net:'
                    'stage1/rootfs/usr/lib/rkt/plugins/net',
        'CNI_NETNS': NETNS_PATH,
        'CNI_PODID': POD_ID,
    }, autospec=True)
    # @patch.object(sys, 'stdin', ['/usr/lib/rkt/plugins/net/calico'])
    @patch('sys.stdin',  autospec=True)
    def test_main(self, m_stdin, m_create):
        """Test that the main() function parses inputs correctly."""
        m_stdin.readlines.return_value = STDIN_JSON

        plugin.main()

        m_create.assert_called_with(pod_id=POD_ID, netns_path=NETNS_PATH,
                                    ip='192.168.0.111')

    @patch('calico_rkt.tests.test_rkt_plugin.plugin._create_calico_endpoint',
           autospec=True)
    @patch('calico_rkt.tests.test_rkt_plugin.plugin._configure_profile',
           autospec=True)
    def test_add(self, m_conf_profile, m_create_ep):
        id_ = '123'
        path = '/a/b/c'
        ip = '1.2.3.4/24'
        mock_ep = Mock()
        m_create_ep.return_value = mock_ep

        plugin.add(id_, path, ip)

        m_create_ep.assert_called_with(id_, path)
        m_conf_profile.assert_called_with(endpoint=mock_ep, profile_name=id_)

    # @patch('socket.gethostname', return_value='HOST', autospec=True)
    # @patch('pycalico.datastore.set_endpoint', autospec=True)
    # @patch('pycalico.netns.provision_veth', autospec=True)
    # @patch('pycalico.datastore.create_endpoint', autospec=True)
    # def test_create_calico_endpoint(self, m_create_endpoint, m_provision_veth, m_set_endpoint):
    #     # TODO: impl-specific
    #     pass

    @patch('socket.gethostname', return_value='HOST', autospec=True)
    @patch('pycalico.datastore.set_endpoint', autospec=True)
    @patch('pycalico.netns.provision_veth', autospec=True)
    @patch('pycalico.datastore.create_endpoint', autospec=True)
    def test_create_profile(self, m_create_endpoint, m_provision_veth, m_set_endpoint):
        # TODO: impl-specific
        pass


    #     with patch.object(self.plugin, "_configure_interface",
    #                 autospec=True) as m_configure_interface, \
    #             patch.object(self.plugin, "_configure_profile",
    #                 autospec=True) as m_configure_profile:
    #         # Set up mock objects
    #         m_configure_interface.return_value = "endpt_id"
    #
    #         # Set up args
    #         pod_name = "pod1"
    #         docker_id = 13
    #
    #         # Call method under test
    #         self.plugin.create(pod_name, docker_id)
    #
    #         # Assert
    #         self.assertEqual(pod_name, self.plugin.pod_name)
    #         self.assertEqual(docker_id, self.plugin.docker_id)
    #         m_configure_interface.assert_called_once_with()
    #         m_configure_profile.assert_called_once_with("endpt_id")
    #
    # def test_create_error(self):
    #     with patch.object(self.plugin, "_configure_interface",
    #                 autospec=True) as m_configure_interface, \
    #             patch("sys.exit", autospec=True) as m_sys_exit:
    #         # Set up mock objects
    #         m_configure_interface.side_effect = CalledProcessError(1,"","")
    #
    #         # Set up args
    #         pod_name = "pod1"
    #         docker_id = 13
    #
    #         # Call method under test
    #         self.plugin.create(pod_name, docker_id)
    #
    #         # Assert
    #         m_sys_exit.assert_called_once_with(1)
    #
    # def test_delete(self):
    #     with patch.object(self.plugin, "_datastore_client", autospec=True) as m_datastore_client, \
    #             patch.object(self.plugin, "calicoctl", autospec=True) as m_calicoctl:
    #         # Set up mock objs
    #         m_datastore_client.profile_exists.return_value = True
    #
    #         # Set up args
    #         pod_name = "pod1"
    #         docker_id = 13
    #
    #         # Call method under test
    #         self.plugin.delete(pod_name, docker_id)
    #
    #         # Assert
    #         self.assertEqual(self.plugin.pod_name, pod_name)
    #         self.assertEqual(self.plugin.docker_id, docker_id)
    #         m_calicoctl.assert_called_once_with("container", "remove", docker_id)
    #         m_datastore_client.remove_profile(pod_name)
    #
    # def test_configure_interface(self):
    #     with patch.object(self.plugin, "_read_docker_ip",
    #                 autospec=True) as m_read_docker, \
    #             patch.object(self.plugin, "_delete_docker_interface",
    #                 autospec=True) as m_delete_docker_interface, \
    #             patch.object(self.plugin, "calicoctl",
    #                 autospec=True) as m_calicoctl, \
    #             patch.object(calico_kubernetes, "generate_cali_interface_name",
    #                 autospec=True) as m_generate_cali_interface_name, \
    #             patch.object(self.plugin, "_get_node_ip",
    #                 autospec=True) as m_get_node_ip, \
    #             patch.object(calico_kubernetes, "check_call",
    #                 autospec=True) as m_check_call,\
    #             patch.object(self.plugin, "_datastore_client",
    #                 autospec=True) as m_datastore_client,\
    #             patch.object(self.plugin, "_docker_client", \
    #                 autospec=True) as m_docker_client:
    #         # Set up mock objects
    #         m_read_docker.return_value = "docker_ip"
    #         class ep:
    #             endpoint_id = "ep_id"
    #         m_datastore_client.get_endpoint.return_value = ep
    #         m_generate_cali_interface_name.return_value = "interface_name"
    #         m_get_node_ip.return_value = "1.2.3.4"
    #
    #         # Call method under test
    #         return_val = self.plugin._configure_interface()
    #
    #         # Assert
    #         m_read_docker.assert_called_once_with()
    #         m_delete_docker_interface.assert_called_once_with()
    #         m_calicoctl.assert_called_once_with(
    #             "container", "add", self.plugin.docker_id, "docker_ip", "eth0")
    #         m_datastore_client.get_endpoint.assert_called_once_with(
    #             workload_id=m_docker_client.inspect_container().__getitem__())
    #         m_generate_cali_interface_name.assert_called_once_with(IF_PREFIX, "ep_id")
    #         m_get_node_ip.assert_called_once_with()
    #         m_check_call.assert_called_once_with(
    #             ["ip", "addr", "add", "1.2.3.4" + "/32",
    #             "dev", "interface_name"])
    #         self.assertEqual(return_val.endpoint_id, "ep_id")
    #
    # def test_get_node_ip(self):
    #     with patch("calico_kubernetes.calico_kubernetes.get_host_ips",
    #                autospec=True) as m_get_host_ips:
    #         # Set up mock objects
    #         m_get_host_ips.return_value = ["1.2.3.4","4.2.3.4"]
    #
    #         # Call method under test
    #         return_val = self.plugin._get_node_ip()
    #
    #         # Assert
    #         m_get_host_ips.assert_called_once_with(version=4)
    #         self.assertEqual(return_val, "1.2.3.4")
    #
    # def test_read_docker_ip(self):
    #     with patch.object(calico_kubernetes, "check_output",
    #                       autospec=True) as m_check_output:
    #         # Set up mock objects
    #         m_check_output.return_value = "1.2.3.4"
    #
    #         # Call method under test
    #         return_val = self.plugin._read_docker_ip()
    #
    #         # Assert
    #         m_check_output.assert_called_once_with([
    #             "docker", "inspect", "-format", "{{ .NetworkSettings.IPAddress }}",
    #             self.plugin.docker_id])
    #         self.assertEqual(return_val, "1.2.3.4")
    #
    # def test_delete_docker_interface(self):
    #     with patch.object(calico_kubernetes, "check_output",
    #                       autospec=True) as m_check_output:
    #         # Set up mock objects
    #         m_check_output.return_value = "pid"
    #
    #         # Call method under test
    #         self.plugin._delete_docker_interface()
    #
    #         # Assert call list
    #         call_1 = call([
    #             "docker", "inspect", "-format", "{{ .State.Pid }}",
    #             self.plugin.docker_id])
    #         call_2 = call(["mkdir", "-p", "/var/run/netns"])
    #         call_3 = call(["ln", "-s", "/proc/" + "pid" + "/ns/net",
    #                         "/var/run/netns/pid"])
    #         call_4 = call(["ip", "netns", "exec", "pid", "ip", "link", "del", "eth0"])
    #         call_5 = call(["rm", "/var/run/netns/pid"])
    #         calls = [call_1,call_2,call_3,call_4,call_5]
    #
    #         m_check_output.assert_has_calls(calls)
    #
    # def test_configure_profile(self):
    #     with patch.object(self.plugin, "_datastore_client",
    #                 autospec=True) as m_datastore_client, \
    #             patch.object(self.plugin, "_get_pod_config",
    #                 autospec=True) as m_get_pod_config, \
    #             patch.object(self.plugin, "_apply_rules",
    #                 autospec=True) as m_apply_rules, \
    #             patch.object(self.plugin, "_apply_tags",
    #                 autospec=True) as m_apply_tags:
    #         # Set up mock objects
    #         m_datastore_client.profile_exists.return_value = False
    #         m_endpoint = Mock()
    #         m_endpoint.endpoint_id = "ep_id"
    #         m_get_pod_config.return_value = "pod"
    #
    #         # Set up class members
    #         profile_name = "podname"
    #         self.plugin.pod_name = profile_name
    #
    #         # Call method under test
    #         self.plugin._configure_profile(m_endpoint)
    #
    #         # Assert
    #         m_datastore_client.profile_exists.assert_called_once_with(profile_name)
    #         m_datastore_client.create_profile.assert_called_once_with(profile_name)
    #         m_get_pod_config.assert_called_once_with()
    #         m_apply_rules.assert_called_once_with(profile_name)
    #         m_apply_tags.assert_called_once_with(profile_name, "pod")
    #         m_datastore_client.set_profiles_on_endpoint(profile_name, endpoint_id="ep_id")
    #
    # def test_get_pod_ports(self):
    #     # Initialize pod dictionary and expected outcome
    #     pod = {"spec": {"containers": [{"ports": [1, 2, 3]},{"ports": [4, 5]}]}}
    #     ports = [1, 2, 3, 4, 5]
    #
    #     # Call method under test
    #     return_val = self.plugin._get_pod_ports(pod)
    #
    #     # Assert
    #     self.assertEqual(return_val, ports)
    #
    # def test_get_pod_ports_no_ports(self):
    #     """
    #     Tests for getting ports for a pod, which has no ports.
    #     Mocks the pod spec reponse from the apiserver such that it
    #     does not inclue the "ports" key for each of its containers.
    #     Asserts not ports are returned and no error is thrown.
    #     """
    #     # Initialize pod dictionary and expected outcome
    #     pod = {"spec": {"containers": [{"":[1, 2, 3]}, {"": [4, 5]}]}}
    #     ports = []
    #
    #     # Call method under test
    #     return_val = self.plugin._get_pod_ports(pod)
    #
    #     # Assert
    #     self.assertListEqual(return_val, ports)
    #
    # def test_get_pod_config(self):
    #     with patch.object(self.plugin, "_get_api_path",
    #                 autospec=True) as m_get_api_path:
    #         # Set up mock object
    #         pod1 = {"metadata": {"name": "pod-1"}}
    #         pod2 = {"metadata": {"name": "pod-2"}}
    #         pod3 = {"metadata": {"name": "pod-3"}}
    #         pods = [pod1, pod2, pod3]
    #         m_get_api_path.return_value = pods
    #
    #         # Set up class member
    #         self.plugin.pod_name = "pod-2"
    #
    #         # Call method under test
    #         return_val = self.plugin._get_pod_config()
    #
    #         # Assert
    #         self.assertEqual(return_val, pod2)
    #
    # def test_get_pod_config_error(self):
    #     with patch.object(self.plugin, "_get_api_path",
    #                 autospec=True) as m_get_api_path:
    #         # Set up mock object and class members
    #         pod1 = {"metadata": {"name": "pod-1"}}
    #         pod2 = {"metadata": {"name": "pod-2"}}
    #         pod3 = {"metadata": {"name": "pod-3"}}
    #         pods = [pod1, pod2, pod3]
    #         m_get_api_path.return_value = pods
    #
    #         # Set up class member
    #         self.plugin.pod_name = "pod_4"
    #
    #         # Call method under test expecting exception
    #         with self.assertRaises(KeyError):
    #             self.plugin._get_pod_config()
    #
    # def test_get_api_path(self):
    #     with patch.object(self.plugin, "_get_api_token",
    #                 autospec=True) as m_api_token, \
    #             patch("calico_kubernetes.calico_kubernetes.requests.Session",
    #                 autospec=True) as m_session, \
    #             patch.object(json, "loads", autospec=True) as m_json_load:
    #         # Set up mock objects
    #         m_api_token.return_value = "Token"
    #         m_session_return = Mock()
    #         m_session_return.headers = Mock()
    #         m_get_return = Mock()
    #         m_get_return.text = "response_body"
    #         m_session_return.get.return_value = m_get_return
    #         m_session.return_value = m_session_return
    #
    #         # Initialize args
    #         path = "path/to/api/object"
    #
    #         # Call method under test
    #         self.plugin._get_api_path(path)
    #
    #         # Assert
    #         m_api_token.assert_called_once_with()
    #         m_session.assert_called_once_with()
    #         m_session_return.headers.update.assert_called_once_with(
    #             {"Authorization": "Bearer " + "Token"})
    #         m_session_return.get.assert_called_once_with(
    #             calico_kubernetes.KUBE_API_ROOT + "path/to/api/object",
    #             verify=False)
    #         m_json_load.assert_called_once_with("response_body")
    #
    # def test_get_api_token(self):
    #     with patch("__builtin__.open", autospec=True) as m_open, \
    #             patch.object(json, "loads", autospec=True) as m_json:
    #         # Set up mock objects
    #         m_open().__enter__().read.return_value = "json_string"
    #         m_open.reset_mock()
    #         m_json.return_value = {"BearerToken" : "correct_return"}
    #
    #         # Call method under test
    #         return_val = self.plugin._get_api_token()
    #
    #         # Assert
    #         m_open.assert_called_once_with("/var/lib/kubelet/kubernetes_auth")
    #         m_json.assert_called_once_with("json_string")
    #         self.assertEqual(return_val, "correct_return")
    #
    # def test_generate_rules(self):
    #     # Call method under test
    #     return_val = self.plugin._generate_rules()
    #
    #     # Assert
    #     self.assertEqual(return_val, ([{"action": "allow"}], [{"action": "allow"}]))
    #
    # def test_generate_profile_json(self):
    #     with patch("calico_kubernetes.calico_kubernetes.json.dumps",
    #                autospec=True) as m_json:
    #         # Set up mock objects
    #         m_json.return_value = "correct_return"
    #
    #         # Initialize args
    #         rules = ("inbound", "outbound")
    #         profile_name = "profile_name"
    #
    #         # Call method under test
    #         return_val = self.plugin._generate_profile_json(
    #             profile_name, rules)
    #
    #         # Assert
    #         m_json.assert_called_once_with(
    #             {"id": "profile_name",
    #             "inbound_rules": "inbound",
    #             "outbound_rules": "outbound"},
    #              indent=2)
    #         self.assertEqual(return_val, "correct_return")
    #
    # def test_apply_rules(self):
    #     with patch.object(self.plugin, "_generate_rules",
    #                 autospec=True) as m_generate_rules, \
    #             patch.object(self.plugin, "_generate_profile_json",
    #                 autospec=True) as m_generate_profile_json, \
    #             patch.object(self.plugin, "_datastore_client",
    #                 autospec=True) as m_datastore_client, \
    #             patch("calico_kubernetes.calico_kubernetes.Rules",
    #                   autospec=True) as m_Rules:
    #         # Set up mock objects
    #         m_profile = Mock()
    #         m_datastore_client.get_profile.return_value = m_profile
    #         m_generate_rules.return_value = "rules"
    #         m_generate_profile_json.return_value = "json_profile"
    #
    #         # Call method under test
    #         self.plugin._apply_rules("profile")
    #
    #         # Assert
    #         m_datastore_client.get_profile.assert_called_once_with("profile")
    #         m_generate_rules.assert_called_once_with()
    #         m_generate_profile_json.assert_called_once_with("profile", "rules")
    #         m_Rules.from_json.assert_called_once_with("json_profile")
    #         m_datastore_client.profile_update_rules(m_profile)
    #
    # def test_apply_tags(self):
    #     with patch.object(self.plugin, "_datastore_client", autospec=True) as m_datastore_client:
    #         # Intialize args
    #         pod = {"metadata": {"labels": {1: 1, 2: 2}}}
    #         profile_name = "profile_name"
    #
    #         # Set up mock objs
    #         m_profile = Mock(spec=Profile, name = profile_name)
    #         m_profile.tags = set()
    #         m_datastore_client.get_profile.return_value = m_profile
    #         check_tags = set()
    #         check_tags.add("1_1")
    #         check_tags.add("2_2")
    #
    #         # Call method under test
    #         self.plugin._apply_tags(profile_name, pod)
    #
    #         # Assert
    #         m_datastore_client.get_profile.assert_called_once_with(profile_name)
    #         m_datastore_client.profile_update_tags.assert_called_once_with(m_profile)
    #         self.assertEqual(m_profile.tags, check_tags)
    #
    # def test_apply_tags_error(self):
    #     with patch.object(self.plugin, "calicoctl",autospec=True) as m_calicoctl:
    #         # Intialize args
    #         pod = {}
    #         profile_name = "profile_name"
    #
    #         # Call method under test
    #         self.plugin._apply_tags(profile_name, pod)
    #
    #         # Assert
    #         self.assertFalse(m_calicoctl.called)
