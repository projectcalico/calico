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

import json
import unittest

from mock import patch, MagicMock, ANY
from netaddr import IPNetwork
from nose.tools import assert_equal, assert_true, assert_false, assert_raises
from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import Rule, Rules
from pycalico.datastore_errors import DataStoreError

import calico
import ipam
from calico_cni import container_engines
from calico_cni.constants import *
from calico_cni.container_engines import DockerEngine
from calico_cni.policy_drivers import (DefaultPolicyDriver,
        KubernetesDefaultPolicyDriver, KubernetesAnnotationDriver)


class CniPluginFvTest(unittest.TestCase):
    """
    Performs FV testing on an instance of CniPlugin.

    Mocked out interfaces:
    - Popen
    - netns
    - pycalico.DatastoreClient
    """
    def setUp(self):
        self.command = None
        self.network_name = "calico-fv"
        self.plugin_type = "calico"
        self.ipam_type = "not-calico-ipam"
        self.container_id = "ff3afbd1-17ad-499d-b514-72438c009e81"
        self.cni_ifname = "eth0"
        self.cni_args = ""
        self.cni_path = "/usr/bin/rkt/"
        self.cni_netns = "netns"
        self.policy = {} 

        # Mock out the datastore client.
        self.client = MagicMock(spec=DatastoreClient)

        # Setup module mocks.
        self.popen = calico.Popen
        self.m_popen = MagicMock(spec=self.popen)
        calico.Popen = self.m_popen

        self.os = calico.os
        self.m_os = MagicMock(spec=self.os)
        calico.os = self.m_os

        self.netns = calico.netns
        self.m_netns = MagicMock(spec=self.netns)
        calico.netns = self.m_netns

        self.docker_client = container_engines.Client
        self.m_docker_client = MagicMock(self.docker_client)
        container_engines.Client = self.m_docker_client

        self.ipam_plugin_client = ipam.IPAMClient
        self.m_ipam_plugin_client = MagicMock(self.ipam_plugin_client)
        ipam.IPAMClient = self.m_ipam_plugin_client

    def tearDown(self):
        # Reset module mocks.
        calico.Popen = self.m_popen
        calico.os = self.os
        calico.netns = self.m_netns
        container_engines.Client = self.docker_client
        ipam.IPAMClient = self.ipam_plugin_client

    def create_plugin(self):
        self.network_config = {
            "name": self.network_name, 
            "type": self.plugin_type,
            "ipam": {
                "type": self.ipam_type,
                "assign_ipv6": "true",
                "assign_ipv4": "true"
            },
            "policy": self.policy
        }

        self.env = {
                CNI_COMMAND_ENV: self.command, 
                CNI_CONTAINERID_ENV: self.container_id,
                CNI_IFNAME_ENV: self.cni_ifname,
                CNI_ARGS_ENV: self.cni_args,
                CNI_PATH_ENV: self.cni_path, 
                CNI_NETNS_ENV: self.cni_netns
        }

        # Create the CniPlugin to test.
        plugin = calico.CniPlugin(self.network_config, self.env)

        # Mock out the datastore client.
        plugin._client = self.client
        plugin.policy_driver._client = self.client

        return plugin

    def set_ipam_result(self, rc, stdout, stderr):
        """
        Set the output of the mock IPAM plugin before execution.
        """
        self.m_popen().communicate.return_value = stdout, stderr
        self.m_popen().returncode = rc

    def test_add_mainline(self):
        """
        Tests basic CNI add functionality.

        Uses DefaultPolicyDriver.
        """
        # Configure.
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        ipam_stdout = json.dumps({"ip4": {"ip": ip4}, 
                                  "ip6": {"ip": ip6}})
        self.set_ipam_result(0, ipam_stdout, "")

        # Create plugin.
        p = self.create_plugin()

        # Mock DatastoreClient such that no endpoints exist.
        self.client.get_endpoint.side_effect = KeyError

        # Mock profile such that it doesn't exist.
        self.client.profile_exists.return_value = False

        # Execute.
        p.execute()
        
        # Assert the correct policy driver was chosen.
        assert_true(isinstance(p.policy_driver, DefaultPolicyDriver)) 

        # Assert an endpoint was created.
        self.client.create_endpoint.assert_called_once_with(ANY, 
                "cni", self.container_id, [IPNetwork(ip4), IPNetwork(ip6)])

        # Assert a profile was applied.
        self.client.append_profiles_to_endpoint.assert_called_once_with(
                profile_names=[self.network_name],
                endpoint_id=self.client.create_endpoint().endpoint_id
        )

    def test_add_mainline_kubernetes_docker(self):
        """
        Tests basic CNI add functionality using k8s and Docker.
        """
        # Configure.
        self.cni_args = "K8S_POD_NAME=podname;K8S_POD_NAMESPACE=default"
        workload_id = "default.podname"
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        ipam_stdout = json.dumps({"ip4": {"ip": ip4}, 
                                  "ip6": {"ip": ip6}})
        self.set_ipam_result(0, ipam_stdout, "")

        # Set up docker client response.
        inspect_result = {"HostConfig": {"NetworkMode": ""}}
        self.m_docker_client().inspect_container.return_value = inspect_result

        # Create plugin.
        p = self.create_plugin()
        assert_true(isinstance(p.container_engine, DockerEngine))

        # Mock DatastoreClient such that no endpoints exist.
        self.client.get_endpoint.side_effect = KeyError

        # Mock profile such that it doesn't exist.
        self.client.profile_exists.return_value = False

        # Execute.
        p.execute()
        
        # Assert the correct policy driver was chosen.
        assert_true(isinstance(p.policy_driver, KubernetesDefaultPolicyDriver)) 

        # Assert an endpoint was created.
        self.client.create_endpoint.assert_called_once_with(ANY, 
                "k8s", workload_id, [IPNetwork(ip4), IPNetwork(ip6)])

        # Assert a profile was applied.
        self.client.append_profiles_to_endpoint.assert_called_once_with(
                profile_names=[self.network_name],
                endpoint_id=self.client.create_endpoint().endpoint_id
        )

    @patch("calico_cni.policy_drivers.requests", autospec=True)
    def test_add_mainline_kubernetes_annotations(self, m_requests):
        """
        Tests add functionality using Kubernetes annotation policy driver. 
        """
        # Configure.
        self.cni_args = "K8S_POD_NAME=podname;K8S_POD_NAMESPACE=defaultns"
        workload_id = "defaultns.podname"
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        ipam_stdout = json.dumps({"ip4": {"ip": ip4}, 
                                  "ip6": {"ip": ip6}})
        self.set_ipam_result(0, ipam_stdout, "")
        self.policy = {"type": "k8s-annotations"}

        # Set up docker client response.
        inspect_result = {"HostConfig": {"NetworkMode": ""}}
        self.m_docker_client().inspect_container.return_value = inspect_result

        # Create plugin.
        p = self.create_plugin()
        assert_true(isinstance(p.container_engine, DockerEngine))

        # Mock DatastoreClient such that no endpoints exist.
        self.client.get_endpoint.side_effect = KeyError

        # Mock profile such that it doesn't exist.
        self.client.profile_exists.return_value = False

        # Mock the API response.
        response = MagicMock()
        response.status_code = 200
        api_pod = {"kind": "pod", 
                   "metadata": {
                   "annotations": {"projectcalico.org/policy": "allow from label X=Y"},
                   "labels": {"a":"b", "c":"d"}}}
        response.text = json.dumps(api_pod)
        m_requests.Session().__enter__().get.return_value = response

        # Execute.
        p.execute()
        
        # Assert the correct policy driver was chosen.
        assert_true(isinstance(p.policy_driver, KubernetesAnnotationDriver)) 

        # Assert an endpoint was created.
        self.client.create_endpoint.assert_called_once_with(ANY, 
                "k8s", workload_id, [IPNetwork(ip4), IPNetwork(ip6)])

        # Assert profile was created.
        self.client.create_profile.assert_called_once_with(
                "defaultns_podname",
                Rules(id="defaultns_podname",
                    inbound_rules=[Rule(action="allow", src_tag="defaultns_X_Y")],
                    outbound_rules=[Rule(action="allow")])
        )

        # Assert tags were added.
        self.client.profile_update_tags.assert_called_once_with(self.client.get_profile())

        # Assert a profile was applied.
        self.client.append_profiles_to_endpoint.assert_called_once_with(
                profile_names=["defaultns_podname"],
                endpoint_id=self.client.create_endpoint().endpoint_id
        )

    def test_add_kubernetes_docker_host_networking(self):
        """
        Test CNI add in k8s docker when NetworkMode == host.
        """
        # Configure.
        self.cni_args = "K8S_POD_NAME=podname;K8S_POD_NAMESPACE=default"
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        ipam_stdout = json.dumps({"ip4": {"ip": ip4}, 
                                  "ip6": {"ip": ip6}})
        self.set_ipam_result(0, ipam_stdout, "")

        # Create plugin.
        p = self.create_plugin()

        # Mock NetworkMode == host.
        inspect_result = {"HostConfig": {"NetworkMode": "host"}}
        self.m_docker_client().inspect_container.return_value = inspect_result

        # Execute.
        with assert_raises(SystemExit) as err:
            p.execute()
        e = err.exception

        # Assert success.
        assert_equal(e.code, 0)
        
        # Assert an endpoint was not created.
        assert_false(self.client.create_endpoint.called)

    def test_add_ipam_error(self):
        """
        Tests CNI add, IPAM plugin fails. 

        The plugin should return an error code and print the IPAM result,
        but should not need to clean anything up since IPAM is the first
        step in CNI add.
        """
        # Configure.
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        ipam_stdout = json.dumps({"code": 100, "msg": "Test IPAM error"})
        self.set_ipam_result(100, ipam_stdout, "")

        # Mock DatastoreClient such that no endpoints exist.
        self.client.get_endpoint.side_effect = KeyError

        # Create plugin.
        p = self.create_plugin()

        # Execute.
        with assert_raises(SystemExit) as err:
            p.execute()
        e = err.exception

        # Assert success.
        assert_equal(e.code, ERR_CODE_GENERIC)
        
        # Assert an endpoint was not created.
        assert_false(self.client.create_endpoint.called) 

    def test_add_ipam_error_missing_ip(self):
        """
        Tests CNI add, IPAM does not contain IPv4 address. 
        """
        # Configure.
        self.command = CNI_CMD_ADD
        ipam_stdout = json.dumps({"ip4": {"ip": ""}, 
                                  "ip6": {"ip": ""}})

        # Set the return code to 0, even though IPAM failed.  This shouldn't
        # ever happen, but at least we know we're ready for it.  We have other
        # test cases that handle rc != 0.
        self.set_ipam_result(0, ipam_stdout, "")

        # Create plugin.
        p = self.create_plugin()

        # Mock DatastoreClient such that no endpoints exist.
        self.client.get_endpoint.side_effect = KeyError

        # Execute.
        with assert_raises(SystemExit) as err:
            p.execute()
        e = err.exception

        # Assert failure.
        assert_equal(e.code, ERR_CODE_GENERIC)
        
        # Assert an endpoint was not created.
        assert_false(self.client.create_endpoint.called) 

        # Assert a profile was not set.
        assert_false(self.client.append_profiles_to_endpoint.called)

    def test_add_ipam_error_invalid_response(self):
        """
        Tests CNI add, IPAM response is not valid json. 
        """
        # Configure.
        self.command = CNI_CMD_ADD
        ipam_stdout = "{some invalid json}" 

        # Set the return code to 0, even though IPAM failed.  This shouldn't
        # ever happen, but at least we know we're ready for it.  We have other
        # test cases that handle rc != 0.
        self.set_ipam_result(0, ipam_stdout, "")

        # Create plugin.
        p = self.create_plugin()

        # Mock DatastoreClient such that no endpoints exist.
        self.client.get_endpoint.side_effect = KeyError

        # Execute.
        with assert_raises(SystemExit) as err:
            p.execute()
        e = err.exception

        # Assert failure.
        assert_equal(e.code, ERR_CODE_GENERIC)
        
        # Assert an endpoint was not created.
        assert_false(self.client.create_endpoint.called) 

        # Assert a profile was not set.
        assert_false(self.client.append_profiles_to_endpoint.called)

    def test_add_etcd_down(self):
        """
        Tests CNI add, etcd is not running when we attempt to get 
        an Endpoint from etcd.
        """
        # Configure.
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        ipam_stdout = json.dumps({"ip4": {"ip": ip4}, 
                                  "ip6": {"ip": ip6}})
        self.set_ipam_result(0, ipam_stdout, "")

        # Mock out get_endpoint to raise DataStoreError.
        self.client.get_endpoint.side_effect = DataStoreError

        # Create plugin.
        p = self.create_plugin()

        # Execute.
        with assert_raises(SystemExit) as err:
            p.execute()
        e = err.exception

        # Assert failure.
        assert_equal(e.code, ERR_CODE_GENERIC)
        
        # Assert an endpoint was not created.
        assert_false(self.client.create_endpoint.called) 

        # Assert a profile was not set.
        assert_false(self.client.append_profiles_to_endpoint.called)

    def test_add_error_profile_create(self):
        """
        Tests CNI add, plugin fails to create profile.

        Uses DefaultPolicyDriver.
        """
        # Configure.
        self.command = CNI_CMD_ADD
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        ipam_stdout = json.dumps({"ip4": {"ip": ip4}, 
                                  "ip6": {"ip": ip6}})
        self.set_ipam_result(0, ipam_stdout, "")

        # Create plugin.
        p = self.create_plugin()

        # Mock DatastoreClient such that no endpoints exist.
        self.client.get_endpoint.side_effect = KeyError

        # Configure EtcdException when setting profile.
        p.policy_driver._client.append_profiles_to_endpoint.side_effect = MagicMock(side_effect=KeyError)

        # Execute.
        with assert_raises(SystemExit) as err:
            p.execute()
        e = err.exception

        # Assert failure.
        assert_equal(e.code, ERR_CODE_GENERIC)

        # Assert an endpoint was created.
        self.client.create_endpoint.assert_called_once_with(ANY, 
                "cni", self.container_id, [IPNetwork(ip4), IPNetwork(ip6)])

        # Assert set_profile called by policy driver.
        self.client.append_profiles_to_endpoint.assert_called_once_with(
                profile_names=[self.network_name],
                endpoint_id=self.client.create_endpoint().endpoint_id
        )

        # Assert the endpoint was removed from the datastore.
        self.client.remove_workload.assert_called_once_with(hostname=ANY, 
                orchestrator_id="cni", workload_id=self.container_id)

    def test_delete_mainline(self):
        """
        Tests CNI delete, success.
        """
        # Configure.
        self.command = CNI_CMD_DELETE

        # Don't expect output from IPAM plugin when performing a delete.
        self.set_ipam_result(0, "", "")

        # Create plugin.
        p = self.create_plugin()

        # Execute.
        rc = p.execute()

    def test_delete_no_endpoint(self):
        """
        Tests CNI delete with no endpoint. 
        """
        # Configure.
        self.command = CNI_CMD_DELETE

        # Don't expect output from IPAM plugin when performing a delete.
        self.set_ipam_result(0, "", "")

        # Mock datastore to return no endpoint.
        self.client.get_endpoint.side_effect = KeyError

        # Create plugin.
        p = self.create_plugin()

        # Execute.
        with assert_raises(SystemExit) as err:
            p.execute()
        e = err.exception

        # Assert success.
        assert_equal(e.code, 0)


class CniPluginFvWithIpamTest(CniPluginFvTest):
    """
    Runs tests from CniPluginFvTest but using calico-ipam.

    Exercises the ipam.IpamPlugin code.
    """
    def setUp(self):
        CniPluginFvTest.setUp(self)
        self.ipam_type = "calico-ipam"

    def set_ipam_result(self, rc, stdout, stderr):
        """
        Set up the correct mocks based on the desired stdout.
        """
        if stdout and not rc:
            # A successful add response.
            ip4 = json.loads(stdout)["ip4"]["ip"]
            ip6 = json.loads(stdout)["ip6"]["ip"]
            ip4s = [ip4] if ip4 else []
            ip6s = [ip6] if ip6 else []
            self.m_ipam_plugin_client().auto_assign_ips.return_value = ip4s, ip6s
 
    def test_add_ipam_error(self):
        # Mock out auto_assign_ips to throw an error.
        self.m_ipam_plugin_client().auto_assign_ips.side_effect = RuntimeError

        # Assert we handle the error properly in calling code.
        CniPluginFvTest.test_add_ipam_error(self)

    def test_add_ipam_error_invalid_response(self):
        # Not applicable.
        pass

