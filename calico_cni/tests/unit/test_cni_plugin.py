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
import sys
import json
import unittest
from mock import patch, MagicMock, Mock, call
from netaddr import IPAddress, IPNetwork
from subprocess32 import CalledProcessError, Popen, PIPE
from nose.tools import assert_equal, assert_true, assert_false, assert_raises

import pycalico.netns
from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import IPPool, Endpoint

from calico_cni.constants import *
from calico_cni.calico_cni import CniPlugin
from calico_cni.policy_drivers import DefaultPolicyDriver, ApplyProfileError 


class CniPluginTest(unittest.TestCase):
    """
    Test class for CniPlugin class.
    """
    def setUp(self):
        """
        Per-test setup method.
        """
        self.container_id = "ff3afbd1-17ad-499d-b514-72438c009e81"
        self.network_config = {
            "name": "ut-network",
            "type": "calico",
            "ipam": {
                "type": "calico-ipam",
                "subnet": "10.22.0.0/16",
                "routes": [{"dst": "0.0.0.0/0"}],
                "range-start": "",
                "range-end": ""
            }
        }
        self.env = {
                CNI_CONTAINERID_ENV: self.container_id,
                CNI_IFNAME_ENV: "eth0",
                CNI_ARGS_ENV: "",
                CNI_COMMAND_ENV: CNI_CMD_ADD, 
                CNI_PATH_ENV: "/usr/bin/rkt/",
                CNI_NETNS_ENV: "netns",
        }

        # Create the CniPlugin to test.
        self.plugin = CniPlugin(self.network_config, self.env)

        # Mock out policy driver. 
        self.plugin.policy_driver = MagicMock(spec=DefaultPolicyDriver)

        # Mock out the datastore client.
        self.m_datastore_client = MagicMock(spec=DatastoreClient)
        self.plugin._client = self.m_datastore_client

    def test_execute_mainline(self):
        # Mock out _execute() for this test.
        self.plugin._execute = MagicMock(spec=self.plugin._execute)

        # Call execute()
        rc = self.plugin.execute()

        # Assert success.
        assert_equal(rc, 0)

    def test_execute_sys_exit(self):
        """Test execute() SystemExit handling"""
        # Mock out _execute to throw SystemExit
        self.plugin._execute = MagicMock(spec=self.plugin._execute)
        self.plugin._execute.side_effect = SystemExit(5) 

        # Call execute()
        rc = self.plugin.execute()

        # Assert success.
        assert_equal(rc, 5)

    def test_execute_unhandled_exception(self):
        """Test execute() unhandled Exception"""
        # Mock out _execute to throw KeyError.
        self.plugin._execute = MagicMock(spec=self.plugin._execute)
        self.plugin._execute.side_effect = KeyError 

        # Call execute()
        rc = self.plugin.execute()

        # Assert returns unhandled error code
        assert_equal(rc, ERR_CODE_UNHANDLED)

    def test__execute_add_mainline(self):
        """Test _execute() ADD

        Set command to add, assert add() called.
        """
        self.plugin.command = CNI_CMD_ADD
        self.plugin.add = MagicMock(self.plugin.add)
        self.plugin._execute()
        self.plugin.add.assert_called_once_with()

    def test__execute_del_mainline(self):
        """Test _execute() DEL

        Set command to delete, assert delete() called.
        """
        self.plugin.command = CNI_CMD_DELETE
        self.plugin.delete = MagicMock(self.plugin.delete)
        self.plugin._execute()
        self.plugin.delete.assert_called_once_with()

    @patch("calico_cni.calico_cni.json", autospec=True)
    def test_add_mainline(self, m_json): 
        # Mock out _assign_ips.
        ip4 = IPNetwork("10.0.0.1/32")
        ip6 = IPNetwork("0:0:0:0:0:ffff:a00:1/128")
        self.plugin._assign_ips = MagicMock(spec=self.plugin._assign_ips)
        self.plugin._assign_ips.return_value = ip4, ip6

        # Mock out IPAM response.
        ipam_response = json.dumps({"ip4": {"ip": str(ip4.cidr)},
                                    "ip6": {"ip": str(ip6.cidr)}})
        self.plugin.ipam_result = ipam_response 

        # Mock out _create_endpoint.
        endpoint = MagicMock(spec=Endpoint)
        self.plugin._create_endpoint = MagicMock(spec=self.plugin._create_endpoint)
        self.plugin._create_endpoint.return_value = endpoint

        # Mock out _provision_veth. 
        self.plugin._provision_veth = MagicMock(spec=self.plugin._provision_veth)
        self.plugin._provision_veth.return_value = endpoint

        # Mock out _get_endpoint - no endpoint exists.
        self.plugin._get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        self.plugin._get_endpoint.return_value = None

        # Call method.
        self.plugin.add()

        # Assert.
        self.plugin._assign_ips.assert_called_once_with(self.plugin.env)
        self.plugin._create_endpoint.assert_called_once_with([ip4])
        self.plugin._provision_veth.assert_called_once_with(endpoint)
        self.plugin.policy_driver.apply_profile.assert_called_once_with(endpoint)
        m_json.dumps.assert_called_once_with(ipam_response)

    @patch("calico_cni.calico_cni.json", autospec=True)
    def test_add_exists_new_network(self, m_json): 
        """
        Test add when the endpoint already exists, adding to a new 
        network.
        """
        # Mock out methods that should not be called.
        self.plugin._assign_ips = MagicMock(spec=self.plugin._assign_ips)
        self.plugin._create_endpoint = MagicMock(spec=self.plugin._create_endpoint)
        self.plugin._provision_veth = MagicMock(spec=self.plugin._provision_veth)

        # Mock out _get_endpoint - endpoint exists.
        ip4 = IPNetwork("10.0.0.1")
        ip6 = IPNetwork("bad::beef")
        endpoint = MagicMock(spec=Endpoint)
        endpoint.ipv4_nets = [ip4]
        endpoint.ipv6_nets = [ip6]
        self.plugin._get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        self.plugin._get_endpoint.return_value = endpoint

        # Expected response.
        expected = {"ip4": {"ip": str(ip4)}, "ip6": {"ip": str(ip6)}}

        # Call method.
        self.plugin.add()

        # Assert.
        assert_false(self.plugin._assign_ips.called)
        assert_false(self.plugin._create_endpoint.called)
        assert_false(self.plugin._provision_veth.called)
        self.plugin.policy_driver.apply_profile.assert_called_once_with(endpoint)
        m_json.dumps.assert_called_once_with(expected)

    @patch("calico_cni.calico_cni.json", autospec=True)
    def test_add_profile_error(self, m_json): 
        """
        Test add when the endpoint does not exist, error applying profile.
        """
        # Mock out cleanup methods.
        self.plugin._release_ip = MagicMock(spec=self.plugin._release_ip)
        self.plugin._remove_endpoint = MagicMock(spec=self.plugin._remove_endpoint)
        self.plugin._remove_veth = MagicMock(spec=self.plugin._remove_veth)

        # Mock out _assign_ips.
        ip4 = IPNetwork("10.0.0.1/32")
        ip6 = IPNetwork("0:0:0:0:0:ffff:a00:1/128")
        self.plugin._assign_ips = MagicMock(spec=self.plugin._assign_ips)
        self.plugin._assign_ips.return_value = ip4, ip6

        # Mock out IPAM response.
        ipam_response = json.dumps({"ip4": {"ip": str(ip4.cidr)},
                                    "ip6": {"ip": str(ip6.cidr)}})
        self.plugin.ipam_result = ipam_response 

        # Mock out _create_endpoint.
        endpoint = MagicMock(spec=Endpoint)
        endpoint.name = "cali12345"
        self.plugin._create_endpoint = MagicMock(spec=self.plugin._create_endpoint)
        self.plugin._create_endpoint.return_value = endpoint

        # Mock out _provision_veth. 
        self.plugin._provision_veth = MagicMock(spec=self.plugin._provision_veth)
        self.plugin._provision_veth.return_value = endpoint

        # Mock out apply_profile to throw error.
        msg = "Apply Profile Error Message"
        error = ApplyProfileError(msg)
        self.plugin.policy_driver.apply_profile.side_effect = error  

        # Mock out _get_endpoint - endpoint exists.
        self.plugin._get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        self.plugin._get_endpoint.return_value = None 

        # Call method.
        assert_raises(SystemExit, self.plugin.add)

    @patch("calico_cni.calico_cni.json", autospec=True)
    def test_add_exists_new_network_profile_error(self, m_json): 
        """
        Test add when the endpoint already exists, adding to a new 
        network, error applying profile.
        """
        # Mock out apply_profile to throw error.
        self.plugin.policy_driver.apply_profile.side_effect = ApplyProfileError

        # Mock out _get_endpoint - endpoint exists.
        ip4 = IPNetwork("10.0.0.1")
        ip6 = IPNetwork("bad::beef")
        endpoint = MagicMock(spec=Endpoint)
        endpoint.ipv4_nets = [ip4]
        endpoint.ipv6_nets = [ip6]
        endpoint.name = "cali12345"
        self.plugin._get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        self.plugin._get_endpoint.return_value = endpoint

        # Call method.
        assert_raises(SystemExit, self.plugin.add)

    @patch("calico_cni.calico_cni.json", autospec=True)
    def test_add_exists_no_ips(self, m_json): 
        """
        Tests add to new network when endpoint exists,
        no IP addresses are assigned. 
        """
        # Mock out _get_endpoint - endpoint exists.
        endpoint = MagicMock(spec=Endpoint)
        endpoint.ipv4_nets = []
        endpoint.ipv6_nets = []
        endpoint.name = "cali12345"
        self.plugin._get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        self.plugin._get_endpoint.return_value = endpoint

        # Call method.
        self.plugin.add()

        # Assert profile add is called.
        self.plugin.policy_driver.apply_profile.assert_called_once_with(endpoint)

    @patch("calico_cni.calico_cni.netns", autospec=True)
    def test_delete_mainline(self, m_netns):
        # Mock out _release_ip.
        self.plugin._release_ip = MagicMock(spec=self.plugin._release_ip)

        # Mock out _get_endpoint.
        endpoint = MagicMock(spec=Endpoint)
        endpoint.name = "cali12345"
        self.plugin._get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        self.plugin._get_endpoint.return_value = endpoint

        # Mock out _remove_endpoint.
        self.plugin._remove_endpoint = MagicMock(spec=self.plugin._remove_endpoint)

        # Call delete()
        self.plugin.delete()

        # Assert.
        self.plugin._release_ip.assert_called_once_with(self.plugin.env)
        self.plugin._get_endpoint.assert_called_once_with()
        self.plugin._remove_endpoint.assert_called_once_with()
        m_netns.remove_veth.assert_called_once_with("cali12345")
        self.plugin.policy_driver.remove_profile.assert_called_once_with()

    @patch("calico_cni.calico_cni.netns", autospec=True)
    def test_delete_no_endpoint(self, m_netns):
        # Mock out _release_ip.
        self.plugin._release_ip = MagicMock(spec=self.plugin._release_ip)

        # Mock out _remove_endpoint.
        self.plugin._remove_endpoint = MagicMock(spec=self.plugin._remove_endpoint)

        # Mock out _get_endpoint.
        self.plugin._get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        self.plugin._get_endpoint.return_value = None  

        # Call delete()
        assert_raises(SystemExit, self.plugin.delete)

        # Assert.
        self.plugin._release_ip.assert_called_once_with(self.plugin.env)
        self.plugin._get_endpoint.assert_called_once_with()
        assert_false(self.plugin._remove_endpoint.called)
        assert_false(m_netns.remove_veth.called)

    def test_assign_ip_mainline(self):
        # Mock _call_ipam_plugin.
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        rc = 0
        ipam_result = json.dumps({"ip4": {"ip": ip4}, "ip6": {"ip": ip6}})
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ipam_result
        env = {CNI_COMMAND_ENV: CNI_CMD_ADD}

        # Call _assign_ips.
        assigned_ips = self.plugin._assign_ips(env)

        # Assert.
        assert_equal(assigned_ips, (IPNetwork(ip4), IPNetwork(ip6)))

    def test_assign_ip_invalid_response(self):
        # Mock _call_ipam_plugin.
        rc = 1
        ipam_result = "Invalid json" 
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ipam_result
        env = {CNI_COMMAND_ENV: CNI_CMD_ADD}

        # Call _assign_ips.
        with assert_raises(SystemExit) as err:
            self.plugin._assign_ips(env)
        e = err.exception
        assert_equal(e.code, ERR_CODE_GENERIC)

    def test_assign_ip_bad_rc(self):
        # Mock _call_ipam_plugin.
        rc = ERR_CODE_GENERIC
        msg = "Message"
        details = "Details"
        ipam_result = json.dumps({"code": rc, 
                                  "msg": msg, 
                                  "details": details})
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ipam_result
        env = {CNI_COMMAND_ENV: CNI_CMD_ADD}

        # Call _assign_ips.
        with assert_raises(SystemExit) as err:
            self.plugin._assign_ips(env)
        e = err.exception
        assert_equal(e.code, ERR_CODE_GENERIC)

    def test_assign_ip_no_ipv4(self):
        # Mock _call_ipam_plugin.
        ip6 = "0:0:0:0:0:ffff:a00:1"
        rc = 0
        ipam_result = json.dumps({"ip4": {}, "ip6": {"ip": ip6}})
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ipam_result
        env = {CNI_COMMAND_ENV: CNI_CMD_ADD}

        # Call _assign_ips.
        with assert_raises(SystemExit) as err:
            self.plugin._assign_ips(env)
        e = err.exception
        assert_equal(e.code, ERR_CODE_GENERIC)

    def test_assign_ip_no_ipv6(self):
        # Mock _call_ipam_plugin.
        ip4 = "10.0.0.1"
        rc = 0
        ipam_result = json.dumps({"ip4": {"ip": ip4}})
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ipam_result
        env = {CNI_COMMAND_ENV: CNI_CMD_ADD}

        # Call _assign_ips.
        with assert_raises(SystemExit) as err:
            self.plugin._assign_ips(env)
        e = err.exception
        assert_equal(e.code, ERR_CODE_GENERIC)

    def test_assign_ip_invalid_ipv6(self):
        # Mock _call_ipam_plugin.
        ip6 = "invalid"
        ip4 = "10.0.0.5"
        rc = 0
        ipam_result = json.dumps({"ip4": {"ip": ip4}, "ip6": {"ip": ip6}})
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ipam_result
        env = {CNI_COMMAND_ENV: CNI_CMD_ADD}

        # Call _assign_ips.
        with assert_raises(SystemExit) as err:
            self.plugin._assign_ips(env)
        e = err.exception
        assert_equal(e.code, ERR_CODE_GENERIC)

    def test_assign_ip_invalid_ipv4(self):
        # Mock _call_ipam_plugin.
        ip4 = "10.0.0.500"
        rc = 0
        ipam_result = json.dumps({"ip4": {"ip": ip4}})
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ipam_result
        env = {CNI_COMMAND_ENV: CNI_CMD_ADD}

        # Call _assign_ips.
        with assert_raises(SystemExit) as err:
            self.plugin._assign_ips(env)
        e = err.exception
        assert_equal(e.code, ERR_CODE_GENERIC)


    def test_release_ip_mainline(self):
        # Mock _call_ipam_plugin.
        rc = 0
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ""
        env = {CNI_COMMAND_ENV: CNI_CMD_DELETE}

        # Call _release_ip.
        self.plugin._release_ip(env)

    def test_release_ip_failed(self):
        # Mock _call_ipam_plugin.
        rc = 100
        self.plugin._call_ipam_plugin = MagicMock(spec=self.plugin._call_ipam_plugin)
        self.plugin._call_ipam_plugin.return_value = rc, ""
        env = {CNI_COMMAND_ENV: CNI_CMD_DELETE}

        # Call _release_ip.
        self.plugin._release_ip(env)


    @patch("calico_cni.calico_cni.Popen", autospec=True)
    def test_call_ipam_plugin_mainline(self, m_popen):
        # Mock _find_ipam_plugin.
        plugin_path = "/opt/bin/cni/calico-ipam"
        self.plugin._find_ipam_plugin = MagicMock(spec=self.plugin._find_ipam_plugin)
        self.plugin._find_ipam_plugin.return_value = plugin_path

        # Mock out return values.
        ip4 = "10.0.0.1/32"
        ip6 = "0:0:0:0:0:ffff:a00:1"
        stdout = json.dumps({"ip4": {"ip": ip4}, "ip6": {"ip": ip6}})
        stderr = ""
        m_proc = MagicMock(spec=Popen)
        m_proc.communicate.return_value = (stdout, stderr)
        m_proc.returncode = 0
        m_popen.return_value = m_proc
        env = {}

        # Call _call_ipam_plugin.
        rc, result = self.plugin._call_ipam_plugin(env)

        # Assert.
        assert_equal(rc, 0)
        m_popen.assert_called_once_with(plugin_path, 
                                        stdin=PIPE, 
                                        stdout=PIPE, 
                                        stderr=PIPE,
                                        env=env)
        m_proc.communicate.assert_called_once_with(json.dumps(self.plugin.network_config))
        assert_equal(result, stdout)

    @patch("calico_cni.calico_cni.Popen", autospec=True)
    def test_call_ipam_plugin_missing(self, m_popen):
        """
        Unable to find IPAM plugin.
        """
        # Mock _find_ipam_plugin.
        self.plugin._find_ipam_plugin = MagicMock(spec=self.plugin._find_ipam_plugin)
        self.plugin._find_ipam_plugin.return_value = None 
        env = {}

        # Call method.
        with assert_raises(SystemExit) as err:
            self.plugin._call_ipam_plugin(env)
        e = err.exception
        assert_equal(e.code, ERR_CODE_GENERIC)

