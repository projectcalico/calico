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

import json
import unittest

from mock import Mock, ANY
from netaddr import IPAddress, IPNetwork
from nose.tools import assert_equal, assert_dict_equal

from calico_containers import docker_plugin
from calico_containers.pycalico.datastore_data import Endpoint

TEST_ID = "TEST_ID"

class TestPlugin(unittest.TestCase):

    def setUp(self):
        self.app = docker_plugin.app.test_client()

    def tearDown(self):
        pass

    def test_404(self):
        rv = self.app.post('/')
        assert_equal(rv.status_code, 404)

    def test_activate(self):
        rv = self.app.post('/Plugin.Activate')
        activate_response = '{\n  "Implements": [\n    "NetworkDriver"\n  ]\n}'
        assert_equal(rv.data, activate_response)

    def test_create_network(self):
        docker_plugin.client.create_profile = Mock()

        rv = self.app.post('/NetworkDriver.CreateNetwork',
                           data='{"NetworkID": "%s"}' % TEST_ID)
        docker_plugin.client.create_profile.assert_called_once_with(TEST_ID)
        assert_equal(rv.data, '{}')

    def test_delete_network(self):
        docker_plugin.client.remove_profile = Mock()

        rv = self.app.post('/NetworkDriver.DeleteNetwork',
                           data='{"NetworkID": "%s"}' % TEST_ID)
        docker_plugin.client.remove_profile.assert_called_once_with(TEST_ID)
        assert_equal(rv.data, '{}')

    def test_oper_info(self):
        rv = self.app.post('/NetworkDriver.EndpointOperInfo',
                           data='{"EndpointID": "%s"}' % TEST_ID)
        assert_equal(rv.data, '{\n  "Value": {}\n}')

    def test_join(self):
        endpoint_mock = Mock()
        endpoint = Endpoint("hostname",
                            "docker",
                            "undefined",
                            TEST_ID,
                            "active",
                            "mac")
        endpoint.ipv4_gateway = IPAddress("1.2.3.4")
        endpoint.ipv6_gateway = IPAddress("FE80::0202:B3FF:FE1E:8329")
        endpoint.ipv4_nets.add(IPNetwork("1.2.3.4/24"))
        endpoint.ipv6_nets.add(IPNetwork("FE80::0202:B3FF:FE1E:8329/128"))
        endpoint_mock.return_value = endpoint
        docker_plugin.client.get_endpoint = endpoint_mock

        rv = self.app.post('/NetworkDriver.Join',
                           data='{"EndpointID": "%s"}' % TEST_ID)
        endpoint_mock.assert_called_once_with(hostname=ANY,
                                              orchestrator_id="docker",
                                              workload_id="libnetwork",
                                              endpoint_id=TEST_ID)

        expected_response = """{
  "Gateway": "1.2.3.4",
  "GatewayIPv6": "fe80::202:b3ff:fe1e:8329",
  "InterfaceNames": [
    {
      "DstPrefix": "cali",
      "SrcName": "tmpTEST_ID"
    }
  ],
  "StaticRoutes": [
    {
      "Destination": "1.2.3.4/32",
      "InterfaceID": 0,
      "NextHop": "",
      "RouteType": 1
    },
    {
      "Destination": "fe80::202:b3ff:fe1e:8329/128",
      "InterfaceID": 0,
      "NextHop": "",
      "RouteType": 1
    }
  ]
}"""
        assert_dict_equal(json.loads(rv.data),
                          json.loads(expected_response))

    def test_leave(self):
        rv = self.app.post('/NetworkDriver.Leave',
                           data='{"EndpointID": "%s"}' % TEST_ID)
        assert_equal(rv.data, '{}')

# TODO - test_delete_endpoint and test_create_endpoint