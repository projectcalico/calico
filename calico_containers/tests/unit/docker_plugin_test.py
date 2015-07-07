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
from etcd import EtcdResult
import json
import unittest

from mock import Mock
from netaddr import IPAddress, IPNetwork
from nose.tools import assert_equal, assert_dict_equal

from libnetwork_plugin import docker_plugin
from pycalico.datastore_datatypes import Endpoint

TEST_ENDPOINT_ID = "TEST_ENDPOINT_ID"
TEST_NETWORK_ID = "TEST_NETWORK_ID"

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
                           data='{"NetworkID": "%s"}' % TEST_NETWORK_ID)
        docker_plugin.client.create_profile.assert_called_once_with(TEST_NETWORK_ID)
        assert_equal(rv.data, '{}')

    def test_delete_network(self):
        docker_plugin.client.remove_profile = Mock()

        rv = self.app.post('/NetworkDriver.DeleteNetwork',
                           data='{"NetworkID": "%s"}' % TEST_NETWORK_ID)
        docker_plugin.client.remove_profile.assert_called_once_with(TEST_NETWORK_ID)
        assert_equal(rv.data, '{}')

    def test_oper_info(self):
        rv = self.app.post('/NetworkDriver.EndpointOperInfo',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        assert_equal(rv.data, '{\n  "Value": {}\n}')

    def test_join(self):
        endpoint_json = """
            {"Interfaces": [{"Address": "1.2.3.4",
                            "ID": 0,
                            "MacAddress": "EE:EE:EE:EE:EE:EE"}]}"""
        etcd_read_mock = Mock(return_value=EtcdResult(
            node={'value':endpoint_json}))
        docker_plugin.client.etcd_client.read = etcd_read_mock

        etcd_write_mock = Mock()
        docker_plugin.client.etcd_client.write = etcd_write_mock


        endpoint = Endpoint("hostname",
                            "docker",
                            "undefined",
                            TEST_ENDPOINT_ID,
                            "active",
                            "mac")
        endpoint.ipv4_gateway = IPAddress("1.2.3.4")
        # endpoint.ipv6_gateway = IPAddress("FE80::0202:B3FF:FE1E:8329")
        endpoint.ipv4_nets.add(IPNetwork("1.2.3.4/24"))
        # endpoint.ipv6_nets.add(IPNetwork("FE80::0202:B3FF:FE1E:8329/128"))
        # endpoint_mock.return_value = endpoint
        set_endpoint_mock = Mock()
        docker_plugin.client.set_endpoint = set_endpoint_mock

        docker_plugin.create_veth = Mock()

        next_hop_mock = Mock()
        docker_plugin.client.get_default_next_hops = next_hop_mock
        #assert that it's always called with hostname'
        next_hop_mock.return_value = {4: IPAddress("1.2.3.4"),
                                      6: IPAddress("fe80::202:b3ff:fe1e:8329")}


        # Actually make the request to the plugin.
        rv = self.app.post('/NetworkDriver.Join',
                           data='{"EndpointID": "%s", "NetworkID": "%s"}' %
                                (TEST_ENDPOINT_ID, TEST_NETWORK_ID))
        etcd_read_mock.assert_called_once_with("/"+TEST_ENDPOINT_ID)
        # set_endpoint_mock.assert_called_once_with(endpoint)

        # Assert that create_veth mock was called with ep
        # docker_plugin.create_veth.assert_called_once_with(endpoint)

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
        expected_response = """{
  "Gateway": "1.2.3.4",
  "InterfaceNames": [
    {
      "DstPrefix": "cali",
      "SrcName": "tmpTEST_ENDPOI"
    }
  ],
  "StaticRoutes": [
    {
      "Destination": "1.2.3.4/32",
      "InterfaceID": 0,
      "NextHop": "",
      "RouteType": 1
    }
  ]
}"""
        self.maxDiff=None
        assert_dict_equal(json.loads(rv.data),
                          json.loads(expected_response))

    def test_leave(self):
        rv = self.app.post('/NetworkDriver.Leave',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        assert_equal(rv.data, '{}')

    def test_delete_endpoint(self):
        rv = self.app.post('/NetworkDriver.DeleteEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        #TODO - actually test something...
        assert_equal(rv.data, '{}')

    def test_create_endpoint(self):
        # Mock out assign_ipv4 and assign_ipv6
        # Make the ipv4 one return an address but not ipv6
        assign_ipv4_mock = Mock(return_value=IPAddress("1.2.3.4"))
        assign_ipv6_mock = Mock(return_value=None)
        docker_plugin.assign_ipv4 = assign_ipv4_mock
        docker_plugin.assign_ipv6 = assign_ipv6_mock

        # Mock out etcd and later make sure the data is written
        etcd_mock = Mock()
        docker_plugin.client.etcd_client.write = etcd_mock

        rv = self.app.post('/NetworkDriver.CreateEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)

        assign_ipv4_mock.assert_called_once_with(TEST_ENDPOINT_ID)
        assign_ipv6_mock.assert_called_once_with(TEST_ENDPOINT_ID)

        expected_response = json.loads("""
            {"Interfaces": [{"Address": "1.2.3.4",
                            "ID": 0,
                            "MacAddress": "EE:EE:EE:EE:EE:EE"}]}""")
        etcd_mock.assert_called_once_with('/'+TEST_ENDPOINT_ID,
                                          json.dumps(expected_response))

        assert_dict_equal(json.loads(rv.data),
                          expected_response)