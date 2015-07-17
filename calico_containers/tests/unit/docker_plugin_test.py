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

from mock import patch, Mock, ANY
from netaddr import IPAddress, IPNetwork
from nose.tools import assert_equal, assert_dict_equal

from libnetwork_plugin import docker_plugin
from pycalico.datastore_datatypes import Endpoint

TEST_ENDPOINT_ID = "TEST_ENDPOINT_ID"
TEST_NETWORK_ID = "TEST_NETWORK_ID"

#@TODO Misuse of Mock - when mocking out a function, safest to use patch.

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

    @patch("libnetwork_plugin.docker_plugin.client.remove_profile", autospec=True)
    def test_delete_network(self, m_remove):
        """
        Test the delete_network hook correctly removes the etcd data and
        returns the correct response.
        """
        rv = self.app.post('/NetworkDriver.DeleteNetwork',
                           data='{"NetworkID": "%s"}' % TEST_NETWORK_ID)
        m_remove.assert_called_once_with(TEST_NETWORK_ID)
        assert_equal(rv.data, '{}')

    @patch("libnetwork_plugin.docker_plugin.client.remove_profile", autospec=True)
    def test_delete_network_no_profile(self, m_remove):
        """
        Test the delete_network hook correctly removes the etcd data and
        returns the correct response.
        """
        m_remove.side_effect = KeyError
        rv = self.app.post('/NetworkDriver.DeleteNetwork',
                           data='{"NetworkID": "%s"}' % TEST_NETWORK_ID)
        m_remove.assert_called_once_with(TEST_NETWORK_ID)
        assert_equal(rv.data, '{}')

    def test_oper_info(self):
        rv = self.app.post('/NetworkDriver.EndpointOperInfo',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        assert_equal(rv.data, '{\n  "Value": {}\n}')

    @patch("libnetwork_plugin.docker_plugin.client.get_default_next_hops", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.read_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.create_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.set_endpoint", autospec=True)
    def test_join(self, m_set, m_veth, m_read, m_next_hops):
        endpoint_json = {"Interfaces":
                          [
                            {"Address": "1.2.3.4",
                             "AddressIPv6": "FE80::0202:B3FF:FE1E:8329",
                             "ID": 0,
                             "MacAddress": "EE:EE:EE:EE:EE:EE"}
                          ]
                        }
        m_read.return_value = endpoint_json

        m_next_hops.return_value = {4: IPAddress("1.2.3.4"),
                                    6: IPAddress("fe80::202:b3ff:fe1e:8329")}

        # Actually make the request to the plugin.
        rv = self.app.post('/NetworkDriver.Join',
                           data='{"EndpointID": "%s", "NetworkID": "%s"}' %
                                (TEST_ENDPOINT_ID, TEST_NETWORK_ID))
        m_read.assert_called_once_with(TEST_ENDPOINT_ID)

        # Check that the create_veth and set_endpoint are called with this
        # endpoint.
        endpoint = Endpoint("hostname",
                            "docker",
                            "libnetwork",
                            TEST_ENDPOINT_ID,
                            "active",
                            "EE:EE:EE:EE:EE:EE")
        endpoint.ipv4_gateway = IPAddress("1.2.3.4")
        endpoint.ipv6_gateway = IPAddress("FE80::0202:B3FF:FE1E:8329")
        endpoint.ipv4_nets.add(IPNetwork("1.2.3.4/32"))
        endpoint.ipv6_nets.add(IPNetwork("FE80::0202:B3FF:FE1E:8329/128"))
        endpoint.profile_ids.append(TEST_NETWORK_ID)

        m_veth.assert_called_once_with(endpoint)
        m_set.assert_called_once_with(endpoint)

        expected_response = """{
  "Gateway": "1.2.3.4",
  "GatewayIPv6": "fe80::202:b3ff:fe1e:8329",
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
    },
    {
      "Destination": "fe80::202:b3ff:fe1e:8329/128",
      "InterfaceID": 0,
      "NextHop": "",
      "RouteType": 1
    }
  ]
}"""
        self.maxDiff=None
        self.assertDictEqual(json.loads(rv.data),
                             json.loads(expected_response))

    @patch("libnetwork_plugin.docker_plugin.remove_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.get_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.remove_endpoint", autospec=True)
    def test_leave(self, m_remove, m_get, m_veth):
        endpoint = Endpoint("hostname",
                            "docker",
                            "libnetwork",
                            TEST_ENDPOINT_ID,
                            "active",
                            "EE:EE:EE:EE:EE:EE")
        m_get.return_value = endpoint

        # Send the leave request.
        rv = self.app.post('/NetworkDriver.Leave',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        assert_equal(rv.data, '{}')

        # Check parameters
        m_get.assert_called_once_with(hostname=ANY,
                                      orchestrator_id="docker",
                                      workload_id="libnetwork",
                                      endpoint_id=TEST_ENDPOINT_ID)
        m_remove.assert_called_once_with(endpoint)
        m_veth.assert_called_once_with(endpoint)

    def test_delete_endpoint(self):
        rv = self.app.post('/NetworkDriver.DeleteEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        #TODO - actually test something...
        assert_equal(rv.data, '{}')

    @patch("libnetwork_plugin.docker_plugin.assign_ip", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.write_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.get_default_next_hops", autospec=True)
    def test_create_endpoint(self, m_next_hops, m_write, m_assign_ip):
        """
        Test the create_endpoint hook correctly writes the appropriate data
        to etcd based on IP assignment.
        """

        # Iterate using various different mixtures of next hops and IP
        # assignments.
        #
        # (IPv4 NH, IPv4 addr, IPv6 NH, IPv6 addr)
        parms = [(IPAddress("10.20.30.40"), IPAddress("1.2.3.4"),
                  IPAddress("aa:bb::ff"), IPAddress("aa:bb::bb")),
                 (IPAddress("10.20.30.40"), None,
                  IPAddress("aa:bb::ff"), IPAddress("aa:bb::bb")),
                 (IPAddress("10.20.30.40"), IPAddress("1.2.3.4"),
                  IPAddress("aa:bb::ff"), None),
                 (IPAddress("10.20.30.40"), IPAddress("1.2.3.4"),
                  None, None),
                 (None, None,
                  IPAddress("aa:bb::ff"), IPAddress("aa:bb::bb"))]

        # Loop through different combinations of IP availability.
        for ipv4_nh, ipv4, ipv6_nh, ipv6 in parms:

            # Return the required next hops.
            m_next_hops.return_value = {4: ipv4_nh,
                                        6: ipv6_nh}

            # Return the required assigned IPs.
            def assign_ip(version):
                if version == "v4":
                    return ipv4
                elif version == "v6":
                    return ipv6
                raise AssertionError("Unexpected version: %s" % version)
            m_assign_ip.side_effect = assign_ip

            # Invoke create endpoint.
            rv = self.app.post('/NetworkDriver.CreateEndpoint',
                               data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)

            # Construct the expected data.
            expected_data = {
                              "Interfaces":
                                [
                                  {"ID": 0, "MacAddress": "EE:EE:EE:EE:EE:EE"}
                                ]
                            }
            if ipv4:
                expected_data["Interfaces"][0]["Address"] = str(ipv4)
            if ipv6:
                expected_data["Interfaces"][0]["AddressIPv6"] = str(ipv6)

            # Assert that the assign IP was called the correct number of
            # times based on whether a next hop was returned.
            expected_assign_count = 0
            if ipv4_nh:
                expected_assign_count += 1
            if ipv6_nh:
                expected_assign_count += 1
            assert_equal(m_assign_ip.call_count, expected_assign_count)

            # Assert expected data is written to etcd and returned from
            # request.
            m_write.assert_called_once_with(TEST_ENDPOINT_ID,
                                            expected_data)
            assert_dict_equal(json.loads(rv.data),
                              expected_data)

            # Reset the Mocks before continuing.
            m_write.reset_mock()
            m_next_hops.reset_mock()
            m_assign_ip.reset_mock()

    @patch("libnetwork_plugin.docker_plugin.client.write_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.get_default_next_hops", autospec=True)
    def test_create_endpoint_no_ip(self, m_next_hops, m_write):
        """
        Test the create_endpoint hook writes no data and returns a 500 error
        when no IP addresses can be assigned.
        """
        m_next_hops.return_value = {4: None, 6: None}

        # Invoke create endpoint.
        rv = self.app.post('/NetworkDriver.CreateEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)

        # Assert no data is written and returns 500 response.
        assert_equal(m_write.call_count, 0)

        expected_data = {"Err": "500: Internal Server Error"}
        assert_dict_equal(json.loads(rv.data),
                          expected_data)

