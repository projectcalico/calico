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

from mock import patch, ANY, call
from netaddr import IPAddress, IPNetwork
from nose.tools import assert_equal
from subprocess32 import CalledProcessError

from libnetwork_plugin import docker_plugin
from pycalico.datastore_datatypes import Endpoint
from pycalico.datastore_errors import DataStoreError

TEST_ENDPOINT_ID = "TEST_ENDPOINT_ID"
TEST_NETWORK_ID = "TEST_NETWORK_ID"

# Expected 500 error response.
ERROR_RESPONSE_500 = {"Err": "500: Internal Server Error"}


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
        activate_response = {"Implements": ["NetworkDriver"]}
        self.assertDictEqual(json.loads(rv.data), activate_response)

    @patch("libnetwork_plugin.docker_plugin.client.profile_exists", autospec=True, return_value=False)
    @patch("libnetwork_plugin.docker_plugin.client.create_profile", autospec=True)
    def test_create_network(self, m_create, m_exists):
        """
        Test create_network when the profile does not exist.
        """
        rv = self.app.post('/NetworkDriver.CreateNetwork',
                           data='{"NetworkID": "%s"}' % TEST_NETWORK_ID)
        m_exists.assert_called_once_with(TEST_NETWORK_ID)
        m_create.assert_called_once_with(TEST_NETWORK_ID)
        self.assertDictEqual(json.loads(rv.data), {})

    @patch("libnetwork_plugin.docker_plugin.client.profile_exists", autospec=True, return_value=True)
    @patch("libnetwork_plugin.docker_plugin.client.create_profile", autospec=True)
    def test_create_network_exists(self, m_create, m_exists):
        """
        Test create_network when the profile already exists.
        """
        rv = self.app.post('/NetworkDriver.CreateNetwork',
                           data='{"NetworkID": "%s"}' % TEST_NETWORK_ID)
        m_exists.assert_called_once_with(TEST_NETWORK_ID)
        assert_equal(m_create.call_count, 0)
        self.assertDictEqual(json.loads(rv.data), {})

    @patch("libnetwork_plugin.docker_plugin.client.remove_profile", autospec=True)
    def test_delete_network(self, m_remove):
        """
        Test the delete_network hook correctly removes the etcd data and
        returns the correct response.
        """
        rv = self.app.post('/NetworkDriver.DeleteNetwork',
                           data='{"NetworkID": "%s"}' % TEST_NETWORK_ID)
        m_remove.assert_called_once_with(TEST_NETWORK_ID)
        self.assertDictEqual(json.loads(rv.data), {})

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
        self.assertDictEqual(json.loads(rv.data), {})

    def test_oper_info(self):
        """
        Test oper_info returns the correct data.
        """
        rv = self.app.post('/NetworkDriver.EndpointOperInfo',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        self.assertDictEqual(json.loads(rv.data), {"Value": {}})

    @patch("libnetwork_plugin.docker_plugin.client.get_default_next_hops", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.read_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.create_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.set_endpoint", autospec=True)
    def test_join(self, m_set, m_veth, m_read, m_next_hops):
        """
        Test the join() processing correctly creates the veth and the Endpoint.
        """
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

    @patch("libnetwork_plugin.docker_plugin.client.get_default_next_hops", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.read_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.create_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.remove_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.set_endpoint", autospec=True)
    def test_join_veth_fail(self, m_set, m_del_veth, m_veth, m_read, m_next_hops):
        """
        Test the join() processing when create_veth fails.
        """
        m_veth.side_effect = CalledProcessError(2, "testcmd")

        endpoint_json = {"Interfaces":
                          [
                            {"Address": "1.2.3.4",
                             "ID": 0,
                             "MacAddress": "EE:EE:EE:EE:EE:EE"}
                          ]
                        }
        m_read.return_value = endpoint_json

        m_next_hops.return_value = {4: IPAddress("1.2.3.4"),
                                    6: None}

        # Actually make the request to the plugin.
        rv = self.app.post('/NetworkDriver.Join',
                           data='{"EndpointID": "%s", "NetworkID": "%s"}' %
                                (TEST_ENDPOINT_ID, TEST_NETWORK_ID))
        m_read.assert_called_once_with(TEST_ENDPOINT_ID)

        # Check that the create_veth is called with this
        # endpoint.
        endpoint = Endpoint("hostname",
                            "docker",
                            "libnetwork",
                            TEST_ENDPOINT_ID,
                            "active",
                            "EE:EE:EE:EE:EE:EE")
        endpoint.ipv4_gateway = IPAddress("1.2.3.4")
        endpoint.ipv4_nets.add(IPNetwork("1.2.3.4/32"))
        endpoint.profile_ids.append(TEST_NETWORK_ID)

        # Check that create veth is called with the expected endpoint, and
        # that set_endpoint is not (since create_veth is raising an exception).
        m_veth.assert_called_once_with(endpoint)
        assert_equal(m_set.call_count, 0)

        # Check that we delete the veth.
        m_del_veth.assert_called_once_with(endpoint)

        # Expect a 500 response.
        self.assertDictEqual(json.loads(rv.data), ERROR_RESPONSE_500)

    @patch("libnetwork_plugin.docker_plugin.client.get_default_next_hops", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.read_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.create_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.remove_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.set_endpoint", autospec=True, side_effect=DataStoreError)
    def test_join_set_fail(self, m_set, m_del_veth, m_veth, m_read, m_next_hops):
        """
        Test the join() processing when set_endpoint fails.
        """
        endpoint_json = {"Interfaces":
                          [
                            {"Address": "1.2.3.4",
                             "ID": 0,
                             "MacAddress": "EE:EE:EE:EE:EE:EE"}
                          ]
                        }
        m_read.return_value = endpoint_json

        m_next_hops.return_value = {4: IPAddress("1.2.3.4"),
                                    6: None}

        # Actually make the request to the plugin.
        rv = self.app.post('/NetworkDriver.Join',
                           data='{"EndpointID": "%s", "NetworkID": "%s"}' %
                                (TEST_ENDPOINT_ID, TEST_NETWORK_ID))
        m_read.assert_called_once_with(TEST_ENDPOINT_ID)

        # Check that the create_veth is called with this
        # endpoint.
        endpoint = Endpoint("hostname",
                            "docker",
                            "libnetwork",
                            TEST_ENDPOINT_ID,
                            "active",
                            "EE:EE:EE:EE:EE:EE")
        endpoint.ipv4_gateway = IPAddress("1.2.3.4")
        endpoint.ipv4_nets.add(IPNetwork("1.2.3.4/32"))
        endpoint.profile_ids.append(TEST_NETWORK_ID)

        # Check that create veth and set_endpoint are called with the
        # endpoint.  The set throws a DataStoreError and so we clean up the
        # veth.
        m_veth.assert_called_once_with(endpoint)
        m_set.assert_called_once_with(endpoint)

        # Check that we delete the veth.
        m_del_veth.assert_called_once_with(endpoint)

        # Expect a 500 response.
        self.assertDictEqual(json.loads(rv.data), ERROR_RESPONSE_500)

    @patch("libnetwork_plugin.docker_plugin.remove_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.get_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.remove_endpoint", autospec=True)
    def test_leave(self, m_remove, m_get, m_veth):
        """
        Test leave() processing removes the endpoint and veth.
        """
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
        self.assertDictEqual(json.loads(rv.data), {})

        # Check parameters
        m_get.assert_called_once_with(hostname=ANY,
                                      orchestrator_id="docker",
                                      workload_id="libnetwork",
                                      endpoint_id=TEST_ENDPOINT_ID)
        m_remove.assert_called_once_with(endpoint)
        m_veth.assert_called_once_with(endpoint)

    @patch("libnetwork_plugin.docker_plugin.remove_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.get_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.remove_endpoint", autospec=True)
    def test_leave_no_endpoint(self, m_remove, m_get, m_veth):
        """
        Test the leave processing when these is no endpoint.
        """
        m_get.side_effect = KeyError

        # Send the leave request.
        rv = self.app.post('/NetworkDriver.Leave',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        self.assertDictEqual(json.loads(rv.data), ERROR_RESPONSE_500)

        # Check parameters
        m_get.assert_called_once_with(hostname=ANY,
                                      orchestrator_id="docker",
                                      workload_id="libnetwork",
                                      endpoint_id=TEST_ENDPOINT_ID)
        assert_equal(m_remove.call_count, 0)
        assert_equal(m_veth.call_count, 0)

    @patch("libnetwork_plugin.docker_plugin.remove_veth", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.get_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.remove_endpoint", autospec=True)
    def test_leave_delete_failed(self, m_remove, m_get, m_veth):
        """
        Test the leave processing when these is no endpoint.
        """
        endpoint = Endpoint("hostname",
                            "docker",
                            "libnetwork",
                            TEST_ENDPOINT_ID,
                            "active",
                            "EE:EE:EE:EE:EE:EE")
        m_get.return_value = endpoint
        m_remove.side_effect = DataStoreError

        # Send the leave request.
        rv = self.app.post('/NetworkDriver.Leave',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        self.assertDictEqual(json.loads(rv.data), {})

        # Check parameters
        m_get.assert_called_once_with(hostname=ANY,
                                      orchestrator_id="docker",
                                      workload_id="libnetwork",
                                      endpoint_id=TEST_ENDPOINT_ID)
        m_remove.assert_called_once_with(endpoint)
        m_veth.assert_called_once_with(endpoint)

    @patch("libnetwork_plugin.docker_plugin.backout_ip_assignments", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.read_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.delete_cnm_endpoint", autospec=True)
    def test_delete_endpoint(self, m_delete, m_read, m_backout):
        """
        Test delete_endpoint() deletes the endpoint and backout IP assignment.
        """
        ep = {"test": 1}
        m_read.return_value = ep
        m_delete.return_value = True
        rv = self.app.post('/NetworkDriver.DeleteEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        m_read.assert_called_once_with(TEST_ENDPOINT_ID)
        m_delete.assert_called_once_with(TEST_ENDPOINT_ID)
        m_backout.assert_called_once_with(ep)
        self.assertDictEqual(json.loads(rv.data), {})

    @patch("libnetwork_plugin.docker_plugin.backout_ip_assignments", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.read_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.delete_cnm_endpoint", autospec=True)
    def test_delete_endpoint_does_not_exist(self, m_delete, m_read, m_backout):
        """
        Test delete_endpoint() when the endpoint does not exist.
        """
        m_read.return_value = None
        rv = self.app.post('/NetworkDriver.DeleteEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        m_read.assert_called_once_with(TEST_ENDPOINT_ID)
        assert_equal(m_delete.call_count, 0)
        assert_equal(m_backout.call_count, 0)
        self.assertDictEqual(json.loads(rv.data), {})

    @patch("libnetwork_plugin.docker_plugin.backout_ip_assignments", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.read_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.delete_cnm_endpoint", autospec=True)
    def test_delete_endpoint_just_deleted(self, m_delete, m_read, m_backout):
        """
        Test delete_endpoint() when the endpoint is deleted just before we
        were about to.
        """
        ep = {"test": 1}
        m_read.return_value = ep
        m_delete.return_value = False
        rv = self.app.post('/NetworkDriver.DeleteEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)
        m_read.assert_called_once_with(TEST_ENDPOINT_ID)
        m_delete.assert_called_once_with(TEST_ENDPOINT_ID)
        assert_equal(m_backout.call_count, 0)
        self.assertDictEqual(json.loads(rv.data), {})

    @patch("libnetwork_plugin.docker_plugin.client.cnm_endpoint_exists", autospec=True, return_value=False)
    @patch("libnetwork_plugin.docker_plugin.assign_ip", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.write_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.get_default_next_hops", autospec=True)
    def test_create_endpoint(self, m_next_hops, m_write, m_assign_ip, m_exists):
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
                if version == 4:
                    return ipv4
                elif version == 6:
                    return ipv6
                raise AssertionError("Unexpected version: %s" % version)
            m_assign_ip.side_effect = assign_ip

            # Invoke create endpoint.
            rv = self.app.post('/NetworkDriver.CreateEndpoint',
                               data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)

            # Assert cnm_endpoint_exists was called.
            m_exists.assert_called_once_with(TEST_ENDPOINT_ID)

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
            self.assertDictEqual(json.loads(rv.data), expected_data)

            # Reset the Mocks before continuing.
            m_write.reset_mock()
            m_next_hops.reset_mock()
            m_assign_ip.reset_mock()
            m_exists.reset_mock()

    @patch("libnetwork_plugin.docker_plugin.client.cnm_endpoint_exists", autospec=True, return_value=False)
    @patch("libnetwork_plugin.docker_plugin.client.write_cnm_endpoint", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.get_default_next_hops", autospec=True)
    def test_create_endpoint_no_ip(self, m_next_hops, m_write, m_exists):
        """
        Test the create_endpoint hook writes no data and returns a 500 error
        when no IP addresses can be assigned.
        """
        m_next_hops.return_value = {4: None, 6: None}

        # Invoke create endpoint.
        rv = self.app.post('/NetworkDriver.CreateEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)

        # Assert cnm_endpoint_exists was called.
        m_exists.assert_called_once_with(TEST_ENDPOINT_ID)

        # Assert no data is written and returns 500 response.
        assert_equal(m_write.call_count, 0)
        self.assertDictEqual(json.loads(rv.data), ERROR_RESPONSE_500)

    @patch("libnetwork_plugin.docker_plugin.client.cnm_endpoint_exists", autospec=True, return_value=True)
    @patch("libnetwork_plugin.docker_plugin.client.write_cnm_endpoint", autospec=True)
    def test_create_endpoint_exists(self, m_write, m_exists):
        """
        Test the create_endpoint hook writes no data and returns a 500 error
        when no IP addresses can be assigned.
        """
        # Invoke create endpoint.
        rv = self.app.post('/NetworkDriver.CreateEndpoint',
                           data='{"EndpointID": "%s"}' % TEST_ENDPOINT_ID)

        # Assert cnm_endpoint_exists was called.
        m_exists.assert_called_once_with(TEST_ENDPOINT_ID)

        # Assert no data is written.
        assert_equal(m_write.call_count, 0)

        # Assert empty data is returned.
        self.assertDictEqual(json.loads(rv.data), {})

    @patch("libnetwork_plugin.docker_plugin.client.get_ip_pools", autospec=True)
    @patch("pycalico.ipam.SequentialAssignment.allocate", autospec=True)
    def test_assign_ip(self, m_allocate, m_pools):
        """
        Test assign_ip assigns an IP address.
        """
        m_pools.return_value = [IPNetwork("1.2.3.0/24"), IPNetwork("2.3.4.5/32")]
        m_allocate.return_value = IPAddress("1.2.3.6")
        ip = docker_plugin.assign_ip(4)
        assert_equal(ip, IPNetwork("1.2.3.6"))
        m_pools.assert_called_once_with(4)
        m_allocate.assert_called_once_with(ANY, IPNetwork("1.2.3.0/24"))

    @patch("libnetwork_plugin.docker_plugin.client.get_ip_pools", autospec=True)
    @patch("pycalico.ipam.SequentialAssignment.allocate", autospec=True)
    def test_assign_ip_no_ip(self, m_allocate, m_pools):
        """
        Test assign_ip when no IP addresses can be allocated.
        """
        m_pools.return_value = [IPNetwork("1.2.3.0/24"),
                                IPNetwork("2.3.4.5/32")]
        m_allocate.return_value = None
        ip = docker_plugin.assign_ip(4)
        assert_equal(ip, None)
        m_pools.assert_called_once_with(4)

        # We should have attempted to allocate for each pool.
        m_allocate.assert_has_calls([call(ANY, IPNetwork("1.2.3.0/24")),
                                     call(ANY, IPNetwork("2.3.4.5/32"))])

    @patch("libnetwork_plugin.docker_plugin.client.get_ip_pools", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.unassign_address", autospec=True)
    def test_unassign_ip(self, m_unassign, m_pools):
        """
        Test unassign_ip unassigns an IP address.
        """
        m_pools.return_value = [IPNetwork("1.2.3.0/24"), IPNetwork("2.3.0.0/16")]
        m_unassign.return_value = True
        self.assertTrue(docker_plugin.unassign_ip(IPAddress("2.3.4.5")))

        m_pools.assert_called_once_with(4)
        m_unassign.assert_called_once_with(IPNetwork("2.3.0.0/16"),
                                           IPAddress("2.3.4.5"))

    @patch("libnetwork_plugin.docker_plugin.client.get_ip_pools", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.unassign_address", autospec=True)
    def test_unassign_ip_no_pools(self, m_unassign, m_pools):
        """
        Test unassign_ip when the IP does not fall in any configured pools.
        """
        m_pools.return_value = [IPNetwork("1.2.3.0/24"), IPNetwork("2.3.0.0/16")]
        m_unassign.return_value = False
        self.assertFalse(docker_plugin.unassign_ip(IPAddress("2.30.11.11")))
        m_pools.assert_called_once_with(4)
        self.assertEquals(m_unassign.call_count, 0)

    @patch("libnetwork_plugin.docker_plugin.client.get_ip_pools", autospec=True)
    @patch("libnetwork_plugin.docker_plugin.client.unassign_address", autospec=True)
    def test_unassign_ip_not_in_pools(self, m_unassign, m_pools):
        """
        Test unassign_ip when the IP does not fall in any configured pools.
        """
        m_pools.return_value = [IPNetwork("1.2.3.0/24"),
                                IPNetwork("2.3.0.0/16"),
                                IPNetwork("1.2.0.0/16")]
        m_unassign.return_value = False
        self.assertFalse(docker_plugin.unassign_ip(IPAddress("1.2.3.4")))
        m_pools.assert_called_once_with(4)
        m_unassign.assert_has_calls([call(IPNetwork("1.2.3.0/24"),
                                          IPAddress("1.2.3.4")),
                                     call(IPNetwork("1.2.0.0/16"),
                                          IPAddress("1.2.3.4"))])

    @patch("libnetwork_plugin.docker_plugin.unassign_ip", autospec=True)
    def test_backout_ip_assignments(self, m_unassign):
        """
        Test backout_ip_assignment processing.
        :return:
        """
        m_unassign.return_value = True

        cnm_ep = {"Interfaces": [{"Address": "1.2.3.4"}]}
        docker_plugin.backout_ip_assignments(cnm_ep)
        m_unassign.assert_called_once_with(IPAddress("1.2.3.4"))
        m_unassign.reset_mock()

        cnm_ep = {"Interfaces": [{"AddressIPv6": "aa:bb::ff"}]}
        docker_plugin.backout_ip_assignments(cnm_ep)
        m_unassign.assert_called_once_with(IPAddress("aa:bb::ff"))
        m_unassign.reset_mock()

        cnm_ep = {"Interfaces": [{"Address": "1.2.3.4",
                                  "AddressIPv6": "aa:bb::ff"}]}
        docker_plugin.backout_ip_assignments(cnm_ep)
        m_unassign.assert_has_calls([call(IPAddress("1.2.3.4")),
                                     call(IPAddress("aa:bb::ff"))])

    @patch("libnetwork_plugin.docker_plugin.unassign_ip", autospec=True)
    def test_backout_ip_assignments_failed_unassign(self, m_unassign):
        """
        Test backout_ip_assignment processing when unassignment fails.
        :return:
        """
        m_unassign.return_value = False

        cnm_ep = {"Interfaces": [{"Address": "1.2.3.4"}]}
        docker_plugin.backout_ip_assignments(cnm_ep)
        m_unassign.assert_called_once_with(IPAddress("1.2.3.4"))

    @patch("pycalico.netns.set_veth_mac", autospec=True)
    @patch("pycalico.netns.create_veth", autospec=True)
    def test_create_veth(self, m_create, m_set):
        """
        Test create_veth calls through to netns to create the veth and
        set the MAC.
        """
        endpoint = Endpoint("hostname",
                            "docker",
                            "libnetwork",
                            TEST_ENDPOINT_ID,
                            "active",
                            "EE:EE:EE:EE:EE:EE")

        docker_plugin.create_veth(endpoint)
        m_create.assert_called_once_with(endpoint.name,
                                         endpoint.temp_interface_name)
        m_set.assert_called_once_with(endpoint.temp_interface_name,
                                      endpoint.mac)

    @patch("pycalico.netns.remove_veth", autospec=True, side_effect=CalledProcessError(2, "test"))
    def test_remove_veth_fail(self, m_remove):
        """
        Test remove_veth calls through to netns to remove the veth.
        Fail with a CalledProcessError to write the log.
        """
        endpoint = Endpoint("hostname",
                            "docker",
                            "libnetwork",
                            TEST_ENDPOINT_ID,
                            "active",
                            "EE:EE:EE:EE:EE:EE")

        docker_plugin.remove_veth(endpoint)
        m_remove.assert_called_once_with(endpoint.name)
