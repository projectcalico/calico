__author__ = 'spike@projectcalico.org'


from mock import patch, Mock, call
from node.adapter.datastore import (DatastoreClient,
                                    Rule,
                                    Profile,
                                    Rules,
                                    Endpoint,
                                    NoEndpointForContainer,
                                    CALICO_V_PATH,
                                    DataStoreError)
from etcd import Client as EtcdClient
from etcd import EtcdKeyNotFound, EtcdResult, EtcdException
from netaddr import IPNetwork, IPAddress
import json
from nose.tools import *
import unittest

TEST_HOST = "TEST_HOST"
TEST_PROFILE = "TEST"
TEST_CONT_ID = "1234"
TEST_ENDPOINT_ID = "1234567890ab"
TEST_HOST_PATH = CALICO_V_PATH + "/host/TEST_HOST"
IPV4_POOLS_PATH = CALICO_V_PATH + "/ipam/v4/pool/"
IPV6_POOLS_PATH = CALICO_V_PATH + "/ipam/v6/pool/"
BGP_PEERS_PATH = CALICO_V_PATH + "/config/bgp_peer_rr_v4/"
TEST_PROFILE_PATH = CALICO_V_PATH + "/policy/profile/TEST/"
ALL_PROFILES_PATH = CALICO_V_PATH + "/policy/profile/"
ALL_ENDPOINTS_PATH = CALICO_V_PATH + "/host/"
ALL_HOSTS_PATH = CALICO_V_PATH + "/host/"
TEST_ENDPOINT_PATH = CALICO_V_PATH + "/host/TEST_HOST/workload/docker/1234/" \
                                     "endpoint/1234567890ab"
TEST_CONT_ENDPOINT_PATH = CALICO_V_PATH + "/host/TEST_HOST/workload/docker/" \
                                          "1234/endpoint/"
TEST_CONT_PATH = CALICO_V_PATH + "/host/TEST_HOST/workload/docker/1234/"
CONFIG_PATH = CALICO_V_PATH + "/config/"

# 4 endpoints, with 2 TEST profile and 2 UNIT profile.
EP_56 = Endpoint("567890abcdef", "active", "11-22-33-44-55-66")
EP_56.profile_id = "TEST"
EP_78 = Endpoint("7890abcdef12", "active", "11-22-33-44-55-66")
EP_78.profile_id = "TEST"
EP_90 = Endpoint("90abcdef1234", "active", "11-22-33-44-55-66")
EP_90.profile_id = "UNIT"
EP_12 = Endpoint(TEST_ENDPOINT_ID, "active", "11-22-33-44-55-66")
EP_12.profile_id = "UNIT"


class TestRule(unittest.TestCase):

    def test_create(self):
        """
        Test creating a rule from constructor.
        """
        rule1 = Rule(action="allow",
                     src_tag="TEST",
                     src_ports=[300, 400])
        assert_dict_equal({"action": "allow",
                           "src_tag": "TEST",
                           "src_ports": [300, 400]}, rule1)

    def test_to_json(self):
        """
        Test to_json() method.
        """
        rule1 = Rule(action="deny",
                     dst_net=IPNetwork("192.168.13.0/24"))
        json_str = rule1.to_json()
        expected = json.dumps({"action": "deny",
                               "dst_net": "192.168.13.0/24"})
        assert_equal(json_str, expected)

        rule2 = Rule(action="deny",
                     src_net="192.168.13.0/24")
        json_str = rule2.to_json()
        expected = json.dumps({"action": "deny",
                               "src_net": "192.168.13.0/24"})
        assert_equal(json_str, expected)

    @raises(KeyError)
    def test_wrong_keys(self):
        """
        Test that instantiating a Rule with mistyped keys fails.
        """
        _ = Rule(action="deny", dst_nets="192.168.13.0/24")

    @raises(ValueError)
    def test_wrong_value(self):
        """
        Test that instantiating a Rule with action not allow|deny will fail.
        """
        _ = Rule(action="accept")

    def test_pprint(self):
        """
        Test pprint() method for human readable representation.
        """
        rule1 = Rule(action="allow",
                     src_tag="TEST",
                     src_ports=[300, 400])
        assert_equal("allow from tag TEST ports [300, 400]",
                     rule1.pprint())

        rule2 = Rule(action="allow",
                     dst_tag="TEST",
                     dst_ports=[300, 400],
                     protocol="udp")
        assert_equal("allow udp to tag TEST ports [300, 400]",
                     rule2.pprint())

        rule3 = Rule(action="deny",
                     src_net=IPNetwork("fd80::4:0/112"),
                     dst_ports=[80],
                     dst_net=IPNetwork("fd80::23:0/112"))
        assert_equal(
            "deny from fd80::4:0/112 to fd80::23:0/112 ports [80]",
            rule3.pprint())

        rule4 = Rule(action="allow",
                     protocol="icmp",
                     icmp_type=8,
                     src_net=IPNetwork("10/8"))
        assert_equal("allow icmp type 8 from 10.0.0.0/8",
                     rule4.pprint())


class TestEndpoint(unittest.TestCase):

    def test_to_json(self):
        """
        Test to_json() method.
        """
        endpoint1 = Endpoint("aabbccddeeff112233",
                             "active",
                             "11-22-33-44-55-66")
        assert_equal(endpoint1.ep_id, "aabbccddeeff112233")
        assert_equal(endpoint1.state, "active")
        assert_equal(endpoint1.mac, "11-22-33-44-55-66")
        assert_equal(endpoint1.profile_id, None)
        expected = {"state": "active",
                    "name": "caliaabbccddeef",
                    "mac": "11-22-33-44-55-66",
                    "profile_id": None,
                    "ipv4_nets": [],
                    "ipv6_nets": [],
                    "ipv4_gateway": None,
                    "ipv6_gateway": None}
        assert_dict_equal(json.loads(endpoint1.to_json()), expected)

        endpoint1.profile_id = "TEST12"
        endpoint1.ipv4_nets.add(IPNetwork("192.168.1.23/32"))
        endpoint1.ipv4_gateway = IPAddress("192.168.1.1")
        expected["profile_id"] = "TEST12"
        expected["ipv4_nets"] = ["192.168.1.23/32"]
        expected["ipv4_gateway"] = "192.168.1.1"
        assert_dict_equal(json.loads(endpoint1.to_json()), expected)

    def test_from_json(self):
        """
        Test from_json() class method
          - Directly from JSON
          - From to_json() method of existing Endpoint.
        """
        ep_id = "aabbccddeeff112233"
        expected = {"state": "active",
                    "name": "caliaabbccddeef",
                    "mac": "11-22-33-44-55-66",
                    "profile_id": "TEST23",
                    "ipv4_nets": ["192.168.3.2/32", "10.3.4.23/32"],
                    "ipv6_nets": ["fd20::4:2:1/128"],
                    "ipv4_gateway": "10.3.4.2",
                    "ipv6_gateway": "2001:2:4a::1"}
        endpoint = Endpoint.from_json(ep_id, json.dumps(expected))
        assert_equal(endpoint.state, "active")
        assert_equal(endpoint.ep_id, ep_id)
        assert_equal(endpoint.mac, "11-22-33-44-55-66")
        assert_equal(endpoint.profile_id, "TEST23")
        assert_equal(endpoint.ipv4_gateway, IPAddress("10.3.4.2"))
        assert_equal(endpoint.ipv6_gateway, IPAddress("2001:2:4a::1"))
        assert_set_equal(endpoint.ipv4_nets, {IPNetwork("192.168.3.2/32"),
                                              IPNetwork("10.3.4.23/32")})
        assert_set_equal(endpoint.ipv6_nets, {IPNetwork("fd20::4:2:1/128")})

        endpoint2 = Endpoint.from_json(ep_id, endpoint.to_json())
        assert_equal(endpoint.state, endpoint2.state)
        assert_equal(endpoint.ep_id, endpoint2.ep_id)
        assert_equal(endpoint.mac, endpoint2.mac)
        assert_equal(endpoint.profile_id, endpoint2.profile_id)
        assert_equal(endpoint.ipv4_gateway, endpoint2.ipv4_gateway)
        assert_equal(endpoint.ipv6_gateway, endpoint2.ipv6_gateway)
        assert_set_equal(endpoint.ipv4_nets, endpoint2.ipv4_nets)
        assert_set_equal(endpoint.ipv6_nets, endpoint2.ipv6_nets)

    def test_operators(self):
        """
        Test Endpoint operators __eq__, __ne__ and copy.
        """
        endpoint1 = Endpoint("aabbccddeeff112233",
                             "active",
                             "11-22-33-44-55-66")
        endpoint2 = Endpoint("aabbccddeeff112233",
                             "inactive",
                             "11-22-33-44-55-66")
        endpoint3 = endpoint1.copy()

        assert_equal(endpoint1, endpoint3)
        assert_not_equal(endpoint1, endpoint2)
        assert_not_equal(endpoint1, 1)
        assert_false(endpoint1 == "this is not an endpoint")


class TestDatastoreClient(unittest.TestCase):

    @patch("node.adapter.datastore.os.getenv", autospec=True)
    @patch("node.adapter.datastore.etcd.Client", autospec=True)
    def setUp(self, m_etcd_client, m_getenv):
        m_getenv.return_value = "127.0.0.2:4002"
        self.etcd_client = Mock(spec=EtcdClient)
        m_etcd_client.return_value = self.etcd_client
        self.datastore = DatastoreClient()
        m_etcd_client.assert_called_once_with(host="127.0.0.2", port=4002)

    def test_ensure_global_config(self):
        """
        Test ensure_global_config when it doesn't already exist.
        """
        self.etcd_client.read.side_effect = EtcdKeyNotFound 
        self.datastore.ensure_global_config()
        expected_writes = [call(CALICO_V_PATH + "/Ready", "true"),
                           call(CONFIG_PATH + "InterfacePrefix", "cali")]
        self.etcd_client.write.assert_has_calls(expected_writes,
                                                any_order=True)

    def test_ensure_global_config_exists(self):
        """
        Test ensure_global_config() when it already exists.
        """
        self.datastore.ensure_global_config()
        self.etcd_client.read.assert_called_once_with(CONFIG_PATH)

    def test_ensure_global_config_exists_etcd_exc(self):
        """
        Test ensure_global_config() when etcd raises an EtcdException.
        """
        self.etcd_client.read.side_effect = EtcdException
        self.assertRaises(DataStoreError, self.datastore.ensure_global_config)
        self.etcd_client.read.assert_called_once_with(CONFIG_PATH)

    def test_get_profile(self):
        """
        Test getting a named profile that exists.
        Test getting a named profile that doesn't exist raises a KeyError.
        """

        def mock_read(path):
            result = Mock(spec=EtcdResult)
            if path == TEST_PROFILE_PATH:
                return result
            elif path == TEST_PROFILE_PATH + "tags":
                result.value = '["TAG1", "TAG2", "TAG3"]'
                return result
            elif path == TEST_PROFILE_PATH + "rules":
                result.value = """
{
  "id": "TEST",
  "inbound_rules": [
    {"action": "allow", "src_net": "192.168.1.0/24", "src_ports": [200,2001]}
  ],
  "outbound_rules": [
    {"action": "allow", "src_tag": "TEST", "src_ports": [200,2001]}
  ]
}
"""
                return result
            else:
                raise EtcdKeyNotFound()
        self.etcd_client.read.side_effect = mock_read

        profile = self.datastore.get_profile("TEST")
        assert_equal(profile.name, "TEST")
        assert_set_equal({"TAG1", "TAG2", "TAG3"}, profile.tags)
        assert_equal(Rule(action="allow",
                          src_net=IPNetwork("192.168.1.0/24"),
                          src_ports=[200, 2001]),
                     profile.rules.inbound_rules[0])
        assert_equal(Rule(action="allow",
                          src_tag="TEST",
                          src_ports=[200, 2001]),
                     profile.rules.outbound_rules[0])

        assert_raises(KeyError, self.datastore.get_profile, "TEST2")

    def test_get_profile_no_tags_or_rules(self):
        """
        Test getting a named profile that exists, but has no tags or rules.
        """

        def mock_read(path):
            result = Mock(spec=EtcdResult)
            if path == TEST_PROFILE_PATH:
                return result
            else:
                raise EtcdKeyNotFound()
        self.etcd_client.read.side_effect = mock_read

        profile = self.datastore.get_profile("TEST")
        assert_equal(profile.name, "TEST")
        assert_set_equal(set(), profile.tags)
        assert_equal([], profile.rules.inbound_rules)
        assert_equal([], profile.rules.outbound_rules)

    @raises(KeyError)
    def test_remove_profile_doesnt_exist(self):
        """
        Remove profile when it doesn't exist.  Check it throws a KeyError.
        :return: None
        """
        self.etcd_client.delete.side_effect = EtcdKeyNotFound
        self.datastore.remove_profile(TEST_PROFILE)

    def test_profile_update_tags(self):
        """
        Test updating tags on an existing profile.
        :return:
        """

        profile = Profile("TEST")
        profile.tags = {"TAG4", "TAG5"}
        profile.rules = Rules(id="TEST",
                              inbound_rules=[
                                  Rule(action="allow", dst_ports=[12]),
                                  Rule(action="allow", protocol="udp"),
                                  Rule(action="deny")
                              ],
                              outbound_rules=[
                                  Rule(action="allow", src_ports=[23]),
                                  Rule(action="deny")
                              ])

        self.datastore.profile_update_tags(profile)
        self.etcd_client.write.assert_called_once_with(
            TEST_PROFILE_PATH + "tags",
            '["TAG4", "TAG5"]')

    def test_profile_update_rules(self):
        """
        Test updating rules on an existing profile.
        :return:
        """

        profile = Profile("TEST")
        profile.tags = {"TAG4", "TAG5"}
        profile.rules = Rules(id="TEST",
                              inbound_rules=[
                                  Rule(action="allow", dst_ports=[12]),
                                  Rule(action="allow", protocol="udp"),
                                  Rule(action="deny")
                              ],
                              outbound_rules=[
                                  Rule(action="allow", src_ports=[23]),
                                  Rule(action="deny")
                              ])

        self.datastore.profile_update_rules(profile)
        self.etcd_client.write.assert_called_once_with(
            TEST_PROFILE_PATH + "rules",
            profile.rules.to_json())

    def test_create_host_exists(self):
        """
        Test create_host() when the .../workload key already exists.
        :return: None
        """
        def mock_read_success(path):
            result = Mock(spec=EtcdResult)
            if path == TEST_HOST_PATH + "/workload":
                return result
            else:
                assert False

        self.etcd_client.read.side_effect = mock_read_success

        bird_ip = "192.168.2.4"
        bird6_ip = "fd80::4"
        self.datastore.create_host(TEST_HOST, bird_ip, bird6_ip)
        expected_writes = [call(TEST_HOST_PATH + "/bird_ip", bird_ip),
                           call(TEST_HOST_PATH + "/bird6_ip", bird6_ip),
                           call(TEST_HOST_PATH + "/config/marker",
                                "created")]
        self.etcd_client.write.assert_has_calls(expected_writes,
                                                any_order=True)
        assert_equal(self.etcd_client.write.call_count, 3)

    def test_create_host_mainline(self):
        """
        Test create_host() when none of the keys exists (specifically,
        .../workload is checked and doesn't exist).
        :return: None
        """
        def mock_read(path):
            if path == CALICO_V_PATH + "/host/TEST_HOST/workload":
                raise EtcdKeyNotFound()
            else:
                assert False

        self.etcd_client.read.side_effect = mock_read

        bird_ip = "192.168.2.4"
        bird6_ip = "fd80::4"
        self.datastore.create_host(TEST_HOST, bird_ip, bird6_ip)
        expected_writes = [call(TEST_HOST_PATH + "/bird_ip", bird_ip),
                           call(TEST_HOST_PATH + "/bird6_ip", bird6_ip),
                           call(TEST_HOST_PATH + "/config/marker",
                                "created"),
                           call(TEST_HOST_PATH + "/workload",
                                None, dir=True)]
        self.etcd_client.write.assert_has_calls(expected_writes,
                                                any_order=True)
        assert_equal(self.etcd_client.write.call_count, 4)

    def test_remove_host_mainline(self):
        """
        Test remove_host() when the key exists.
        :return:
        """
        self.datastore.remove_host(TEST_HOST)
        self.etcd_client.delete.assert_called_once_with(TEST_HOST_PATH + "/",
                                                        dir=True,
                                                        recursive=True)

    def test_remove_host_doesnt_exist(self):
        """
        Remove host when it doesn't exist.  Check it doesn't throw an
        exception.
        :return: None
        """
        self.etcd_client.delete.side_effect = EtcdKeyNotFound
        self.datastore.remove_host(TEST_HOST)

    def test_get_ip_pools(self):
        """
        Test getting IP pools from the datastore when there are some pools.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_2_pools
        pools = self.datastore.get_ip_pools("v4")
        assert_set_equal({IPNetwork("192.168.3.0/24"),
                          IPNetwork("192.168.5.0/24")}, set(pools))

    def test_get_ip_pools_no_key(self):
        """
        Test getting IP pools from the datastore when the key doesn't exist.
        :return: None
        """
        def mock_read(path):
            assert_equal(path, IPV4_POOLS_PATH)
            raise EtcdKeyNotFound()

        self.etcd_client.read.side_effect = mock_read
        pools = self.datastore.get_ip_pools("v4")
        assert_list_equal([], pools)

    def test_get_ip_pools_no_pools(self):
        """
        Test getting IP pools from the datastore when the key is there but has
        no children.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_no_pools
        pools = self.datastore.get_ip_pools("v4")
        assert_list_equal([], pools)

    def test_add_ip_pool(self):
        """
        Test adding an IP pool when the directory exists, but pool doesn't.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_2_pools

        pool = IPNetwork("192.168.100.5/24")
        self.datastore.add_ip_pool("v4", pool)
        self.etcd_client.write.assert_called_once_with(IPV4_POOLS_PATH,
                                                       "192.168.100.0/24",
                                                       append=True)

    def test_add_ip_pool_exists(self):
        """
        Test adding an IP pool when the pool already exists.
        :return: None
        """

        self.etcd_client.read.side_effect = mock_read_2_pools

        pool = IPNetwork("192.168.3.5/24")
        self.datastore.add_ip_pool("v4", pool)
        assert_false(self.etcd_client.write.called)

    def test_del_ip_pool_exists(self):
        """
        Test remove_ip_pool() when the pool does exist.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_2_pools
        pool = IPNetwork("192.168.3.1/24")
        self.datastore.remove_ip_pool("v4", pool)
        # 192.168.3.0/24 has a key .../v4/pool/0 in the ordered list.
        self.etcd_client.delete.assert_called_once_with(IPV4_POOLS_PATH + "0")

    def test_del_ip_pool_doesnt_exist(self):
        """
        Test remove_ip_pool() when the pool does not exist.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_2_pools
        pool = IPNetwork("192.168.100.1/24")
        assert_raises(KeyError, self.datastore.remove_ip_pool, "v4", pool)
        assert_false(self.etcd_client.delete.called)

    def test_profile_exists_true(self):
        """
        Test profile_exists() when it does.
        """
        def mock_read(path):
            assert_equal(path, TEST_PROFILE_PATH)
            return Mock(spec=EtcdResult)

        self.etcd_client.read.side_effect = mock_read
        assert_true(self.datastore.profile_exists("TEST"))

    def test_profile_exists_false(self):
        """
        Test profile_exists() when it doesn't exist.
        """
        def mock_read(path):
            assert_equal(path, TEST_PROFILE_PATH)
            raise EtcdKeyNotFound()

        self.etcd_client.read.side_effect = mock_read
        assert_false(self.datastore.profile_exists("TEST"))

    def test_create_profile(self):
        """
        Test create_profile()
        """
        self.datastore.create_profile("TEST")
        rules = Rules(id="TEST",
                      inbound_rules=[Rule(action="allow",
                                          src_tag="TEST"),
                                     Rule(action="deny")],
                      outbound_rules=[Rule(action="allow")])
        expected_calls = [call(TEST_PROFILE_PATH + "tags", '["TEST"]'),
                          call(TEST_PROFILE_PATH + "rules", rules.to_json())]
        self.etcd_client.write.assert_has_calls(expected_calls, any_order=True)

    def test_delete_profile(self):
        """
        Test deleting a policy profile.
        """
        self.datastore.remove_profile("TEST")
        self.etcd_client.delete.assert_called_once_with(TEST_PROFILE_PATH,
                                                        recursive=True,
                                                        dir=True)

    def test_get_profile_names_2(self):
        """
        Test get_profile_names() when there are two profiles.
        """
        self.etcd_client.read.side_effect = mock_read_2_profiles
        profiles = self.datastore.get_profile_names()
        assert_set_equal(profiles, {"UNIT", "TEST"})

    def test_get_profile_names_no_key(self):
        """
        Test get_profile_names() when the key hasn't been set up.  Should
        return empty set and not raise a KeyError.
        """
        self.etcd_client.read.side_effect = mock_read_profiles_key_error
        profiles = self.datastore.get_profile_names()
        assert_set_equal(profiles, set())

    def test_get_profile_names_no_profiles(self):
        """
        Test get_profile_names() when there are no profiles.
        """
        self.etcd_client.read.side_effect = mock_read_no_profiles
        profiles = self.datastore.get_profile_names()
        assert_set_equal(profiles, set())

    def test_get_profile_members_ep_ids(self):
        """
        Test get_profile_members_ep_ids() when there are endpoints.
        """
        self.etcd_client.read.side_effect = mock_read_4_endpoints
        members = self.datastore.get_profile_members_ep_ids("TEST")
        assert_set_equal({"567890abcdef", "7890abcdef12"},
                         set(members))

        members = self.datastore.get_profile_members_ep_ids("UNIT")
        assert_set_equal({"90abcdef1234", TEST_ENDPOINT_ID},
                         set(members))

        members = self.datastore.get_profile_members_ep_ids("UNIT_TEST")
        assert_set_equal(set(), set(members))

    def test_get_profile_members_ep_ids_no_key(self):
        """
        Test get_profile_members_ep_ids() when the endpoints path has not been
        set up.
        """
        self.etcd_client.read.side_effect = mock_read_endpoints_key_error
        members = self.datastore.get_profile_members_ep_ids("UNIT_TEST")
        assert_set_equal(set(), set(members))

    def test_get_profile_members(self):
        """
        Test get_profile_members() when there are endpoints.
        """
        self.maxDiff = 1000
        self.etcd_client.read.side_effect = mock_read_4_endpoints
        members = self.datastore.get_profile_members("TEST")
        assert_dict_equal({"TEST_HOST":
                            {"docker":
                              {"1234":
                                {"567890abcdef": EP_56}}},
                           "TEST_HOST2":
                            {"docker":
                              {"1234":
                                {"7890abcdef12": EP_78}}}
                          },
                          members)

        members = self.datastore.get_profile_members("UNIT")
        assert_dict_equal({"TEST_HOST":
                            {"docker":
                              {"5678":
                                {"90abcdef1234": EP_90}}},
                           "TEST_HOST2":
                            {"docker":
                              {"5678":
                                {"1234567890ab": EP_12}}}
                          },
                          members)

        members = self.datastore.get_profile_members("UNIT_TEST")
        assert_dict_equal({}, members)

    def test_get_profile_members_no_key(self):
        """
        Test get_profile_members() when the endpoints path has not been
        set up.
        """
        self.etcd_client.read.side_effect = mock_read_endpoints_key_error
        members = self.datastore.get_profile_members("UNIT_TEST")
        assert_dict_equal({}, members)

    def test_get_endpoint_exists(self):
        """
        Test get_endpoint() for an endpoint that exists.
        """
        ep = Endpoint(TEST_ENDPOINT_ID, "active", "11-22-33-44-55-66")
        self.etcd_client.read.side_effect = mock_read_for_endpoint(ep)
        ep2 = self.datastore.get_endpoint(TEST_HOST,
                                          TEST_CONT_ID,
                                          TEST_ENDPOINT_ID)
        assert_equal(ep.to_json(), ep2.to_json())
        assert_equal(ep.ep_id, ep2.ep_id)

    def test_get_endpoint_doesnt_exist(self):
        """
        Test get_endpoint() for an endpoint that doesn't exist.
        """
        def mock_read(path):
            assert_equal(path, TEST_ENDPOINT_PATH)
            raise EtcdKeyNotFound()
        self.etcd_client.read.side_effect = mock_read
        assert_raises(KeyError,
                      self.datastore.get_endpoint,
                      TEST_HOST, TEST_CONT_ID, TEST_ENDPOINT_ID)

    def test_set_endpoint(self):
        """
        Test set_endpoint().
        """
        self.datastore.set_endpoint(TEST_HOST, TEST_CONT_ID, EP_12)
        self.etcd_client.write.assert_called_once_with(TEST_ENDPOINT_PATH,
                                                       EP_12.to_json())

    def test_update_endpoint(self):
        """
        Test update_endpoint().
        """
        self.datastore.update_endpoint(TEST_HOST, TEST_CONT_ID, EP_90, EP_12)
        self.etcd_client.write.assert_called_once_with(TEST_ENDPOINT_PATH,
                                                       EP_12.to_json(),
                                                       prevValue=EP_90.to_json())

    def test_get_ep_id_from_cont(self):
        """
        Test get_ep_id_from_cont() when container and endpoint exist.
        """
        self.etcd_client.read.side_effect = mock_read_2_ep_for_cont
        ep_id = self.datastore.get_ep_id_from_cont(TEST_HOST, TEST_CONT_ID)
        assert_equal(ep_id, EP_12.ep_id)

    def test_get_ep_id_from_cont_no_ep(self):
        """
        Test get_ep_id_from_cont() when the container exists, but there are
        no endpoints.
        """
        self.etcd_client.read.side_effect = mock_read_0_ep_for_cont
        assert_raises(NoEndpointForContainer,
                      self.datastore.get_ep_id_from_cont,
                      TEST_HOST, TEST_CONT_ID)

    def test_get_ep_id_from_cont_no_cont(self):
        """
        Test get_ep_id_from_cont() when the container doesn't exist.
        """
        self.etcd_client.read.side_effect = EtcdKeyNotFound
        assert_raises(KeyError,
                      self.datastore.get_ep_id_from_cont,
                      TEST_HOST, TEST_CONT_ID)

    def test_add_workload_to_profile(self):
        """
        Test add_workload_to_profile() when the workload exists.
        """
        ep = Endpoint.from_json(EP_12.ep_id, EP_12.to_json())

        def mock_read(path):
            if path == TEST_CONT_ENDPOINT_PATH:
                return mock_read_2_ep_for_cont(path)
            elif path == TEST_CONT_ENDPOINT_PATH + ep.ep_id:
                return mock_read_for_endpoint(ep)(path)
            else:
                assert_true(False)

        self.etcd_client.read.side_effect = mock_read
        self.datastore.add_workload_to_profile(TEST_HOST,
                                               "UNITTEST",
                                               TEST_CONT_ID)
        ep.profile_id = "UNITTEST"
        expected_write_json = ep.to_json()
        self.etcd_client.write.assert_called_once_with(TEST_ENDPOINT_PATH,
                                                       expected_write_json)

    def test_remove_workload_from_profile(self):
        """
        Test remove_workload_from_profile() when the workload exists.
        """
        ep = Endpoint.from_json(EP_12.ep_id, EP_12.to_json())

        def mock_read(path):
            if path == TEST_CONT_ENDPOINT_PATH:
                return mock_read_2_ep_for_cont(path)
            elif path == TEST_CONT_ENDPOINT_PATH + ep.ep_id:
                return mock_read_for_endpoint(ep)(path)
            else:
                assert_true(False)

        self.etcd_client.read.side_effect = mock_read
        self.datastore.remove_workload_from_profile(TEST_HOST, TEST_CONT_ID)
        ep.profile_id = None
        expected_write_json = ep.to_json()
        self.etcd_client.write.assert_called_once_with(TEST_ENDPOINT_PATH,
                                                       expected_write_json)

    def test_get_hosts(self):
        """
        Test get_hosts with two hosts, each with two containers, each with
        one endpoint.
        """
        # Reuse etcd read from test_get_profile_members_* since it's the same
        # query.
        self.etcd_client.read.side_effect = mock_read_4_endpoints
        hosts = self.datastore.get_hosts()
        assert_equal(len(hosts), 2)
        assert_true(TEST_HOST in hosts)
        assert_true("TEST_HOST2" in hosts)
        test_host = hosts[TEST_HOST]
        assert_equal(len(test_host), 1)
        assert_true("docker" in test_host)
        test_host_workloads = test_host["docker"]
        assert_equal(len(test_host_workloads), 2)
        assert_true(TEST_CONT_ID in test_host_workloads)
        assert_true("5678" in test_host_workloads)
        assert_true(EP_56.ep_id in test_host_workloads[TEST_CONT_ID])
        assert_equal(len(test_host_workloads[TEST_CONT_ID]), 1)
        assert_true(EP_90.ep_id in test_host_workloads["5678"])
        assert_equal(len(test_host_workloads["5678"]), 1)

        test_host2 = hosts["TEST_HOST2"]
        assert_equal(len(test_host2), 1)
        assert_true("docker" in test_host2)
        test_host2_workloads = test_host2["docker"]
        assert_equal(len(test_host2_workloads), 2)
        assert_true(TEST_CONT_ID in test_host2_workloads)
        assert_true("5678" in test_host2_workloads)
        assert_true(EP_78.ep_id in test_host2_workloads[TEST_CONT_ID])
        assert_equal(len(test_host2_workloads[TEST_CONT_ID]), 1)
        assert_true(EP_12.ep_id in test_host2_workloads["5678"])
        assert_equal(len(test_host2_workloads["5678"]), 1)

    def test_get_hosts_key_error(self):
        """
        Test get_hosts() when the read returns a KeyError.
        """
        self.etcd_client.read.side_effect = EtcdKeyNotFound
        hosts = self.datastore.get_hosts()
        assert_dict_equal({}, hosts)

    def test_get_default_next_hops(self):
        """
        Test get_default_next_hops when both are present.
        """
        def mock_read(path):
            result = Mock(spec=EtcdResult)
            if path == TEST_HOST_PATH + "/bird_ip":
                result.value = "192.168.24.1"
                return result
            if path == TEST_HOST_PATH + "/bird6_ip":
                result.value = "fd30:4500::1"
                return result
            assert False
        self.etcd_client.read.side_effect = mock_read
        next_hops = self.datastore.get_default_next_hops(TEST_HOST)
        assert_dict_equal(next_hops, {4: IPAddress("192.168.24.1"),
                                      6: IPAddress("fd30:4500::1")})

    def test_get_default_next_hops_missing(self):
        """
        Test get_default_next_hops when both are missing.
        """
        def mock_read(path):
            result = Mock(spec=EtcdResult)
            if path == TEST_HOST_PATH + "/bird_ip":
                result.value = ""
                return result
            if path == TEST_HOST_PATH + "/bird6_ip":
                result.value = ""
                return result
            assert False
        self.etcd_client.read.side_effect = mock_read
        next_hops = self.datastore.get_default_next_hops(TEST_HOST)
        assert_dict_equal(next_hops, {})

    @raises(KeyError)
    def test_get_default_next_hops_missing_config(self):
        """
        Test get_default_next_hops raises a KeyError when the BIRD
        configuration is missing from etcd.
        """
        self.etcd_client.read.side_effect = EtcdKeyNotFound
        next_hops = self.datastore.get_default_next_hops(TEST_HOST)

    def test_remove_all_data(self):
        """
        Test remove_all_data() when /calico does exist.
        """
        self.datastore.remove_all_data()
        self.etcd_client.delete.assert_called_once_with("/calico",
                                                        recursive=True,
                                                        dir=True)

    def test_remove_all_data_key_error(self):
        """
        Test remove_all_data() when delete() throws a KeyError.
        """
        self.etcd_client.delete.side_effect = EtcdKeyNotFound
        self.datastore.remove_all_data()  # should not throw exception.

    def test_remove_container(self):
        """
        Test remove_container()
        """
        self.datastore.remove_container(TEST_HOST, TEST_CONT_ID)
        self.etcd_client.delete.assert_called_once_with(TEST_CONT_PATH,
                                                        recursive=True,
                                                        dir=True)

    @raises(KeyError)
    def test_remove_container_missing(self):
        """
        Test remove_container() raises a KeyError if the container does not
        exist.
        """
        self.etcd_client.delete.side_effect = EtcdKeyNotFound
        self.datastore.remove_container(TEST_HOST, TEST_CONT_ID)

    def test_get_bgp_peer(self):
        """
        Test getting IP peers from the datastore when there are some peers.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_2_peers
        peers = self.datastore.get_bgp_peers("v4")
        assert_set_equal({IPAddress("192.168.3.1"),
                          IPAddress("192.168.5.1")}, set(peers))

    def test_get_bgp_peer_no_key(self):
        """
        Test getting IP peers from the datastore when the key doesn't exist.
        :return: None
        """
        def mock_read(path):
            assert_equal(path, BGP_PEERS_PATH)
            raise EtcdKeyNotFound()

        self.etcd_client.read.side_effect = mock_read
        peers = self.datastore.get_bgp_peers("v4")
        assert_list_equal([], peers)

    def test_get_bgp_peer_no_peers(self):
        """
        Test getting BGP peers from the datastore when the key is there but has
        no children.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_no_bgppeers
        peers = self.datastore.get_bgp_peers("v4")
        assert_list_equal([], peers)

    def test_add_bgp_peer(self):
        """
        Test adding an IP peer when the directory exists, but peer doesn't.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_2_peers

        peer = IPAddress("192.168.100.5")
        self.datastore.add_bgp_peer("v4", peer)
        self.etcd_client.write.assert_called_once_with(BGP_PEERS_PATH,
                                                       "192.168.100.5",
                                                       append=True)

    def test_add_bgp_peer_exists(self):
        """
        Test adding an IP peer when the peer already exists.
        :return: None
        """

        self.etcd_client.read.side_effect = mock_read_2_peers

        peer = IPAddress("192.168.3.1")
        self.datastore.add_bgp_peer("v4", peer)
        assert_false(self.etcd_client.write.called)

    def test_del_bgp_peer_exists(self):
        """
        Test del_bgp_peer() when the peer does exist.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_2_peers
        peer = IPAddress("192.168.3.1")
        self.datastore.remove_bgp_peer("v4", peer)
        # 192.168.3.1 has a key ...v4/0 in the ordered list.
        self.etcd_client.delete.assert_called_once_with(BGP_PEERS_PATH + "0")

    def test_del_bgp_peer_doesnt_exist(self):
        """
        Test del_bgp_peer() when the peer does not exist.
        :return: None
        """
        self.etcd_client.read.side_effect = mock_read_2_peers
        peer = IPAddress("192.168.100.1")
        assert_raises(KeyError, self.datastore.remove_bgp_peer, "v4", peer)
        assert_false(self.etcd_client.delete.called)


def mock_read_2_peers(path):
    """
    EtcdClient mock side effect for read with 2 IPv4 peers.
    """
    result = Mock(spec=EtcdResult)
    assert path == BGP_PEERS_PATH
    children = []
    for i, net in enumerate(["192.168.3.1", "192.168.5.1"]):
        node = Mock(spec=EtcdResult)
        node.value = net
        node.key = BGP_PEERS_PATH + str(i)
        children.append(node)
    result.children = iter(children)
    return result

def mock_read_2_pools(path):
    """
    EtcdClient mock side effect for read with 2 IPv4 pools.
    """
    result = Mock(spec=EtcdResult)
    assert path == IPV4_POOLS_PATH
    children = []
    for i, net in enumerate(["192.168.3.0/24", "192.168.5.0/24"]):
        node = Mock(spec=EtcdResult)
        node.value = net
        node.key = IPV4_POOLS_PATH + str(i)
        children.append(node)
    result.children = iter(children)
    return result


def mock_read_no_pools(path):
    """
    EtcdClient mock side effect for read with no IPv4 pools.
    """
    result = Mock(spec=EtcdResult)
    assert path == IPV4_POOLS_PATH
    result.children = []
    return result

def mock_read_no_bgppeers(path):
    """
    EtcdClient mock side effect for read with no IPv4 BGP Peers
    """
    result = Mock(spec=EtcdResult)
    assert path == BGP_PEERS_PATH
    result.children = iter([])
    return result


def mock_read_2_profiles(path, recursive):
    assert path == ALL_PROFILES_PATH
    assert recursive
    nodes = [CALICO_V_PATH + "/policy/profile/TEST",
             CALICO_V_PATH + "/policy/profile/TEST/tags",
             CALICO_V_PATH + "/policy/profile/TEST/rules",
             CALICO_V_PATH + "/policy/profile/UNIT",
             CALICO_V_PATH + "/policy/profile/UNIT/tags",
             CALICO_V_PATH + "/policy/profile/UNIT/rules"]
    children = []
    for node in nodes:
        result = Mock(spec=EtcdResult)
        result.key = node
        children.append(result)
    results = Mock(spec=EtcdResult)
    results.children = iter(children)
    return results


def mock_read_no_profiles(path, recursive):
    assert path == ALL_PROFILES_PATH
    assert recursive
    results = Mock(spec=EtcdResult)
    results.children = iter([])
    return results


def mock_read_profiles_key_error(path, recursive):
    assert path == ALL_PROFILES_PATH
    assert recursive
    raise EtcdKeyNotFound()


def mock_read_4_endpoints(path, recursive):
    assert path == ALL_ENDPOINTS_PATH
    assert recursive
    leaves = []

    specs = [
        (CALICO_V_PATH + "/host/TEST_HOST/bird_ip", "192.168.1.1"),
        (CALICO_V_PATH + "/host/TEST_HOST/bird6_ip", "fd80::4"),
        (CALICO_V_PATH + "/host/TEST_HOST/config/marker", "created"),
        (CALICO_V_PATH + "/host/TEST_HOST/workload/docker/1234/endpoint/567890abcdef",
         EP_56.to_json()),
        (CALICO_V_PATH + "/host/TEST_HOST/workload/docker/5678/endpoint/90abcdef1234",
         EP_90.to_json()),
        (CALICO_V_PATH + "/host/TEST_HOST2/bird_ip", "192.168.1.2"),
        (CALICO_V_PATH + "/host/TEST_HOST2/bird6_ip", "fd80::3"),
        (CALICO_V_PATH + "/host/TEST_HOST2/config/marker", "created"),
        (CALICO_V_PATH + "/host/TEST_HOST2/workload/docker/1234/endpoint/7890abcdef12",
         EP_78.to_json()),
        (CALICO_V_PATH + "/host/TEST_HOST2/workload/docker/5678/endpoint/1234567890ab",
         EP_12.to_json())]
    for spec in specs:
        leaf = Mock(spec=EtcdResult)
        leaf.key = spec[0]
        leaf.value = spec[1]
        leaves.append(leaf)

    result = Mock(spec=EtcdResult)
    result.leaves = iter(leaves)
    return result


def mock_read_endpoints_key_error(path, recursive):
    assert path == ALL_ENDPOINTS_PATH
    assert recursive
    raise EtcdKeyNotFound()


def mock_read_for_endpoint(ep):
    def mock_read_get_endpoint(path):
        assert path == TEST_ENDPOINT_PATH
        result = Mock(spec=EtcdResult)
        result.value = ep.to_json()
        return result
    return mock_read_get_endpoint


def mock_read_2_ep_for_cont(path):
    assert path == TEST_CONT_ENDPOINT_PATH
    leaves = []

    specs = [
        (CALICO_V_PATH + "/host/TEST_HOST/workload/docker/1234/endpoint/1234567890ab",
         EP_12.to_json()),
        (CALICO_V_PATH + "/host/TEST_HOST/workload/docker/1234/endpoint/90abcdef1234",
         EP_78.to_json())
    ]
    for spec in specs:
        leaf = Mock(spec=EtcdResult)
        leaf.key = spec[0]
        leaf.value = spec[1]
        leaves.append(leaf)

    result = Mock(spec=EtcdResult)
    result.leaves = iter(leaves)
    return result


def mock_read_0_ep_for_cont(path):
    assert path == TEST_CONT_ENDPOINT_PATH
    leaves = []
    result = Mock(spec=EtcdResult)
    result.leaves = iter(leaves)
    return result
