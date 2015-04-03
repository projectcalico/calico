__author__ = 'sjc'


import unittest
from mock import patch, Mock
from node.adapter.datastore import DatastoreClient, Rule, Profile, Rules
from etcd import Client as EtcdClient
from netaddr import IPNetwork
import json


class TestRule(unittest.TestCase):

    def test_create(self):
        rule1 = Rule(action="allow",
                     src_tag="TEST",
                     src_ports=[300, 400])
        self.assertDictEqual({"action": "allow",
                              "src_tag": "TEST",
                              "src_ports": [300, 400]}, rule1)

    def test_to_json(self):
        rule1 = Rule(action="deny",
                     dst_net=IPNetwork("192.168.13.0/24"))
        json_str = rule1.to_json()
        expected = json.dumps({"action": "deny",
                               "dst_net": "192.168.13.0/24"})
        self.assertEqual(json_str, expected)

        rule2 = Rule(action="deny",
                     src_net="192.168.13.0/24")
        json_str = rule2.to_json()
        expected = json.dumps({"action": "deny",
                               "src_net": "192.168.13.0/24"})
        self.assertEqual(json_str, expected)

    def test_wrong_keys(self):
        try:
            Rule(action="deny", dst_nets="192.168.13.0/24")
        except KeyError:
            pass
        else:
            self.assertTrue(False, "Should raise key error.")

    def test_pprint(self):
        rule1 = Rule(action="allow",
                     src_tag="TEST",
                     src_ports=[300, 400])
        self.assertEqual("allow from tag TEST ports [300, 400]",
                         rule1.pprint())

        rule2 = Rule(action="allow",
                     dst_tag="TEST",
                     dst_ports=[300, 400],
                     protocol="udp")
        self.assertEqual("allow udp to tag TEST ports [300, 400]",
                         rule2.pprint())

        rule3 = Rule(action="deny",
                     src_net=IPNetwork("fd80::4:0/112"),
                     dst_ports=[80])
        self.assertEqual("deny from fd80::4:0/112 to ports [80]",
                         rule3.pprint())

        rule4 = Rule(action="allow",
                     protocol="icmp",
                     icmp_type=8,
                     src_net=IPNetwork("10/8"))
        self.assertEqual("allow icmp type 8 from 10.0.0.0/8",
                         rule4.pprint())


class TestDatastoreClient(unittest.TestCase):

    @patch("node.adapter.datastore.os.getenv", autospec=True)
    @patch("node.adapter.datastore.etcd.Client", autospec=True)
    def setUp(self, m_etcd_client, m_getenv):
        m_getenv.return_value = "127.0.0.2:4002"
        self.etcd_client = Mock(spec=EtcdClient)
        m_etcd_client.return_value = self.etcd_client
        self.datastore = DatastoreClient()
        m_etcd_client.assert_called_once_with(host="127.0.0.2", port=4002)

    def test_get_profile(self):

        def mock_read(path):
            result = Mock()
            if path == "/calico/policy/profile/TEST/":
                return result
            elif path == "/calico/policy/profile/TEST/tags":
                result.value = '["TAG1", "TAG2", "TAG3"]'
                return result
            elif path == "/calico/policy/profile/TEST/rules":
                result.value = """
{
  "id": "TEST",
  "inbound_rules": [],
  "outbound_rules": [
    {"action": "allow", "src_tag": "TEST", "src_ports": [200,2001]}
  ]
}
"""
                return result
            else:
                raise KeyError()
        self.etcd_client.read.side_effect = mock_read

        profile = self.datastore.get_profile("TEST")
        self.assertEqual(profile.name, "TEST")
        self.assertSetEqual({"TAG1", "TAG2", "TAG3"}, profile.tags)
        self.assertEqual([], profile.rules.inbound_rules)
        rule = Rule(action="allow",
                    src_tag="TEST",
                    src_ports=[200,2001])
        self.assertEqual(rule, profile.rules.outbound_rules[0])

        self.assertRaises(KeyError, self.datastore.get_profile, "TEST2")

    def test_profile_update_tags(self):

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
            "/calico/policy/profile/TEST/tags",
            '["TAG4", "TAG5"]')

    def test_profile_update_rules(self):

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
            "/calico/policy/profile/TEST/rules",
            profile.rules.to_json())

