__author__ = 'sjc'


import unittest
from mock import patch, Mock
from node.adapter.datastore import DatastoreClient, Rule, Profile, Rules
from etcd import Client as EtcdClient


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

