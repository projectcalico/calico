# Copyright (c) Metaswitch Networks 2015. All rights reserved.
import json

import logging
from etcd import EtcdResult
from mock import Mock, call
from calico.datamodel_v1 import EndpointId
from calico.felix.ipsets import IpsetActor
from calico.felix.fetcd import _EtcdWatcher, ResyncRequired
from calico.felix.splitter import UpdateSplitter
from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


VALID_ENDPOINT = {
    "state": "active",
    "name": "tap1234",
    "mac": "aa:bb:cc:dd:ee:ff",
    "profile_ids": ["prof1"],
    "ipv4_nets": [
        "10.0.0.1/32",
    ],
    "ipv6_nets": [
        "dead::beef/128"
    ]
}
ENDPOINT_STR = json.dumps(VALID_ENDPOINT)

RULES = {
    "inbound_rules": [],
    "outbound_rules": [],
}
RULES_STR = json.dumps(RULES)

TAGS = ["a", "b"]
TAGS_STR = json.dumps(TAGS)


class TestExcdWatcher(BaseTestCase):

    def setUp(self):
        super(TestExcdWatcher, self).setUp()
        self.m_config = Mock()
        self.m_config.IFACE_PREFIX = "tap"
        self.m_hosts_ipset = Mock(spec=IpsetActor)
        self.watcher = _EtcdWatcher(self.m_config, self.m_hosts_ipset)
        self.m_splitter = Mock(spec=UpdateSplitter)
        self.watcher.splitter = self.m_splitter

    def test_ready_flag_set(self):
        self.dispatch("/calico/v1/Ready", "set", value="true")
        self.assertRaises(ResyncRequired, self.dispatch,
                          "/calico/v1/Ready", "set", value="false")
        self.assertRaises(ResyncRequired, self.dispatch,
                          "/calico/v1/Ready", "set", value="foo")

    def test_endpoint_set(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value=ENDPOINT_STR)
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            VALID_ENDPOINT,
            async=True,
        )

    def test_endpoint_set_bad_json(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value="{")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            None,
            async=True,
        )

    def test_endpoint_set_invalid(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value="{}")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            None,
            async=True,
        )

    def test_parent_dir_delete(self):
        """
        Test that deletions of parent directories of endpoints are
        correctly handled.
        """
        # This additional  endpoint should be ignored by the deletes below.
        self.dispatch("/calico/v1/host/h2/workload/o1/w2/endpoint/e2",
                      "set", value=ENDPOINT_STR)
        for path in ["/calico/v1/host/h1",
                     "/calico/v1/host/h1/workload",
                     "/calico/v1/host/h1/workload/o1",
                     "/calico/v1/host/h1/workload/o1/w1",
                     "/calico/v1/host/h1/workload/o1/w1/endpoint"]:
            # Create endpoints in the cache.
            self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                          "set", value=ENDPOINT_STR)
            self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e2",
                          "set", value=ENDPOINT_STR)
            # This endpoint should not get cleaned up if only workload w1 is
            # deleted...
            self.dispatch("/calico/v1/host/h1/workload/o1/w3/endpoint/e3",
                          "set", value=ENDPOINT_STR)

            self.assertEqual(self.watcher.endpoint_ids_per_host, {
                "h1": set([EndpointId("h1", "o1", "w1", "e1"),
                           EndpointId("h1", "o1", "w1", "e2"),
                           EndpointId("h1", "o1", "w3", "e3")]),
                "h2": set([EndpointId("h2", "o1", "w2", "e2")]),
            })
            self.m_splitter.on_endpoint_update.reset_mock()
            # Delete one of its parent dirs, should delete the endpoint.
            self.dispatch(path, "delete")
            exp_calls = [
                call(EndpointId("h1", "o1", "w1", "e1"), None, async=True),
                call(EndpointId("h1", "o1", "w1", "e2"), None, async=True),
            ]
            if path < "/calico/v1/host/h1/workload/o1/w1":
                # Should also delete workload w3.
                exp_calls.append(call(EndpointId("h1", "o1", "w3", "e3"),
                                      None, async=True))
            self.m_splitter.on_endpoint_update.assert_has_calls(exp_calls,
                                                                any_order=True)
            # Cache should be cleaned up.
            exp_cache = {"h2": set([EndpointId("h2", "o1", "w2", "e2")])}
            if path >= "/calico/v1/host/h1/workload/o1/w1":
                # Should not have deleted workload w3.  Add it in.
                exp_cache["h1"] = set([EndpointId("h1", "o1", "w3", "e3")])
            self.assertEqual(self.watcher.endpoint_ids_per_host, exp_cache)

            # Then simulate another delete, should have no effect.
            self.m_splitter.on_endpoint_update.reset_mock()
            self.dispatch(path, "delete")
            self.assertFalse(self.m_splitter.on_endpoint_update.called)

    def test_rules_set(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value=RULES_STR)
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                RULES,
                                                                async=True)

    def test_rules_set_bad_json(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value="{")
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                None,
                                                                async=True)

    def test_rules_set_invalid(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value='{}')
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                None,
                                                                async=True)

    def test_tags_set(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value=TAGS_STR)
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               TAGS,
                                                               async=True)

    def test_tags_set_bad_json(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value="{")
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               None,
                                                               async=True)

    def test_tags_set_invalid(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value="[{}]")
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               None,
                                                               async=True)

    def test_dispatch_delete_resync(self):
        """
        Test dispatcher is correctly configured to trigger resync for
        expected paths.
        """
        for key in ["/calico/v1",
                    "/calico/v1/host",
                    "/calico/v1/policy",
                    "/calico/v1/policy/profile",
                    "/calico/v1/config",
                    "/calico/v1/Ready",]:
            self.assertRaises(ResyncRequired, self.dispatch, key, "delete")

    def test_per_profile_del(self):
        """
        Test profile deletion triggers dleetion for tags and rules.
        """
        self.dispatch("/calico/v1/policy/profile/profA", action="delete")
        self.m_splitter.on_tags_update.assert_called_once_with("profA", None,
                                                               async=True)
        self.m_splitter.on_rules_update.assert_called_once_with("profA", None,
                                                                async=True)

    def test_tags_del(self):
        """
        Test tag-only deletion.
        """
        self.dispatch("/calico/v1/policy/profile/profA/tags", action="delete")
        self.m_splitter.on_tags_update.assert_called_once_with("profA", None,
                                                               async=True)
        self.assertFalse(self.m_splitter.on_rules_update.called)

    def test_rules_del(self):
        """
        Test rules-only deletion.
        """
        self.dispatch("/calico/v1/policy/profile/profA/rules", action="delete")
        self.m_splitter.on_rules_update.assert_called_once_with("profA", None,
                                                                async=True)
        self.assertFalse(self.m_splitter.on_tags_update.called)

    def test_endpoint_del(self):
        """
        Test endpoint-only deletion.
        """
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      action="delete")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            None,
            async=True,
        )

    def test_host_ip_set(self):
        """
        Test set for the IP of a host.
        """
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            ["10.0.0.1"],
            async=True,
        )

    def test_host_ip_ipip_disabled(self):
        """
        Test set for the IP of a host.
        """
        self.m_config.IP_IN_IP_ENABLED = False
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.assertFalse(self.m_hosts_ipset.replace_members.called)
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="delete")
        self.assertFalse(self.m_hosts_ipset.replace_members.called)

    def test_host_ip_del(self):
        """
        Test set for the IP of a host.
        """
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.reset_mock()
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="delete")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            [],
            async=True,
        )

    def test_host_ip_invalid(self):
        """
        Test set for the IP of a host.
        """
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.reset_mock()
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="gibberish")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            [],
            async=True,
        )

    def test_host_del_clears_ip(self):
        """
        Test set for the IP of a host.
        """
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.reset_mock()
        self.dispatch("/calico/v1/host/foo",
                      action="delete")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            [],
            async=True,
        )

    def dispatch(self, key, action, value=None):
        """
        Send an EtcdResult to the watcher's dispatcher.
        """
        m_response = Mock(spec=EtcdResult)
        m_response.key = key
        m_response.action = action
        m_response.value = value
        self.watcher.dispatcher.handle_event(m_response)
