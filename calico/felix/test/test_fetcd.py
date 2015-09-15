# Copyright (c) Metaswitch Networks 2015. All rights reserved.
from datetime import datetime
import json
import logging

from etcd import EtcdResult, EtcdException
import etcd
from gevent.event import Event
from mock import Mock, call, patch, ANY

from calico.datamodel_v1 import EndpointId
from calico.felix.config import Config
from calico.felix.ipsets import IpsetActor
from calico.felix.fetcd import (_FelixEtcdWatcher, ResyncRequired, EtcdAPI,
    die_and_restart)
from calico.felix.splitter import UpdateSplitter
from calico.felix.test.base import BaseTestCase, JSONString

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

ETCD_ADDRESS = 'localhost:4001'


class TestEtcdAPI(BaseTestCase):

    @patch("calico.felix.fetcd._FelixEtcdWatcher", autospec=True)
    @patch("gevent.spawn", autospec=True)
    def test_create(self, m_spawn, m_etcd_watcher):
        m_config = Mock(spec=Config)
        m_config.ETCD_ADDR = ETCD_ADDRESS
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        m_etcd_watcher.assert_has_calls([
            call(m_config, m_hosts_ipset).link(api._on_worker_died),
            call(m_config, m_hosts_ipset).start(),
        ])
        m_spawn.assert_has_calls([
            call(api._periodically_resync),
            call(api._periodically_resync).link_exception(api._on_worker_died)
        ])

    @patch("calico.felix.fetcd._FelixEtcdWatcher", autospec=True)
    @patch("gevent.spawn", autospec=True)
    @patch("gevent.sleep", autospec=True)
    def test_periodic_resync_mainline(self, m_sleep, m_spawn, m_etcd_watcher):
        m_configured = Mock(spec=Event)
        m_etcd_watcher.return_value.configured = m_configured
        m_config = Mock(spec=Config)
        m_config.ETCD_ADDR = ETCD_ADDRESS
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        m_config.RESYNC_INTERVAL = 10
        with patch.object(api, "force_resync") as m_force_resync:
            m_force_resync.side_effect = ExpectedException()
            self.assertRaises(ExpectedException, api._periodically_resync)
        m_configured.wait.assert_called_once_with()
        m_sleep.assert_called_once_with(ANY)
        sleep_time = m_sleep.call_args[0][0]
        self.assertTrue(sleep_time >= 10)
        self.assertTrue(sleep_time <= 12)

    @patch("calico.felix.fetcd._FelixEtcdWatcher", autospec=True)
    @patch("gevent.spawn", autospec=True)
    @patch("gevent.sleep", autospec=True)
    def test_periodic_resync_disabled(self, m_sleep, m_spawn, m_etcd_watcher):
        m_etcd_watcher.return_value.configured = Mock(spec=Event)
        m_config = Mock(spec=Config)
        m_config.ETCD_ADDR = ETCD_ADDRESS
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        m_config.RESYNC_INTERVAL = 0
        with patch.object(api, "force_resync") as m_force_resync:
            m_force_resync.side_effect = Exception()
            api._periodically_resync()

    @patch("calico.felix.fetcd._FelixEtcdWatcher", autospec=True)
    @patch("gevent.spawn", autospec=True)
    def test_force_resync(self, m_spawn, m_etcd_watcher):
        m_config = Mock(spec=Config)
        m_config.ETCD_ADDR = ETCD_ADDRESS
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        api.force_resync(async=True)
        self.step_actor(api)
        self.assertTrue(m_etcd_watcher.return_value.resync_after_current_poll)


class ExpectedException(Exception):
    pass


class TestEtcdWatcher(BaseTestCase):

    def setUp(self):
        super(TestEtcdWatcher, self).setUp()
        self.m_config = Mock()
        self.m_config.HOSTNAME = "hostname"
        self.m_config.IFACE_PREFIX = "tap"
        self.m_config.ETCD_ADDR = ETCD_ADDRESS
        self.m_hosts_ipset = Mock(spec=IpsetActor)
        self.watcher = _FelixEtcdWatcher(self.m_config, self.m_hosts_ipset)
        self.m_splitter = Mock(spec=UpdateSplitter)
        self.watcher.splitter = self.m_splitter
        self.client = Mock(spec=etcd.Client)
        self.watcher.client = self.client

    @patch("gevent.sleep", autospec=True)
    @patch("calico.felix.fetcd._build_config_dict", autospec=True)
    @patch("calico.felix.fetcd.die_and_restart", autospec=True)
    def test_load_config(self, m_die, m_build_dict, m_sleep):
        # First call, loads the config.
        global_cfg = {"foo": "bar"}
        m_build_dict.side_effect = iter([
            # First call, global-only.
            global_cfg,
            # Second call, no change.
            global_cfg,
            # Third call, change of config.
            {"foo": "baz"}, {"biff": "bop"}])
        self.client.read.side_effect = iter([
            # First time round the loop, fail to read global config, should
            # retry.
            etcd.EtcdKeyNotFound,
            # Then get the global config but there's not host-only config.
            None, etcd.EtcdKeyNotFound,
            # Twice...
            None, etcd.EtcdKeyNotFound,
            # Then some host-only config shows up.
            None, None])

        # First call.
        self.watcher._load_config()

        m_sleep.assert_called_once_with(5)
        self.assertFalse(m_die.called)

        m_report = self.m_config.report_etcd_config
        rpd_host_cfg, rpd_global_cfg = m_report.mock_calls[0][1]
        self.assertEqual(rpd_host_cfg, {})
        self.assertEqual(rpd_global_cfg, global_cfg)
        self.assertTrue(rpd_host_cfg is not self.watcher.last_host_config)
        self.assertTrue(rpd_global_cfg is not self.watcher.last_global_config)
        self.assertEqual(rpd_host_cfg, self.watcher.last_host_config)
        self.assertEqual(rpd_global_cfg, self.watcher.last_global_config)

        self.assertEqual(self.watcher.last_host_config, {})
        self.assertEqual(self.watcher.last_global_config, global_cfg)
        self.watcher.configured.set()  # Normally done by the caller.
        self.client.read.assert_has_calls([
            call("/calico/v1/config", recursive=True),
            call("/calico/v1/host/hostname/config", recursive=True),
        ])

        # Second call, no change.
        self.watcher._load_config()
        self.assertFalse(m_die.called)

        # Third call, should detect the config change and die.
        self.watcher._load_config()
        m_die.assert_called_once_with()

    def test_resync_flag(self):
        self.watcher.resync_after_current_poll = True
        self.watcher.next_etcd_index = 1
        self.assertRaises(ResyncRequired,
                          self.watcher.wait_for_etcd_event)
        self.assertFalse(self.watcher.resync_after_current_poll)

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
                    "/calico/v1/config/Foo",
                    "/calico/v1/Ready",]:
            self.assertRaises(ResyncRequired, self.dispatch, key, "delete")

    def test_per_profile_del(self):
        """
        Test profile deletion triggers deletion for tags and rules.
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

    def test_config_update_triggers_resync(self):
        self.assertRaises(ResyncRequired, self.dispatch,
                          "/calico/v1/config/Foo", "set", "bar")
        self.assertRaises(ResyncRequired, self.dispatch,
                          "/calico/v1/host/foo/config/Foo", "set", "bar")

    @patch("os._exit", autospec=True)
    @patch("gevent.sleep", autospec=True)
    def test_die_and_restart(self, m_sleep, m_exit):
        die_and_restart()
        m_sleep.assert_called_once_with(2)
        m_exit.assert_called_once_with(1)

    def dispatch(self, key, action, value=None):
        """
        Send an EtcdResult to the watcher's dispatcher.
        """
        m_response = Mock(spec=EtcdResult)
        m_response.key = key
        m_response.action = action
        m_response.value = value
        self.watcher.dispatcher.handle_event(m_response)


class TestEtcdReporting(BaseTestCase):
    def setUp(self):
        super(TestEtcdReporting, self).setUp()
        self.m_config = Mock()
        self.m_config.IFACE_PREFIX = "tap"
        self.m_config.ETCD_ADDR = "localhost:4001"
        self.m_config.HOSTNAME = "hostname"
        self.m_config.RESYNC_INTERVAL = 0
        self.m_config.REPORTING_INTERVAL_SECS = 1
        self.m_config.REPORTING_TTL_SECS = 10
        self.m_hosts_ipset = Mock(spec=IpsetActor)
        with patch("gevent.spawn", autospec=True):
            with patch("calico.felix.fetcd._FelixEtcdWatcher", autospec=True):
                with patch("calico.felix.fetcd.monotonic_time",
                           return_value=100):
                    self.api = EtcdAPI(self.m_config, self.m_hosts_ipset)

    @patch("gevent.sleep", autospec=True)
    def test_reporting_loop_mainline(self, m_sleep):
        """
        Test the mainline function of the status reporting loop.

        It should repeatedly call the _update_felix_status method,
        retrying on various exceptions.
        """
        with patch.object(self.api, "_update_felix_status") as m_update:
            m_update.side_effect = [EtcdException, None, RuntimeError]
            self.assertRaises(RuntimeError,
                              self.api._periodically_report_status)
        self.assertEqual(m_update.mock_calls,
                         [call(10)] * 3)

        retry_call, jittered_call = m_sleep.mock_calls
        self.assertEqual(retry_call, call(5))
        _, (delay,), _ = jittered_call
        self.assertTrue(delay >= 1)
        self.assertTrue(delay <= 1.1005)

    def test_reporting_loop_disabled(self):
        self.m_config.REPORTING_INTERVAL_SECS = 0
        with patch.object(self.api, "_update_felix_status") as m_update:
            m_update.side_effect = RuntimeError
            self.api._periodically_report_status()

    @patch("datetime.datetime", autospec=True)
    @patch("calico.felix.fetcd.monotonic_time", return_value=200)
    def test_update_felix_status(self, m_monotime, m_datetime):
        m_datetime.utcnow.return_value = datetime(2015, 9, 10, 2, 1, 53, 1234)
        with patch.object(self.api.client, "set") as m_set:
            self.api._update_felix_status(10)
        # Should write two keys into etcd, one with a TTL and another with
        # richer status.
        self.assertEqual(m_set.mock_calls, [
            call("/calico/felix/v1/host/hostname/last_reported_status",
                 JSONString({"uptime": 100, "time": "2015-09-10T02:01:53Z"})),
            call("/calico/felix/v1/host/hostname/uptime", '100', ttl=10),
        ])


