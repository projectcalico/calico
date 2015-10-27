# -*- coding: utf-8 -*-
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
from datetime import datetime
import json
import logging

from etcd import EtcdResult, EtcdException
import etcd
from gevent.event import Event
from mock import Mock, call, patch, ANY

from calico.datamodel_v1 import EndpointId
from calico.felix.config import Config
from calico.felix.futils import IPV4, IPV6
from calico.felix.ipsets import IpsetActor
from calico.felix.fetcd import (_FelixEtcdWatcher, EtcdAPI,
    die_and_restart, EtcdStatusReporter, combine_statuses)
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
        m_config.REPORT_ENDPOINT_STATUS = True
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        endpoint_id = EndpointId("foo", "bar", "baz", "biff")
        with patch.object(api, "status_reporter") as m_status_rep:
            api.force_resync(async=True)
            self.step_actor(api)
        m_status_rep.resync.assert_called_once_with(async=True)
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
        self.m_api = Mock(spec=EtcdAPI)
        self.m_status_rep = Mock(spec=EtcdStatusReporter)
        self.watcher = _FelixEtcdWatcher(self.m_config,
                                         self.m_api,
                                         self.m_status_rep,
                                         self.m_hosts_ipset)
        self.m_splitter = Mock(spec=UpdateSplitter)
        self.watcher.splitter = self.m_splitter
        self.client = Mock()
        self.watcher.client = self.client

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
        self.watcher._been_in_sync = True
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
        self.watcher._been_in_sync = True
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
        self.watcher._been_in_sync = True
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.reset_mock()
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="gibberish")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            [],
            async=True,
        )

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
        self.api._watcher.configured = Mock()

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

    @patch("calico.felix.futils.datetime", autospec=True)
    @patch("calico.felix.fetcd.monotonic_time", return_value=200)
    def test_update_felix_status(self, m_monotime, m_datetime):
        m_datetime.utcnow.return_value = datetime(2015, 9, 10, 2, 1, 53, 1234)
        with patch.object(self.api.client, "set") as m_set:
            self.api._update_felix_status(10)
            self.api._update_felix_status(10)
        # Should write two keys into etcd, one with a TTL and another with
        # richer status.
        self.assertEqual(m_set.mock_calls, [
            call("/calico/felix/v1/host/hostname/last_reported_status",
                 JSONString({"uptime": 100,
                             "time": "2015-09-10T02:01:53Z",
                             "first_update": True})),
            call("/calico/felix/v1/host/hostname/status",
                 JSONString({"uptime": 100,
                             "time": "2015-09-10T02:01:53Z",
                             "first_update": True}), ttl=10),
            call("/calico/felix/v1/host/hostname/last_reported_status",
                 JSONString({"uptime": 100,
                             "time": "2015-09-10T02:01:53Z",
                             "first_update": False})),
            call("/calico/felix/v1/host/hostname/status",
                 JSONString({"uptime": 100,
                             "time": "2015-09-10T02:01:53Z",
                             "first_update": False}), ttl=10),
        ])


class TestEtcdStatusReporter(BaseTestCase):
    def setUp(self):
        super(TestEtcdStatusReporter, self).setUp()
        self.m_config = Mock(spec=Config)
        self.m_config.ETCD_ADDR = ETCD_ADDRESS
        self.m_config.HOSTNAME = "foo"
        self.m_config.REPORT_ENDPOINT_STATUS = True
        self.m_config.ENDPOINT_REPORT_DELAY = 1
        self.m_client = Mock()
        self.rep = EtcdStatusReporter(self.m_config)
        self.rep.client = self.m_client

    def test_on_endpoint_status_mainline(self):
        # Send in an endpoint status update.
        endpoint_id = EndpointId("foo", "bar", "baz", "biff")
        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.rep.on_endpoint_status_changed(endpoint_id, IPV4,
                                                {"status": "up"},
                                                async=True)
            self.step_actor(self.rep)
        # Should record the status.
        self.assertEqual(
            self.rep._endpoint_status[IPV4],
            {
                endpoint_id: {"status": "up"}
            }
        )
        # And do a write.
        self.assertEqual(
            self.m_client.set.mock_calls,
            [call("/calico/felix/v1/host/foo/workload/bar/baz/endpoint/biff",
                  JSONString({"status": "up"}))]
        )
        # Since we did a write, the rate limit timer should be scheduled.
        self.assertEqual(
            m_spawn.mock_calls,
            [call(ANY, self.rep._on_timer_pop, async=True)]
        )
        self.assertTrue(self.rep._timer_scheduled)
        self.assertFalse(self.rep._reporting_allowed)

        # Send in another update, shouldn't get written until we pop the timer.
        self.m_client.reset_mock()
        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.rep.on_endpoint_status_changed(endpoint_id,
                                                IPV4,
                                                None,
                                                async=True)
            self.step_actor(self.rep)
        self.assertFalse(self.m_client.set.called)
        # Timer already scheduled, shouldn't get rescheduled.
        self.assertFalse(m_spawn.called)

        # Pop the timer, should trigger write and reschedule.
        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.rep._on_timer_pop(async=True)
            self.step_actor(self.rep)
        self.maxDiff = 10000
        self.assertEqual(
            self.m_client.delete.mock_calls,
            [
                call("/calico/felix/v1/host/foo/workload/bar/baz/endpoint/"
                     "biff"),
                call("calico/felix/v1/host/foo/workload/bar/baz/endpoint",
                     dir=True, timeout=5),
                call("calico/felix/v1/host/foo/workload/bar/baz",
                     dir=True, timeout=5),
                call("calico/felix/v1/host/foo/workload/bar",
                     dir=True, timeout=5),
                call("calico/felix/v1/host/foo/workload",
                     dir=True, timeout=5),
             ]
        )
        # Rate limit timer should be scheduled.
        self.assertEqual(
            m_spawn.mock_calls,
            [call(ANY, self.rep._on_timer_pop, async=True)]
        )
        spawn_delay = m_spawn.call_args[0][0]
        self.assertTrue(spawn_delay >= 0.89999)
        self.assertTrue(spawn_delay <= 1.10001)

        self.assertTrue(self.rep._timer_scheduled)
        self.assertFalse(self.rep._reporting_allowed)
        # Cache should be cleaned up.
        self.assertEqual(self.rep._endpoint_status[IPV4], {})
        # Nothing queued.
        self.assertEqual(self.rep._newer_dirty_endpoints, set())
        self.assertEqual(self.rep._older_dirty_endpoints, set())

    def test_on_endpoint_status_failure(self):
        # Send in an endpoint status update.
        endpoint_id = EndpointId("foo", "bar", "baz", "biff")
        self.m_client.set.side_effect = EtcdException()
        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.rep.on_endpoint_status_changed(endpoint_id,
                                                IPV4,
                                                {"status": "up"},
                                                async=True)
            self.step_actor(self.rep)
        # Should do the write.
        self.assertEqual(
            self.m_client.set.mock_calls,
            [call("/calico/felix/v1/host/foo/workload/bar/baz/endpoint/biff",
                  JSONString({"status": "up"}))]
        )
        # But endpoint should be re-queued in the newer set.
        self.assertEqual(self.rep._newer_dirty_endpoints, set([endpoint_id]))
        self.assertEqual(self.rep._older_dirty_endpoints, set())

    def test_on_endpoint_status_changed_disabled(self):
        self.m_config.REPORT_ENDPOINT_STATUS = False
        endpoint_id = EndpointId("foo", "bar", "baz", "biff")

        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.rep.on_endpoint_status_changed(endpoint_id,
                                                IPV4,
                                                {"status": "up"},
                                                async=True)
            self.step_actor(self.rep)
        self.assertFalse(m_spawn.called)
        self.assertEqual(self.rep._endpoint_status[IPV4], {})
        # Nothing queued.
        self.assertEqual(self.rep._newer_dirty_endpoints, set())
        self.assertEqual(self.rep._older_dirty_endpoints, set())

    def test_on_endpoint_status_v4_v6(self):
        # Send in endpoint status updates for v4 and v6.
        endpoint_id = EndpointId("foo", "bar", "baz", "biff")
        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.rep.on_endpoint_status_changed(endpoint_id, IPV4,
                                                {"status": "up"},
                                                async=True)
            self.rep.on_endpoint_status_changed(endpoint_id, IPV6,
                                                {"status": "down"},
                                                async=True)
            self.step_actor(self.rep)
        # Should record the status.
        self.assertEqual(
            self.rep._endpoint_status,
            {
                IPV4: {endpoint_id: {"status": "up"}},
                IPV6: {endpoint_id: {"status": "down"}},
            }
        )
        # And do a write.
        self.assertEqual(
            self.m_client.set.mock_calls,
            [call("/calico/felix/v1/host/foo/workload/bar/baz/endpoint/biff",
                  JSONString({"status": "down"}))]
        )

    def test_resync(self):
        endpoint_id = EndpointId("foo", "bar", "baz", "biff")
        self.rep.on_endpoint_status_changed(endpoint_id, IPV4, {"status": "up"}, async=True)
        endpoint_id_2 = EndpointId("foo", "bar", "baz", "boff")
        self.rep.on_endpoint_status_changed(endpoint_id_2, IPV6, {"status": "up"}, async=True)
        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.step_actor(self.rep)
            self.rep._on_timer_pop(async=True)
            self.step_actor(self.rep)
        self.assertEqual(self.rep._older_dirty_endpoints, set())
        self.assertEqual(self.rep._newer_dirty_endpoints, set())

        self.rep.resync(async=True)
        self.step_actor(self.rep)

        self.assertEqual(self.rep._older_dirty_endpoints, set())
        self.assertEqual(self.rep._newer_dirty_endpoints, set([endpoint_id, endpoint_id_2]))

    def test_combine_statuses(self):
        """
        Test the "truth table" for combining status reports.
        """
        self.assert_combined_status(None, None, None)
        self.assert_combined_status({"status": "up"}, None, {"status": "up"})
        self.assert_combined_status({"status": "up"}, {"status": "up"},
                                    {"status": "up"})
        self.assert_combined_status({"status": "down"}, {"status": "up"},
                                    {"status": "down"})
        self.assert_combined_status({"status": "error"}, {"status": "up"},
                                    {"status": "error"})

    def assert_combined_status(self, a, b, expected):
        # Should be symmetric so check the arguments both ways round.
        for lhs, rhs in [(a, b), (b, a)]:
            result = combine_statuses(lhs, rhs)
            self.assertEqual(result, expected,
                             "Expected %r and %r to combine to %s but got %r" %
                             (lhs, rhs, expected, result))

    def test_clean_up_endpoint_status(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        ep_id = EndpointId("foo",
                           "openstack",
                           "workloadid",
                           "endpointid")

        empty_dir = Mock()
        empty_dir.key = ("/calico/felix/v1/host/foo/workload/"
                         "openstack/foobar")
        empty_dir.dir = True

        missing_ep = Mock()
        missing_ep.key = ("/calico/felix/v1/host/foo/workload/"
                          "openstack/aworkload/endpoint/anendpoint")

        self.m_client.read.return_value.leaves = [
            empty_dir,
            missing_ep,
        ]
        with patch.object(self.rep, "_mark_endpoint_dirty") as m_mark:
            self.rep.clean_up_endpoint_statuses(async=True)
            self.step_actor(self.rep)

            # Missing endpoint should have been marked for cleanup.
            m_mark.assert_called_once_with(
                EndpointId("foo",
                           "openstack",
                           "aworkload",
                           "anendpoint")
            )

    def test_clean_up_endpoint_status_not_found(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        self.m_client.read.side_effect = etcd.EtcdKeyNotFound()
        with patch.object(self.rep, "_mark_endpoint_dirty") as m_mark:
            self.rep.clean_up_endpoint_statuses(async=True)
            self.step_actor(self.rep)
            self.assertFalse(m_mark.called)

    def test_clean_up_endpoint_status_disabled(self):
        self.m_config.REPORT_ENDPOINT_STATUS = False
        self.m_client.read.side_effect = self.failureException
        self.rep.clean_up_endpoint_statuses(async=True)
        self.step_actor(self.rep)

