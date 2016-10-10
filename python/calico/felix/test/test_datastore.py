# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
import logging
import socket
import subprocess
from datetime import datetime

import gevent
from calico.datamodel_v1 import WloadEndpointId, TieredPolicyId, HostEndpointId
from calico.felix.config import Config
from calico.felix.datastore import (DatastoreReader, DatastoreAPI,
                                    die_and_restart, DatastoreWriter, combine_statuses)
from calico.felix.futils import IPV4, IPV6
from calico.felix.ipsets import IpsetActor
from calico.felix.protocol import MessageReader, MessageWriter, \
    MSG_TYPE_CONFIG_UPDATE, MSG_TYPE_IN_SYNC, \
    MSG_KEY_TYPE, \
    MSG_KEY_HOST_CONFIG, MSG_KEY_GLOBAL_CONFIG, MSG_TYPE_CONFIG_RESOLVED, \
    MSG_KEY_LOG_FILE, MSG_KEY_SEV_FILE, MSG_KEY_SEV_SCREEN, MSG_KEY_SEV_SYSLOG, \
    SocketClosed, MSG_KEY_PROM_PORT
from calico.felix.splitter import UpdateSplitter
from calico.felix.test.base import BaseTestCase, JSONString
from gevent.event import Event
from mock import Mock, call, patch, ANY
from unittest2 import skip

_log = logging.getLogger(__name__)

patch.object = getattr(patch, "object")  # Keep PyCharm linter happy.

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

VALID_HOST_ENDPOINT = {
    "name": "tap1234",
    "profile_ids": ["prof1"],
    "expected_ipv4_addrs": [
        "10.0.0.1",
    ],
    "expected_ipv6_addrs": [
        "dead::beef",
    ]
}
HOST_ENDPOINT_STR = json.dumps(VALID_HOST_ENDPOINT)

RULES = {
    "inbound_rules": [],
    "outbound_rules": [],
}
RULES_STR = json.dumps(RULES)

TAGS = ["a", "b"]
TAGS_STR = json.dumps(TAGS)

ETCD_ADDRESS = 'localhost:4001'

POLICY_ID = TieredPolicyId("tiername", "polname")
POLICY = {
    "selector": "a == 'b'",
    "inbound_rules": [],
    "outbound_rules": [],
    "order": 10,
}
POLICY_PARSED = {
    "inbound_rules": [],
    "outbound_rules": [],
}
POLICY_STR = json.dumps(POLICY)


@skip("golang rewrite")
class TestDatastoreAPI(BaseTestCase):
    def setUp(self):
        super(TestDatastoreAPI, self).setUp()
        self.m_config = Mock(spec=Config)
        self.m_config.ETCD_ADDRS = [ETCD_ADDRESS]
        self.m_config.ETCD_SCHEME = "http"
        self.m_config.ETCD_KEY_FILE = None
        self.m_config.ETCD_CERT_FILE = None
        self.m_config.ETCD_CA_FILE = None
        self.m_config.USAGE_REPORT = False
        self.m_hosts_ipset = Mock(spec=IpsetActor)
        with patch("calico.felix.datastore.DatastoreReader",
                   autospec=True) as m_etcd_watcher:
            with patch("gevent.spawn", autospec=True) as m_spawn:
                self.api = DatastoreAPI(self.m_config, self.m_hosts_ipset)
        self.m_spawn = m_spawn
        self.m_etcd_watcher = m_etcd_watcher.return_value
        self.m_etcd_watcher.load_config = Mock(spec=Event)
        self.m_etcd_watcher.begin_polling = Mock(spec=Event)
        self.m_etcd_watcher.configured = Mock(spec=Event)

    def test_create(self):
        self.m_etcd_watcher.assert_has_calls([
            call.link(self.api._on_worker_died),
        ])
        self.assertFalse(self.m_spawn.called)

    def test_on_start(self):
        with patch.object(self.api._resync_greenlet, "start") as m_resync_st, \
                patch.object(self.api._status_reporting_greenlet, "start") as m_stat_start, \
                patch.object(self.api.status_reporter, "start") as m_sr_start:
            self.api._on_actor_started()
        m_resync_st.assert_called_once_with()
        m_stat_start.assert_called_once_with()
        m_sr_start.assert_called_once_with()
        self.m_etcd_watcher.start.assert_called_once_with()

    def test_load_config(self):
        result = self.api.load_config(async=True)
        self.step_actor(self.api)
        conf = result.get()
        self.assertEqual(conf, self.m_etcd_watcher.configured)
        self.m_etcd_watcher.load_config.set.assert_called_once_with()

    def test_start_watch(self):
        m_splitter = Mock()
        self.api.load_config(async=True)
        result = self.api.start_watch(m_splitter, async=True)
        self.step_actor(self.api)
        self.m_etcd_watcher.load_config.set.assert_called_once_with()
        self.assertEqual(self.m_etcd_watcher.splitter, m_splitter)
        self.m_etcd_watcher.begin_polling.set.assert_called_once_with()

    @patch("sys.exit", autospec=True)
    def test_on_worker_died(self, m_exit):
        glet = gevent.spawn(lambda: None)
        glet.link(self.api._on_worker_died)
        glet.join(1)
        m_exit.assert_called_once_with(1)


class ExpectedException(Exception):
    pass


@skip("golang rewrite")
class TestEtcdWatcher(BaseTestCase):

    def setUp(self):
        super(TestEtcdWatcher, self).setUp()
        self.m_config = Mock()
        self.m_config.HOSTNAME = "hostname"
        self.m_config.IFACE_PREFIX = ["tap"]
        self.m_config.ETCD_ADDRS = [ETCD_ADDRESS]
        self.m_config.ETCD_SCHEME = "http"
        self.m_config.ETCD_KEY_FILE = None
        self.m_config.ETCD_CERT_FILE = None
        self.m_config.ETCD_CA_FILE = None
        self.m_config.USAGE_REPORT = False
        self.m_hosts_ipset = Mock(spec=IpsetActor)
        self.m_api = Mock(spec=DatastoreAPI)
        self.m_status_rep = Mock(spec=DatastoreWriter)
        self.watcher = DatastoreReader(self.m_config,
                                         self.m_api,
                                         self.m_status_rep,
                                         self.m_hosts_ipset)
        self.m_splitter = Mock(spec=UpdateSplitter)
        self.watcher.splitter = self.m_splitter
        self.m_reader = Mock(spec=MessageReader)
        self.m_writer = Mock(spec=MessageWriter)
        self.watcher._msg_reader = self.m_reader
        self.watcher._msg_writer = self.m_writer
        self.m_driver_proc = Mock(spec=subprocess.Popen)
        self.watcher._driver_process = self.m_driver_proc

    def test_run(self):
        with patch.object(self.watcher.load_config, "wait") as m_wait:
            with patch.object(self.watcher, "_start_driver") as m_start:
                m_reader = Mock()
                m_writer = Mock()
                m_start.return_value = (m_reader, m_writer)
                m_reader.new_messages.side_effect = ExpectedException()
                self.assertRaises(ExpectedException, self.watcher._run)
        self.assertEqual(m_wait.mock_calls, [call()])

    @patch("calico.felix.datastore.die_and_restart", autospec=True)
    def test_read_loop(self, m_die):
        self.m_reader.new_messages.side_effect = iter([
            iter([]),
            iter([(MSG_TYPE_IN_SYNC, {MSG_KEY_STATUS: STATUS_RESYNC})])
        ])
        self.m_driver_proc.poll.side_effect = iter([
            None, 1
        ])
        m_die.side_effect = ExpectedException()
        with patch.object(self.watcher, "_dispatch_msg_from_driver") as m_disp:
            self.assertRaises(ExpectedException,
                              self.watcher._loop_reading_from_driver)
        self.assertEqual(m_disp.mock_calls,
                         [call(MSG_TYPE_IN_SYNC,
                               {MSG_KEY_STATUS: STATUS_RESYNC})])

    @patch("calico.felix.datastore.die_and_restart", autospec=True)
    def test_read_loop_socket_error(self, m_die):
        self.m_reader.new_messages.side_effect = SocketClosed()
        m_die.side_effect = ExpectedException
        self.assertRaises(ExpectedException,
                          self.watcher._loop_reading_from_driver)
        self.assertEqual(m_die.mock_calls, [call()])

    @patch("calico.felix.datastore.die_and_restart", autospec=True)
    def test_read_loop_resync(self, m_die):
        self.m_reader.new_messages.side_effect = iter([iter([]), iter([])])
        self.m_driver_proc.poll.side_effect = iter([None, 1])
        self.watcher.resync_requested = True
        m_die.side_effect = ExpectedException()
        self.assertRaises(ExpectedException,
                          self.watcher._loop_reading_from_driver)

    def test_dispatch_from_driver(self):
        for msg_type, expected_method in [
                (MSG_TYPE_UPDATE, "_on_update_from_driver"),
                (MSG_TYPE_CONFIG_UPDATE, "_on_config_loaded_from_driver"),
                (MSG_TYPE_IN_SYNC, "_on_status_from_driver"),]:
            with patch.object(self.watcher, expected_method) as m_meth:
                msg = Mock()
                self.watcher._dispatch_msg_from_driver(msg_type, msg)
                self.assertEqual(m_meth.mock_calls, [call(msg)])

    def test_dispatch_from_driver_unexpected(self):
        self.assertRaises(RuntimeError,
                          self.watcher._dispatch_msg_from_driver,
                          "unknown", {})

    @patch("gevent.sleep")
    def test_dispatch_yield(self, m_sleep):
        for _ in xrange(399):
            with patch.object(self.watcher, "_on_update_from_driver") as m_upd:
                msg = Mock()
                self.watcher._dispatch_msg_from_driver(MSG_TYPE_UPDATE, msg)
        self.assertEqual(m_sleep.mock_calls, [call(0.000001)])

    def test_on_update_from_driver(self):
        self.watcher.read_count = 999
        self.watcher.configured.set()
        with patch.object(self.watcher, "begin_polling") as m_begin:
            self.watcher._on_update_from_driver({
                MSG_KEY_TYPE: MSG_TYPE_UPDATE,
                MSG_KEY_KEY: "/calico/v1/Ready",
                MSG_KEY_VALUE: "true",
            })
        m_begin.wait.assert_called_once_with()

    @patch("calico.felix.datastore.die_and_restart", autospec=True)
    def test_on_config_loaded(self, m_die):
        self.m_config.DRIVERLOGFILE = "/tmp/driver.log"
        self.m_config.PROM_METRICS_DRIVER_PORT = 9092
        self.m_config.PROM_METRICS_ENABLED = True
        global_config = {"InterfacePrefix": "tap"}
        local_config = {"LogSeverityFile": "DEBUG"}
        self.watcher._on_config_update({
            MSG_KEY_GLOBAL_CONFIG: global_config,
            MSG_KEY_HOST_CONFIG: local_config,
        })
        self.assertTrue(self.watcher.configured.is_set())
        self.assertEqual(
            self.m_config.report_etcd_config.mock_calls,
            [call(local_config, global_config)]
        )
        self.assertEqual(
            self.m_writer.send_message.mock_calls,
            [call(MSG_TYPE_CONFIG_RESOLVED,
                  {
                      MSG_KEY_LOG_FILE: "/tmp/driver.log",
                      MSG_KEY_SEV_FILE: self.m_config.LOGLEVFILE,
                      MSG_KEY_SEV_SCREEN: self.m_config.LOGLEVSCR,
                      MSG_KEY_SEV_SYSLOG: self.m_config.LOGLEVSYS,
                      MSG_KEY_PROM_PORT: 9092,
                  })]
        )
        self.assertEqual(m_die.mock_calls, [])

        # Check a subsequent config change results in Felix dying.
        global_config = {"InterfacePrefix": "not!tap"}
        local_config = {"LogSeverityFile": "not!DEBUG"}
        self.watcher._on_config_update({
            MSG_KEY_GLOBAL_CONFIG: global_config,
            MSG_KEY_HOST_CONFIG: local_config,
        })
        self.assertEqual(m_die.mock_calls, [call()])

    def test_on_status_from_driver(self):
        self.watcher._on_in_sync({
            MSG_KEY_STATUS: STATUS_RESYNC
        })
        self.assertFalse(self.watcher._been_in_sync)

        with patch.object(self.watcher, "begin_polling") as m_begin:
            # Two calls but second should be ignored...
            self.watcher._on_in_sync({
                MSG_KEY_STATUS: STATUS_IN_SYNC
            })
            self.watcher._on_in_sync({
                MSG_KEY_STATUS: STATUS_IN_SYNC
            })
        m_begin.wait.assert_called_once_with()
        self.assertTrue(self.watcher._been_in_sync)
        self.assertEqual(self.m_splitter.on_datamodel_in_sync.mock_calls,
                         [call()])
        self.assertEqual(self.m_hosts_ipset.replace_members.mock_calls,
                         [call(frozenset([]), async=True)])

    @patch("os.path.exists", autospec=True)
    @patch("subprocess.Popen")
    @patch("gevent.Timeout", autospec=True)
    @patch("socket.socket")
    @patch("os.unlink")
    def test_start_driver(self, m_unlink, m_socket, m_timeout, m_popen,
                          m_exists):
        m_exists.return_value = True
        m_sck = Mock()
        m_socket.return_value = m_sck
        m_conn = Mock()
        m_sck.accept.return_value = m_conn, None
        reader, writer = self.watcher._start_driver()
        self.assertEqual(m_socket.mock_calls[0], call(socket.AF_UNIX,
                                                      socket.SOCK_STREAM))
        self.assertEqual(m_sck.bind.mock_calls,
                         [call("/run/felix-driver.sck")])
        self.assertEqual(m_sck.listen.mock_calls, [call(1)])
        self.assertEqual(m_popen.mock_calls[0],
                         call([ANY, "-m", "calico.etcddriver",
                               "/run/felix-driver.sck"]))
        self.assertEqual(m_unlink.mock_calls,
                         [call("/run/felix-driver.sck")] * 2)
        self.assertTrue(isinstance(reader, MessageReader))
        self.assertTrue(isinstance(writer, MessageWriter))
        m_exists.assert_called_once_with("/run")
        m_timeout.assert_called_once_with(10)

    @patch("calico.felix.datastore.sys")
    @patch("os.path.exists", autospec=True)
    @patch("subprocess.Popen")
    @patch("socket.socket")
    @patch("os.unlink")
    def test_start_driver_run_missing(self, m_unlink, m_socket, m_popen,
                                      m_exists, m_sys):
        """Check that we fall back to /var/run if /run is missing."""
        # Simulate being in a pyinstaller.  Should trigger alternative
        # executable path.
        m_sys.frozen = True
        m_sys.argv = ["calico-felix"]

        m_exists.return_value = False
        m_sck = Mock()
        m_socket.return_value = m_sck
        m_conn = Mock()
        m_sck.accept.return_value = m_conn, None
        reader, writer = self.watcher._start_driver()
        self.assertEqual(m_socket.mock_calls[0], call(socket.AF_UNIX,
                                                      socket.SOCK_STREAM))
        self.assertEqual(m_sck.bind.mock_calls,
                         [call("/var/run/felix-driver.sck")])
        self.assertEqual(m_sck.listen.mock_calls, [call(1)])
        self.assertEqual(m_popen.mock_calls[0],
                         call(["calico-felix", "driver",
                               "/var/run/felix-driver.sck"]))
        self.assertEqual(m_unlink.mock_calls,
                         [call("/var/run/felix-driver.sck")] * 2)
        self.assertTrue(isinstance(reader, MessageReader))
        self.assertTrue(isinstance(writer, MessageWriter))
        m_exists.assert_called_once_with("/run")

    @patch("subprocess.Popen")
    @patch("socket.socket")
    @patch("os.unlink")
    def test_start_driver_unlink_fail(self, m_unlink, m_socket, m_popen):
        m_unlink.side_effect = OSError()
        m_sck = Mock()
        m_socket.return_value = m_sck
        m_conn = Mock()
        m_sck.accept.return_value = m_conn, None
        reader, writer = self.watcher._start_driver()
        self.assertTrue(isinstance(reader, MessageReader))
        self.assertTrue(isinstance(writer, MessageWriter))

    def test_update_hosts_ipset_not_in_sync(self):
        self.watcher._update_hosts_ipset()
        self.assertEqual(self.m_hosts_ipset.mock_calls, [])

    @patch("calico.felix.datastore.die_and_restart", autospec=True)
    def test_config_set(self, m_die):
        self.watcher.last_global_config = {}
        self.dispatch("/calico/v1/config/InterfacePrefix",
                      "set", value="foo")
        self.assertEqual(m_die.mock_calls, [call()])

    @patch("calico.felix.datastore.die_and_restart", autospec=True)
    def test_host_config_set(self, m_die):
        self.watcher.last_host_config = {}
        self.dispatch("/calico/v1/host/notourhostname/config/InterfacePrefix",
                      "set", value="foo")
        self.dispatch("/calico/v1/host/hostname/config/InterfacePrefix",
                      "set", value="foo")
        self.assertEqual(m_die.mock_calls, [call()])

    def test_endpoint_set(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value=ENDPOINT_STR)
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            WloadEndpointId("h1", "o1", "w1", "e1"),
            VALID_ENDPOINT,
        )

    def test_endpoint_set_bad_json(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value="{")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            WloadEndpointId("h1", "o1", "w1", "e1"),
            None,
        )

    def test_endpoint_set_invalid(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value="{}")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            WloadEndpointId("h1", "o1", "w1", "e1"),
            None,
        )

    def test_host_endpoint_set(self):
        self.dispatch("/calico/v1/host/h1/endpoint/e1",
                      "set", value=HOST_ENDPOINT_STR)
        self.m_splitter.on_host_ep_update.assert_called_once_with(
            HostEndpointId("h1", "e1"),
            VALID_HOST_ENDPOINT,
        )

    def test_host_endpoint_set_bad_json(self):
        self.dispatch("/calico/v1/host/h1/endpoint/e1",
                      "set", value="{")
        self.m_splitter.on_host_ep_update.assert_called_once_with(
            HostEndpointId("h1", "e1"),
            None,
        )

    def test_host_endpoint_del_bad_json(self):
        self.dispatch("/calico/v1/host/h1/endpoint/e1", "delete")
        self.m_splitter.on_host_ep_update.assert_called_once_with(
            HostEndpointId("h1", "e1"),
            None,
        )

    def test_host_endpoint_set_invalid(self):
        self.dispatch("/calico/v1/host/h1/endpoint/e1",
                      "set", value="{}")
        self.m_splitter.on_host_ep_update.assert_called_once_with(
            HostEndpointId("h1", "e1"),
            None,
        )

    def test_prof_labels_set(self):
        self.dispatch("/calico/v1/policy/profile/prof1/labels", "set",
                      value='{"a": "b"}')
        self.m_splitter.on_prof_labels_set.assert_called_once_with("prof1",
                                                                   {"a": "b"})

    def test_prof_labels_set_bad_data(self):
        self.dispatch("/calico/v1/policy/profile/prof1/labels", "set",
                      value='{"a": "b}')
        self.m_splitter.on_prof_labels_set.assert_called_once_with("prof1",
                                                                   None)

    def test_prof_labels_del(self):
        self.dispatch("/calico/v1/policy/profile/prof1/labels", "delete")
        self.m_splitter.on_prof_labels_set.assert_called_once_with("prof1",
                                                                   None)

    def test_on_tiered_policy_set(self):
        self.dispatch("/calico/v1/policy/tier/tiername/policy/polname", "set",
                      value=POLICY_STR)
        self.m_splitter.on_rules_update.assert_called_once_with(
            POLICY_ID,
            POLICY_PARSED
        )
        self.m_splitter.on_policy_selector_update.assert_called_once_with(
            POLICY_ID, SELECTOR, 10
        )

    def test_on_tiered_policy_set_bad_data(self):
        self.dispatch("/calico/v1/policy/tier/tiername/policy/polname", "set",
                      value=POLICY_STR[:10])
        self.m_splitter.on_rules_update.assert_called_once_with(
            POLICY_ID,
            None
        )
        self.m_splitter.on_policy_selector_update.assert_called_once_with(
            POLICY_ID, None, None
        )

    def test_on_tiered_policy_del(self):
        self.dispatch("/calico/v1/policy/tier/tiername/policy/polname",
                      "delete")
        self.m_splitter.on_rules_update.assert_called_once_with(
            POLICY_ID,
            None
        )
        self.m_splitter.on_policy_selector_update.assert_called_once_with(
            POLICY_ID, None, None
        )

    def test_on_tier_data_set(self):
        self.dispatch("/calico/v1/policy/tier/tiername/metadata", "set",
                      value='{"order": 10}')
        self.m_splitter.on_tier_data_update.assert_called_once_with(
            "tiername",
            {"order": 10}
        )

    def test_on_tier_data_set_bad_data(self):
        self.dispatch("/calico/v1/policy/tier/tiername/metadata", "set",
                      value='{"order": 10')
        self.m_splitter.on_tier_data_update.assert_called_once_with(
            "tiername",
            None
        )

    def test_on_tier_data_del(self):
        self.dispatch("/calico/v1/policy/tier/tiername/metadata", "delete")
        self.m_splitter.on_tier_data_update.assert_called_once_with(
            "tiername",
            None
        )

    def test_rules_set(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value=RULES_STR)
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                RULES)

    def test_rules_set_bad_json(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value="{")
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                None,)

    def test_rules_set_invalid(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value='[]')
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                None,)

    def test_tags_set(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value=TAGS_STR)
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               TAGS)

    def test_tags_set_bad_json(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value="{")
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               None)

    def test_tags_set_invalid(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value="[{}]")
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               None)

    def test_tags_del(self):
        """
        Test tag-only deletion.
        """
        self.dispatch("/calico/v1/policy/profile/profA/tags", action="delete")
        self.m_splitter.on_tags_update.assert_called_once_with("profA", None)
        self.assertFalse(self.m_splitter.on_rules_update.called)

    def test_rules_del(self):
        """
        Test rules-only deletion.
        """
        self.dispatch("/calico/v1/policy/profile/profA/rules", action="delete")
        self.m_splitter.on_rules_update.assert_called_once_with("profA", None)
        self.assertFalse(self.m_splitter.on_tags_update.called)

    def test_endpoint_del(self):
        """
        Test endpoint-only deletion.
        """
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      action="delete")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            WloadEndpointId("h1", "o1", "w1", "e1"),
            None,
        )

    def test_host_ip_set(self):
        """
        Test set for the IP of a host.
        """
        self.watcher._been_in_sync = True
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            frozenset(["10.0.0.1"]),
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
            frozenset([]),
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
            frozenset([]),
            async=True,
        )

    def test_ipam_pool_set(self):
        self.dispatch("/calico/v1/ipam/v4/pool/1234", action="set", value="{}")
        self.assertEqual(self.m_splitter.on_ipam_pool_updated.mock_calls,
                         [call("1234", None)])

    def test_ipam_pool_del(self):
        self.dispatch("/calico/v1/ipam/v4/pool/1234", action="delete")
        self.assertEqual(self.m_splitter.on_ipam_pool_updated.mock_calls,
                         [call("1234", None)])

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

    @patch("gevent.sleep", autospec=True)
    def test_usage_report_disabled(self,m_sleep):
        self.m_config.USAGE_REPORT = False
        self.watcher._periodically_usage_report()

    @patch("calico.felix.futils.report_usage_and_get_warnings", autospec=True)
    @patch("pkg_resources.require", autospec=True)
    @patch("random.random", autospec=True)
    @patch("gevent.sleep", autospec=True)
    def test_usage_report_enabled(self, m_sleep, m_random, m_pkg, m_report):

        with patch.object(self.watcher, "estimated_host_count") as m_host_count:
            m_host_count.side_effect = [RuntimeError]
            m_host_count.return_value = 1

            m_report.side_effect = RuntimeError
            self.m_config.USAGE_REPORT = True
            m_random.return_value = 0
            require = Mock()
            require.version = "1.4.0"
            m_pkg.return_value = [require]


    def test_usage_report_disabled(self):
        self.m_config.USAGE_REPORT = 0
        # self.m_periodically_usage_report()


@skip("golang rewrite")
class TestEtcdReporting(BaseTestCase):
    def setUp(self):
        super(TestEtcdReporting, self).setUp()
        self.m_config = Mock()
        self.m_config.IFACE_PREFIX = ["tap"]
        self.m_config.ETCD_ADDRS = ["localhost:4001"]
        self.m_config.ETCD_SCHEME = "http"
        self.m_config.ETCD_KEY_FILE = None
        self.m_config.ETCD_CERT_FILE = None
        self.m_config.ETCD_CA_FILE = None
        self.m_config.USAGE_REPORT = False
        self.m_config.HOSTNAME = "hostname"
        self.m_config.RESYNC_INTERVAL = 0
        self.m_config.REPORTING_INTERVAL_SECS = 1
        self.m_config.REPORTING_TTL_SECS = 10
        self.m_hosts_ipset = Mock(spec=IpsetActor)
        with patch("gevent.spawn", autospec=True):
            with patch("calico.felix.datastore.DatastoreReader", autospec=True):
                with patch("calico.felix.datastore.monotonic_time",
                           return_value=100):
                    self.api = DatastoreAPI(self.m_config, self.m_hosts_ipset)
        self.api._reader.configured = Mock()

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
    @patch("calico.felix.datastore.monotonic_time", return_value=200)
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


@skip("golang rewrite")
class TestStatusReporter(BaseTestCase):
    def setUp(self):
        super(TestStatusReporter, self).setUp()
        self.m_config = Mock(spec=Config)
        self.m_config.ETCD_ADDRS = [ETCD_ADDRESS]
        self.m_config.ETCD_SCHEME = "http"
        self.m_config.ETCD_KEY_FILE = None
        self.m_config.ETCD_CERT_FILE = None
        self.m_config.ETCD_CA_FILE = None
        self.m_config.USAGE_REPORT = False
        self.m_config.HOSTNAME = "foo"
        self.m_config.REPORT_ENDPOINT_STATUS = True
        self.m_config.ENDPOINT_REPORT_DELAY = 1
        self.m_client = Mock()
        self.rep = DatastoreWriter(self.m_config)
        self.rep.client = self.m_client

    def test_on_endpoint_status_mainline(self):
        # Send in an endpoint status update.
        endpoint_id = WloadEndpointId("foo", "bar", "baz", "biff")
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
        self.assertEqual(self.rep._dirty_endpoints, set())
        self.assertEqual(self.rep._older_dirty_endpoints, set())

    def test_mark_endpoint_dirty_already_dirty(self):
        endpoint_id = WloadEndpointId("a", "b", "c", "d")
        self.rep._older_dirty_endpoints.add(endpoint_id)
        self.rep._mark_endpoint_dirty(endpoint_id)
        self.assertFalse(endpoint_id in self.rep._dirty_endpoints)

    def test_on_endpoint_status_failure(self):
        # Send in an endpoint status update.
        endpoint_id = WloadEndpointId("foo", "bar", "baz", "biff")
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
        self.assertEqual(self.rep._dirty_endpoints, set([endpoint_id]))
        self.assertEqual(self.rep._older_dirty_endpoints, set())

    def test_on_endpoint_status_changed_disabled(self):
        self.m_config.REPORT_ENDPOINT_STATUS = False
        endpoint_id = WloadEndpointId("foo", "bar", "baz", "biff")

        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.rep.on_endpoint_status_changed(endpoint_id,
                                                IPV4,
                                                {"status": "up"},
                                                async=True)
            self.step_actor(self.rep)
        self.assertFalse(m_spawn.called)
        self.assertEqual(self.rep._endpoint_status[IPV4], {})
        # Nothing queued.
        self.assertEqual(self.rep._dirty_endpoints, set())
        self.assertEqual(self.rep._older_dirty_endpoints, set())

    def test_on_endpoint_status_v4_v6(self):
        # Send in endpoint status updates for v4 and v6.
        endpoint_id = WloadEndpointId("foo", "bar", "baz", "biff")
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
        endpoint_id = WloadEndpointId("foo", "bar", "baz", "biff")
        self.rep.on_endpoint_status_changed(endpoint_id, IPV4, {"status": "up"}, async=True)
        endpoint_id_2 = WloadEndpointId("foo", "bar", "baz", "boff")
        self.rep.on_endpoint_status_changed(endpoint_id_2, IPV6, {"status": "up"}, async=True)
        with patch("gevent.spawn_later", autospec=True) as m_spawn:
            self.step_actor(self.rep)
            self.rep._on_timer_pop(async=True)
            self.step_actor(self.rep)
        self.assertEqual(self.rep._older_dirty_endpoints, set())
        self.assertEqual(self.rep._dirty_endpoints, set())

        self.rep.resync(async=True)
        self.step_actor(self.rep)

        self.assertEqual(self.rep._older_dirty_endpoints, set())
        self.assertEqual(self.rep._dirty_endpoints, set([endpoint_id, endpoint_id_2]))

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
        ep_id = WloadEndpointId("foo",
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
                WloadEndpointId("foo",
                                "openstack",
                                "aworkload",
                                "anendpoint")
            )

    def test_clean_up_endpoint_status_etcd_error(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        with patch.object(self.rep, "_attempt_cleanup") as m_clean:
            m_clean.side_effect = EtcdException()
            self.rep.clean_up_endpoint_statuses(async=True)
            self.step_actor(self.rep)
            self.assertTrue(self.rep._cleanup_pending)

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
