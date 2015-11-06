# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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
"""
felix.test.test_endpoint
~~~~~~~~~~~~~~~~~~~~~~~~

Tests of endpoint module.
"""
from contextlib import nested
import logging
from calico.felix.endpoint import EndpointManager, LocalEndpoint
from calico.felix.fetcd import EtcdAPI, EtcdStatusReporter
from calico.felix.fiptables import IptablesUpdater
from calico.felix.dispatch import DispatchChains
from calico.felix.futils import FailedSystemCall
from calico.felix.profilerules import RulesManager

import mock
from mock import Mock

from calico.felix.test.base import BaseTestCase
from calico.felix.test import stub_utils
from calico.felix import config
from calico.felix import endpoint
from calico.felix import futils
from calico.datamodel_v1 import EndpointId

_log = logging.getLogger(__name__)

mock.patch.object = getattr(mock.patch, "object")  # Keep PyCharm linter happy.

ENDPOINT_ID = EndpointId("hostname", "b", "c", "d")


class TestEndpointManager(BaseTestCase):
    def setUp(self):
        super(TestEndpointManager, self).setUp()
        self.m_config = Mock(spec=config.Config)
        self.m_config.HOSTNAME = "hostname"
        self.m_updater = Mock(spec=IptablesUpdater)
        self.m_dispatch = Mock(spec=DispatchChains)
        self.m_rules_mgr = Mock(spec=RulesManager)
        self.m_status_reporter = Mock(spec=EtcdStatusReporter)
        self.mgr = EndpointManager(self.m_config, "IPv4", self.m_updater,
                                   self.m_dispatch, self.m_rules_mgr,
                                   self.m_status_reporter)
        self.mgr.get_and_incref = Mock()
        self.mgr.decref = Mock()

    def test_create(self):
        obj = self.mgr._create(ENDPOINT_ID)
        self.assertTrue(isinstance(obj, LocalEndpoint))

    def test_on_started(self):
        ep = {"name": "tap1234"}
        self.mgr.on_endpoint_update(ENDPOINT_ID,
                                    ep,
                                    async=True)
        self.step_actor(self.mgr)
        m_endpoint = Mock(spec=LocalEndpoint)
        self.mgr._on_object_started(ENDPOINT_ID, m_endpoint)
        self.assertEqual(
            m_endpoint.on_endpoint_update.mock_calls,
            [mock.call(ep, async=True)]
        )

    def test_on_datamodel_in_sync(self):
        ep = {"name": "tap1234"}
        self.mgr.on_endpoint_update(ENDPOINT_ID,
                                    ep,
                                    async=True)
        self.step_actor(self.mgr)
        self.mgr.on_datamodel_in_sync(async=True)
        self.step_actor(self.mgr)
        self.assertEqual(
            self.m_dispatch.apply_snapshot.mock_calls,
            [mock.call(frozenset(["tap1234"]), async=True)]
        )
        # Second call should have no effect.
        self.m_dispatch.apply_snapshot.reset_mock()
        self.mgr.on_datamodel_in_sync(async=True)
        self.step_actor(self.mgr)
        self.assertEqual(self.m_dispatch.apply_snapshot.mock_calls, [])

    def test_endpoint_update_not_our_host(self):
        ep = {"name": "tap1234"}
        with mock.patch.object(self.mgr, "_is_starting_or_live") as m_sol:
            self.mgr.on_endpoint_update(EndpointId("notus", "b", "c", "d"),
                                        ep,
                                        async=True)
            self.step_actor(self.mgr)
        self.assertFalse(m_sol.called)

    def test_endpoint_live_obj(self):
        ep = {"name": "tap1234"}
        # First send in an update to trigger creation.
        self.mgr.on_endpoint_update(ENDPOINT_ID, ep, async=True)
        self.step_actor(self.mgr)
        self.assertEqual(self.mgr.get_and_incref.mock_calls,
                         [mock.call(ENDPOINT_ID)])
        m_endpoint = Mock(spec=LocalEndpoint)
        self.mgr.objects_by_id[ENDPOINT_ID] = m_endpoint
        # Then send a second update to check that it gets passed on to the
        # LocalEndpoint.
        with mock.patch.object(self.mgr, "_is_starting_or_live") as m_sol:
            m_sol.return_value = True
            self.mgr.on_endpoint_update(ENDPOINT_ID, ep, async=True)
            self.step_actor(self.mgr)
        self.assertEqual(m_sol.mock_calls, [mock.call(ENDPOINT_ID)])
        self.assertEqual(m_endpoint.on_endpoint_update.mock_calls,
                         [mock.call(ep, force_reprogram=False,
                                    async=True)])
        self.assertTrue(ENDPOINT_ID in self.mgr.local_endpoint_ids)
        # Finally, send in a deletion.
        m_endpoint.on_endpoint_update.reset_mock()
        with mock.patch.object(self.mgr, "_is_starting_or_live") as m_sol:
            m_sol.return_value = True
            self.mgr.on_endpoint_update(ENDPOINT_ID, None, async=True)
            self.step_actor(self.mgr)
        self.assertEqual(m_endpoint.on_endpoint_update.mock_calls,
                         [mock.call(None, force_reprogram=False,
                                    async=True)])
        self.assertEqual(self.mgr.decref.mock_calls, [mock.call(ENDPOINT_ID)])
        self.assertFalse(ENDPOINT_ID in self.mgr.local_endpoint_ids)

    def test_on_interface_update_unknown(self):
        with mock.patch.object(self.mgr, "_is_starting_or_live") as m_sol:
            self.mgr.on_interface_update("foo", True, async=True)
            self.step_actor(self.mgr)
        self.assertFalse(m_sol.called)

    def test_on_interface_update_known(self):
        ep = {"name": "tap1234"}
        m_endpoint = Mock(spec=LocalEndpoint)
        self.mgr.objects_by_id[ENDPOINT_ID] = m_endpoint
        with mock.patch.object(self.mgr, "_is_starting_or_live") as m_sol:
            m_sol.return_value = True
            self.mgr.on_endpoint_update(ENDPOINT_ID, ep, async=True)
            self.mgr.on_interface_update("tap1234", True, async=True)
            self.step_actor(self.mgr)
        self.assertEqual(
            m_endpoint.on_interface_update.mock_calls,
            [mock.call(True, async=True)]
        )

    def test_on_interface_update_known_but_not_live(self):
        ep = {"name": "tap1234"}
        m_endpoint = Mock(spec=LocalEndpoint)
        self.mgr.objects_by_id[ENDPOINT_ID] = m_endpoint
        with mock.patch.object(self.mgr, "_is_starting_or_live") as m_sol:
            m_sol.return_value = False
            self.mgr.on_endpoint_update(ENDPOINT_ID, ep, async=True)
            self.mgr.on_interface_update("tap1234", True, async=True)
            self.step_actor(self.mgr)
        self.assertEqual(m_endpoint.on_interface_update.mock_calls, [])


class TestLocalEndpoint(BaseTestCase):
    def setUp(self):
        super(TestLocalEndpoint, self).setUp()
        self.m_config = Mock(spec=config.Config)
        self.m_config.IFACE_PREFIX = "tap"
        self.m_config.REPORT_ENDPOINT_STATUS = False
        self.m_iptables_updater = Mock(spec=IptablesUpdater)
        self.m_dispatch_chains = Mock(spec=DispatchChains)
        self.m_rules_mgr = Mock(spec=RulesManager)
        self.m_manager = Mock(spec=EndpointManager)
        self.m_status_rep = Mock(spec=EtcdStatusReporter)

    def get_local_endpoint(self, combined_id, ip_type):
        local_endpoint = endpoint.LocalEndpoint(self.m_config,
                                                combined_id,
                                                ip_type,
                                                self.m_iptables_updater,
                                                self.m_dispatch_chains,
                                                self.m_rules_mgr,
                                                self.m_status_rep)
        local_endpoint._manager = self.m_manager
        return local_endpoint

    def test_on_endpoint_update_v4(self):
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)

        # Call with no data; should be ignored (no configuration to remove).
        local_ep.on_endpoint_update(None, async=True)
        self.step_actor(local_ep)

        ips = ["1.2.3.4"]
        iface = "tapabcdef"
        data = {
            'state': "active",
            'endpoint': "endpoint_id",
            'mac': stub_utils.get_mac(),
            'name': iface,
            'ipv4_nets': ips,
            'profile_ids': ["prof1"]
        }

        # Report an initial update (endpoint creation) and check configured
        with nested(
                mock.patch('calico.felix.devices.set_routes'),
                mock.patch('calico.felix.devices.configure_interface_ipv4'),
                mock.patch('calico.felix.devices.interface_up'),
        ) as [m_set_routes, m_conf, m_iface_up]:
            m_iface_up.return_value = True
            local_ep.on_endpoint_update(data, async=True)
            self.step_actor(local_ep)
            self.assertEqual(local_ep._mac, data['mac'])
            m_conf.assert_called_once_with(iface)
            m_set_routes.assert_called_once_with(ip_type,
                                                 set(ips),
                                                 iface,
                                                 data['mac'],
                                                 reset_arp=True)

        # Send through an update with no changes - should be a no-op.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes:
            with mock.patch('calico.felix.devices.'
                            'configure_interface_ipv4') as m_conf:
                local_ep.on_endpoint_update(data, async=True)
                self.step_actor(local_ep)
                self.assertEqual(local_ep._mac, data['mac'])
                self.assertFalse(m_conf.called)
                self.assertFalse(m_set_routes.called)

        # Change the MAC address and try again, leading to reset of ARP
        data = data.copy()
        data['mac'] = stub_utils.get_mac()
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes:
            with mock.patch('calico.felix.devices.'
                            'configure_interface_ipv4') as m_conf:
                local_ep.on_endpoint_update(data, async=True)
                self.step_actor(local_ep)
                self.assertEqual(local_ep._mac, data['mac'])
                m_conf.assert_called_once_with(iface)
                m_set_routes.assert_called_once_with(ip_type,
                                                     set(ips),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=True)

        # Send empty data, which deletes the endpoint.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes:
            local_ep.on_endpoint_update(None, async=True)
            self.step_actor(local_ep)
            m_set_routes.assert_called_once_with(ip_type, set(),
                                                 data["name"], None)

    def test_on_endpoint_update_v6(self):
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV6
        local_ep = self.get_local_endpoint(combined_id, ip_type)

        # Call with no data; should be ignored (no configuration to remove).
        local_ep.on_endpoint_update(None, async=True)
        self.step_actor(local_ep)

        ips = ["2001::abcd"]
        gway = "2020:ab::9876"
        iface = "tapabcdef"
        data = {
            'state': "active",
            'endpoint': "endpoint_id",
            'mac': stub_utils.get_mac(),
            'name': iface,
            'ipv6_nets': ips,
            'ipv6_gateway': gway,
            'profile_ids': ["prof1"]
        }

        # Report an initial update (endpoint creation) and check configured
        with nested(
                mock.patch('calico.felix.devices.set_routes'),
                mock.patch('calico.felix.devices.configure_interface_ipv6'),
                mock.patch('calico.felix.devices.interface_up'),
        ) as [m_set_routes, m_conf, m_iface_up]:
                m_iface_up.return_value = True
                local_ep.on_endpoint_update(data, async=True)
                self.step_actor(local_ep)
                self.assertEqual(local_ep._mac, data['mac'])
                m_conf.assert_called_once_with(iface, gway)
                m_set_routes.assert_called_once_with(ip_type,
                                                     set(ips),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=False)

        # Send through an update with no changes but a force update.  Should
        # force a re-write to iptables.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes:
            with mock.patch('calico.felix.devices.'
                            'configure_interface_ipv6') as m_conf:
                local_ep.on_endpoint_update(data, force_reprogram=True,
                                            async=True)
                self.step_actor(local_ep)
                self.assertEqual(local_ep._mac, data['mac'])
                self.assertTrue(m_conf.called)
                self.assertTrue(m_set_routes.called)

        # Send through an update with no changes - would reset ARP, but this is
        # IPv6 so it won't.
        data = data.copy()
        data['mac'] = stub_utils.get_mac()
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes:
            with mock.patch('calico.felix.devices.'
                            'configure_interface_ipv6') as m_conf:
                local_ep.on_endpoint_update(data, async=True)
                self.step_actor(local_ep)
                self.assertEqual(local_ep._mac, data['mac'])
                m_conf.assert_called_once_with(iface, gway)
                m_set_routes.assert_called_once_with(ip_type,
                                                     set(ips),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=False)

        # Send empty data, which deletes the endpoint.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes:
            local_ep.on_endpoint_update(None, async=True)
            local_ep.on_unreferenced(async=True)
            self.step_actor(local_ep)
            m_set_routes.assert_called_once_with(ip_type, set(),
                                                 data["name"], None)
            self.assertRaises(AssertionError,
                              local_ep._finish_msg_batch, [], [])
            self.m_manager.on_object_cleanup_complete.assert_called_once_with(
                local_ep._id,
                local_ep,
                async=True,
            )

    def test_on_interface_update_v4(self):
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)

        ips = ["1.2.3.4"]
        iface = "tapabcdef"
        data = {
            'state': "active",
            'endpoint': "endpoint_id",
            'mac': stub_utils.get_mac(),
            'name': iface,
            'ipv4_nets': ips,
            'profile_ids': ["prof1"]
        }

        # We can only get on_interface_update calls after the first
        # on_endpoint_update, so trigger that.
        with nested(
                mock.patch('calico.felix.devices.set_routes'),
                mock.patch('calico.felix.devices.configure_interface_ipv4'),
                mock.patch('calico.felix.devices.interface_up'),
        ) as [m_set_routes, m_conf, m_iface_up]:
                m_iface_up.return_value = False
                local_ep.on_endpoint_update(data, async=True)
                self.step_actor(local_ep)
                self.assertEqual(local_ep._mac, data['mac'])
                m_conf.assert_called_once_with(iface)
                m_set_routes.assert_called_once_with(ip_type,
                                                     set(ips),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=True)
                self.assertTrue(local_ep._device_in_sync)

        # Now pretend to get an interface update - does all the same work.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes:
            with mock.patch('calico.felix.devices.'
                            'configure_interface_ipv4') as m_conf:
                local_ep.on_interface_update(True, async=True)
                self.step_actor(local_ep)
                m_conf.assert_called_once_with(iface)
                m_set_routes.assert_called_once_with(ip_type,
                                                     set(ips),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=True)
                self.assertTrue(local_ep._device_in_sync)

    def test_on_interface_update_v6(self):
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV6
        local_ep = self.get_local_endpoint(combined_id, ip_type)

        ips = ["1234::5678"]
        iface = "tapabcdef"
        data = {
            'state': "active",
            'endpoint': "endpoint_id",
            'mac': stub_utils.get_mac(),
            'name': iface,
            'ipv6_nets': ips,
            'profile_ids': ["prof1"]
        }

        # We can only get on_interface_update calls after the first
        # on_endpoint_update, so trigger that.
        with nested(
                mock.patch('calico.felix.devices.set_routes'),
                mock.patch('calico.felix.devices.configure_interface_ipv6'),
                mock.patch('calico.felix.devices.interface_up'),
        ) as [m_set_routes, m_conf, m_iface_up]:
                m_iface_up.return_value = False
                local_ep.on_endpoint_update(data, async=True)
                self.step_actor(local_ep)
                self.assertEqual(local_ep._mac, data['mac'])
                m_conf.assert_called_once_with(iface, None)
                m_set_routes.assert_called_once_with(ip_type,
                                                     set(ips),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=False)

        # Now pretend to get an interface update - does all the same work.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes:
            with mock.patch('calico.felix.devices.'
                            'configure_interface_ipv6') as m_conf:
                local_ep.on_interface_update(True, async=True)
                self.step_actor(local_ep)
                m_conf.assert_called_once_with(iface, None)
                m_set_routes.assert_called_once_with(ip_type,
                                                     set(ips),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=False)
                self.assertTrue(local_ep._device_in_sync)

        # Now cover the error cases...
        with mock.patch('calico.felix.devices.'
                        'configure_interface_ipv6') as m_conf:
            with mock.patch('calico.felix.devices.'
                            'interface_exists') as ifce_exists:
                with mock.patch('calico.felix.devices.'
                                'interface_up') as ifce_up:
                    # Cycle through all the possibilities for the state.
                    ifce_exists.side_effect = [True, False, True]
                    ifce_up.side_effect = [True, False]
                    m_conf.side_effect = FailedSystemCall("", [], 1, "", "")
                    local_ep.on_interface_update(False, async=True)
                    self.step_actor(local_ep)
                    local_ep.on_interface_update(True, async=True)
                    self.step_actor(local_ep)
                    local_ep.on_interface_update(True, async=True)
                    self.step_actor(local_ep)
                    self.assertFalse(local_ep._device_in_sync)

    def test_profile_id_update_triggers_iptables(self):
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)

        ips = ["10.0.0.1"]
        iface = "tapabcdef"
        mac = stub_utils.get_mac()
        data = {'endpoint': "endpoint_id", 'mac': mac,
                'name': iface, 'ipv4_nets': ips, 'profile_ids': [],
                'state': "active"}
        local_ep._pending_endpoint = data.copy()

        # First update with endpoint not yet set, should trigger full sync.
        with mock.patch("calico.felix.devices.interface_up",
                        return_value=True):
            local_ep._apply_endpoint_update()
        self.assertEqual(local_ep.endpoint, data)
        self.assertFalse(local_ep._iptables_in_sync)
        self.assertFalse(local_ep._device_in_sync)

        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = True

        # No-op update
        local_ep._pending_endpoint = data.copy()
        local_ep._apply_endpoint_update()
        self.assertTrue(local_ep._iptables_in_sync)
        self.assertTrue(local_ep._device_in_sync)

        # Set the state.
        local_ep._pending_endpoint = data.copy()
        local_ep._pending_endpoint["state"] = "inactive"
        local_ep._apply_endpoint_update()
        self.assertFalse(local_ep._iptables_in_sync)
        self.assertFalse(local_ep._device_in_sync)
        local_ep._device_in_sync = True
        local_ep._iptables_in_sync = True

        # Set the state back again...
        local_ep._pending_endpoint = data.copy()
        local_ep._pending_endpoint["state"] = "active"
        local_ep._apply_endpoint_update()
        self.assertFalse(local_ep._iptables_in_sync)
        self.assertFalse(local_ep._device_in_sync)
        local_ep._device_in_sync = True
        local_ep._iptables_in_sync = True

        # Profiles update.  Should update iptables.
        data = {'endpoint': "endpoint_id", 'mac': mac,
                'name': iface, 'ipv4_nets': ips, 'profile_ids': ["prof2"],
                "state": "active"}
        local_ep._pending_endpoint = data.copy()
        local_ep._apply_endpoint_update()
        self.assertFalse(local_ep._iptables_in_sync)
        local_ep._iptables_in_sync = True
        self.assertTrue(local_ep._device_in_sync)

        # IP update.  Should update routing.
        data = {'endpoint': "endpoint_id", 'mac': mac,
                'name': iface, 'ipv4_nets': ["10.0.0.2"],
                'profile_ids': ["prof2"],
                "state": "active"}
        local_ep._pending_endpoint = data.copy()
        local_ep._apply_endpoint_update()
        self.assertTrue(local_ep._iptables_in_sync)
        self.assertFalse(local_ep._device_in_sync)
        local_ep._device_in_sync = True

        # Delete, should update everything.
        local_ep._pending_endpoint = None
        local_ep._apply_endpoint_update()
        self.assertFalse(local_ep._iptables_in_sync)
        self.assertFalse(local_ep._device_in_sync)

    def test_maybe_update_status_missing_deps(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'down'}, async=True
        )

    def test_maybe_update_status_iptables_failure(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._iptables_in_sync = False
        local_ep._device_in_sync = True
        local_ep._device_has_been_in_sync = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'error'}, async=True
        )

    def test_maybe_update_status_device_failure(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = False
        local_ep._device_has_been_in_sync = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'error'}, async=True
        )

    def test_maybe_update_status_device_failure_first_time(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = False
        local_ep._device_has_been_in_sync = False
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'down'}, async=True
        )

    def test_maybe_update_status_iptables_up(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._device_is_up = True
        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = True
        local_ep._device_has_been_in_sync = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'up'}, async=True
        )

    def test_maybe_update_status_admin_down(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "inactive"}
        local_ep._device_is_up = True
        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = True
        local_ep._device_has_been_in_sync = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'down'}, async=True
        )

    def test_maybe_update_status_oper_down(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._device_is_up = False
        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = True
        local_ep._device_has_been_in_sync = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'down'}, async=True
        )

    def test_maybe_update_status_iptables_unreferenced(self):
        self.m_config.REPORT_ENDPOINT_STATUS = True
        combined_id = EndpointId("host_id", "orchestrator_id",
                                 "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.on_unreferenced(async=True)
        self.step_actor(local_ep)
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, None, async=True
        )


class TestEndpoint(BaseTestCase):
    def test_get_endpoint_rules(self):
        to_pfx = '--append felix-to-abcd'
        from_pfx = '--append felix-from-abcd'
        expected_result = (
            {
                'felix-from-abcd': 
                [
                    # Always start with a 0 MARK.
                    from_pfx + ' --jump MARK --set-mark 0',
                    # From chain polices the MAC address.
                    from_pfx + ' --match mac ! --mac-source aa:22:33:44:55:66 '
                               '--jump DROP --match comment --comment '
                               '"Incorrect source MAC"',

                    # Jump to the first profile.
                    from_pfx + ' --jump felix-p-prof-1-o',
                    # Short-circuit: return if the first profile matched.
                    from_pfx + ' --match mark --mark 1/1 --match comment '
                               '--comment "Profile accepted packet" '
                               '--jump RETURN',

                    # Jump to second profile.
                    from_pfx + ' --jump felix-p-prof-2-o',
                    # Return if the second profile matched.
                    from_pfx + ' --match mark --mark 1/1 --match comment '
                               '--comment "Profile accepted packet" '
                               '--jump RETURN',

                    # Drop the packet if nothing matched.
                    from_pfx + ' --jump DROP -m comment --comment '
                               '"Default DROP if no match (endpoint e1):"'
                ],
                'felix-to-abcd': 
                [
                    # Always start with a 0 MARK.
                    to_pfx + ' --jump MARK --set-mark 0',

                    # Jump to first profile and return iff it matched.
                    to_pfx + ' --jump felix-p-prof-1-i',
                    to_pfx + ' --match mark --mark 1/1 --match comment '
                             '--comment "Profile accepted packet" '
                             '--jump RETURN',

                    # Jump to second profile and return iff it matched.
                    to_pfx + ' --jump felix-p-prof-2-i',
                    to_pfx + ' --match mark --mark 1/1 --match comment '
                             '--comment "Profile accepted packet" '
                             '--jump RETURN',

                    # Drop anything that doesn't match.
                    to_pfx + ' --jump DROP -m comment --comment '
                             '"Default DROP if no match (endpoint e1):"'
                ]
            },
            {
                # From chain depends on the outbound profiles.
                'felix-from-abcd': set(['felix-p-prof-1-o',
                                        'felix-p-prof-2-o']),
                # To chain depends on the inbound profiles.
                'felix-to-abcd': set(['felix-p-prof-1-i',
                                      'felix-p-prof-2-i'])
            }
        )
        result = endpoint._get_endpoint_rules("e1", "abcd",
                                              "aa:22:33:44:55:66",
                                              ["prof-1", "prof-2"])

        # Log the whole diff if the comparison fails.
        self.maxDiff = None
        self.assertEqual(result, expected_result)
