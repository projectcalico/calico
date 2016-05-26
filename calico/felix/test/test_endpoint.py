# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
# Copyright (c) 2015 Cisco Systems.  All Rights Reserved.
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
from collections import OrderedDict
from contextlib import nested
import logging

from calico.felix.plugins.fiptgenerator import FelixIptablesGenerator
from calico.felix.selectors import parse_selector

from calico.felix.endpoint import EndpointManager, WorkloadEndpoint
from calico.felix.fetcd import EtcdStatusReporter
from calico.felix.fiptables import IptablesUpdater
from calico.felix.dispatch import DispatchChains
from calico.felix.futils import FailedSystemCall
from calico.felix.profilerules import RulesManager
from calico.felix.fipmanager import FloatingIPManager

import mock
from mock import Mock

from calico.felix.test.base import BaseTestCase, load_config
from calico.felix.test import stub_utils
from calico.felix import endpoint
from calico.felix import futils
from calico.datamodel_v1 import WloadEndpointId, TieredPolicyId

_log = logging.getLogger(__name__)

mock.patch.object = getattr(mock.patch, "object")  # Keep PyCharm linter happy.

ENDPOINT_ID = WloadEndpointId("hostname", "b", "c", "d")
ENDPOINT_ID_2 = WloadEndpointId("hostname", "b", "c1", "d1")


class TestEndpointManager(BaseTestCase):
    def setUp(self):
        super(TestEndpointManager, self).setUp()
        self.config = load_config("felix_default.cfg", env_dict={
            "FELIX_FELIXHOSTNAME": "hostname"})
        self.m_updater = Mock(spec=IptablesUpdater)
        self.m_dispatch = Mock(spec=DispatchChains)
        self.m_rules_mgr = Mock(spec=RulesManager)
        self.m_fip_manager = Mock(spec=FloatingIPManager)
        self.m_status_reporter = Mock(spec=EtcdStatusReporter)
        self.mgr = EndpointManager(self.config, "IPv4", self.m_updater,
                                   self.m_dispatch, self.m_rules_mgr,
                                   self.m_fip_manager, self.m_status_reporter)
        self.mgr.get_and_incref = Mock()
        self.mgr.decref = Mock()

    def test_create(self):
        obj = self.mgr._create(ENDPOINT_ID)
        self.assertTrue(isinstance(obj, WorkloadEndpoint))

    def test_on_started(self):
        ep = {"name": "tap1234"}
        self.mgr.on_endpoint_update(ENDPOINT_ID,
                                    ep,
                                    async=True)
        self.step_actor(self.mgr)
        m_endpoint = Mock(spec=WorkloadEndpoint)
        self.mgr.objects_by_id[ENDPOINT_ID] = m_endpoint
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

    def test_tiered_policy_ordering_and_updates(self):
        """
        Check that the tier_sequence ordering is updated correctly as we
        add and remove tiers and policies.
        """
        # Make sure we have an endpoint so that we can check that it gets
        # put in the dirty set.
        self.mgr.on_datamodel_in_sync(async=True)
        self.mgr.on_endpoint_update(ENDPOINT_ID,
                                    {"name": "tap12345"},
                                    async=True)
        self.step_actor(self.mgr)

        # Pretend that the endpoint is alive so that we'll send updates to id.
        m_endpoint = Mock(spec=WorkloadEndpoint)
        self.mgr.objects_by_id[ENDPOINT_ID] = m_endpoint
        self.mgr._is_starting_or_live = Mock(return_value=True)

        # Add a profile into the tier so it'll apply to the endpoint.
        pol_id_a = TieredPolicyId("a", "a1")
        self.mgr.on_policy_selector_update(pol_id_a, parse_selector("all()"),
                                           10, async=True)
        pol_id_b = TieredPolicyId("b", "b1")
        self.mgr.on_policy_selector_update(pol_id_b, parse_selector("all()"),
                                           10, async=True)
        pol_id_c1 = TieredPolicyId("c1", "c1")
        self.mgr.on_policy_selector_update(pol_id_c1, parse_selector("all()"),
                                           10, async=True)
        pol_id_c2 = TieredPolicyId("c2", "c2")
        self.mgr.on_policy_selector_update(pol_id_c2, parse_selector("all()"),
                                           10, async=True)
        pol_id_c3 = TieredPolicyId("c3", "c3")
        self.mgr.on_policy_selector_update(pol_id_c3, parse_selector("all()"),
                                           10, async=True)
        self.step_actor(self.mgr)
        # Since we haven't set the tier ID yet, the policy won't get applied...
        self.assertEqual(m_endpoint.on_tiered_policy_update.mock_calls,
                         [mock.call(OrderedDict(), async=True)] * 5)
        m_endpoint.on_tiered_policy_update.reset_mock()

        # Adding a tier should trigger an update, adding the tier and policy.
        self.mgr.on_tier_data_update("a", {"order": 1}, async=True)
        self.step_actor(self.mgr)
        self.assertEqual(self.mgr.endpoints_with_dirty_policy, set())
        tiers = OrderedDict()
        tiers["a"] = [pol_id_a]
        self.assertEqual(m_endpoint.on_tiered_policy_update.mock_calls,
                         [mock.call(tiers, async=True)])
        m_endpoint.on_tiered_policy_update.reset_mock()

        # Idempotent update should get squashed.
        self.mgr.on_tier_data_update("a", {"order": 2}, async=True)
        self.mgr.on_tier_data_update("a", {"order": 2}, async=True)
        self.step_actor(self.mgr)
        self.assertEqual(m_endpoint.on_tiered_policy_update.mock_calls, [])

        # Adding another tier should trigger an update.
        self.mgr.on_tier_data_update("b", {"order": 3}, async=True)
        self.step_actor(self.mgr)
        tiers = OrderedDict()
        tiers["a"] = [pol_id_a]
        tiers["b"] = [pol_id_b]
        self.assertEqual(m_endpoint.on_tiered_policy_update.mock_calls,
                         [mock.call(tiers, async=True)])
        m_endpoint.on_tiered_policy_update.reset_mock()

        # Swapping the order should trigger an update.
        self.mgr.on_tier_data_update("b", {"order": 1}, async=True)
        self.step_actor(self.mgr)
        tiers = OrderedDict()
        tiers["b"] = [pol_id_b]
        tiers["a"] = [pol_id_a]
        self.assertEqual(m_endpoint.on_tiered_policy_update.mock_calls,
                         [mock.call(tiers, async=True)])
        m_endpoint.on_tiered_policy_update.reset_mock()

        # Check deletion and that it's idempotent.
        self.mgr.on_tier_data_update("b", None, async=True)
        self.step_actor(self.mgr)
        self.mgr.on_policy_selector_update(pol_id_b, None, None, async=True)
        self.mgr.on_policy_selector_update(pol_id_b, None, None, async=True)
        self.step_actor(self.mgr)
        self.mgr.on_tier_data_update("b", None, async=True)
        self.step_actor(self.mgr)
        self.mgr.on_policy_selector_update(pol_id_b, None, None, async=True)
        self.mgr.on_policy_selector_update(pol_id_b, None, None, async=True)
        self.step_actor(self.mgr)
        tiers = OrderedDict()
        tiers["a"] = [pol_id_a]
        self.assertEqual(
            m_endpoint.on_tiered_policy_update.mock_calls,
            [mock.call(tiers, async=True)] * 2  # One for policy, one for tier.
        )
        m_endpoint.on_tiered_policy_update.reset_mock()

        # Check lexicographic tie-breaker.
        self.mgr.on_tier_data_update("c1", {"order": 0}, async=True)
        self.mgr.on_tier_data_update("c2", {"order": 0}, async=True)
        self.mgr.on_tier_data_update("c3", {"order": 0}, async=True)
        self.step_actor(self.mgr)
        tiers = OrderedDict()
        # All 'c's should sort before 'a' due to explicit ordering but 'c's
        # should sort in lexicographic order.
        tiers["c1"] = [pol_id_c1]
        tiers["c2"] = [pol_id_c2]
        tiers["c3"] = [pol_id_c3]
        tiers["a"] = [pol_id_a]
        actual_call = m_endpoint.on_tiered_policy_update.mock_calls[-1]
        expected_call = mock.call(tiers, async=True)
        self.assertEqual(actual_call, expected_call,
                         msg="\nExpected: %s\n Got:     %s" %
                             (expected_call, actual_call))
        m_endpoint.on_tiered_policy_update.reset_mock()

    def test_label_inheritance(self):
        # Make sure we have an endpoint so that we can check that it gets
        # put in the dirty set.  These have no labels at all so we test
        # that no labels gets translated to an empty dict.
        self.mgr.on_endpoint_update(ENDPOINT_ID, {"name": "tap12345",
                                                  "profile_ids": ["prof1"]},
                                    async=True)
        self.mgr.on_endpoint_update(ENDPOINT_ID_2, {"name": "tap23456",
                                                    "profile_ids": ["prof2"]},
                                    async=True)
        # And we need a selector to pick out one of the endpoints by the labels
        # attached to its parent.
        self.mgr.on_policy_selector_update(TieredPolicyId("a", "b"),
                                           parse_selector('a == "b"'),
                                           10,
                                           async=True)
        self.step_actor(self.mgr)

        with mock.patch.object(self.mgr, "_update_dirty_policy") as m_update:
            self.mgr.on_prof_labels_set("prof1", {"a": "b"}, async=True)
            self.step_actor(self.mgr)
            # Only the first endpoint should end up matching the selector.
            self.assertEqual(self.mgr.endpoints_with_dirty_policy,
                             set([ENDPOINT_ID]))
            # And an update should be triggered.
            self.assertEqual(m_update.mock_calls, [mock.call()])

    def test_endpoint_update_not_our_host(self):
        ep = {"name": "tap1234"}
        with mock.patch.object(self.mgr, "_is_starting_or_live") as m_sol:
            self.mgr.on_endpoint_update(
                WloadEndpointId("notus", "b", "c", "d"),
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
        m_endpoint = Mock(spec=WorkloadEndpoint)
        self.mgr.objects_by_id[ENDPOINT_ID] = m_endpoint
        # Then send a second update to check that it gets passed on to the
        # WorkloadEndpoint.
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
        m_endpoint = Mock(spec=WorkloadEndpoint)
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
        m_endpoint = Mock(spec=WorkloadEndpoint)
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
        self.config = load_config("felix_default.cfg", global_dict={
            "EndpointReportingEnabled": "False"})
        self.m_ipt_gen = Mock(spec=FelixIptablesGenerator)
        self.m_ipt_gen.endpoint_updates.return_value = {}, {}
        self.m_iptables_updater = Mock(spec=IptablesUpdater)
        self.m_dispatch_chains = Mock(spec=DispatchChains)
        self.m_rules_mgr = Mock(spec=RulesManager)
        self.m_manager = Mock(spec=EndpointManager)
        self.m_fip_manager = Mock(spec=FloatingIPManager)
        self.m_status_rep = Mock(spec=EtcdStatusReporter)

    def get_local_endpoint(self, combined_id, ip_type):
        local_endpoint = endpoint.WorkloadEndpoint(self.config,
                                                   combined_id,
                                                   ip_type,
                                                   self.m_iptables_updater,
                                                   self.m_dispatch_chains,
                                                   self.m_rules_mgr,
                                                   self.m_fip_manager,
                                                   self.m_status_rep)
        local_endpoint._manager = self.m_manager
        return local_endpoint

    def test_on_endpoint_update_v4(self):
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)

        # Call with no data; should be ignored (no configuration to remove).
        local_ep.on_endpoint_update(None, async=True)
        self.step_actor(local_ep)

        ips = ["1.2.3.4/32"]
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
        with mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack,\
                mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
                mock.patch('calico.felix.devices.configure_interface_ipv4') as m_conf,\
                mock.patch('calico.felix.devices.interface_exists') as m_iface_exists,\
                mock.patch('calico.felix.devices.interface_up') as m_iface_up:
            m_iface_exists.return_value = True
            m_iface_up.return_value = True

            local_ep.on_endpoint_update(data, async=True)
            self.step_actor(local_ep)

            self.assertEqual(local_ep._mac, data['mac'])
            m_conf.assert_called_once_with(iface)
            m_set_routes.assert_called_once_with(ip_type,
                                                 set(["1.2.3.4"]),
                                                 iface,
                                                 data['mac'],
                                                 reset_arp=True)
            self.assertFalse(m_rem_conntrack.called)

        # Send through an update with no changes - should be a no-op.
        with mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack,\
                mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
                mock.patch('calico.felix.devices.configure_interface_ipv4') as m_conf:
            local_ep.on_endpoint_update(data, async=True)
            self.step_actor(local_ep)
            self.assertEqual(local_ep._mac, data['mac'])
            self.assertFalse(m_conf.called)
            self.assertFalse(m_set_routes.called)
            self.assertFalse(m_rem_conntrack.called)

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
                                                     set(["1.2.3.4"]),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=True)

        # Change the IP address, causing an iptables and route refresh.
        data = data.copy()
        data["ipv4_nets"] = ["1.2.3.5"]
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
                mock.patch('calico.felix.devices.configure_interface_ipv4') as _m_conf,\
                mock.patch('calico.felix.endpoint.WorkloadEndpoint._update_chains') as _m_up_c,\
                mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack:
            local_ep.on_endpoint_update(data, async=True)
            self.step_actor(local_ep)
            m_set_routes.assert_called_once_with(ip_type,
                                                 set(["1.2.3.5"]),
                                                 iface,
                                                 data['mac'],
                                                 reset_arp=True)
            self.assertFalse(local_ep._update_chains.called)
            m_rem_conntrack.assert_called_once_with(set(["1.2.3.4"]), 4)

        # Change the nat mappings, causing an iptables and route refresh.
        data = data.copy()
        data['ipv4_nat'] = [
            {
                'int_ip': '1.2.3.4',
                'ext_ip': '5.6.7.8'
            }
        ]
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
                mock.patch('calico.felix.devices.configure_interface_ipv4') as _m_conf,\
                mock.patch('calico.felix.endpoint.WorkloadEndpoint._update_chains') as _m_up_c,\
                mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack:
            local_ep.on_endpoint_update(data, async=True)
            self.step_actor(local_ep)
            m_set_routes.assert_called_once_with(ip_type,
                                                 set(["1.2.3.5", "5.6.7.8"]),
                                                 iface,
                                                 data['mac'],
                                                 reset_arp=True)
            local_ep._update_chains.assert_called_once_with()
            self.assertFalse(m_rem_conntrack.called)

        # Send empty data, which deletes the endpoint.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
               mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack:
            local_ep.on_endpoint_update(None, async=True)
            self.step_actor(local_ep)
            m_set_routes.assert_called_once_with(ip_type, set(),
                                                 data["name"], None)
            # Should clean up conntrack entries for all IPs.
            m_rem_conntrack.assert_called_once_with(
                set(['1.2.3.5', '5.6.7.8']), 4
            )

    def test_on_endpoint_update_delete_fail(self):
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)

        ips = ["1.2.3.4/32"]
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
        with mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack,\
                mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
                mock.patch('calico.felix.devices.configure_interface_ipv4') as m_conf,\
                mock.patch('calico.felix.devices.interface_exists') as m_iface_exists,\
                mock.patch('calico.felix.devices.interface_up') as m_iface_up:
            m_iface_exists.return_value = True
            m_iface_up.return_value = True

            local_ep.on_endpoint_update(data, async=True)
            self.step_actor(local_ep)

            self.assertEqual(local_ep._mac, data['mac'])
            m_conf.assert_called_once_with(iface)
            m_set_routes.assert_called_once_with(ip_type,
                                                 set(["1.2.3.4"]),
                                                 iface,
                                                 data['mac'],
                                                 reset_arp=True)
            self.assertFalse(m_rem_conntrack.called)

        # Send empty data, which deletes the endpoint.  Raise an exception
        # from set_routes to check that it's handled.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
               mock.patch('calico.felix.devices.interface_exists', return_value=True),\
               mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack:
            m_set_routes.side_effect = FailedSystemCall("", [], 1, "", "")
            local_ep.on_endpoint_update(None, async=True)
            self.step_actor(local_ep)
            m_set_routes.assert_called_once_with(ip_type, set(),
                                                 data["name"], None)
            # Should clean up conntrack entries for all IPs.
            m_rem_conntrack.assert_called_once_with(
                set(['1.2.3.4']), 4
            )

    def test_on_endpoint_update_v6(self):
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV6
        local_ep = self.get_local_endpoint(combined_id, ip_type)

        # Call with no data; should be ignored (no configuration to remove).
        local_ep.on_endpoint_update(None, async=True)
        self.step_actor(local_ep)

        nets = ["2001::abcd/128"]
        gway = "2020:ab::9876"
        iface = "tapabcdef"
        data = {
            'state': "active",
            'endpoint': "endpoint_id",
            'mac': stub_utils.get_mac(),
            'name': iface,
            'ipv6_nets': nets,
            'ipv6_gateway': gway,
            'profile_ids': ["prof1"]
        }

        # Report an initial update (endpoint creation) and check configured
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
                mock.patch('calico.felix.devices.configure_interface_ipv6') as m_conf,\
                mock.patch('calico.felix.devices.interface_exists') as m_iface_exists,\
                mock.patch('calico.felix.devices.interface_up') as m_iface_up, \
                mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack:
            m_iface_exists.return_value = True
            m_iface_up.return_value = True
            local_ep.on_endpoint_update(data, async=True)
            self.step_actor(local_ep)
            self.assertEqual(local_ep._mac, data['mac'])
            m_conf.assert_called_once_with(iface, gway)
            m_set_routes.assert_called_once_with(ip_type,
                                                 set(["2001::abcd"]),
                                                 iface,
                                                 data['mac'],
                                                 reset_arp=False)
            self.assertFalse(m_rem_conntrack.called)

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
                                                     set(["2001::abcd"]),
                                                     iface,
                                                     data['mac'],
                                                     reset_arp=False)

        # Change the nat mappings, causing an iptables and route refresh.
        data = data.copy()
        nets.append('2001::abce/128')
        data['ipv6_nat'] = [
            {
                'int_ip': '2001::abcd',
                'ext_ip': '2001::abce'
            }
        ]
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
                mock.patch('calico.felix.devices.configure_interface_ipv6') as m_conf,\
                mock.patch('calico.felix.endpoint.WorkloadEndpoint._update_chains') as _m_up_c:
            local_ep.on_endpoint_update(data, async=True)
            self.step_actor(local_ep)
            m_set_routes.assert_called_once_with(
                ip_type,
                set(["2001::abcd", "2001::abce"]),
                iface,
                data['mac'],
                reset_arp=False
            )
            local_ep._update_chains.assert_called_once_with()

        # Send empty data, which deletes the endpoint.
        with mock.patch('calico.felix.devices.set_routes') as m_set_routes,\
                mock.patch('calico.felix.devices.remove_conntrack_flows') as m_rem_conntrack:
            local_ep.on_endpoint_update(None, async=True)
            local_ep.on_unreferenced(async=True)
            self.step_actor(local_ep)
            m_set_routes.assert_called_once_with(ip_type, set(),
                                                 data["name"], None)
            local_ep._finish_msg_batch([], [])  # Should be ignored
            self.m_manager.on_object_cleanup_complete.assert_called_once_with(
                local_ep._id,
                local_ep,
                async=True,
            )
            m_rem_conntrack.assert_called_once_with(set(['2001::abcd',
                                                         '2001::abce']), 6)

    def test_on_interface_update_v4(self):
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
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
                self.assertFalse(m_conf.called)
                self.assertFalse(m_set_routes.called)
                self.assertFalse(local_ep._device_in_sync)

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

    @mock.patch("calico.felix.endpoint.devices", autospec=True)
    def test_tiered_policy_mainline(self, m_devices):
        self.config.plugins["iptables_generator"] = self.m_ipt_gen
        ep = self.get_local_endpoint(ENDPOINT_ID, futils.IPV4)
        mac = stub_utils.get_mac()
        ep.on_endpoint_update(
            {
                'state': "active",
                'endpoint': "endpoint_id",
                'mac': mac,
                'name': "tap1234",
                'ipv4_nets': ["10.0.0.1"],
                'profile_ids': ["prof1"]
            },
            async=True)
        self.step_actor(ep)

        self.assertEqual(
            self.m_ipt_gen.endpoint_updates.mock_calls,
            [
                mock.call(4, 'd', '1234', mac, ['prof1'], {}),
            ]
        )
        self.m_ipt_gen.endpoint_updates.reset_mock()

        tiers = OrderedDict()
        t1_1 = TieredPolicyId("t1", "t1_1")
        t1_2 = TieredPolicyId("t1", "t1_2")
        tiers["t1"] = [t1_1, t1_2]
        t2_1 = TieredPolicyId("t2", "t2_1")
        tiers["t2"] = [t2_1]
        ep.on_tiered_policy_update(tiers, async=True)
        self.step_actor(ep)

        self.assertEqual(
            self.m_ipt_gen.endpoint_updates.mock_calls,
            [
                mock.call(4, 'd', '1234', mac, ['prof1'],
                          OrderedDict([('t1', [TieredPolicyId('t1','t1_1'),
                                               TieredPolicyId('t1','t1_2')]),
                                       ('t2', [TieredPolicyId('t2','t2_1')])]))
            ])

    def test_on_interface_update_v6(self):
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
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
                self.assertFalse(m_conf.called)
                self.assertFalse(m_set_routes.called)
                self.assertFalse(local_ep._device_in_sync)

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
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
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
        self.assertFalse(local_ep._iptables_in_sync)  # Check...
        local_ep._iptables_in_sync = True  # ...then reset
        self.assertTrue(local_ep._device_in_sync)

        # IP update.  Should update routing but not iptables.
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
        self.config.REPORT_ENDPOINT_STATUS = True
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'down'}, async=True
        )

    def test_maybe_update_status_missing_endpoint(self):
        self.config.REPORT_ENDPOINT_STATUS = True
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep._device_is_up = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'down'}, async=True
        )

    def test_maybe_update_status_iptables_failure(self):
        self.config.REPORT_ENDPOINT_STATUS = True
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._device_is_up = True
        local_ep._iptables_in_sync = False
        local_ep._device_in_sync = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'error'}, async=True
        )

    def test_maybe_update_status_device_failure(self):
        self.config.REPORT_ENDPOINT_STATUS = True
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._iptables_in_sync = True
        local_ep._device_is_up = True
        local_ep._device_in_sync = False
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'error'}, async=True
        )

    def test_maybe_update_status_iptables_up(self):
        self.config.REPORT_ENDPOINT_STATUS = True
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._device_is_up = True
        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'up'}, async=True
        )

    def test_maybe_update_status_admin_down(self):
        self.config.REPORT_ENDPOINT_STATUS = True
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "inactive"}
        local_ep._device_is_up = True
        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = True
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'down'}, async=True
        )

    def test_maybe_update_status_oper_down(self):
        self.config.REPORT_ENDPOINT_STATUS = True
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.endpoint = {"state": "active"}
        local_ep._device_is_up = False
        local_ep._iptables_in_sync = True
        local_ep._device_in_sync = False
        local_ep._maybe_update_status()
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, {'status': 'down'}, async=True
        )

    def test_maybe_update_status_iptables_unreferenced(self):
        self.config.REPORT_ENDPOINT_STATUS = True
        combined_id = WloadEndpointId("host_id", "orchestrator_id",
                                      "workload_id", "endpoint_id")
        ip_type = futils.IPV4
        local_ep = self.get_local_endpoint(combined_id, ip_type)
        local_ep.on_unreferenced(async=True)
        self.step_actor(local_ep)
        self.m_status_rep.on_endpoint_status_changed.assert_called_once_with(
            combined_id, futils.IPV4, None, async=True
        )
