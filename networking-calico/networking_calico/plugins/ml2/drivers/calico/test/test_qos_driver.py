# -*- coding: utf-8 -*-
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
Tests for the Calico QoS driver, which tells Neutron's QoS service which rules Calico
can enforce, and passes QoS policy updates on to the mechanism driver.
"""

import mock

import networking_calico.plugins.ml2.drivers.calico.test.lib as lib
from networking_calico.plugins.ml2.drivers.calico import qos_driver


class _Rule(dict):
    """The parts of a Neutron QoS rule object that is_rule_supported() reads."""

    def __init__(self, rule_type, **params):
        super(_Rule, self).__init__(params)
        self.rule_type = rule_type


class TestQoSDriver(lib.Lib):

    def test_registered_for_mechanism_driver(self):
        self.assertIsInstance(qos_driver.DRIVER, qos_driver.CalicoQoSDriver)
        self.assertIs(qos_driver.DRIVER.mechanism_driver, self.driver)
        self.assertEqual(qos_driver.DRIVER.name, "calico")
        self.assertTrue(qos_driver.DRIVER.is_vif_type_compatible("tap"))
        self.assertFalse(qos_driver.DRIVER.is_vif_type_compatible("ovs"))
        self.assertTrue(qos_driver.DRIVER.is_vnic_compatible("normal"))

    def test_update_policy(self):
        context = mock.Mock()
        policy = mock.Mock(id="policy-id")
        with mock.patch.object(self.driver, "handle_qos_policy_update") as m_handle:
            qos_driver.DRIVER.update_policy(context, policy)
        m_handle.assert_called_once_with(context, "policy-id")

    def test_bandwidth_limit_rule_supported(self):
        for direction in ("ingress", "egress"):
            self.assertTrue(
                qos_driver.DRIVER.is_rule_supported(
                    _Rule(
                        "bandwidth_limit",
                        max_kbps=10000,
                        max_burst_kbps=1000,
                        direction=direction,
                    )
                )
            )

    def test_packet_rate_limit_rule_supported_without_burst(self):
        self.assertTrue(
            qos_driver.DRIVER.is_rule_supported(
                _Rule(
                    "packet_rate_limit",
                    max_kpps=5,
                    max_burst_kpps=0,
                    direction="egress",
                )
            )
        )

    def test_packet_rate_limit_burst_not_supported(self):
        # Calico has no equivalent of a packet-rate burst, so only 0 is accepted.
        self.assertFalse(
            qos_driver.DRIVER.is_rule_supported(
                _Rule(
                    "packet_rate_limit",
                    max_kpps=5,
                    max_burst_kpps=1,
                    direction="egress",
                )
            )
        )

    def test_bandwidth_limit_bad_direction_not_supported(self):
        self.assertFalse(
            qos_driver.DRIVER.is_rule_supported(
                _Rule(
                    "bandwidth_limit",
                    max_kbps=10000,
                    max_burst_kbps=0,
                    direction="sideways",
                )
            )
        )

    def test_dscp_marking_not_supported(self):
        self.assertFalse(
            qos_driver.DRIVER.is_rule_supported(_Rule("dscp_marking", dscp_mark=26))
        )
