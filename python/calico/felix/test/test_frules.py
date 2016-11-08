# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
# Copyright 2015 Cisco Systems
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
felix.test.test_frules
~~~~~~~~~~~~~~~~~~~~~~~~~

Tests of iptables rules generation function.
"""
import logging
from mock import Mock, patch, call
from netaddr import IPAddress

from calico.felix import frules
from calico.felix.fiptables import IptablesUpdater
from calico.felix.futils import FailedSystemCall, IPV4
from calico.felix.test.base import BaseTestCase, load_config
from unittest2 import skip

_log = logging.getLogger(__name__)


EXPECTED_TOP_LEVEL_DEPS = {
    'felix-INPUT': set(['felix-FROM-ENDPOINT', 'felix-FROM-HOST-IF']),
    'felix-OUTPUT': set(['felix-TO-HOST-IF']),
    'felix-FORWARD': set(['felix-FROM-ENDPOINT', 'felix-TO-ENDPOINT']),
    'felix-FAILSAFE-IN': set(), 'felix-FAILSAFE-OUT': set()
}


class TestRules(BaseTestCase):

    @skip("golang rewrite")
    @patch("calico.felix.futils.check_call", autospec=True)
    @patch("calico.felix.frules.devices", autospec=True)
    @patch("calico.felix.frules.HOSTS_IPSET_V4", autospec=True)
    def test_install_global_rules(self, m_ipset, m_devices, m_check_call):
        m_devices.interface_exists.return_value = False
        m_devices.interface_up.return_value = False
        m_set_ips = m_devices.set_interface_ips

        env_dict = {
            "FELIX_ETCDADDR": "localhost:4001",
            "FELIX_HOSTNAME": "myhost",
            "FELIX_INTERFACEPREFIX": "tap",
            "FELIX_METADATAADDR": "123.0.0.1",
            "FELIX_METADATAPORT": "1234",
            "FELIX_IPINIPENABLED": "True",
            "FELIX_IPINIPMTU": "1480",
            "FELIX_DEFAULTENDPOINTTOHOSTACTION": "RETURN"
        }
        config = load_config("felix_missing.cfg", env_dict=env_dict)
        config.IP_IN_IP_ADDR = IPAddress("10.0.0.1")

        m_v4_upd = Mock(spec=IptablesUpdater)
        m_v6_upd = Mock(spec=IptablesUpdater)
        m_v6_raw_upd = Mock(spec=IptablesUpdater)
        m_v4_nat_upd = Mock(spec=IptablesUpdater)
        m_v6_nat_upd = Mock(spec=IptablesUpdater)

        frules.install_global_rules(config, m_v4_upd, m_v4_nat_upd,
                                    ip_version=4)
        frules.install_global_rules(config, m_v6_upd, m_v6_nat_upd,
                                    ip_version=6, raw_updater=m_v6_raw_upd)

        self.assertEqual(
            m_v4_nat_upd.ensure_rule_inserted.mock_calls,
            [
                call("POSTROUTING --out-interface tunl0 "
                                  "-m addrtype ! --src-type LOCAL --limit-iface-out "
                                  "-m addrtype --src-type LOCAL "
                                  "-j MASQUERADE",
                                  async=False),
                call("PREROUTING --jump felix-PREROUTING", async=False),
                call("POSTROUTING --jump felix-POSTROUTING", async=False),
                call("OUTPUT --jump felix-OUTPUT", async=False)
            ]
        )

        m_v4_upd.ensure_rule_inserted.assert_has_calls([
                call("INPUT --jump felix-INPUT", async=False),
                call("OUTPUT --jump felix-OUTPUT", async=False),
                call("FORWARD --jump felix-FORWARD", async=False)
            ]
        )

        expected_chains = {
            'felix-FIP-DNAT': [],
            'felix-FIP-SNAT': [],
            'felix-PREROUTING': [
                '--append felix-PREROUTING --jump felix-FIP-DNAT',
                '--append felix-PREROUTING --protocol tcp --dport 80 --destination '
                    '169.254.169.254/32 --jump DNAT --to-destination 123.0.0.1:1234'
            ],
            'felix-POSTROUTING': [
                '--append felix-POSTROUTING --jump felix-FIP-SNAT'
            ],
            'felix-OUTPUT': [
                '--append felix-OUTPUT --jump felix-FIP-DNAT'
            ]
        }
        m_v4_nat_upd.rewrite_chains.assert_called_once_with(
            expected_chains,
            {'felix-PREROUTING': set(['felix-FIP-DNAT']),
             'felix-POSTROUTING': set(['felix-FIP-SNAT']),
             'felix-OUTPUT': set(['felix-FIP-DNAT'])},
            async=False
        )

        expected_chains = {
            'felix-INPUT': [
                '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-INPUT --jump MARK --set-mark 0/0x4000000',
                '--append felix-INPUT --in-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
                '--append felix-INPUT --goto felix-FROM-HOST-IF --match mark --mark 0/0x4000000',
                '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --sport 68 --dport 67 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
                '--append felix-INPUT --jump felix-FROM-ENDPOINT'
            ],
            'felix-OUTPUT': [
                '--append felix-OUTPUT --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-OUTPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-OUTPUT --jump MARK --set-mark 0/0x4000000',
                '--append felix-OUTPUT --out-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
                '--append felix-OUTPUT --goto felix-TO-HOST-IF --match mark --mark 0/0x4000000',
            ],
            'felix-FORWARD': [
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-FORWARD --jump felix-FROM-ENDPOINT --in-interface tap+',
                '--append felix-FORWARD --jump felix-TO-ENDPOINT --out-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --in-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --out-interface tap+'
            ],
            'felix-FAILSAFE-IN': [
                '--append felix-FAILSAFE-IN --protocol tcp --dport 22 --jump ACCEPT'
            ],
            'felix-FAILSAFE-OUT': [
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 2379 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 2380 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 4001 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 7001 --jump ACCEPT'
            ]
        }
        m_v4_upd.rewrite_chains.assert_called_once_with(
            expected_chains,
            EXPECTED_TOP_LEVEL_DEPS,
            async=False
        )

        self.assertEqual(
            m_v6_nat_upd.ensure_rule_inserted.mock_calls,
            [
                call("PREROUTING --jump felix-PREROUTING", async=False),
                call("POSTROUTING --jump felix-POSTROUTING", async=False),
                call("OUTPUT --jump felix-OUTPUT", async=False),
            ]
        )

        m_v6_upd.ensure_rule_inserted.assert_has_calls([
                call("INPUT --jump felix-INPUT", async=False),
                call("OUTPUT --jump felix-OUTPUT", async=False),
                call("FORWARD --jump felix-FORWARD", async=False)
            ]
        )

        expected_chains = {
            'felix-FIP-DNAT': [],
            'felix-FIP-SNAT': [],
            'felix-PREROUTING': [
                '--append felix-PREROUTING --jump felix-FIP-DNAT'
            ],
            'felix-POSTROUTING': [
                '--append felix-POSTROUTING --jump felix-FIP-SNAT'
            ],
            'felix-OUTPUT': [
                '--append felix-OUTPUT --jump felix-FIP-DNAT'
            ]
        }
        m_v6_nat_upd.rewrite_chains.assert_called_once_with(
            expected_chains, {
                'felix-PREROUTING': set(['felix-FIP-DNAT']),
                'felix-POSTROUTING': set(['felix-FIP-SNAT']),
                'felix-OUTPUT': set(['felix-FIP-DNAT'])
            }, async=False
        )

        m_v6_raw_upd.rewrite_chains.assert_called_once_with(
            {'felix-PREROUTING': [
                '--append felix-PREROUTING --jump DROP -m comment '
                '--comment "IPv6 rpfilter failed"'
            ]},
            {
                'felix-PREROUTING': {}
            },
            async=False
        )

        m_ipset.ensure_exists.assert_called_once_with()
        self.assertEqual(
            m_check_call.mock_calls,
            [
                call(["ip", "tunnel", "add", "tunl0", "mode", "ipip"]),
                call(["ip", "link", "set", "tunl0", "mtu", "1480"]),
                call(["ip", "link", "set", "tunl0", "up"]),
            ]
        )
        self.assertEqual(
            m_set_ips.mock_calls,
            [call(IPV4, "tunl0", set([IPAddress("10.0.0.1")]))]
        )

    @skip("golang rewrite")
    @patch("calico.felix.futils.check_call", autospec=True)
    @patch("calico.felix.frules.devices", autospec=True)
    @patch("calico.felix.frules.HOSTS_IPSET_V4", autospec=True)
    def test_install_global_ipip_disabled(self, m_ipset, m_devices, m_check_call):
        m_devices.interface_exists.return_value = False
        m_devices.interface_up.return_value = False
        m_set_ips = m_devices.set_interface_ips

        env_dict = {
            "FELIX_ETCDADDR": "localhost:4001",
            "FELIX_HOSTNAME": "myhost",
            "FELIX_INTERFACEPREFIX": "tap",
            "FELIX_METADATAADDR": "123.0.0.1",
            "FELIX_METADATAPORT": "1234",
            "FELIX_IPINIPENABLED": "false",
            "FELIX_IPINIPMTU": "1480",
            "FELIX_DEFAULTENDPOINTTOHOSTACTION": "RETURN"
        }
        config = load_config("felix_missing.cfg", env_dict=env_dict)

        m_v4_upd = Mock(spec=IptablesUpdater)
        m_v6_upd = Mock(spec=IptablesUpdater)
        m_v6_raw_upd = Mock(spec=IptablesUpdater)
        m_v6_nat_upd = Mock(spec=IptablesUpdater)
        m_v4_nat_upd = Mock(spec=IptablesUpdater)

        frules.install_global_rules(config, m_v4_upd, m_v4_nat_upd,
                                    ip_version=4)
        frules.install_global_rules(config, m_v6_upd, m_v6_nat_upd,
                                    ip_version=6, raw_updater=m_v6_raw_upd)

        self.assertEqual(
            m_v4_nat_upd.ensure_rule_inserted.mock_calls,
            [call("PREROUTING --jump felix-PREROUTING", async=False),
             call("POSTROUTING --jump felix-POSTROUTING", async=False),
             call("OUTPUT --jump felix-OUTPUT", async=False)]
        )

        m_v4_upd.ensure_rule_inserted.assert_has_calls([
                call("INPUT --jump felix-INPUT", async=False),
                call("OUTPUT --jump felix-OUTPUT", async=False),
                call("FORWARD --jump felix-FORWARD", async=False)
            ]
        )

        self.assertEqual(
            m_v4_nat_upd.ensure_rule_removed.mock_calls,
            [call("POSTROUTING --out-interface tunl0 "
                  "-m addrtype ! --src-type LOCAL --limit-iface-out "
                  "-m addrtype --src-type LOCAL "
                  "-j MASQUERADE",
                  async=False)]
        )

        m_v6_raw_upd.ensure_rule_inserted.assert_called_once_with(
            'PREROUTING --in-interface tap+ --match rpfilter --invert --jump '
            'felix-PREROUTING',
            async=False,
        )
        m_v6_raw_upd.rewrite_chains.assert_called_once_with(
            {'felix-PREROUTING': [
                '--append felix-PREROUTING --jump DROP -m comment '
                '--comment "IPv6 rpfilter failed"'
            ]},
            {
                'felix-PREROUTING': {}
            },
            async=False
        )

        self.assertFalse(m_ipset.ensure_exists.called)
        self.assertFalse(m_check_call.called)
        self.assertFalse(m_set_ips.called)

        expected_chains = {
            'felix-FIP-DNAT': [],
            'felix-FIP-SNAT': [],
            'felix-PREROUTING': [
                '--append felix-PREROUTING --jump felix-FIP-DNAT',
                '--append felix-PREROUTING --protocol tcp --dport 80 --destination '
                    '169.254.169.254/32 --jump DNAT --to-destination 123.0.0.1:1234'
            ],
            'felix-POSTROUTING': [
                '--append felix-POSTROUTING --jump felix-FIP-SNAT'
            ],
            'felix-OUTPUT': [
                '--append felix-OUTPUT --jump felix-FIP-DNAT'
            ]
        }
        m_v4_nat_upd.rewrite_chains.assert_called_once_with(
            expected_chains,
            {'felix-PREROUTING': set(['felix-FIP-DNAT']),
             'felix-POSTROUTING': set(['felix-FIP-SNAT']),
             'felix-OUTPUT': set(['felix-FIP-DNAT'])},
            async=False
        )

        expected_chains = {
            'felix-INPUT': [
                '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-INPUT --jump MARK --set-mark 0/0x4000000',
                '--append felix-INPUT --in-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
                '--append felix-INPUT --goto felix-FROM-HOST-IF --match mark --mark 0/0x4000000',
                '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --sport 68 --dport 67 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
                '--append felix-INPUT --jump felix-FROM-ENDPOINT'
            ],
            'felix-OUTPUT': [
                '--append felix-OUTPUT --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-OUTPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-OUTPUT --jump MARK --set-mark 0/0x4000000',
                '--append felix-OUTPUT --out-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
                '--append felix-OUTPUT --goto felix-TO-HOST-IF --match mark --mark 0/0x4000000',
            ],
            'felix-FORWARD': [
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-FORWARD --jump felix-FROM-ENDPOINT --in-interface tap+',
                '--append felix-FORWARD --jump felix-TO-ENDPOINT --out-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --in-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --out-interface tap+'
            ],
            'felix-FAILSAFE-IN': [
                '--append felix-FAILSAFE-IN --protocol tcp --dport 22 --jump ACCEPT'
            ],
            'felix-FAILSAFE-OUT': [
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 2379 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 2380 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 4001 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 7001 --jump ACCEPT'
            ]
        }
        m_v4_upd.rewrite_chains.assert_called_once_with(
            expected_chains,
            EXPECTED_TOP_LEVEL_DEPS,
            async=False
        )

    @skip("golang rewrite")
    @patch("calico.felix.futils.check_call", autospec=True)
    @patch("calico.felix.frules.devices", autospec=True)
    @patch("calico.felix.frules.HOSTS_IPSET_V4", autospec=True)
    def test_install_global_no_ipv6(self, m_ipset, m_devices, m_check_call):
        m_devices.interface_exists.return_value = False
        m_devices.interface_up.return_value = False
        m_set_ips = m_devices.set_interface_ips

        env_dict = {
            "FELIX_ETCDADDR": "localhost:4001",
            "FELIX_HOSTNAME": "myhost",
            "FELIX_INTERFACEPREFIX": "tap",
            "FELIX_METADATAADDR": "123.0.0.1",
            "FELIX_METADATAPORT": "1234",
            "FELIX_IPINIPENABLED": "false",
            "FELIX_IPINIPMTU": "1480",
            "FELIX_DEFAULTENDPOINTTOHOSTACTION": "RETURN"
        }
        config = load_config("felix_missing.cfg", env_dict=env_dict)

        m_v4_upd = Mock(spec=IptablesUpdater)
        m_v4_nat_upd = Mock(spec=IptablesUpdater)

        frules.install_global_rules(config, m_v4_upd, m_v4_nat_upd,
                                    ip_version=4)

        self.assertEqual(
            m_v4_nat_upd.ensure_rule_inserted.mock_calls,
            [call("PREROUTING --jump felix-PREROUTING", async=False),
             call("POSTROUTING --jump felix-POSTROUTING", async=False),
             call("OUTPUT --jump felix-OUTPUT", async=False)]
        )

        m_v4_upd.ensure_rule_inserted.assert_has_calls([
                call("INPUT --jump felix-INPUT", async=False),
                call("OUTPUT --jump felix-OUTPUT", async=False),
                call("FORWARD --jump felix-FORWARD", async=False)
            ]
        )

        self.assertEqual(
            m_v4_nat_upd.ensure_rule_removed.mock_calls,
            [call("POSTROUTING --out-interface tunl0 "
                  "-m addrtype ! --src-type LOCAL --limit-iface-out "
                  "-m addrtype --src-type LOCAL "
                  "-j MASQUERADE",
                  async=False)]
        )

        self.assertFalse(m_ipset.ensure_exists.called)
        self.assertFalse(m_check_call.called)
        self.assertFalse(m_set_ips.called)

        expected_chains = {
            'felix-FIP-DNAT': [],
            'felix-FIP-SNAT': [],
            'felix-PREROUTING': [
                '--append felix-PREROUTING --jump felix-FIP-DNAT',
                '--append felix-PREROUTING --protocol tcp --dport 80 --destination '
                    '169.254.169.254/32 --jump DNAT --to-destination 123.0.0.1:1234'
            ],
            'felix-POSTROUTING': [
                '--append felix-POSTROUTING --jump felix-FIP-SNAT'
            ],
            'felix-OUTPUT': [
                '--append felix-OUTPUT --jump felix-FIP-DNAT'
            ]
        }
        m_v4_nat_upd.rewrite_chains.assert_called_once_with(
            expected_chains,
            {'felix-PREROUTING': set(['felix-FIP-DNAT']),
             'felix-POSTROUTING': set(['felix-FIP-SNAT']),
             'felix-OUTPUT': set(['felix-FIP-DNAT'])},
            async=False
        )

        expected_chains = {
            'felix-INPUT': [
                '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-INPUT --jump MARK --set-mark 0/0x4000000',
                '--append felix-INPUT --in-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
                '--append felix-INPUT --goto felix-FROM-HOST-IF --match mark --mark 0/0x4000000',
                '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --sport 68 --dport 67 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
                '--append felix-INPUT --jump felix-FROM-ENDPOINT'
            ],
            'felix-OUTPUT': [
                '--append felix-OUTPUT --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-OUTPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-OUTPUT --jump MARK --set-mark 0/0x4000000',
                '--append felix-OUTPUT --out-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
                '--append felix-OUTPUT --goto felix-TO-HOST-IF --match mark --mark 0/0x4000000',
            ],
            'felix-FORWARD': [
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-FORWARD --jump felix-FROM-ENDPOINT --in-interface tap+',
                '--append felix-FORWARD --jump felix-TO-ENDPOINT --out-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --in-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --out-interface tap+'
            ],
            'felix-FAILSAFE-IN': [
                '--append felix-FAILSAFE-IN --protocol tcp --dport 22 --jump ACCEPT'
            ],
            'felix-FAILSAFE-OUT': [
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 2379 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 2380 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 4001 --jump ACCEPT',
                '--append felix-FAILSAFE-OUT --protocol tcp --dport 7001 --jump ACCEPT'
            ]
        }
        m_v4_upd.rewrite_chains.assert_called_once_with(
            expected_chains,
            EXPECTED_TOP_LEVEL_DEPS,
            async=False
        )

    def test_install_global_rules_retries_ipip(self):
        m_config = Mock()
        m_config.IFACE_PREFIX = ["tap"]
        m_config.IP_IN_IP_ENABLED = True
        with patch("calico.felix.frules._configure_ipip_device") as m_ipip:
            m_ipip.side_effect = FailedSystemCall("", [], 1, "", "")
            self.assertRaises(FailedSystemCall,
                              frules.install_global_rules,
                              m_config, None, None, 4)
            self.assertEqual(m_ipip.mock_calls,
                             [
                                 call(m_config),
                                 call(m_config)
                             ])

    def test_load_nf_conntrack(self):
        with patch("calico.felix.futils.check_call", autospec=True) as m_call:
            frules.load_nf_conntrack()
        m_call.assert_called_once_with(
            ["conntrack", "-L", "-s", "169.254.45.169"]
        )

    def test_load_nf_conntrack_fail(self):
        with patch("calico.felix.futils.check_call", autospec=True) as m_call:
            m_call.side_effect = FailedSystemCall(
                message="bad call",
                args=["conntrack", "-L",
                      "-s",
                      "169.254.45.169"],
                retcode=1,
                stdout="", stderr="")
            frules.load_nf_conntrack()  # Exception should be caught
        m_call.assert_called_once_with(
            ["conntrack", "-L", "-s", "169.254.45.169"]
        )

    def test_interface_to_chain_suffix(self):
        config = Mock()

        config.IFACE_PREFIX = ['tap']
        self.assertEqual(
            frules.interface_to_chain_suffix(config, 'tap0123456'),
            '0123456')

        config.IFACE_PREFIX = ['tap', 'cali']
        self.assertEqual(
            frules.interface_to_chain_suffix(config, 'tap0123456'),
            '0123456')
        self.assertEqual(
            frules.interface_to_chain_suffix(config, 'cali0123456'),
            '0123456')

        config.IFACE_PREFIX = ['tap', 'tab', 'tabq', 't']
        self.assertEqual(
            frules.interface_to_chain_suffix(config, 'tap0123456'),
            '0123456')
        self.assertEqual(
            frules.interface_to_chain_suffix(config, 'tab0123456'),
            '0123456')
        self.assertEqual(
            frules.interface_to_chain_suffix(config, 'tabq0123456'),
            '0123456')
        self.assertEqual(
            frules.interface_to_chain_suffix(config, 't0123456'),
            '0123456')
