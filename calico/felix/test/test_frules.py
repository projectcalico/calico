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
"""
felix.test.test_frules
~~~~~~~~~~~~~~~~~~~~~~~~~

Tests of iptables rules generation function.
"""
import logging
from mock import Mock, patch, call, ANY
from calico.felix import frules
from calico.felix.config import Config
from calico.felix.fiptables import IptablesUpdater
from calico.felix.frules import (
    profile_to_chain_name,  rules_to_chain_rewrite_lines, UnsupportedICMPType,
    _rule_to_iptables_fragment
)
from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)

DEFAULT_MARK = ('--append chain-foo --match comment '
                '--comment "Mark as not matched" --jump MARK --set-mark 1')
RULES_TESTS = [
    ([{"src_net": "10.0.0.0/8"},], 4,
     ["--append chain-foo --source 10.0.0.0/8 --jump RETURN",
      DEFAULT_MARK]),

    ([{"protocol": "icmp",
       "src_net": "10.0.0.0/8",
       "icmp_type": 7,
       "icmp_code": 123},], 4,
     ["--append chain-foo --protocol icmp --source 10.0.0.0/8 "
      "--match icmp --icmp-type 7/123 "
      "--jump RETURN",
      DEFAULT_MARK]),

    ([{"protocol": "icmp",
       "src_net": "10.0.0.0/8",
       "icmp_type": 7},], 4,
     ["--append chain-foo --protocol icmp --source 10.0.0.0/8 "
      "--match icmp --icmp-type 7 "
      "--jump RETURN",
      DEFAULT_MARK]),

    ([{"protocol": "icmpv6",
       "src_net": "1234::beef",
       "icmp_type": 7},], 6,
     ["--append chain-foo --protocol icmpv6 --source 1234::beef "
      "--match icmp6 --icmpv6-type 7 "
      "--jump RETURN",
      DEFAULT_MARK]),

    ([{"protocol": "tcp",
       "src_tag": "tag-foo",
       "src_ports": ["0:12", 13]}], 4,
     ["--append chain-foo --protocol tcp "
      "--match set --match-set ipset-foo src "
      "--match multiport --source-ports 0:12,13 --jump RETURN",
      DEFAULT_MARK]),

    ([{"protocol": "tcp",
       "src_ports": [0, "2:3", 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]}], 4,
     ["--append chain-foo --protocol tcp "
      "--match multiport --source-ports 0,2:3,4,5,6,7,8,9,10,11,12,13,14,15 "
      "--jump RETURN",
      "--append chain-foo --protocol tcp "
      "--match multiport --source-ports 16,17 "
      "--jump RETURN",
      DEFAULT_MARK]),
]

IP_SET_MAPPING = {
    "tag-foo": "ipset-foo",
    "tag-bar": "ipset-bar",
}


class TestRules(BaseTestCase):

    def test_profile_to_chain_name(self):
        self.assertEqual(profile_to_chain_name("inbound", "prof1"),
                         "felix-p-prof1-i")
        self.assertEqual(profile_to_chain_name("outbound", "prof1"),
                         "felix-p-prof1-o")

    def test_split_port_lists(self):
        self.assertEqual(
            frules._split_port_lists([1, 2, 3, 4, 5, 6, 7, 8, 9,
                                      10, 11, 12, 13, 14, 15]),
            [['1', '2', '3', '4', '5', '6', '7', '8', '9',
              '10', '11', '12', '13', '14', '15']]
        )
        self.assertEqual(
            frules._split_port_lists([1, 2, 3, 4, 5, 6, 7, 8, 9,
                                      10, 11, 12, 13, 14, 15, 16]),
            [['1', '2', '3', '4', '5', '6', '7', '8', '9',
              '10', '11', '12', '13', '14', '15'],
             ['16']]
        )
        self.assertEqual(
            frules._split_port_lists([1, "2:3", 4, 5, 6, 7, 8, 9,
                                      10, 11, 12, 13, 14, 15, 16, 17]),
            [['1', '2:3', '4', '5', '6', '7', '8', '9',
              '10', '11', '12', '13', '14', '15'],
             ['16', '17']]
        )

    def test_rules_generation(self):
        for rules, ip_version, expected_output in RULES_TESTS:
            fragments = rules_to_chain_rewrite_lines(
                "chain-foo",
                rules,
                ip_version,
                IP_SET_MAPPING,
                on_allow="RETURN",
            )
            self.assertEqual(fragments, expected_output)

    def test_bad_icmp_type(self):
        with self.assertRaises(UnsupportedICMPType):
            _rule_to_iptables_fragment("foo", {"icmp_type": 255}, 4, {})

    def test_bad_protocol_with_ports(self):
        with self.assertRaises(AssertionError):
            _rule_to_iptables_fragment("foo", {"protocol": "10",
                                               "src_ports": [1]}, 4, {})

    def test_build_input_chain(self):
        chain, deps = frules._build_input_chain("tap+",
                                                "123.0.0.1",
                                                1234,
                                                546, 547,
                                                False,
                                                "DROP")
        self.assertEqual(chain, [
            '--append felix-INPUT ! --in-interface tap+ --jump RETURN',
            '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
            '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
            '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
            '--append felix-INPUT --protocol udp --sport 546 --dport 547 --jump ACCEPT',
            '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
            '--append felix-INPUT --jump DROP',
        ])
        self.assertEqual(deps, set())

    def test_build_input_chain_ipip(self):
        chain, deps = frules._build_input_chain("tap+",
                                                "123.0.0.1",
                                                1234,
                                                546, 547,
                                                False,
                                                "DROP",
                                                "felix-hosts")
        self.assertEqual(chain, [
            '--append felix-INPUT --protocol ipencap --match set ! --match-set felix-hosts src --jump DROP',
            '--append felix-INPUT ! --in-interface tap+ --jump RETURN',
            '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
            '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
            '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
            '--append felix-INPUT --protocol udp --sport 546 --dport 547 --jump ACCEPT',
            '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
            '--append felix-INPUT --jump DROP',
        ])
        self.assertEqual(deps, set())

    def test_build_input_chain_return(self):
        chain, deps = frules._build_input_chain("tap+",
                                                None,
                                                None,
                                                546, 547,
                                                True,
                                                "RETURN")
        self.assertEqual(chain, [
            '--append felix-INPUT ! --in-interface tap+ --jump RETURN',
            '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
            '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
            '--append felix-INPUT --jump ACCEPT --protocol ipv6-icmp --icmpv6-type 130',
            '--append felix-INPUT --jump ACCEPT --protocol ipv6-icmp --icmpv6-type 131',
            '--append felix-INPUT --jump ACCEPT --protocol ipv6-icmp --icmpv6-type 132',
            '--append felix-INPUT --jump ACCEPT --protocol ipv6-icmp --icmpv6-type 133',
            '--append felix-INPUT --jump ACCEPT --protocol ipv6-icmp --icmpv6-type 135',
            '--append felix-INPUT --jump ACCEPT --protocol ipv6-icmp --icmpv6-type 136',
            '--append felix-INPUT --protocol udp --sport 546 --dport 547 --jump ACCEPT',
            '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
            '--append felix-INPUT --jump felix-FROM-ENDPOINT',
        ])
        self.assertEqual(deps, set(["felix-FROM-ENDPOINT"]))

    @patch("calico.felix.futils.check_call", autospec=True)
    @patch("calico.felix.frules.devices", autospec=True)
    @patch("calico.felix.frules.HOSTS_IPSET_V4", autospec=True)
    def test_install_global_rules(self, m_ipset, m_devices, m_check_call):
        m_devices.interface_exists.return_value = False
        m_devices.interface_up.return_value = False

        m_config = Mock(spec=Config)
        m_config.IP_IN_IP_ENABLED = True
        m_config.METADATA_IP = "123.0.0.1"
        m_config.METADATA_PORT = 1234
        m_config.DEFAULT_INPUT_CHAIN_ACTION = "RETURN"
        m_config.IFACE_PREFIX = "tap"

        m_v4_upd = Mock(spec=IptablesUpdater)
        m_v6_upd = Mock(spec=IptablesUpdater)
        m_v4_nat_upd = Mock(spec=IptablesUpdater)

        frules.install_global_rules(m_config, m_v4_upd, m_v6_upd, m_v4_nat_upd)

        m_ipset.ensure_exists.assert_called_once_with()
        self.assertEqual(
            m_check_call.mock_calls,
            [
                call(["ip", "tunnel", "add", "tunl0", "mode", "ipip"]),
                call(["ip", "link", "set", "tunl0", "up"]),
            ]
        )

        expected_chains = {
            'felix-INPUT': [
                '--append felix-INPUT ! --in-interface tap+ --jump RETURN',
                '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
                '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --sport 68 --dport 67 --jump ACCEPT',
                '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
                '--append felix-INPUT --jump felix-FROM-ENDPOINT'
            ],
            'felix-FORWARD': [
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate INVALID --jump DROP',
                '--append felix-FORWARD --in-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump RETURN',
                '--append felix-FORWARD --out-interface tap+ --match conntrack --ctstate RELATED,ESTABLISHED --jump RETURN',
                '--append felix-FORWARD --jump felix-FROM-ENDPOINT --in-interface tap+',
                '--append felix-FORWARD --jump felix-TO-ENDPOINT --out-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --in-interface tap+',
                '--append felix-FORWARD --jump ACCEPT --out-interface tap+'
            ]
        }
        m_v4_upd.rewrite_chains.assert_called_once_with(
            expected_chains,
            {
                'felix-INPUT': set(['felix-FROM-ENDPOINT']),
                'felix-FORWARD': set([
                    'felix-FROM-ENDPOINT',
                    'felix-TO-ENDPOINT'
                ])
            },
            async=False
        )

        self.assertEqual(
            m_v4_upd.ensure_rule_inserted.mock_calls,
            [
                call("INPUT --jump felix-INPUT", async=False),
                call("FORWARD --jump felix-FORWARD", async=False),
            ]
        )