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
felix.test.test_fiptgenerator.py
~~~~~~~~~~~~~~~~~~~~~~~~~

Tests of iptables rules generation function.
"""

import logging
from mock import Mock
from calico.felix.fiptables import IptablesUpdater
from calico.felix.profilerules import UnsupportedICMPType
from calico.felix.test.base import BaseTestCase, load_config

_log = logging.getLogger(__name__)

DEFAULT_MARK = '--append %s --jump MARK --set-mark 1'

DEFAULT_UNMARK = (
    '--append %s '
    '--match comment --comment "No match, fall through to next profile" '
    '--jump MARK --set-mark 0'
)

INPUT_CHAINS = {
    "Default": [
        '--append felix-INPUT ! --in-interface tap+ --jump RETURN',
        '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
        '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
        '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
        '--append felix-INPUT --protocol udp --sport 68 --dport 67 '
        '--jump ACCEPT',
        '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
        '--append felix-INPUT --jump DROP -m comment --comment "Drop all packets from endpoints to the host"',
    ],
    "IPIP": [
        '--append felix-INPUT --protocol 4 --match set ! --match-set felix-hosts src --jump DROP',
        '--append felix-INPUT ! --in-interface tap+ --jump RETURN',
        '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
        '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
        '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
        '--append felix-INPUT --protocol udp --sport 68 --dport 67 '
        '--jump ACCEPT',
        '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
        '--append felix-INPUT --jump DROP -m comment --comment "Drop all packets from endpoints to the host"',
    ],
    "Return": [
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
    ]
}

RULES_TESTS = [
    {
        "ip_version": 4,
        "tag_to_ipset": {
            "src-tag": "src-tag-name",
            "dst-tag": "dst-tag-name"
        },
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {"src_net": "10.0.0.0/8"}
            ],
            "outbound_rules": [
                {"protocol": "icmp",
                 "src_net": "10.0.0.0/8",
                 "icmp_type": 7,
                 "icmp_code": 123}
            ]
        },
        "updates": {
            'felix-p-prof1-i':
                [
                    DEFAULT_MARK % "felix-p-prof1-i",
                    '--append felix-p-prof1-i --source 10.0.0.0/8 --jump RETURN',
                    DEFAULT_UNMARK % "felix-p-prof1-i",
                ],
            'felix-p-prof1-o':
                [
                    DEFAULT_MARK % "felix-p-prof1-o",
                    "--append felix-p-prof1-o --protocol icmp --source "
                    "10.0.0.0/8 --match icmp --icmp-type 7/123 --jump RETURN",
                    DEFAULT_UNMARK % "felix-p-prof1-o",
                ]
        },
    },
    {
        "ip_version": 4,
        "tag_to_ipset": {
            "src-tag": "src-tag-name",
            "dst-tag": "dst-tag-name"
        },
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {"protocol": "icmp",
                 "src_net": "10.0.0.0/8",
                 "icmp_type": 7
                }
            ],
            "outbound_rules": [
                {"protocol": "tcp",
                  "src_ports": [0, "2:3", 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                14, 15, 16, 17]
                }
            ]
        },
        "updates": {
            'felix-p-prof1-i':
                [
                    DEFAULT_MARK % "felix-p-prof1-i",
                    "--append felix-p-prof1-i --protocol icmp --source 10.0.0.0/8 "
                    "--match icmp --icmp-type 7 --jump RETURN",
                    DEFAULT_UNMARK % "felix-p-prof1-i",
                ],
            'felix-p-prof1-o':
                [
                    DEFAULT_MARK % "felix-p-prof1-o",
                    "--append felix-p-prof1-o --protocol tcp "
                    "--match multiport --source-ports 0,2:3,4,5,6,7,8,9,10,11,12,13,14,15 "
                    "--jump RETURN",
                    "--append felix-p-prof1-o --protocol tcp "
                    "--match multiport --source-ports 16,17 "
                    "--jump RETURN",
                    DEFAULT_UNMARK % "felix-p-prof1-o",
                ]
        },
    },
    {
        "ip_version": 6,
        "tag_to_ipset": {
            "src-tag": "src-tag-name",
            "dst-tag": "dst-tag-name"
        },
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {"protocol": "icmpv6",
                 "src_net": "1234::beef",
                 "icmp_type": 7
                }
            ],
            "outbound_rules": [
                {"protocol": "icmpv6",
                 "src_net": "1234::beef",
                 "icmp_type": 7,
                 "action": "deny"
                }
            ]
        },
        "updates": {
            'felix-p-prof1-i':
                [
                    DEFAULT_MARK % "felix-p-prof1-i",
                    "--append felix-p-prof1-i --protocol icmpv6 --source "
                    "1234::beef --match icmp6 --icmpv6-type 7 --jump RETURN",
                    DEFAULT_UNMARK % "felix-p-prof1-i",
                ],
            'felix-p-prof1-o':
                [
                    DEFAULT_MARK % "felix-p-prof1-o",
                    "--append felix-p-prof1-o --protocol icmpv6 --source "
                    "1234::beef --match icmp6 --icmpv6-type 7 --jump DROP",
                    DEFAULT_UNMARK % "felix-p-prof1-o",
                ]
        },
    },
]

FROM_ENDPOINT_CHAIN = [
    # Always start with a 0 MARK.
    '--append felix-from-abcd --jump MARK --set-mark 0',
    # From chain polices the MAC address.
    '--append felix-from-abcd --match mac ! --mac-source aa:22:33:44:55:66 '
               '--jump DROP -m comment --comment '
               '"Incorrect source MAC"',

    # Jump to the first profile.
    '--append felix-from-abcd --jump felix-p-prof-1-o',
    # Short-circuit: return if the first profile matched.
    '--append felix-from-abcd --match mark --mark 1/1 --match comment '
               '--comment "Profile accepted packet" '
               '--jump RETURN',

    # Jump to second profile.
    '--append felix-from-abcd --jump felix-p-prof-2-o',
    # Return if the second profile matched.
    '--append felix-from-abcd --match mark --mark 1/1 --match comment '
               '--comment "Profile accepted packet" '
               '--jump RETURN',

    # Drop the packet if nothing matched.
    '--append felix-from-abcd --jump DROP -m comment --comment '
               '"Packet did not match any profile (endpoint e1)"'
]

TO_ENDPOINT_CHAIN = [
    # Always start with a 0 MARK.
    '--append felix-to-abcd --jump MARK --set-mark 0',

    # Jump to first profile and return iff it matched.
    '--append felix-to-abcd --jump felix-p-prof-1-i',
    '--append felix-to-abcd --match mark --mark 1/1 --match comment '
             '--comment "Profile accepted packet" '
             '--jump RETURN',

    # Jump to second profile and return iff it matched.
    '--append felix-to-abcd --jump felix-p-prof-2-i',
    '--append felix-to-abcd --match mark --mark 1/1 --match comment '
             '--comment "Profile accepted packet" '
             '--jump RETURN',

    # Drop anything that doesn't match.
    '--append felix-to-abcd --jump DROP -m comment --comment '
             '"Packet did not match any profile (endpoint e1)"'
]


class TestGlobalChains(BaseTestCase):
    def setUp(self):
        super(TestGlobalChains, self).setUp()
        host_dict = {
            "MetadataAddr": "123.0.0.1",
            "MetadataPort": "1234",
            "DefaultEndpointToHostAction": "DROP"
        }
        self.config = load_config("felix_default.cfg", host_dict=host_dict)
        self.iptables_generator = self.config.plugins["iptables_generator"]

        self.m_iptables_updater = Mock(spec=IptablesUpdater)

    def test_build_input_chain(self):

        chain, deps = self.iptables_generator.filter_input_chain(ip_version=4)
        self.assertEqual(chain, INPUT_CHAINS["Default"])
        self.assertEqual(deps, set())

    def test_build_input_chain_ipip(self):
        chain, deps = self.iptables_generator.filter_input_chain(
            ip_version=4,
            hosts_set_name="felix-hosts")
        self.assertEqual(chain, INPUT_CHAINS["IPIP"])
        self.assertEqual(deps, set())

    def test_build_input_chain_return(self):
        host_dict = {
            "MetadataAddr": "123.0.0.1",
            "MetadataPort": "1234",
            "DefaultEndpointToHostAction": "RETURN"
        }
        config = load_config("felix_default.cfg", host_dict=host_dict)
        chain, deps = config.plugins["iptables_generator"].filter_input_chain(
            ip_version=6)

        self.assertEqual(chain, INPUT_CHAINS["Return"])
        self.assertEqual(deps, set(["felix-FROM-ENDPOINT"]))


class TestRules(BaseTestCase):
    def setUp(self):
        super(TestRules, self).setUp()
        host_dict = {
            "MetadataAddr": "123.0.0.1",
            "MetadataPort": "1234",
            "DefaultEndpointToHostAction": "DROP"
        }
        self.config = load_config("felix_default.cfg", host_dict=host_dict)
        self.iptables_generator = self.config.plugins["iptables_generator"]

        self.m_iptables_updater = Mock(spec=IptablesUpdater)

    def test_profile_chain_names(self):
        chain_names = self.iptables_generator.profile_chain_names("prof1")
        self.assertEqual(chain_names, set(["felix-p-prof1-i", "felix-p-prof1-o"]))

    def test_split_port_lists(self):
        self.assertEqual(
            self.iptables_generator._split_port_lists([1, 2, 3, 4, 5, 6, 7, 8, 9,
                                      10, 11, 12, 13, 14, 15]),
            [['1', '2', '3', '4', '5', '6', '7', '8', '9',
              '10', '11', '12', '13', '14', '15']]
        )
        self.assertEqual(
            self.iptables_generator._split_port_lists([1, 2, 3, 4, 5, 6, 7, 8, 9,
                                      10, 11, 12, 13, 14, 15, 16]),
            [['1', '2', '3', '4', '5', '6', '7', '8', '9',
              '10', '11', '12', '13', '14', '15'],
             ['16']]
        )
        self.assertEqual(
            self.iptables_generator._split_port_lists([1, "2:3", 4, 5, 6, 7, 8, 9,
                                      10, 11, 12, 13, 14, 15, 16, 17]),
            [['1', '2:3', '4', '5', '6', '7', '8', '9',
              '10', '11', '12', '13', '14', '15'],
             ['16', '17']]
        )

    def test_rules_generation(self):
        for test in RULES_TESTS:
            updates, deps = self.iptables_generator.profile_updates(
                test["profile"]["id"],
                test["profile"],
                test["ip_version"],
                test["tag_to_ipset"],
                on_allow=test.get("on_allow", "RETURN"),
                on_deny=test.get("on_deny", "DROP")
            )
            self.assertEqual((updates, deps), (test["updates"], {}))

    def test_bad_icmp_type(self):
        with self.assertRaises(UnsupportedICMPType):
            self.iptables_generator._rule_to_iptables_fragments_inner("foo",
                                                                 {"icmp_type": 255}, 4, {})

    def test_bad_protocol_with_ports(self):
        with self.assertRaises(AssertionError):
            self.iptables_generator._rule_to_iptables_fragments_inner("foo",
                                                                 {"protocol": "10",
                                               "src_ports": [1]}, 4, {})


class TestEndpoint(BaseTestCase):
    def setUp(self):
        super(TestEndpoint, self).setUp()
        self.config = load_config("felix_default.cfg")
        self.iptables_generator = self.config.plugins["iptables_generator"]
        self.m_iptables_updater = Mock(spec=IptablesUpdater)

    def test_endpoint_chain_names(self):
        self.assertEqual(
            self.iptables_generator.endpoint_chain_names("abcd"),
            set(["felix-to-abcd", "felix-from-abcd"]))

    def test_get_endpoint_rules(self):
        expected_result = (
            {
                'felix-from-abcd': FROM_ENDPOINT_CHAIN,
                'felix-to-abcd': TO_ENDPOINT_CHAIN
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
        result = self.iptables_generator.endpoint_updates(4, "e1", "abcd",
                                              "aa:22:33:44:55:66",
                                              ["prof-1", "prof-2"])

        # Log the whole diff if the comparison fails.
        self.maxDiff = None
        self.assertEqual(result, expected_result)



