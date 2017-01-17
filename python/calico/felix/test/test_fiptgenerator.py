# -*- coding: utf-8 -*-
# Copyright (c) 2015-2017 Tigera, Inc. All rights reserved.
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
from collections import OrderedDict
from pprint import pformat

from mock import Mock

from calico.datamodel_v1 import TieredPolicyId
from calico.felix.fiptables import IptablesUpdater
from calico.felix.profilerules import UnsupportedICMPType
from calico.felix.test.base import BaseTestCase, load_config
from unittest2 import skip

_log = logging.getLogger(__name__)

INPUT_CHAINS = {
    "Default": [
        '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
        '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
        '--append felix-INPUT --jump MARK --set-mark 0/0x4000000',
        '--append felix-INPUT --in-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
        '--append felix-INPUT --goto felix-FROM-HOST-IF --match mark --mark 0/0x4000000',
        '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
        '--append felix-INPUT --protocol udp --sport 68 --dport 67 --jump ACCEPT',
        '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
        '--append felix-INPUT --jump DROP -m comment --comment "Drop all packets from endpoints to the host"',
    ],
    "IPIP": [
        '--append felix-INPUT --protocol 4 --match set ! --match-set felix-hosts src --jump DROP',
        '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
        '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
        '--append felix-INPUT --jump MARK --set-mark 0/0x4000000',
        '--append felix-INPUT --in-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
        '--append felix-INPUT --goto felix-FROM-HOST-IF --match mark --mark 0/0x4000000',
        '--append felix-INPUT --protocol tcp --destination 123.0.0.1 --dport 1234 --jump ACCEPT',
        '--append felix-INPUT --protocol udp --sport 68 --dport 67 --jump ACCEPT',
        '--append felix-INPUT --protocol udp --dport 53 --jump ACCEPT',
        '--append felix-INPUT --jump DROP -m comment --comment "Drop all packets from endpoints to the host"',
    ],
    "Return": [
        '--append felix-INPUT --match conntrack --ctstate INVALID --jump DROP',
        '--append felix-INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',
        '--append felix-INPUT --jump MARK --set-mark 0/0x4000000',
        '--append felix-INPUT --in-interface tap+ --jump MARK --set-mark 0x4000000/0x4000000',
        '--append felix-INPUT --goto felix-FROM-HOST-IF --match mark --mark 0/0x4000000',
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

IPSET_ID = "s:abcdefg1234567890_-"

RULES_TESTS = [
    {
        "ip_version": 4,
        "tag_to_ipset": {IPSET_ID: "felix-_123456"},
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {"src_ip_set_ids": [IPSET_ID],
                 "log_prefix": "foo",
                 "action": "next-tier"}
            ],
            "outbound_rules": [
                {"dst_ip_set_ids": [IPSET_ID],
                 "action": "next-tier"}
            ]
        },
        "updates": {
            'felix-p-prof1-i':
                [
                    '--append felix-p-prof1-i '
                    '--match set --match-set felix-_123456 src '
                    '--jump MARK --set-mark 0x2000000/0x2000000',
                    '--append felix-p-prof1-i --match mark '
                    '--mark 0x2000000/0x2000000 --jump LOG '
                    '--log-prefix "foo: " --log-level 5',
                    '--append felix-p-prof1-i --match mark '
                    '--mark 0x2000000/0x2000000 --jump RETURN',
                ],
            'felix-p-prof1-o':
                [
                    '--append felix-p-prof1-o '
                    '--match set --match-set felix-_123456 dst '
                    '--jump MARK --set-mark 0x2000000/0x2000000',
                    '--append felix-p-prof1-o --match mark '
                    '--mark 0x2000000/0x2000000 --jump RETURN',
                ]
        },
    },
    {
        "ip_version": 4,
        "tag_to_ipset": {},
        "sel_to_ipset": {},
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {"log_prefix": "foo", "action": "log"}
            ],
            "outbound_rules": [
                {"action": "log"}
            ]
        },
        "updates": {
            'felix-p-prof1-i':
                [
                    '--append felix-p-prof1-i  --jump LOG '
                    '--log-prefix "foo: " --log-level 5',
                ],
            'felix-p-prof1-o':
                [
                    '--append felix-p-prof1-o  --jump LOG '
                    '--log-prefix "calico-packet: " --log-level 5',
                ]
        },
    },
    {
        "ip_version": 4,
        "tag_to_ipset": {
            "tag1": "t1",
            "tag2": "t2",
            IPSET_ID: "felix-_123456",
        },
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {"protocol": "tcp",
                 "src_net": "10.0.0.0/8",
                 "src_ip_set_ids": ["tag1", IPSET_ID],
                 "src_ports": [1, "2:3"],
                 "!src_net": "11.0.0.0/8",
                 "!src_ip_set_ids": ["tag2", IPSET_ID],
                 "!src_ports": [1, "2:3", 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                14, 15, 16, 17],
                 "action": "next-tier",}
            ],
            "outbound_rules": [
                {"protocol": "udp",
                 "dst_net": "10.0.0.0/8",
                 "dst_ip_set_ids": ["tag1", IPSET_ID],
                 "dst_ports": [1, "2:3"],
                 "!dst_net": "11.0.0.0/8",
                 "!dst_ip_set_ids": ["tag2", IPSET_ID],
                 "!dst_ports": [1, "2:3", 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                14, 15, 16, 17],
                 "action": "next-tier",}
            ]
        },
        "updates": {
            'felix-p-prof1-i': [
                '--append felix-p-prof1-i'
                ' --protocol tcp'
                ' --source 10.0.0.0/8'
                ' --match set --match-set t1 src'
                ' --match set --match-set felix-_123456 src'
                ' --match multiport --source-ports 1,2:3'
                ' ! --source 11.0.0.0/8'
                ' --match set ! --match-set t2 src'
                ' --match set ! --match-set felix-_123456 src'
                ' --match multiport ! --source-ports'
                ' 1,2:3,4,5,6,7,8,9,10,11,12,13,14,15'
                ' --match multiport ! --source-ports 16,17'
                ' --jump MARK --set-mark 0x2000000/0x2000000',

                '--append felix-p-prof1-i'
                ' --match mark --mark 0x2000000/0x2000000 --jump RETURN',
            ],
            'felix-p-prof1-o': [
                '--append felix-p-prof1-o'
                ' --protocol udp'
                ' --destination 10.0.0.0/8'
                ' --match set --match-set t1 dst'
                ' --match set --match-set felix-_123456 dst'
                ' --match multiport --destination-ports 1,2:3'
                ' ! --destination 11.0.0.0/8'
                ' --match set ! --match-set t2 dst'
                ' --match set ! --match-set felix-_123456 dst'
                ' --match multiport ! --destination-ports'
                ' 1,2:3,4,5,6,7,8,9,10,11,12,13,14,15'
                ' --match multiport ! --destination-ports 16,17'
                ' --jump MARK --set-mark 0x2000000/0x2000000',

                '--append felix-p-prof1-o'
                ' --match mark --mark 0x2000000/0x2000000 --jump RETURN',
            ]
        }
    },
    {
        "ip_version": 4,
        "tag_to_ipset": {"tag1": "t1", "tag2": "t2", IPSET_ID: "felix-_123456"},
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {"protocol": "icmp",
                 "!icmp_type": 7,
                 "!icmp_code": 123}
            ],
            "outbound_rules": [
            ]
        },
        "updates": {
            'felix-p-prof1-i': [
                '--append felix-p-prof1-i'
                ' --protocol icmp'
                ' --match icmp ! --icmp-type 7/123'
                ' --jump MARK --set-mark 0x1000000/0x1000000',
                '--append felix-p-prof1-i'
                ' --match mark --mark 0x1000000/0x1000000 --jump RETURN',
            ],
            'felix-p-prof1-o': [
            ]
        }
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
                    '--append felix-p-prof1-i --source 10.0.0.0/8 '
                    '--jump MARK --set-mark 0x1000000/0x1000000',
                    '--append felix-p-prof1-i --match mark '
                    '--mark 0x1000000/0x1000000 --jump RETURN',
                ],
            'felix-p-prof1-o':
                [
                    '--append felix-p-prof1-o --protocol icmp --source '
                    '10.0.0.0/8 --match icmp --icmp-type 7/123 --jump MARK '
                    '--set-mark 0x1000000/0x1000000',
                    '--append felix-p-prof1-o --match mark '
                    '--mark 0x1000000/0x1000000 --jump RETURN',
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
                    "--append felix-p-prof1-i --protocol icmp --source 10.0.0.0/8 "
                    "--match icmp --icmp-type 7 --jump MARK "
                    "--set-mark 0x1000000/0x1000000",
                    '--append felix-p-prof1-i --match mark '
                    '--mark 0x1000000/0x1000000 --jump RETURN',
                ],
            'felix-p-prof1-o':
                [
                    "--append felix-p-prof1-o --protocol tcp "
                    "--match multiport --source-ports 0,2:3,4,5,6,7,8,9,10,11,12,13,14,15 "
                    "--jump MARK --set-mark 0x1000000/0x1000000",
                    '--append felix-p-prof1-o --match mark '
                    '--mark 0x1000000/0x1000000 --jump RETURN',
                    "--append felix-p-prof1-o --protocol tcp "
                    "--match multiport --source-ports 16,17 "
                    "--jump MARK --set-mark 0x1000000/0x1000000",
                    '--append felix-p-prof1-o --match mark '
                    '--mark 0x1000000/0x1000000 --jump RETURN',
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
                 "log_prefix": "dropped",
                 "action": "deny"
                }
            ]
        },
        "updates": {
            'felix-p-prof1-i':
                [
                    "--append felix-p-prof1-i --protocol icmpv6 --source "
                    "1234::beef --match icmp6 --icmpv6-type 7 "
                    "--jump MARK --set-mark 0x1000000/0x1000000",
                    '--append felix-p-prof1-i --match mark '
                    '--mark 0x1000000/0x1000000 --jump RETURN',
                ],
            'felix-p-prof1-o':
                [
                    "--append felix-p-prof1-o --protocol icmpv6 --source "
                    "1234::beef --match icmp6 --icmpv6-type 7 "
                    "--jump LOG --log-prefix \"dropped: \" --log-level 5",
                    "--append felix-p-prof1-o --protocol icmpv6 --source "
                    "1234::beef --match icmp6 --icmpv6-type 7 "
                    "--jump DROP",
                ]
        },
    },

    # Test that ICMPv6 rules are ignored when rendering IPv4 rules.
    {
        "ip_version": 4,
        "tag_to_ipset": {},
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {
                    "protocol": "icmp",
                    "icmp_type": 8,
                }
            ],
            "outbound_rules": [
                {
                    "protocol": "icmpv6",
                    "icmp_type": 8,
                }
            ]
        },
        "updates": {
            'felix-p-prof1-i':
                [
                    "--append felix-p-prof1-i --protocol icmp "
                    "--match icmp --icmp-type 8 --jump MARK "
                    "--set-mark 0x1000000/0x1000000",
                    '--append felix-p-prof1-i --match mark '
                    '--mark 0x1000000/0x1000000 --jump RETURN',
                ],
            'felix-p-prof1-o': []
        },
    },

    # Test that ICMPv4 rules are ignored when rendering IPv6 rules.
    {
        "ip_version": 6,
        "tag_to_ipset": {},
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {
                    "protocol": "icmp",
                    "icmp_type": 8,
                }
            ],
            "outbound_rules": [
                {
                    "protocol": "icmpv6",
                    "icmp_type": 8,
                }
            ]
        },
        "updates": {
            'felix-p-prof1-i': [],
            'felix-p-prof1-o': [
                "--append felix-p-prof1-o --protocol icmpv6 "
                "--match icmp6 --icmpv6-type 8 --jump MARK "
                "--set-mark 0x1000000/0x1000000",
                '--append felix-p-prof1-o --match mark '
                '--mark 0x1000000/0x1000000 --jump RETURN',
            ]
        },
    },

    # Test that rules with IPv4 CIDRs/IPs are ignored when rendering IPv6 rules.
    {
        "ip_version": 6,
        "tag_to_ipset": {},
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {
                    "protocol": "udp",
                    "src_net": "10.0.0.0/24",
                }
            ],
            "outbound_rules": [
                {
                    "protocol": "udp",
                    "dst_net": "1.2.3.4",
                }
            ]
        },
        "updates": {
            'felix-p-prof1-i': [],
            'felix-p-prof1-o': []
        },
    },

    # Test that rules with IPv6 CIDRs/IPs are ignored when rendering IPv4 rules.
    {
        "ip_version": 4,
        "tag_to_ipset": {},
        "profile": {
            "id": "prof1",
            "inbound_rules": [
                {
                    "protocol": "udp",
                    "src_net": "fe80::/96",
                }
            ],
            "outbound_rules": [
                {
                    "protocol": "udp",
                    "dst_net": "fe80::1",
                }
            ]
        },
        "updates": {
            'felix-p-prof1-i': [],
            'felix-p-prof1-o': []
        },
    },
]
FROM_ENDPOINT_CHAIN = [
    # Always start with a 0 MARK.
    '--append felix-from-abcd --jump MARK --set-mark 0/0x1000000',
    # From chain polices the MAC address.
    '--append felix-from-abcd --match mac ! --mac-source aa:22:33:44:55:66 '
               '--jump DROP -m comment --comment '
               '"Incorrect source MAC"',

    # Now the tiered policies.  For each tier we reset the "next tier" mark.
    '--append felix-from-abcd --jump MARK --set-mark 0/0x2000000 '
              '--match comment --comment "Start of tier tier_1"',
    # Then, for each policies, we jump to the policies, and check if it set the
    # accept mark, which immediately accepts.
    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump felix-p-t1p1-o',
    '--append felix-from-abcd '
              '--match mark --mark 0x1000000/0x1000000 '
              '--match comment --comment "Return if policy accepted" '
              '--jump RETURN',

    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump felix-p-t1p2-o',
    '--append felix-from-abcd '
              '--match mark --mark 0x1000000/0x1000000 '
              '--match comment --comment "Return if policy accepted" '
              '--jump RETURN',
    # Then, at the end of the tier, drop if nothing in the tier did a
    # "next-tier"
    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump DROP '
              '-m comment --comment "Drop if no policy in tier passed"',

    # Now the second tier...
    '--append felix-from-abcd '
              '--jump MARK --set-mark 0/0x2000000 --match comment '
              '--comment "Start of tier tier_2"',
    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump felix-p-t2p1-o',
    '--append felix-from-abcd '
              '--match mark --mark 0x1000000/0x1000000 --match comment '
              '--comment "Return if policy accepted" --jump RETURN',
    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump DROP -m comment '
              '--comment "Drop if no policy in tier passed"',

    # Jump to the first profile.
    '--append felix-from-abcd --jump felix-p-prof-1-o',
    # Short-circuit: return if the first profile matched.
    '--append felix-from-abcd --match mark --mark 0x1000000/0x1000000 '
               '--match comment --comment "Profile accepted packet" '
               '--jump RETURN',

    # Jump to second profile.
    '--append felix-from-abcd --jump felix-p-prof-2-o',
    # Return if the second profile matched.
    '--append felix-from-abcd --match mark --mark 0x1000000/0x1000000 '
               '--match comment --comment "Profile accepted packet" '
               '--jump RETURN',

    # Drop the packet if nothing matched.
    '--append felix-from-abcd --jump DROP -m comment --comment '
               '"Packet did not match any profile (endpoint e1)"'
]

TO_ENDPOINT_CHAIN = [
    # Always start with a 0 MARK.
    '--append felix-to-abcd --jump MARK --set-mark 0/0x1000000',

    # Then do the tiered policies in order.  Tier 1:
    '--append felix-to-abcd --jump MARK --set-mark 0/0x2000000 '
            '--match comment --comment "Start of tier tier_1"',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 '
            '--jump felix-p-t1p1-i',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
            '--match comment --comment "Return if policy accepted" --jump RETURN',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 '
            '--jump felix-p-t1p2-i',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
            '--match comment --comment "Return if policy accepted" --jump RETURN',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 --jump DROP '
            '-m comment --comment "Drop if no policy in tier passed"',
    # Tier 2:
    '--append felix-to-abcd --jump MARK --set-mark 0/0x2000000 '
            '--match comment --comment "Start of tier tier_2"',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 '
            '--jump felix-p-t2p1-i',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
            '--match comment --comment "Return if policy accepted" '
            '--jump RETURN',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 --jump DROP '
            '-m comment --comment "Drop if no policy in tier passed"',

    # Jump to first profile and return iff it matched.
    '--append felix-to-abcd --jump felix-p-prof-1-i',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
             '--match comment --comment "Profile accepted packet" '
             '--jump RETURN',

    # Jump to second profile and return iff it matched.
    '--append felix-to-abcd --jump felix-p-prof-2-i',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
             '--match comment --comment "Profile accepted packet" '
             '--jump RETURN',

    # Drop anything that doesn't match.
    '--append felix-to-abcd --jump DROP -m comment --comment '
             '"Packet did not match any profile (endpoint e1)"'
]

FROM_HOST_ENDPOINT_CHAIN = [
    # First the failsafe rules...
    '--append felix-from-abcd --jump felix-FAILSAFE-IN',

    # Always start with a 0 MARK.
    '--append felix-from-abcd --jump MARK --set-mark 0/0x1000000',

    # Now the tiered policies.  For each tier we reset the "next tier" mark.
    '--append felix-from-abcd --jump MARK --set-mark 0/0x2000000 '
              '--match comment --comment "Start of tier tier_1"',
    # Then, for each policies, we jump to the policies, and check if it set the
    # accept mark, which immediately accepts.
    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump felix-p-t1p1-i',
    '--append felix-from-abcd '
              '--match mark --mark 0x1000000/0x1000000 '
              '--match comment --comment "Return if policy accepted" '
              '--jump RETURN',

    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump felix-p-t1p2-i',
    '--append felix-from-abcd '
              '--match mark --mark 0x1000000/0x1000000 '
              '--match comment --comment "Return if policy accepted" '
              '--jump RETURN',
    # Then, at the end of the tier, drop if nothing in the tier did a
    # "next-tier"
    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump DROP '
              '-m comment --comment "Drop if no policy in tier passed"',

    # Now the second tier...
    '--append felix-from-abcd '
              '--jump MARK --set-mark 0/0x2000000 --match comment '
              '--comment "Start of tier tier_2"',
    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump felix-p-t2p1-i',
    '--append felix-from-abcd '
              '--match mark --mark 0x1000000/0x1000000 --match comment '
              '--comment "Return if policy accepted" --jump RETURN',
    '--append felix-from-abcd '
              '--match mark --mark 0/0x2000000 --jump DROP -m comment '
              '--comment "Drop if no policy in tier passed"',

    # Jump to the first profile.
    '--append felix-from-abcd --jump felix-p-prof-1-i',
    # Short-circuit: return if the first profile matched.
    '--append felix-from-abcd --match mark --mark 0x1000000/0x1000000 '
               '--match comment --comment "Profile accepted packet" '
               '--jump RETURN',

    # Jump to second profile.
    '--append felix-from-abcd --jump felix-p-prof-2-i',
    # Return if the second profile matched.
    '--append felix-from-abcd --match mark --mark 0x1000000/0x1000000 '
               '--match comment --comment "Profile accepted packet" '
               '--jump RETURN',

    # Drop the packet if nothing matched.
    '--append felix-from-abcd --jump DROP -m comment --comment '
    '"Packet did not match any profile (endpoint e1)"'
]

TO_HOST_ENDPOINT_CHAIN = [
    # First the failsafe rules...
    '--append felix-to-abcd --jump felix-FAILSAFE-OUT',

    # Always start with a 0 MARK.
    '--append felix-to-abcd --jump MARK --set-mark 0/0x1000000',

    # Then do the tiered policies in order.  Tier 1:
    '--append felix-to-abcd --jump MARK --set-mark 0/0x2000000 '
            '--match comment --comment "Start of tier tier_1"',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 '
            '--jump felix-p-t1p1-o',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
            '--match comment --comment "Return if policy accepted" --jump RETURN',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 '
            '--jump felix-p-t1p2-o',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
            '--match comment --comment "Return if policy accepted" --jump RETURN',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 --jump DROP '
            '-m comment --comment "Drop if no policy in tier passed"',
    # Tier 2:
    '--append felix-to-abcd --jump MARK --set-mark 0/0x2000000 '
            '--match comment --comment "Start of tier tier_2"',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 '
            '--jump felix-p-t2p1-o',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
            '--match comment --comment "Return if policy accepted" '
            '--jump RETURN',
    '--append felix-to-abcd --match mark --mark 0/0x2000000 --jump DROP '
            '-m comment --comment "Drop if no policy in tier passed"',

    # Jump to first profile and return iff it matched.
    '--append felix-to-abcd --jump felix-p-prof-1-o',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
             '--match comment --comment "Profile accepted packet" '
             '--jump RETURN',

    # Jump to second profile and return iff it matched.
    '--append felix-to-abcd --jump felix-p-prof-2-o',
    '--append felix-to-abcd --match mark --mark 0x1000000/0x1000000 '
             '--match comment --comment "Profile accepted packet" '
             '--jump RETURN',

    # Drop anything that doesn't match.
    '--append felix-to-abcd --jump DROP -m comment --comment '
    '"Packet did not match any profile (endpoint e1)"'
]


TAP_FORWARD_CHAIN = [
    # Conntrack rules.
    '--append felix-FORWARD --match conntrack --ctstate INVALID --jump DROP',
    '--append felix-FORWARD --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',

    # Jump to egress and ingress policies.
    '--append felix-FORWARD --jump felix-FROM-ENDPOINT --in-interface tap+',
    '--append felix-FORWARD --jump felix-TO-ENDPOINT --out-interface tap+',

    # Then accept the packet if both pass.
    '--append felix-FORWARD --jump ACCEPT --in-interface tap+',
    '--append felix-FORWARD --jump ACCEPT --out-interface tap+',

    # For non-workload packets, sent to the host endpoint chains.
    "--append felix-FORWARD --jump felix-FROM-HOST-IF",
    "--append felix-FORWARD --jump felix-TO-HOST-IF",
]

TAP_CALI_FORWARD_CHAIN = [
    # Conntrack rules for all interfaces come first.
    '--append felix-FORWARD --match conntrack --ctstate INVALID --jump DROP',
    '--append felix-FORWARD --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT',

    # Then, all policies.  It's important that these come as a block since a packet may be going
    # from one prefix to another so we need to make sure it hits the tap and cali policies
    # before we accept the packet.
    '--append felix-FORWARD --jump felix-FROM-ENDPOINT --in-interface tap+',
    '--append felix-FORWARD --jump felix-TO-ENDPOINT --out-interface tap+',
    '--append felix-FORWARD --jump felix-FROM-ENDPOINT --in-interface cali+',
    '--append felix-FORWARD --jump felix-TO-ENDPOINT --out-interface cali+',

    # Accept traffic that passed all the policies.
    '--append felix-FORWARD --jump ACCEPT --in-interface tap+',
    '--append felix-FORWARD --jump ACCEPT --out-interface tap+',
    '--append felix-FORWARD --jump ACCEPT --in-interface cali+',
    '--append felix-FORWARD --jump ACCEPT --out-interface cali+',

    # For non-workload packets, sent to the host endpoint chains.
    "--append felix-FORWARD --jump felix-FROM-HOST-IF",
    "--append felix-FORWARD --jump felix-TO-HOST-IF",
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
        self.assertEqual(deps, set(["felix-FROM-HOST-IF"]))

    def test_build_input_chain_ipip(self):
        chain, deps = self.iptables_generator.filter_input_chain(
            ip_version=4,
            hosts_set_name="felix-hosts")
        self.assertEqual(chain, INPUT_CHAINS["IPIP"])
        self.assertEqual(deps, set(["felix-FROM-HOST-IF"]))

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
        self.assertEqual(deps, set(["felix-FROM-ENDPOINT",
                                    "felix-FROM-HOST-IF"]))

    def test_forward_chain_single_prefix(self):
        host_dict = {
            "InterfacePrefix": "tap",
        }
        config = load_config("felix_empty.cfg", host_dict=host_dict)
        generator = config.plugins["iptables_generator"]
        chain, deps = generator.filter_forward_chain(ip_version=4)
        self.maxDiff = None
        self.assertEqual(chain, TAP_FORWARD_CHAIN)
        self.assertEqual(deps, set(["felix-FROM-ENDPOINT",
                                    "felix-TO-ENDPOINT",
                                    "felix-TO-HOST-IF",
                                    "felix-FROM-HOST-IF"]))

    def test_forward_chain_multiple_prefixes(self):
        host_dict = {
            "InterfacePrefix": "tap,cali",
        }
        config = load_config("felix_empty.cfg", host_dict=host_dict)
        generator = config.plugins["iptables_generator"]
        chain, deps = generator.filter_forward_chain(ip_version=4)
        self.maxDiff = None
        self.assertEqual(chain, TAP_CALI_FORWARD_CHAIN)
        self.assertEqual(deps, set(["felix-FROM-ENDPOINT",
                                    "felix-TO-ENDPOINT",
                                    "felix-TO-HOST-IF",
                                    "felix-FROM-HOST-IF"]))


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

    def test_tiered_policy_chain_names(self):
        chain_names = self.iptables_generator.profile_chain_names(
            TieredPolicyId("tier", "pol")
        )
        self.assertEqual(chain_names,
                         set(['felix-p-tier/pol-o',
                              'felix-p-tier/pol-i']))

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
            _log.info("Running rules test\n%s", pformat(test))
            updates, deps = self.iptables_generator.profile_updates(
                test["profile"]["id"],
                test["profile"],
                test["ip_version"],
                test["tag_to_ipset"],
            )
            _log.info("Updates:\n%s", pformat(updates))
            _log.info("Deps:\n%s", pformat(deps))
            self.assertEqual((updates, deps), (test["updates"], {}))

    def test_unknown_action(self):
        updates, deps = self.iptables_generator.profile_updates(
            "prof1",
            {
                "inbound_rules": [{"action": "unknown"}],
                "outbound_rules": [{"action": "unknown"}],
            },
            4,
            {},
        )
        self.maxDiff = None
        # Should get back a drop rule.
        drop_rules_i = self.iptables_generator.drop_rules(
            4,
            "felix-p-prof1-i",
            None,
            "ERROR failed to parse rules",
        )
        drop_rules_o = self.iptables_generator.drop_rules(
            4,
            "felix-p-prof1-o",
            None,
            "ERROR failed to parse rules",
        )
        self.assertEqual(
            updates,
            {
                'felix-p-prof1-i': drop_rules_i,
                'felix-p-prof1-o': drop_rules_o
            }
        )

    def test_drop_rules_log_accept(self):
        self.iptables_generator.ACTION_ON_DROP = "LOG-and-ACCEPT"
        drop_rules = self.iptables_generator.drop_rules(
            4, "foo", "--rulespec", "comment"
        )
        self.assertEqual(drop_rules, [
            '--append foo --rulespec --jump LOG '
            '--log-prefix "calico-drop: " --log-level 4 -m comment '
            '--comment "comment"',
            '--append foo --rulespec --jump ACCEPT -m comment --comment '
            '"!SECURITY DISABLED! DROP overridden to ACCEPT" '
            '-m comment --comment "comment"'
        ])

    def test_drop_rules_accept(self):
        self.iptables_generator.ACTION_ON_DROP = "ACCEPT"
        drop_rules = self.iptables_generator.drop_rules(
            4, "foo", "--rulespec", "comment"
        )
        self.assertEqual(drop_rules, [
            '--append foo --rulespec --jump ACCEPT -m comment --comment '
            '"!SECURITY DISABLED! DROP overridden to ACCEPT" '
            '-m comment --comment "comment"'
        ])

    def test_drop_rules_log_drop(self):
        self.iptables_generator.ACTION_ON_DROP = "LOG-and-DROP"
        drop_rules = self.iptables_generator.drop_rules(
            4, "foo", "--rulespec", "comment"
        )
        self.assertEqual(drop_rules, [
            '--append foo --rulespec --jump LOG --log-prefix "calico-drop: " '
            '--log-level 4 -m comment --comment "comment"',
            '--append foo --rulespec --jump DROP -m comment '
            '--comment "comment"'
        ])

    def test_log_prefix(self):
        self.iptables_generator.LOG_PREFIX = "calico-something"
        self.iptables_generator.ACTION_ON_DROP = "LOG-and-DROP"
        drop_rules = self.iptables_generator.drop_rules(
            4, "foo", "--rulespec", "comment"
        )
        self.assertEqual(drop_rules, [
            '--append foo --rulespec --jump LOG --log-prefix "calico-something: " '
            '--log-level 4 -m comment --comment "comment"',
            '--append foo --rulespec --jump DROP -m comment '
            '--comment "comment"'
        ])

    def test_bad_icmp_type(self):
        with self.assertRaises(UnsupportedICMPType):
            self.iptables_generator._rule_to_iptables_fragments_inner(
                "foo", {"icmp_type": 255}, 4, {},
            )

    def test_bad_protocol_with_ports(self):
        with self.assertRaises(AssertionError):
            self.iptables_generator._rule_to_iptables_fragments_inner(
                "foo", {"protocol": "10", "src_ports": [1]}, 4, {},
            )


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

    def test_endpoint_rules(self):
        expected_result = (
            {
                'felix-from-abcd': FROM_ENDPOINT_CHAIN,
                'felix-to-abcd': TO_ENDPOINT_CHAIN
            },
            {
                # From chain depends on the outbound profiles.
                'felix-from-abcd': set(['felix-p-prof-1-o',
                                        'felix-p-prof-2-o',
                                        'felix-p-t1p1-o',
                                        'felix-p-t1p2-o',
                                        'felix-p-t2p1-o',]),
                # To chain depends on the inbound profiles.
                'felix-to-abcd': set(['felix-p-prof-1-i',
                                      'felix-p-prof-2-i',
                                      'felix-p-t1p1-i',
                                      'felix-p-t1p2-i',
                                      'felix-p-t2p1-i',])
            }
        )
        tiered_policies = OrderedDict()
        tiered_policies["tier_1"] = ["t1p1", "t1p2"]
        tiered_policies["tier_2"] = ["t2p1"]
        result = self.iptables_generator.endpoint_updates(4, "e1", "abcd",
                                                          "aa:22:33:44:55:66",
                                                          ["prof-1", "prof-2"],
                                                          tiered_policies)

        # Log the whole diff if the comparison fails.
        self.maxDiff = None
        self.assertEqual(result, expected_result)

    def test_host_endpoint_rules(self):
        expected_result = (
            {
                'felix-from-abcd': FROM_HOST_ENDPOINT_CHAIN,
                'felix-to-abcd': TO_HOST_ENDPOINT_CHAIN
            },
            {
                # From chain depends on the outbound profiles.
                'felix-to-abcd': set(['felix-FAILSAFE-OUT',
                                      'felix-p-prof-1-o',
                                      'felix-p-prof-2-o',
                                      'felix-p-t1p1-o',
                                      'felix-p-t1p2-o',
                                      'felix-p-t2p1-o', ]),
                # To chain depends on the inbound profiles.
                'felix-from-abcd': set(['felix-FAILSAFE-IN',
                                        'felix-p-prof-1-i',
                                        'felix-p-prof-2-i',
                                        'felix-p-t1p1-i',
                                        'felix-p-t1p2-i',
                                        'felix-p-t2p1-i', ])
            }
        )
        tiered_policies = OrderedDict()
        tiered_policies["tier_1"] = ["t1p1", "t1p2"]
        tiered_policies["tier_2"] = ["t2p1"]
        result = self.iptables_generator.host_endpoint_updates(
            4, "e1", "abcd", ["prof-1", "prof-2"], tiered_policies
        )

        # Log the whole diff if the comparison fails.
        self.maxDiff = None
        self.assertEqual(result, expected_result)
