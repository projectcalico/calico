# Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

data = {}
data['bgppeer_long_node_name'] = {
    'apiVersion': 'v1',
    'kind': 'bgpPeer',
    'metadata': {
        'scope': 'node',
        'node': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My.Spout.Im_Also.A.Very.LongNodeNameTryingTo-CatchOut_UpgradeCode75',
        'peerIP': '192.168.255.255',
    },
    'spec': {
        'asNumber': "4294967294",
    },
}
data['bgppeer_dotted_asn'] = {
    'apiVersion': 'v1',
    'kind': 'bgpPeer',
    'metadata': {
        'scope': 'global',
        'peerIP': '2006::2:1',
    },
    'spec': {
        'asNumber': "1.10",
    },
}
data['hep_tame'] = {
    'apiVersion': 'v1',
    'kind': 'hostEndpoint',
    'metadata': {'labels': {'type': 'production'},
                 'name': 'eth0',
                 'node': 'myhost'},
    'spec': {'expectedIPs': ['192.168.0.1', '192.168.0.2'],
             'interfaceName': 'eth0',
             'profiles': ['profile1', 'profile2']}
}
data['hep_long_fields'] = {
    'apiVersion': 'v1',
    'kind': 'hostEndpoint',
    'metadata': {'labels': {
        '8roper.evil/02.key_name.which.is-also_very.long...1234567890.p': 'frontendFrontEnd.0123456789-_-23wdffrontendFrontEnd.0124679-_-0',
        'calico/k8s_ns': 'default',
        'type': 'type-endFrontEnd.0123456789-_-23wdffrontendFrontEnd.0124679-_-0'},
        'name': '.123Im_a_LongInterfaceNameTryingToCatchOutUpgradeCode75',
        'node': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My.Spout.Im_Also.A.Very.LongNodeNameTryingTo-CatchOut_UpgradeCode75'},
    'spec': {'expectedIPs': ['fd00:1::321'],
             'interfaceName': 'eth0',
             'profiles': ['profile1', 'profile2']}
}
data['hep_label_too_long'] = {
    'apiVersion': 'v1',
    'kind': 'hostEndpoint',
    'metadata': {'labels': {
        '8roper.evil/02.key_name.which.is-also_very.long...1234567890..proper.evil-02.key_name.which.is-also_very.long...1234567890..proper.evil-02.Key_Name.which.is-also_very.long...1234567890..proper.evil-02.key_name.which.is-also_very.long...1234567890..proper.evil-02.Key_name.which.is-also_very.long...1234567890..proper.evil-02.key_name.which.is-also_very.long...1234567890..proper.evil-02.key_Name.which.is-also_very.long...1234567890..proper.evil-02.key_name.which.is-also_very.long...1234567890..proper.evil-02.9': 'frontendFrontEnd.0123456789-_-23wdffrontendFrontEnd.0124679-_-0',
        'calico/k8s_ns': 'default',
        'type': 'type-endFrontEnd.0123456789-_-23wdffrontendFrontEnd.0124679-_-0'},
        'name': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Her.Im_AlsoAVeryLongInterfaceNameTryingToCatchOutUpgradeCode75',
        'node': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My.Spout.Im_Also.A.Very.LongNodeNameTryingTo-CatchOut_UpgradeCode75'},
    'spec': {'expectedIPs': ['fd00:1::321'],
             'interfaceName': 'eth0',
             'profiles': ['profile1', 'profile2']}
}
data['hep_bad_label'] = {
    'apiVersion': 'v1',
    'kind': 'hostEndpoint',
    'metadata': {'labels': {
        '8roper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/Key_Name.which/is-also_very.long...1234567890//proper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/Key_name.which/is-also_very.long...1234567890//proper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/key_Name.which/is-also_very.long...1234567890//proper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/9': 'frontendFrontEnd.0123456789-_-23wdffrontendFrontEnd.0124679-_-0',
        'calico/k8s_ns': 'default',
        'type': 'type-endFrontEnd.0123456789-_-23wdffrontendFrontEnd.0124679-_-0'},
        'name': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Her.Im_AlsoAVeryLongInterfaceNameTryingToCatchOutUpgradeCode75',
        'node': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My.Spout.Im_Also.A.Very.LongNodeNameTryingTo-CatchOut_UpgradeCode75'},
    'spec': {'expectedIPs': ['fd00:1::321'],
             'interfaceName': 'eth0',
             'profiles': ['profile1', 'profile2']}
}
data['hep_name_too_long'] = {
    'apiVersion': 'v1',
    'kind': 'hostEndpoint',
    'metadata': {'labels': {
        'calico/k8s_ns': 'default',
        'type': 'type-endFrontEnd.0123456789-_-23wdffrontendFrontEnd.0124679-_-0'},
        'name': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My.Spout.Im_AlsoAVeryLongInterfaceNameTryingToCatchOutUpgradeCode75',
        'node': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My.Spout.Im_Also.A.Very.LongNodeNameTryingTo-CatchOut_UpgradeCode75'},
    'spec': {'expectedIPs': ['fd00:1::321'],
             'interfaceName': 'eth0',
             'profiles': ['profile1', 'profile2']}
}
data['hep_mixed_ip'] = {
    'apiVersion': 'v1',
    'kind': 'hostEndpoint',
    'metadata': {'labels': {'type': 'production'},
                 'name': 'eth0',
                 'node': 'myotherhost'},
    'spec': {'expectedIPs': ['192.168.0.1',
                             '192.168.0.2',
                             'fd00:ca:fe:1d:52:bb:e9:80'],
             'interfaceName': 'eth0',
             'profiles': ['profile1', 'profile2']}
}
data['ippool_v4_small'] = {
    'apiVersion': 'v1',
    'kind': 'ipPool',
    'metadata': {'cidr': '10.1.0.0/26'},
    'spec': {'disabled': False,
             'ipip': {'enabled': True, 'mode': 'cross-subnet'},
             'nat-outgoing': True}
}
data['ippool_v4_large'] = {
    'apiVersion': 'v1',
    'kind': 'ipPool',
    'metadata': {'cidr': '10.0.0.0/8'},
    'spec': {'disabled': False,
             'ipip': {'enabled': True, 'mode': 'always'},
             'nat-outgoing': True}
}
data['ippool_mixed'] = {
    'apiVersion': 'v1',
    'kind': 'ipPool',
    'metadata': {'cidr': '2006::/64'},
    'spec': {'disabled': False,
             'ipip': {'enabled': False, 'mode': 'always'},
             'nat-outgoing': False}
}
data['node_long_name'] = {
    'apiVersion': 'v1',
    'kind': 'node',
    'metadata': {
        'name': '-Mary_had-A-Little___Lamb--Whose---Fleece-Was-White.As.Snow...She-Also-Had_an-Evil-NodeName_in_order_to.break.upgrade-code201600'},
    'spec': {'bgp': {'asNumber': '7.20',
                     'ipv4Address': '10.244.0.1/24',
                     'ipv6Address': '2001:db8:85a3::8a2e:370:7334/120'}}
}
data['node_tame'] = {
    'apiVersion': 'v1',
    'kind': 'node',
    'metadata': {'name': 'node-hostname'},
    'spec': {'bgp': {'asNumber': 64512,
                     'ipv4Address': '10.244.0.1/24',
                     'ipv6Address': '2001:db8:85a3::8a2e:370:7334/120'}}
}
data['policy_tame'] = {
    'apiVersion': 'v1',
    'kind': 'policy',
    'metadata': {'name': 'allow-tcp-6379'},
    'spec': {'egress': [{'action': 'allow'}],
             'ingress': [{'action': 'allow',
                          'destination': {'ports': [6379]},
                          'protocol': 'tcp',
                          'source': {'selector': "role == 'frontend'"}}],
             'selector': "role == 'database'",
             'types': ['ingress', 'egress']}
}
data['policy_long_name'] = {
    'apiVersion': 'v1',
    'kind': 'policy',
    'metadata': {
        'name': '-Mary_had-A-Little___Lamb--Whose---Fleece-Was-White.As.Snow...She-Also-Had_an-Evil-PolicyName_in_order_to.break.upgrade-code2016'},
    'spec': {'egress': [{'action': 'allow'}],
             'ingress': [{'action': 'allow',
                          'destination': {'ports': [6379]},
                          'protocol': 'tcp',
                          'source': {'nets': ['192.168.0.1/32']}}],
             'selector': "role == 'database'",
             'types': ['ingress', 'egress']}
}
data['profile_tame'] = {
    'apiVersion': 'v1',
    'kind': 'profile',
    'metadata': {'labels': {'profile': 'profile1'}, 'name': 'profile1'},
    'spec': {'egress': [{'action': 'allow'}],
             'ingress': [{'action': 'deny',
                          'source': {'nets': ['10.0.20.0/24']}},
                         {'action': 'allow',
                          'source': {'selector': "profile == 'profile1'"}}]}
}
data['profile_long_labels'] = {
    'apiVersion': 'v1',
    'kind': 'profile',
    'metadata': {'labels': {
        '8roper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/Key_Name.which/is-also_very.long...1234567890//proper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/Key_name.which/is-also_very.long...1234567890//proper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/key_Name.which/is-also_very.long...1234567890//proper/evil-02/key_name.which/is-also_very.long...1234567890//proper/evil-02/9': 'frontendFrontEnd.0123456789-_-23wdffrontendFrontEnd.0124679-_-0'},
        'name': '-Mary_had-A-Little___Lamb--Whose---Fleece-Was-White.As.Snow...She-Also-Had_an-Evil-ProfileName_in_order_to.break.upgradeprofile1'},
    'spec': {'egress': [{'action': 'allow'}],
             'ingress': [{'action': 'deny',
                          'source': {'nets': ['10.0.20.0/24',
                                              '192.168.0.0/32',
                                              '192.168.1.255/32',
                                              '192.168.2.254/32',
                                              '192.168.3.253/32',
                                              '192.168.4.252/32',
                                              '192.168.5.251/32',
                                              '192.168.6.250/32',
                                              '192.168.7.249/32',
                                              '192.168.8.248/32',
                                              '192.168.9.247/32',
                                              '192.168.10.246/32',
                                              '192.168.11.245/32',
                                              '192.168.12.244/32',
                                              '192.168.13.243/32',
                                              '192.168.14.242/32',
                                              '192.168.15.241/32',
                                              '192.168.16.240/32',
                                              '192.168.17.239/32',
                                              '192.168.18.238/32',
                                              '192.168.100.0/32',
                                              '192.168.101.255/32',
                                              '192.168.102.254/32',
                                              '192.168.103.253/32',
                                              '192.168.104.252/32',
                                              '192.168.105.251/32',
                                              '192.168.106.250/32',
                                              '192.168.107.249/32',
                                              '192.168.108.248/32',
                                              '192.168.109.247/32',
                                              '192.168.110.246/32',
                                              '192.168.111.245/32',
                                              '192.168.112.244/32',
                                              '192.168.113.243/32',
                                              '192.168.114.242/32',
                                              '192.168.115.241/32',
                                              '192.168.116.240/32',
                                              '192.168.117.239/32',
                                              '192.168.118.238/32',
                                              '192.168.200.0/32',
                                              '192.168.201.255/32',
                                              '192.168.202.254/32',
                                              '192.168.203.253/32',
                                              '192.168.204.252/32',
                                              '192.168.205.251/32',
                                              '192.168.206.250/32',
                                              '192.168.207.249/32',
                                              '192.168.208.248/32',
                                              '192.168.209.247/32',
                                              '192.168.210.246/32',
                                              '192.168.211.245/32',
                                              '192.168.212.244/32',
                                              '192.168.213.243/32',
                                              '192.168.214.242/32',
                                              '192.168.215.241/32',
                                              '192.168.216.240/32',
                                              '192.168.217.239/32',
                                              '192.168.218.238/32',
                                              '47.0.0.0/8']}},
                         {'action': 'allow',
                          'source': {'selector': "profile == 'profile1'"}}]}
}
data['policy_big'] = {
    'apiVersion': 'v1',
    'kind': 'policy',
    'metadata': {'annotations': {'aname': 'avalue'}, 'name': 'allow-tcp-6379'},
    'spec': {'egress': [{'action': 'allow',
                         'icmp': {'code': 25, 'type': 25},
                         'protocol': 'icmp'}],
             'ingress': [{'action': 'allow',
                          'destination': {'ports': [6379]},
                          'notProtocol': 'udplite',
                          'protocol': 'tcp',
                          'source': {
                              'notSelector': "role != 'something' && thing in {'one', 'two'}",
                              'selector': "role == 'frontend' && thing not in {'three', 'four'}"}},
                         {'action': 'allow',
                          'protocol': 'tcp',
                          'source': {
                              'notSelector': "role != 'something' && thing in {'one', 'two'}"}},
                         {'action': 'deny',
                          'destination': {'notPorts': [80],
                                          'ports': [22, 443]},
                          'protocol': 'tcp'},
                         {'action': 'allow',
                          'source': {'nets': ['172.18.18.200/32',
                                              '172.18.19.0/24']}},
                         {'action': 'allow',
                          'source': {'net': '172.18.18.100/32'}},
                         {'action': 'deny',
                          'source': {'notNet': '172.19.19.100/32'}},
                         {'action': 'deny',
                          'source': {'notNets': ['172.18.0.0/16']}}],
             'order': 1234,
             'selector': "role == 'database' && !has(demo)",
             'types': ['ingress', 'egress']}
}
data['profile_big'] = {
    'apiVersion': 'v1',
    'kind': 'profile',
    'metadata': {'labels': {'profile': 'profile1'},
                 'name': 'profile1',
                 'tags': ['atag', 'btag']},
    'spec': {'egress': [{'action': 'allow',
                         'destination': {'notSelector': "profile == 'system'"}},
                        {'action': 'allow',
                         'source': {'selector': "something in {'a', 'b'}"}},
                        {'action': 'allow',
                         'destination': {'selector': "something not in {'a', 'b'}"}}],
             'ingress': [{'action': 'deny',
                          'destination': {'notPorts': [22, 443, 21, 8080],
                                          'tag': 'atag'},
                          'protocol': 'udp',
                          'source': {'net': '172.20.0.0/16',
                                     'notNet': '172.20.5.0/24',
                                     'notTag': 'dtag',
                                     'tag': 'ctag'}},
                         {'action': 'deny',
                          'destination': {'notPorts': [22, 443, 21, 8080],
                                          'tag': 'atag'},
                          'protocol': 'tcp',
                          'source': {'nets': ['10.0.21.128/25'],
                                     'notNets': ['10.0.20.0/24']}},
                         {'action': 'deny',
                          'protocol': 'tcp',
                          'source': {'notNets': ['10.0.21.128/25']}},
                         {'action': 'allow',
                          'protocol': 'tcp',
                          'source': {'ports': [1234, 4567, 489],
                                     'selector': "profile != 'profile1' && has(role)"}}]}
}
data['wep_lots_ips'] = {
    'apiVersion': 'v1',
    'kind': 'workloadEndpoint',
    'metadata': {'labels': {'app': 'frontend', 'calico/k8s_ns': 'default'},
                 'name': 'eth0',
                 'node': 'rack1-host1',
                 'orchestrator': 'k8s',
                 'workload': 'default.frontend-5gs43'},
    'spec': {'interfaceName': 'cali0ef24ba',
             'ipNetworks': ['192.168.0.0/32',
                            '192.168.1.255/32',
                            '192.168.2.254/32',
                            '192.168.3.253/32',
                            '192.168.4.252/32',
                            '192.168.5.251/32',
                            '192.168.6.250/32',
                            '192.168.7.249/32',
                            '192.168.8.248/32',
                            '192.168.9.247/32',
                            '192.168.10.246/32',
                            '192.168.11.245/32',
                            '192.168.12.244/32',
                            '192.168.13.243/32',
                            '192.168.14.242/32',
                            '192.168.15.241/32',
                            '192.168.16.240/32',
                            '192.168.17.239/32',
                            '192.168.18.238/32',
                            '192.168.100.0/32',
                            '192.168.101.255/32',
                            '192.168.102.254/32',
                            '192.168.103.253/32',
                            '192.168.104.252/32',
                            '192.168.105.251/32',
                            '192.168.106.250/32',
                            '192.168.107.249/32',
                            '192.168.108.248/32',
                            '192.168.109.247/32',
                            '192.168.110.246/32',
                            '192.168.111.245/32',
                            '192.168.112.244/32',
                            '192.168.113.243/32',
                            '192.168.114.242/32',
                            '192.168.115.241/32',
                            '192.168.116.240/32',
                            '192.168.117.239/32',
                            '192.168.118.238/32',
                            '192.168.200.0/32',
                            '192.168.201.255/32',
                            '192.168.202.254/32',
                            '192.168.203.253/32',
                            '192.168.204.252/32',
                            '192.168.205.251/32',
                            '192.168.206.250/32',
                            '192.168.207.249/32',
                            '192.168.208.248/32',
                            '192.168.209.247/32',
                            '192.168.210.246/32',
                            '192.168.211.245/32',
                            '192.168.212.244/32',
                            '192.168.213.243/32',
                            '192.168.214.242/32',
                            '192.168.215.241/32',
                            '192.168.216.240/32',
                            '192.168.217.239/32',
                            '192.168.218.238/32'],
             'mac': 'ca:fe:1d:52:bb:e9',
             'profiles': ['profile1']}
}
data['wep_similar_name'] = {
    'apiVersion': 'v1',
    'kind': 'workloadEndpoint',
    'metadata': {'labels': {'app': 'frontend', 'calico/k8s_ns': 'default'},
                 'name': 'eth0',
                 'node': 'rack1-host1',
                 'orchestrator': 'k8s',
                 'workload': 'default/frontend-5gs43'},
    'spec': {'interfaceName': 'cali0ef24ba',
             'ipNetworks': ['192.168.0.0/32',
                            '192.168.1.255/32',
                            '192.168.2.254/32',
                            '192.168.3.253/32',
                            '192.168.4.252/32',
                            '192.168.5.251/32',
                            '192.168.6.250/32',
                            '192.168.7.249/32',
                            '192.168.8.248/32',
                            '192.168.9.247/32',
                            '192.168.10.246/32',
                            '192.168.11.245/32',
                            '192.168.12.244/32',
                            '192.168.13.243/32',
                            '192.168.14.242/32',
                            '192.168.15.241/32',
                            '192.168.16.240/32',
                            '192.168.17.239/32',
                            '192.168.18.238/32'],
             'mac': 'fe:ed:ca:fe:00:00',
             'profiles': ['profile1']}
}
data['wep_bad_workload_id'] = {
    'apiVersion': 'v1',
    'kind': 'workloadEndpoint',
    'metadata': {'labels': {
        'calico/k8s_ns': 'default'},
        'name': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My.Spout.Im_AlsoAVeryLongInterfaceNameTryingToCatchOutUpgradeCode75',
        'node': '.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My.Spout.Im_Also.A.Very.LongNodeNameTryingTo-CatchOut_UpgradeCode75',
        'orchestrator': 'k8s',
        'workload': 'default.-_.123Im_a_Little.Teapot-Short_And-Stout.Heres-My-Handle_Heres_My_AlsoAVeryLongWorkload-NameTryingToCatchOutUpgradeCode5'},
    'spec': {'interfaceName': 'cali0ef24ba',
             'ipNetworks': ['192.168.255.255/32', 'fd::1:40'],
             'mac': 'ca:fe:1d:52:bb:e9',
             'profiles': ['profile1']}
}
data['wep_similar_name_2'] = {
    'apiVersion': 'v1',
    'kind': 'workloadEndpoint',
    'metadata': {'labels': {'app': 'frontend', 'calico/k8s_ns': 'default'},
                 'name': 'eth0',
                 'node': 'rack1-host1',
                 'orchestrator': 'k8s',
                 'workload': 'default.frontend.5gs43'},
    'spec': {'interfaceName': 'cali0ef24ba',
             'ipNetworks': ['fd00:ca:fe:1d:52:bb:e9:80'],
             'mac': 'ca:fe:1d:52:bb:e9',
             'profiles': ['profile1']}
}
data['do_not_track'] = {
    'apiVersion': 'v1',
    'kind': 'policy',
    'metadata': {'name': 'allow-tcp-555-donottrack'},
    'spec': {'doNotTrack': True,
             'ingress': [{'action': 'allow',
                          'destination': {'ports': [555]},
                          'protocol': 'tcp',
                          'source': {'selector': "role == 'cache'"}}],
             'order': 1230,
             'selector': "role == 'database'",
             'types': ['ingress']}
}
data['prednat_policy'] = {
    'apiVersion': 'v1',
    'kind': 'policy',
    'metadata': {'name': 'allow-cluster-internal-ingress'},
    'spec': {'ingress': [{'action': 'allow',
                          'source': {'nets': ['10.240.0.0/16',
                                              '192.168.0.0/16']}}],
             'order': 10,
             'preDNAT': True,
             'selector': 'has(host-endpoint)'}
}
