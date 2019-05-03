# Copyright (c) 2015-2019 Tigera, Inc. All rights reserved.
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

# Various test data that may be shared across multiple tests.
# Naming follows the approximate format:
#
# <kind>_name<idx>_rev<revision>_<key attributes>
#
# Incrementing name indexes indicate the order in which they would be listed.
#
# The rev (a-z) indicates that it should be possible to switch between different
# revisions of the same data.
#
# The key attributes provide some useful additonal data, for example (a v4 specific
# resource).
import netaddr

from utils import API_VERSION

#
# IPPools
#
ippool_name1_rev1_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'ippool-name1'
    },
    'spec': {
        'cidr': "10.0.1.0/24",
        'ipipMode': 'Always',
        'vxlanMode': 'Never',
        'blockSize': 27,
        'nodeSelector': "foo == 'bar'",
    }
}

ippool_name1_rev1_table = (
    "NAME           CIDR          SELECTOR       \n"
    "ippool-name1   10.0.1.0/24   foo == 'bar'"
)

ippool_name1_rev1_wide_table = (
    "NAME           CIDR          NAT     IPIPMODE   VXLANMODE   DISABLED   SELECTOR       \n"
    "ippool-name1   10.0.1.0/24   false   Always     Never       false      foo == 'bar'"
)

ippool_name1_rev2_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'ippool-name1'
    },
    'spec': {
        'cidr': "10.0.1.0/24",
        'ipipMode': 'Never',
        'vxlanMode': 'Always',
        'nodeSelector': "all()",
    }
}

ippool_name2_rev1_v6 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'ippool-name2'
    },
    'spec': {
        'cidr': "fed0:8001::/64",
        'ipipMode': 'Never',
        'vxlanMode': 'Never',
        'blockSize': 123,
        'nodeSelector': "all()",
    }
}

ippool_name2_rev1_table = (
    "NAME           CIDR             SELECTOR   \n"
    "ippool-name2   fed0:8001::/64   all()"
)


#
# BGPPeers
#
bgppeer_name1_rev1_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-name-123abc',
    },
    'spec':  {
        'node': 'node1',
        'peerIP': '192.168.0.250',
        'asNumber': 64514,
    },
}

bgppeer_name1_rev2_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-name-123abc',
    },
    'spec':  {
        'node': 'node2',
        'peerIP': '192.168.0.251',
        'asNumber': 64515,
    },
}

bgppeer_name2_rev1_v6 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-name-456def',
    },
    'spec': {
        'node': 'node2',
        'peerIP': 'fd5f::6:ee',
        'asNumber': 64590,
    },
}

#
# Network Policy
#
networkpolicy_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'policy-mypolicy1',
        'namespace': 'default'
    },
    'spec': {
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

networkpolicy_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'policy-mypolicy1',
        'namespace': 'default'
    },
    'spec': {
        'order': 100000,
        'selector': "type=='sql'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

networkpolicy_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'policy-mypolicy2',
        'namespace': 'default',
        'generateName': 'test-policy-',
        'deletionTimestamp': '2006-01-02T15:04:07Z',
        'deletionGracePeriodSeconds': 30,
        'ownerReferences': [{
            'apiVersion': 'extensions/v1beta1',
            'blockOwnerDeletion': True,
            'controller': True,
            'kind': 'DaemonSet',
            'name': 'endpoint1',
            'uid': 'test-uid-change',
        }],
        'initializers': {
            'pending': [{
                'name': 'initializer1',
            }],
            'result': {
                'status': 'test-status',
            },
        },
        'clusterName': 'cluster1',
        'labels': {'label1': 'l1', 'label2': 'l2'},
        'annotations': {'key': 'value'},
        'selfLink': 'test-self-link',
        'uid': 'test-uid-change',
        'generation': 3,
        'finalizers': ['finalizer1', 'finalizer2'],
        'creationTimestamp': '2006-01-02T15:04:05Z',
    },
    'spec': {
        'order': 100000,
        'selector': "type=='sql'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

#
# Global Network Policy
#
globalnetworkpolicy_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkPolicy',
    'metadata': {
        'name': 'policy-mypolicy1',
    },
    'spec': {
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

globalnetworkpolicy_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkPolicy',
    'metadata': {
        'name': 'policy-mypolicy1',
    },
    'spec': {
        'order': 100000,
        'selector': "type=='sql'",
        'doNotTrack': True,
        'applyOnForward': True,
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}


#
# Global network sets
#

globalnetworkset_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkSet',
    'metadata': {
        'name': 'net-set1',
    },
    'spec': {
        'nets': [
            "10.0.0.1",
            "11.0.0.0/16",
            "feed:beef::1",
            "dead:beef::96",
        ]
    }
}

# A network set with a large number of entries.  In prototyping this test, I found that there are
# "upstream" limits that cap how large we can go:
#
# - Kubernetes' gRPC API has a 4MB message size limit.
# - etcdv3 has a 1MB value size limit.
many_nets = []
for i in xrange(10000):
    many_nets.append("10.%s.%s.0/28" % (i >> 8, i % 256))
globalnetworkset_name1_rev1_large = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkSet',
    'metadata': {
        'name': 'net-set1',
    },
    'spec': {
        'nets': many_nets,
    }
}

#
# Network sets
#

networkset_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkSet',
    'metadata': {
        'name': 'net-set1'
    },
    'spec': {
        'nets': [
            "10.0.0.1",
            "11.0.0.0/16",
            "feed:beef::1",
            "dead:beef::96",
        ]
    }
}

# A network set with a large number of entries.  In prototyping this test, I found that there are
# "upstream" limits that cap how large we can go:
#
# - Kubernetes' gRPC API has a 4MB message size limit.
# - etcdv3 has a 1MB value size limit.
many_nets = []
for i in xrange(10000):
    many_nets.append("10.%s.%s.0/28" % (i >> 8, i % 256))
networkset_name1_rev1_large = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkSet',
    'metadata': {
        'name': 'net-set1',
        'namespace': 'namespace-1'
    },
    'spec': {
        'nets': many_nets,
    }
}

#
# Host Endpoints
#
hostendpoint_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'HostEndpoint',
    'metadata': {
        'name': 'endpoint1',
        'labels': {'type': 'database'},
    },
    'spec': {
        'interfaceName': 'eth0',
        'profiles': ['prof1', 'prof2'],
        'node': 'host1'
    }
}

hostendpoint_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'HostEndpoint',
    'metadata': {
        'name': 'endpoint1',
        'labels': {'type': 'frontend'}
    },
    'spec': {
        'interfaceName': 'cali7',
        'profiles': ['prof1', 'prof2'],
        'node': 'host2'
    }
}

hostendpoint_name1_rev3 = {
    'apiVersion': API_VERSION,
    'kind': 'HostEndpoint',
    'metadata': {
        'name': 'endpoint1',
        'labels': {'type': 'frontend', 'misc': 'version1'},
        'annotations': {'key': 'value'},
        'selfLink': 'test-self-link',
        'uid': 'test-uid-change',
        'generation': 3,
        'finalizers': ['finalizer1', 'finalizer2'],
        'creationTimestamp': '2006-01-02T15:04:05Z',
    },
    'spec': {
        'interfaceName': 'cali7',
        'profiles': ['prof1', 'prof2'],
        'node': 'host2'
    }
}

#
# Profiles
#
profile_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Profile',
    'metadata': {
        'labels': {'foo': 'bar'},
        'name': 'profile-name1'
    },
    'spec': {
        'egress': [
            {
                'action': 'Allow',
                'source': {
                      'selector': "type=='application'"
                }
            }
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                   'notNets': ['10.3.0.0/16'],
                   'notPorts': ['110:1050'],
                   'notSelector': "type=='apples'",
                   'nets': ['10.2.0.0/16'],
                   'ports': ['100:200'],
                   'selector': "type=='application'"},
                'protocol': 'TCP',
                'source': {
                   'notNets': ['10.1.0.0/16'],
                   'notPorts': [1050],
                   'notSelector': "type=='database'",
                   'nets': ['10.0.0.0/16'],
                   'ports': [1234, '10:20'],
                   'selector': "type=='application'",
                }
            }
        ],
    }
}

profile_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'Profile',
    'metadata': {
        'name': 'profile-name1',
    },
    'spec': {
        'egress': [
            {
                'action': 'Allow'
            }
        ],
        'ingress': [
            {
                'ipVersion': 6,
                'action': 'Deny',
            },
        ],
    }
}

#
# Workload Endpoints
#
workloadendpoint_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'WorkloadEndpoint',
    'metadata': {
        'labels': {
            'projectcalico.org/namespace': 'namespace1',
            'projectcalico.org/orchestrator': 'k8s',
            'type': 'database',
        },
        'name': 'node1-k8s-abcd-eth0',
        'namespace': 'namespace1',
    },
    'spec': {
        'node': 'node1',
        'orchestrator': 'k8s',
        'pod': 'abcd',
        'endpoint': 'eth0',
        'containerID': 'container1234',
        'ipNetworks': ['1.2.3.4/32'],
        'interfaceName': 'cali1234',
        'profiles': ['prof1', 'prof2'],
    }
}

workloadendpoint_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'WorkloadEndpoint',
    'metadata': {
        'labels': {
            'projectcalico.org/namespace': 'namespace1',
            'projectcalico.org/orchestrator': 'cni',
            'type': 'database'
        },
        'name': 'node2-cni-container1234-eth0',
        'namespace': 'namespace1',
    },
    'spec': {
        'node': 'node2',
        'orchestrator': 'cni',
        'endpoint': 'eth0',
        'containerID': 'container1234',
        'ipNetworks': ['1.2.3.4/32'],
        'interfaceName': 'cali1234',
        'profiles': ['prof1', 'prof2'],
    }
}

#
# Nodes
#
node_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Node',
    'metadata': {
        'name': 'node1',
    },
    'spec': {
        'bgp': {
            'ipv4Address': '1.2.3.4/24',
            'ipv6Address': 'aa:bb:cc::ff/120',
        }
    }
}

node_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Node',
    'metadata': {
        'name': 'node2',
    },
    'spec': {
        'bgp': {
            'ipv4Address': '1.2.3.5/24',
            'ipv6Address': 'aa:bb:cc::ee/120',
        }
    }
}

node_name3_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Node',
    'metadata': {
        'name': 'node3',
    },
    'spec': {
        'bgp': {
            'ipv4Address': '1.2.3.6/24',
            'ipv6Address': 'aa:bb:cc::dd/120',
        }
    }
}

#
# BGPConfigs
#
bgpconfig_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'logSeverityScreen': 'Info',
        'nodeToNodeMeshEnabled': True,
        'asNumber': 6512,
    }
}

bgpconfig_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'logSeverityScreen': 'Info',
        'nodeToNodeMeshEnabled': False,
        'asNumber': 6511,
    }
}

bgpconfig_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'bgpconfiguration1',
    },
    'spec': {
        'logSeverityScreen': 'Info',
    }
}

bgpconfig_name2_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'bgpconfiguration1',
    },
    'spec': {
        'logSeverityScreen': 'Debug',
    }
}

bgpconfig_name2_rev3 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'bgpconfiguration1',
    },
    'spec': {
        'logSeverityScreen': 'Debug',
        'nodeToNodeMeshEnabled': True,
    }
}

#
# FelixConfigs
#
felixconfig_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'FelixConfiguration',
    'metadata': {
        'name': 'felixconfiguration1',
    },
    'spec': {
        'chainInsertMode': 'append',
        'defaultEndpointToHostAction': 'Accept',
        'failsafeInboundHostPorts': [
            {'protocol': 'TCP', 'port': 666},
            {'protocol': 'UDP', 'port': 333}, ],
        'failsafeOutboundHostPorts': [
            {'protocol': 'TCP', 'port': 999},
            {'protocol': 'UDP', 'port': 222},
            {'protocol': 'UDP', 'port': 422}, ],
        'interfacePrefix': 'humperdink',
        'ipipMTU': 1521,
        'ipsetsRefreshInterval': '44s',
        'iptablesFilterAllowAction': 'Return',
        'iptablesLockFilePath': '/run/fun',
        'iptablesLockProbeInterval': '500ms',
        'iptablesLockTimeout': '22s',
        'iptablesMangleAllowAction': 'Accept',
        'iptablesMarkMask': 0xff0000,
        'iptablesPostWriteCheckInterval': '12s',
        'iptablesRefreshInterval': '22s',
        'ipv6Support': True,
        'logFilePath': '/var/log/fun.log',
        'logPrefix': 'say-hello-friend',
        'logSeverityScreen': 'Info',
        'maxIpsetSize': 8192,
        'metadataAddr': '127.1.1.1',
        'metadataPort': 8999,
        'netlinkTimeout': '10s',
        'prometheusGoMetricsEnabled': True,
        'prometheusMetricsEnabled': True,
        'prometheusMetricsPort': 11,
        'prometheusProcessMetricsEnabled': True,
        'reportingInterval': '10s',
        'reportingTTL': '99s',
        'routeRefreshInterval': '33s',
        'usageReportingEnabled': False,
    }
}

felixconfig_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'FelixConfiguration',
    'metadata': {
        'name': 'felixconfiguration1',
    },
    'spec': {
        'ipv6Support': False,
        'logSeverityScreen': 'Debug',
        'netlinkTimeout': '11s',
    }
}

# The large values for `netlinkTimeout` and `reportingTTL` will be transformed
# into a different unit type in the format `XhXmXs`.
felixconfig_name1_rev3 = {
    'apiVersion': API_VERSION,
    'kind': 'FelixConfiguration',
    'metadata': {
        'name': 'felixconfiguration1',
    },
    'spec': {
        'ipv6Support': False,
        'logSeverityScreen': 'Debug',
        'netlinkTimeout': '125s',
        'reportingTTL': '9910s',
    }
}

#
# ClusterInfo
#
clusterinfo_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'ClusterInformation',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'clusterGUID': 'cluster-guid1',
        'datastoreReady': True,
    }
}

clusterinfo_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'ClusterInformation',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'clusterGUID': 'cluster-guid2',
        'clusterType': 'cluster-type2',
        'calicoVersion': 'calico-version2',
    }
}

