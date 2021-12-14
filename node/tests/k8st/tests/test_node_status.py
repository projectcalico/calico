# Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

import logging
import json
import subprocess
import time

from tests.k8st.test_base import TestBase
from tests.k8st.utils.utils import retry_until_success, kubectl, node_info

_log = logging.getLogger(__name__)

def create_status(name, node, interval):
    kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: CalicoNodeStatus
metadata:
    name: %s
spec:
    node: %s
    classes:
    - Agent
    - BGP
    - Routes
    updatePeriodSeconds: %d
EOF
""" % (name, node, interval))

def read_status(name):
    status_json = kubectl("get caliconodestatus %s -o json" % name)
    status_dict = json.loads(status_json)
    return status_dict['status']

def delete_status(name):
    kubectl("delete caliconodestatuses.crd.projectcalico.org %s" % name)

def is_subdict(small, big):
    return dict(big, **small) == big

class TestNodeMeshStatus(TestBase):
    def setUp(self):
        TestBase.setUp(self)

        # Get 2 worker node names. The first name
        # returned is always the master.
        self.nodes, self.ips, self.ip6s = node_info()

        self.test_node = self.nodes[1]
        self.test_node_ip = self.ips[1]
        self.test_node_ip6s = self.ip6s[1]
        self.status_name = "node-status-0"
        create_status(self.status_name, self.test_node, 10)

    def tearDown(self):
        # Delete resource
        delete_status(self.status_name)

    def test_dual_stack_status(self):
        retry_until_success(lambda: read_status(self.status_name), retries=5, wait_time=1)
        status = read_status(self.status_name)

        # Should have correct agent status.
        self.assert_is_subdict({'state': 'Ready', 'routerID': self.test_node_ip}, status['agent']['birdV4'])
        self.assert_is_subdict({'state': 'Ready', 'routerID': self.test_node_ip}, status['agent']['birdV6'])

        # Should have correct BGP status.
        self.assert_is_subdict({'numberEstablishedV4': 3, 'numberEstablishedV6': 3,
                                'numberNotEstablishedV4': 0, 'numberNotEstablishedV6': 0}, status['bgp'])

        # Should have correct peers and routes status.
        for i in [0, 2, 3]:
            peers = status['bgp']['peersV4']
            self.assert_dictlist_has_subdict({'peerIP': self.ips[i], 'state': 'Established', 'type': 'NodeMesh'}, peers)

            peers = status['bgp']['peersV6']
            self.assert_dictlist_has_subdict({'peerIP': self.ip6s[i], 'state': 'Established', 'type': 'NodeMesh'}, peers)

            # Should have correct route status.
            routes = status['routes']['routesV4']
            self.assert_dictlist_has_subdict({"gateway": self.ips[i], "interface": "eth0", 'type': 'FIB',
                                          "learnedFrom": {
                                              "sourceType": "NodeMesh"
                                          }}, routes)

            routes = status['routes']['routesV6']
            self.assert_dictlist_has_subdict({"gateway": self.ip6s[i], "interface": "eth0", 'type': 'FIB',
                                          "learnedFrom": {
                                              "sourceType": "NodeMesh"
                                          }}, routes)

    def assert_is_subdict(self, small, big):
        self.assertTrue(is_subdict(small, big))

    def assert_dictlist_has_subdict(self, small, bigList):
        for big in bigList:
            if is_subdict(small, big):
                return True
        return False

'''
Sample output of caliconodestatus
{
    "apiVersion": "projectcalico.org/v3",
    "kind": "CalicoNodeStatus",
    "metadata": {
        "annotations": {
            "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"projectcalico.org/v3\",\"kind\":\"CalicoNodeStatus\",\"metadata\":{\"annotations\":{},\"name\":\"node-status-0\"},\"spec\":{\"classes\":[\"Agent\",\"BGP\",\"Routes\"],\"node\":\"kind-worker\",\"updatePeriodSeconds\":10}}\n"
        },
        "creationTimestamp": "2021-11-18T23:04:58Z",
        "name": "node-status-0",
        "resourceVersion": "396418",
        "uid": "e306e68e-d7d7-46fb-80a2-d111676012fa"
    },
    "spec": {
        "classes": [
            "Agent",
            "BGP",
            "Routes"
        ],
        "node": "kind-worker",
        "updatePeriodSeconds": 10
    },
    "status": {
        "agent": {
            "birdV4": {
                "lastBootTime": "2021-11-18 23:06:36",
                "lastReconfigurationTime": "2021-11-18 23:06:36",
                "routerID": "172.18.0.2",
                "state": "Ready",
                "version": "v0.3.3+birdv1.6.8"
            },
            "birdV6": {
                "lastBootTime": "2021-11-18 23:06:36",
                "lastReconfigurationTime": "2021-11-18 23:06:36",
                "routerID": "172.18.0.2",
                "state": "Ready",
                "version": "v0.3.3+birdv1.6.8"
            }
        },
        "bgp": {
            "numberEstablishedV4": 3,
            "numberEstablishedV6": 3,
            "numberNotEstablishedV4": 0,
            "numberNotEstablishedV6": 0,
            "peersV4": [
                {
                    "peerIP": "172.18.0.3",
                    "since": "23:06:37",
                    "state": "Established",
                    "type": "NodeMesh"
                },
                {
                    "peerIP": "172.18.0.4",
                    "since": "23:06:37",
                    "state": "Established",
                    "type": "NodeMesh"
                },
                {
                    "peerIP": "172.18.0.5",
                    "since": "23:06:36",
                    "state": "Established",
                    "type": "NodeMesh"
                }
            ],
            "peersV6": [
                {
                    "peerIP": "2001:20::8",
                    "since": "23:06:36",
                    "state": "Established",
                    "type": "NodeMesh"
                },
                {
                    "peerIP": "2001:20::2",
                    "since": "23:06:37",
                    "state": "Established",
                    "type": "NodeMesh"
                },
                {
                    "peerIP": "2001:20::3",
                    "since": "23:06:36",
                    "state": "Established",
                    "type": "NodeMesh"
                }
            ]
        },
        "lastUpdated": "2021-11-18T23:07:05Z",
        "routes": {
            "routesV4": [
                {
                    "destination": "0.0.0.0/0",
                    "gateway": "172.18.0.1",
                    "interface": "eth0",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "192.168.110.128/26",
                    "gateway": "172.18.0.4",
                    "interface": "eth0",
                    "learnedFrom": {
                        "peerIP": "172.18.0.4",
                        "sourceType": "NodeMesh"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "192.168.82.0/26",
                    "gateway": "172.18.0.3",
                    "interface": "eth0",
                    "learnedFrom": {
                        "peerIP": "172.18.0.3",
                        "sourceType": "NodeMesh"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "192.168.82.0/26",
                    "gateway": "172.18.0.3",
                    "interface": "eth0",
                    "learnedFrom": {
                        "peerIP": "172.18.0.3",
                        "sourceType": "NodeMesh"
                    },
                    "type": "RIB"
                },
                {
                    "destination": "192.168.195.192/26",
                    "gateway": "172.18.0.5",
                    "interface": "eth0",
                    "learnedFrom": {
                        "peerIP": "172.18.0.5",
                        "sourceType": "NodeMesh"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "192.168.195.192/26",
                    "gateway": "172.18.0.5",
                    "interface": "eth0",
                    "learnedFrom": {
                        "peerIP": "172.18.0.5",
                        "sourceType": "NodeMesh"
                    },
                    "type": "RIB"
                },
                {
                    "destination": "192.168.162.128/26",
                    "gateway": "N/A",
                    "interface": "blackhole",
                    "learnedFrom": {
                        "sourceType": "Static"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "192.168.162.128/26",
                    "gateway": "N/A",
                    "interface": "blackhole",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "RIB"
                },
                {
                    "destination": "192.168.162.128/32",
                    "gateway": "N/A",
                    "interface": "calibb219784141",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "192.168.162.129/32",
                    "gateway": "N/A",
                    "interface": "calid15e5529ae8",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "192.168.162.130/32",
                    "gateway": "N/A",
                    "interface": "calia7a3e029a7b",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "192.168.162.132/32",
                    "gateway": "N/A",
                    "interface": "wireguard.cali",
                    "learnedFrom": {
                        "sourceType": "Direct"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "172.18.0.0/16",
                    "gateway": "N/A",
                    "interface": "eth0",
                    "learnedFrom": {
                        "sourceType": "Direct"
                    },
                    "type": "FIB"
                }
            ],
            "routesV6": [
                {
                    "destination": "::/0",
                    "gateway": "fc00:f853:ccd:e793::1",
                    "interface": "eth0",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "fd00:10:244:0:586d:4461:e980:a282/128",
                    "gateway": "N/A",
                    "interface": "calia7a3e029a7b",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "fd00:10:244:0:586d:4461:e980:a280/122",
                    "gateway": "N/A",
                    "interface": "blackhole",
                    "learnedFrom": {
                        "sourceType": "Static"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "fd00:10:244:0:586d:4461:e980:a280/128",
                    "gateway": "N/A",
                    "interface": "calibb219784141",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "fd00:10:244:0:586d:4461:e980:a281/128",
                    "gateway": "N/A",
                    "interface": "calid15e5529ae8",
                    "learnedFrom": {
                        "sourceType": "Kernel"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "2001:20::/64",
                    "gateway": "N/A",
                    "interface": "eth0",
                    "learnedFrom": {
                        "sourceType": "Direct"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "fc00:f853:ccd:e793::/64",
                    "gateway": "N/A",
                    "interface": "eth0",
                    "learnedFrom": {
                        "sourceType": "Direct"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "fd00:10:244:0:58fd:b191:5c13:9cc0/122",
                    "gateway": "2001:20::3",
                    "interface": "eth0",
                    "learnedFrom": {
                        "peerIP": "2001:20::3",
                        "sourceType": "NodeMesh"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "fd00:10:244:0:1cc0:b1ac:ad47:e7c0/122",
                    "gateway": "2001:20::2",
                    "interface": "eth0",
                    "learnedFrom": {
                        "peerIP": "2001:20::2",
                        "sourceType": "NodeMesh"
                    },
                    "type": "FIB"
                },
                {
                    "destination": "fd00:10:244:0:dec7:e00b:6677:b640/122",
                    "gateway": "2001:20::8",
                    "interface": "eth0",
                    "learnedFrom": {
                        "peerIP": "2001:20::8",
                        "sourceType": "NodeMesh"
                    },
                    "type": "FIB"
                }
            ]
        }
    }
}
'''