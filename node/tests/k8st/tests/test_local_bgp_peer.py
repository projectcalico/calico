# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
import subprocess
import os
import time

from tests.k8st.test_base import TestBase, Pod
from tests.k8st.utils.utils import start_external_node_with_bgp, \
        retry_until_success, run, curl, DiagsCollector, calicoctl, kubectl, node_info, NGINX_IMAGE

_log = logging.getLogger(__name__)

bird_conf_tor = """
# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 63000;
  multihop;
  gateway recursive; # This should be the default, but just in case.
  import all;        # Import all routes, since we don't know what the upstream
                     # topology is and therefore have to trust the ToR/RR.
  export all;
  source address ip@local;  # The local address we use for the TCP connection
  add paths on;
  graceful restart;  # See comment in kernel section about graceful restart.
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}

# ------------- Node-to-node mesh -------------
protocol bgp Mesh_with_master_node from bgp_template {
  neighbor %s as 64512;
  passive on; 
}

protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on; 
}

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on; 
}

protocol bgp Mesh_with_node_3 from bgp_template {
  neighbor %s as 64512;
  passive on;
}
"""


class _TestLocalBGPPeer(TestBase):

    def setUp(self):
        super(_TestLocalBGPPeer, self).setUp()

        self.router_id_seq = 0

        # Create bgp test namespace
        self.ns = "bgp-test"
        self.create_namespace(self.ns)

        self.nodes, self.ips, _ = node_info()
        self.external_node_ip = start_external_node_with_bgp(
            "kind-node-tor",
            bird_peer_config=self.get_bird_conf_tor(),
        )

        # Enable debug logging on BGP and set endpointStatusPathPrefix
        self.update_ds_env("calico-node",
                           "kube-system",
                           {"BGP_LOGSEVERITYSCREEN": "debug",
                            "FELIX_EndpointStatusPathPrefix": "/var/run/calico"})
        
                # Establish BGPPeer from cluster nodes to tor
        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: node-tor-peer
spec:
  peerIP: %s
  asNumber: 63000
EOF
""" % self.external_node_ip)
        
        # Create three pods. Name format : color-pod-host-sequence number
        # kind-worker node starts from nodes[1]
        self.red_pod_0_0 = self.create_workload_pod(self.nodes[1], "red-pod-0-0", self.ns, "red")
        self.red_pod_1_0 = self.create_workload_pod(self.nodes[2], "red-pod-1-0", self.ns, "red")
        self.blue_pod_0_0 = self.create_workload_pod(self.nodes[1], "blue-pod-0-0", self.ns, "blue")
        self.blue_pod_1_0 = self.create_workload_pod(self.nodes[2], "blue-pod-1-0", self.ns, "blue")
       
        for p in [self.red_pod_0_0, self.red_pod_1_0, self.blue_pod_0_0, self.blue_pod_1_0]:
          p.wait_ready()
          self.setup_workload_pod_v4(p)
          self.setup_workload_pod_v6(p)
        

        # Establish BGPPeer from cluster nodes to node-tor
        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
 name: default
spec:
  localWorkloadPeeringIPV4: 169.254.0.179
  localWorkloadPeeringIPV6: fd12:3456:789a::1
  nodeToNodeMeshEnabled: false
  asNumber: 64512
""")

        kubectl("""apply -f - << EOF    
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
 name: global-peer
spec:
 localWorkloadSelector: color == 'red'
 asNumber: 65401

---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
 name: node-peer
spec:
 nodeSelector: kubernetes.io/hostname == 'kind-worker2' 
 localWorkloadSelector: color == 'blue'
 asNumber: 65401
EOF
""")

    def tearDown(self):
        super(_TestLocalBGPPeer, self).tearDown()
        self.delete_and_confirm(self.ns, "ns")
        try:
            # Delete the extra node.
            run("docker rm -f kind-node-tor")
        except subprocess.CalledProcessError:
            pass

        # Delete BGPPeers.
        calicoctl("delete bgppeer global-peer", allow_fail=True)
        calicoctl("delete bgppeer node-peer", allow_fail=True)

        # Restore node-to-node mesh.
        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata: {name: default}
spec:
  nodeToNodeMeshEnabled: true
  asNumber: 64512
EOF
""")
        
    def create_workload_pod(self, host, name, ns="default", color="red"):
        """
        Create pod as workload peer.
        """

        pod = Pod(ns, name, image=None, yaml="""
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    color: %s
spec:
  containers:
  - name: bird
    image: calico/bird:v0.3.3-211-g9111ec3c
  nodeName: %s
""" % (name, ns, color, host))
        self.add_cleanup(pod.delete)
        return pod

    def setup_workload_pod_v4(self, pod):
        # Copy bird 
        bird_peer_config = self.get_bird_config_workload("65401", "169.254.0.179", "64512")
        with open('peers.conf', 'w') as peerconfig:
            peerconfig.write(bird_peer_config)

        run("kubectl cp peers.conf %s/%s:/etc/bird.conf" % (pod.ns, pod.name))
        run("kubectl exec -t %s -n %s -- sh -c 'birdcl configure'" % (pod.name, pod.ns))

        run("rm peers.conf")

        #run("kubectl exec -t %s -n %s -- sh -c 'ip route add 10.244.0.64/24 via 192.168.0.8'" % (pod.name, pod.ns))

    def setup_workload_pod_v6(self, pod):
        # Copy bird 
        bird_peer_config = self.get_bird_config_workload("65401", "fd12:3456:789a::1", "64512")
        with open('peers.conf', 'w') as peerconfig:
            peerconfig.write(bird_peer_config)

        run("kubectl cp peers.conf %s/%s:/etc/bird6.conf" % (pod.ns, pod.name))
        run("kubectl exec -t %s -n %s -- sh -c 'birdcl6 configure'" % (pod.name, pod.ns))

        run("rm peers.conf")
    
    def get_bird_conf_tor(self):
        return bird_conf_tor % (self.ips[0], self.ips[1], self.ips[2], self.ips[3])
    
    def get_bird_config_workload(self, as_number_child, local_workload_peer_ip, as_number_parent):
        self.router_id_seq += 1
        return """
router id 172.16.8.%s;

function calico_cird_filter() {
  if ( net ~ 192.168.0.0/16 ) then {
    accept;
  }
  if ( net ~ 10.244.0.0/16 ) then {
    accept;
  }
}

# Configure synchronization between routing tables and kernel.
protocol kernel {
  learn;             # Learn all alien routes from the kernel
  persist;           # Don't remove routes on bird shutdown
  scan time 2;       # Scan kernel routing table every 2 seconds
  import all;
  export filter {
    calico_cird_filter();
    reject;
  };
  graceful restart;  # Turn on graceful restart to reduce potential flaps in
                     # routes when reloading BIRD configuration.  With a full
                     # automatic mesh, there is no way to prevent BGP from
                     # flapping since multiple nodes update their BGP
                     # configuration at the same time, GR is not guaranteed to
                     # work correctly in this scenario.
  merge paths on;    # Allow export multipath routes (ECMP)
}

# Watch interface up/down events.
protocol device {
  debug { states };
  scan time 2;    # Scan interfaces every 2 seconds
}

# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as %s;
  gateway recursive; # This should be the default, but just in case.
  add paths on;
  graceful restart;  # See comment in kernel section about graceful restart.
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
  import filter {
    calico_cird_filter();
    reject;
  };
  export filter {
    calico_cird_filter();
    reject;
  };
  ttl security off;
  multihop;
}

protocol bgp from_workload_to_local_host from bgp_template {
  neighbor %s as %s;
}
""" % (str(self.router_id_seq), as_number_child, local_workload_peer_ip, as_number_parent)
        


class TestLocalBGPPeer(_TestLocalBGPPeer):

    # In the tests of this class we have BGP peers between the
    # cluster nodes (kind-control-plane, kind-worker, kind-worker2, kind-worker3) with ASNumber 64512
    # and the external node (kind-node-tor ASNumber 63000). We test BGP connections between local 
    # workload peers (ASNumber 65401) and the cluster nodes.
    #
    # - The full mesh between the cluster nodes is turned off by
    #   nodeToNodeMeshEnabled: false.
    #
    # - Two pods (red & blue) are deployed on kind-worker node and two pods (red & blue)
    #   are deployed on kind-worker2 node.
    #
    # - A global peer is created to select red pods as local bgp peers. 
    #   A node specific peer is created to select the blud pod on kind-worker2 node.

    # Given a pod, check if should have BGP connections with the host. 
    def check_bgp_connections(self, pod, connection=True):
      output = run("kubectl exec -t %s -n %s -- birdcl6 show protocols" % (pod.name, pod.ns))

    def test_local_bgp_peers(self):
        """
        Runs the tests for local bgp peers
        """

        stop_for_debug()

        # Assert bgp sessions has been established to the following local workloads.
        # red pods on kind-worker and kind-worker2. blue pod on kind-worker2.
        self.check_bgp_connections(self.blue_pod_1_0)



def stop_for_debug():
  # Touch debug file under projectcalico/calico/node to stop the process
  debug_file = "/code/stop-for-debug"
  while os.path.exists(debug_file):
    print("File exists. Sleeping...")
    time.sleep(60)  # Sleep for 10 seconds (adjust as needed)

  print("Debug file does not exist. Continuing...")
