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
import os
import random
import subprocess
import time
import enum

from tests.k8st.test_base import TestBase, Pod
from tests.k8st.utils.utils import start_external_node_with_bgp, \
    run, calicoctl, kubectl, node_info, retry_until_success, calico_node_pod_name

_log = logging.getLogger(__name__)

class TopologyMode(enum.Enum):
    RR = "rr"
    MESH = "mesh"

bird_conf_tor_mesh = """
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

bird_conf_tor_rr = """
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

# ------------- RR -------------
protocol bgp RR_with_master_node from bgp_template {
  neighbor %s as 64512;
  passive on;
}
"""


class _TestLocalBGPPeer(TestBase):
    def set_topology(self, value):
        self.topology = value

    def setUp(self):
        super(_TestLocalBGPPeer, self).setUp()

        if self.topology == TopologyMode.MESH:
          _log.info("Topology MESH")
        elif self.topology == TopologyMode.RR:
          _log.info("Topology RR")
        else:
          _log.exception("Topology unknown")

        # Create bgp test namespace
        self.ns = "bgp-test-" + hex(random.randint(0, 0xffffffff))
        self.create_namespace(self.ns)
        self.add_cleanup(lambda: self.delete_and_confirm(self.ns, "ns"))

        self.nodes, self.ips, _ = node_info()

        # Clean up any existing external node just in case it was left over from
        # a previous run.
        self.delete_extra_node()

        # Create the ToR node.
        self.external_node_ip = start_external_node_with_bgp(
            "kind-node-tor",
            bird_peer_config=self.get_bird_conf_tor(),
        )
        self.add_cleanup(self.delete_extra_node)

        # Enable debug logging on BGP and set endpointStatusPathPrefix
        self.update_ds_env("calico-node",
                           "calico-system",
                           {"BGP_LOGSEVERITYSCREEN": "debug",
                            "FELIX_EndpointStatusPathPrefix": "/var/run/calico"})

        # Create the BGP filter to export to the ToR.
        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: export-child-cluster-cidr
spec:
  exportV4:
  - action: Accept
    matchOperator: In
    cidr: 10.123.0.0/16
    source: RemotePeers
  exportV6:
  - action: Accept
    matchOperator: In
    cidr: ca11:c0::/32
    source: RemotePeers
""")
        self.add_cleanup(lambda: calicoctl("delete bgpfilter export-child-cluster-cidr", allow_fail=True))

        if self.topology == TopologyMode.MESH:
          # Establish BGPPeer from cluster nodes to tor
          kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: node-tor-peer
spec:
  peerIP: %s
  asNumber: 63000
  filters:
  - export-child-cluster-cidr
EOF
""" % self.external_node_ip)
          self.add_cleanup(lambda: calicoctl("delete bgppeer node-tor-peer", allow_fail=True))

        if self.topology == TopologyMode.RR:
          # Configure kind-control-plane to be a route reflector (rr)
          kubectl("annotate node kind-control-plane projectcalico.org/RouteReflectorClusterID=244.0.0.1")
          self.add_cleanup(lambda: kubectl("annotate node kind-control-plane projectcalico.org/RouteReflectorClusterID-"))

          # Configure other nodes to peer with rr
          kubectl("""apply -f - << EOF
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: peer-with-rr
spec:
  nodeSelector: all()
  peerSelector: kubernetes.io/hostname == 'kind-control-plane'
  nextHopMode: Self
  reversePeering: Manual
  filters:
  - export-child-cluster-cidr
""")
          self.add_cleanup(lambda: calicoctl("delete bgppeer peer-with-rr", allow_fail=True))

          # Configure rr to peer with other nodes
          kubectl("""apply -f - << EOF
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: peer-from-rr
spec:
  peerSelector: all()
  nodeSelector: kubernetes.io/hostname == 'kind-control-plane'
  reversePeering: Manual
  filters:
  - export-child-cluster-cidr
""")
          self.add_cleanup(lambda: calicoctl("delete bgppeer peer-from-rr", allow_fail=True))

          # Establish BGPPeer from rr to tor
          kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: rr-tor-peer
spec:
  nodeSelector: kubernetes.io/hostname == 'kind-control-plane'
  peerIP: %s
  asNumber: 63000
  nextHopMode: Keep
  filters:
  - export-child-cluster-cidr          
EOF
""" % self.external_node_ip)
          self.add_cleanup(lambda: calicoctl("delete bgppeer rr-tor-peer", allow_fail=True))


        # Create three pods. Name format : color-pod-host-sequence number
        # kind-worker node starts from nodes[1]
        self.red_pod_0_0 = self.create_workload_pod(self.nodes[1], "red-pod-0-0", self.ns, "red")
        self.red_pod_1_0 = self.create_workload_pod(self.nodes[2], "red-pod-1-0", self.ns, "red")
        self.blue_pod_0_0 = self.create_workload_pod(self.nodes[1], "blue-pod-0-0", self.ns, "blue")
        self.blue_pod_1_0 = self.create_workload_pod(self.nodes[2], "blue-pod-1-0", self.ns, "blue")

        for (p, block_v4, block_v6) in [
            (self.red_pod_0_0,"10.123.0.0/26","ca11:c0::/96"),
            (self.red_pod_1_0,"10.123.1.0/26","ca11:c0:1::/96"),
            (self.blue_pod_0_0,"10.123.2.0/26","ca11:c0:2::/96"),
            (self.blue_pod_1_0,"10.123.3.0/26","ca11:c0:3::/96"),
        ]:
            p.wait_ready()
            self.setup_workload_pod_v4(p, block_v4)
            self.setup_workload_pod_v6(p, block_v6)

        # Define localWorkloadPeeringIP and turn off nodeToNodeMesh
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
        self.add_cleanup(lambda: kubectl("delete bgpconfiguration default"))

        # Create the BGP filters for the local peerings.  We want to aviod
        # exporting routes to the local peers since they already have a
        # default route.
        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: accept-pod-cidr-child-cluster
spec:
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 10.123.0.0/16
  importV6:
    - action: Accept
      matchOperator: In
      cidr: ca11:c0::/32
---
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: no-export-from-parent-cluster
spec:
  exportV4:
    - action: Reject
  exportV6:
    - action: Reject
""")

        # Create the local peerings.
        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
 name: global-peer
spec:
 localWorkloadSelector: color == 'red'
 asNumber: 65401
 filters:
 - no-export-from-parent-cluster
 - accept-pod-cidr-child-cluster
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
 name: node-peer
spec:
 nodeSelector: kubernetes.io/hostname == 'kind-worker2'
 localWorkloadSelector: color == 'blue'
 asNumber: 65401
 filters:
 - no-export-from-parent-cluster
 - accept-pod-cidr-child-cluster
EOF
""")
        self.add_cleanup(lambda: calicoctl("delete bgppeer global-peer", allow_fail=True))
        self.add_cleanup(lambda: calicoctl("delete bgppeer node-peer", allow_fail=True))

    @staticmethod
    def delete_extra_node():
        try:
            # Delete the extra node.
            run("docker rm -f kind-node-tor")
        except subprocess.CalledProcessError:
            pass

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
    securityContext:
      privileged: true
  nodeName: %s
  terminationGracePeriodSeconds: 0
""" % (name, ns, color, host))
        self.add_cleanup(pod.delete)
        return pod

    def setup_workload_pod_v4(self, pod, ipam_block):
        # Copy bird
        bird_peer_config = self.get_bird_config_workload("65401", pod.ip,pod.ip, ipam_block, "169.254.0.179", "64512")
        with open('peers.conf', 'w') as peerconfig:
            peerconfig.write(bird_peer_config)

        run("kubectl cp peers.conf %s/%s:/etc/bird.conf" % (pod.ns, pod.name))
        run("kubectl exec -t %s -n %s -- sh -c 'birdcl configure'" % (pod.name, pod.ns))

        run("rm peers.conf")

        # run("kubectl exec -t %s -n %s -- sh -c 'ip route add 10.244.0.64/24 via 192.168.0.8'" % (pod.name, pod.ns))

    def setup_workload_pod_v6(self, pod, ipam_block):
        # Copy bird
        bird_peer_config = self.get_bird_config_workload("65401", pod.ip,pod.ipv6, ipam_block, "fd12:3456:789a::1", "64512")
        with open('peers.conf', 'w') as peerconfig:
            peerconfig.write(bird_peer_config)

        run("kubectl cp peers.conf %s/%s:/etc/bird6.conf" % (pod.ns, pod.name))
        run("kubectl exec -t %s -n %s -- sh -c 'birdcl6 configure'" % (pod.name, pod.ns))

        run("rm peers.conf")

    def get_bird_conf_tor(self):
        if self.topology == TopologyMode.MESH:
          return bird_conf_tor_mesh % (self.ips[0], self.ips[1], self.ips[2], self.ips[3])
        if self.topology == TopologyMode.RR:
          return bird_conf_tor_rr % self.ips[0]

    def get_bird_config_workload(self, as_number_child, router_id, child_ip, child_block, local_workload_peer_ip,
                                 as_number_parent):
        return """
router id %s;

function calico_cidr_filter() {
  if ( net ~ %s ) then {
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
    calico_cidr_filter();
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

# A static route to export to the parent cluster.
protocol static {
    route %s via %s;
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
    calico_cidr_filter();
    reject;
  };
  export filter {
    calico_cidr_filter();
    reject;
  };
  ttl security off;
  multihop;
}

protocol bgp from_workload_to_local_host from bgp_template {
  neighbor %s as %s;
}
""" % (router_id, child_block,  child_block, child_ip, as_number_child, local_workload_peer_ip, as_number_parent)
    
    # Given a pod, check if should have BGP connections with the host.
    def assert_bgp_established(self, pod):
        output = run("kubectl exec -t %s -n %s -- birdcl show protocols" % (pod.name, pod.ns))
        regexp = "from_workload_to_local_host.*Established"
        self.assertRegexpMatches(output, regexp, "IPv4 BGP connection not established, pod " + pod.name)
        output = run("kubectl exec -t %s -n %s -- birdcl6 show protocols" % (pod.name, pod.ns))
        self.assertRegexpMatches(output, regexp, "IPv6 BGP connection not established, pod " + pod.name)

    def assert_bgp_not_established(self, pod):
        output = run("kubectl exec -t %s -n %s -- birdcl show protocols" % (pod.name, pod.ns))
        regexp = "from_workload_to_local_host.*Established"
        self.assertNotRegexpMatches(output, regexp, "IPv4 BGP connection unexpectedly established, pod " + pod.name)
        output = run("kubectl exec -t %s -n %s -- birdcl6 show protocols" % (pod.name, pod.ns))
        self.assertNotRegexpMatches(output, regexp, "IPv6 BGP connection unexpectedly established, pod " + pod.name)

    def test_local_bgp_peers(self):
        """
        Runs the tests for local bgp peers
        """
        stop_for_debug()

        # Assert bgp sessions has been established to the following local workloads.
        # red pods on kind-worker and kind-worker2. blue pod on kind-worker2.
        retry_until_success(self.assert_bgp_established, function_args=[self.red_pod_0_0], retries=60)
        retry_until_success(self.assert_bgp_established, function_args=[self.red_pod_1_0], retries=60)
        self.assert_bgp_not_established(self.blue_pod_0_0)
        retry_until_success(self.assert_bgp_established, function_args=[self.blue_pod_1_0], retries=60)

        # Check the export filter is applied.  Child nodes shouldn't see routes
        # from the parent.
        output = run("kubectl exec -t %s -n %s -- birdcl show route" % (self.red_pod_0_0.name, self.red_pod_0_0.ns))
        self.assertRegexpMatches(output, "0\.0\.0\.0.*via 169.254.1.1")
        self.assertNotRegexpMatches(output, "192\.168\.\d+\.\d+/26", "Unexpected route to parent cluster")

        # Check that the import filter accepts child routes.
        calico_node_w1 = calico_node_pod_name(self.red_pod_0_0.nodename)
        # Expect a single route like this for worker 1.
        # 10.123.0.0/26      via 192.168.162.157 on calicef4c701383 [Local_Workload_192_168_162_157 15:11:46] * (100/0) [AS65401i]
        output = run("kubectl exec -t %s -n calico-system -- birdcl show route" % calico_node_w1)
        self.assertRegexpMatches(output, "10\.123\.0\.0/26.*via .* on cali.*Local_Workload_.*AS65401")
        output = run("kubectl exec -t %s -n calico-system -- birdcl6 show route" % calico_node_w1)
        self.assertRegexpMatches(output, "ca11:c0::/96.*via .* on cali.*Local_Workload_.*AS65401")

        # Worker 2 should have 2 routes of each version, one for each child.
        calico_node_w2 = calico_node_pod_name(self.red_pod_1_0.nodename)
        output = run("kubectl exec -t %s -n calico-system -- birdcl show route" % calico_node_w2)
        self.assertRegexpMatches(output, "10\.123\.1\.0/26.*via .* on cali.*Local_Workload_.*AS65401")
        self.assertRegexpMatches(output, "10\.123\.3\.0/26.*via .* on cali.*Local_Workload_.*AS65401")
        output = run("kubectl exec -t %s -n calico-system -- birdcl6 show route" % calico_node_w2)
        self.assertRegexpMatches(output, "ca11:c0:1::/96.*via .* on cali.*Local_Workload_.*AS65401")
        self.assertRegexpMatches(output, "ca11:c0:3::/96.*via .* on cali.*Local_Workload_.*AS65401")

        if self.topology == TopologyMode.MESH:
          # Check that the ToR hears about all the routes.
          # 10.123.0.0/26      via 172.18.0.3 on eth0 [Mesh_with_node_1 17:19:12] * (100/0) [AS65401i]
          # 10.123.1.0/26      via 172.18.0.2 on eth0 [Mesh_with_node_2 17:19:11] * (100/0) [AS65401i]
          # 10.123.3.0/26      via 172.18.0.2 on eth0 [Mesh_with_node_2 17:19:09] * (100/0) [AS65401i]
          output = run("docker exec kind-node-tor birdcl show route")
          self.assertRegexpMatches(output, "10\.123\.0\.0/26.*via %s on .*Mesh_with_node_1.*AS65401" % (self.ips[1],))
          self.assertRegexpMatches(output, "10\.123\.1\.0/26.*via %s on .*Mesh_with_node_2.*AS65401" % (self.ips[2],))
          self.assertRegexpMatches(output, "10\.123\.3\.0/26.*via %s on .*Mesh_with_node_2.*AS65401" % (self.ips[2],))

        if self.topology == TopologyMode.RR:
          # Check that kind-worker3 hears about all the routes from RR(master node) with original next hop.
          # 10.123.3.0/26      via 172.18.0.5 on eth0 [Node_172_18_0_3 09:46:12 from 172.18.0.3] * (100/0) [AS65401i]
          # 10.123.0.0/26      via 172.18.0.2 on eth0 [Node_172_18_0_3 09:46:10 from 172.18.0.3] * (100/0) [AS65401i]
          # 10.123.1.0/26      via 172.18.0.5 on eth0 [Node_172_18_0_3 09:46:12 from 172.18.0.3] * (100/0) [AS65401i]
          calico_node_w3 = calico_node_pod_name(self.nodes[3])
          output = run("kubectl exec -t %s -n calico-system -- birdcl show route" % calico_node_w3)
          self.assertRegexpMatches(output, "10\.123\.0\.0/26.*via %s on .*Node_172_18_0_.*AS65401" % (self.ips[1],))
          self.assertRegexpMatches(output, "10\.123\.1\.0/26.*via %s on .*Node_172_18_0_.*AS65401" % (self.ips[2],))
          self.assertRegexpMatches(output, "10\.123\.3\.0/26.*via %s on .*Node_172_18_0_.*AS65401" % (self.ips[2],))
          
          # Check that the ToR hears about all the routes from RR(master node).
          # Note that `nextHopMode: Keep` is specified for `rr-tor-peer`, ToR sees routes with original next hop.
          # 10.123.3.0/26      via 172.18.0.5 on eth0 [RR_with_master_node 09:46:12 from 172.18.0.3] * (100/0) [AS65401i]
          # 10.123.0.0/26      via 172.18.0.2 on eth0 [RR_with_master_node 09:46:10 from 172.18.0.3] * (100/0) [AS65401i]
          # 10.123.1.0/26      via 172.18.0.5 on eth0 [RR_with_master_node 09:46:12 from 172.18.0.3] * (100/0) [AS65401i]
          output = run("docker exec kind-node-tor birdcl show route")
          self.assertRegexpMatches(output, "10\.123\.0\.0/26.*via %s on .*RR_with_master_node.*AS65401" % (self.ips[1],))
          self.assertRegexpMatches(output, "10\.123\.1\.0/26.*via %s on .*RR_with_master_node.*AS65401" % (self.ips[2],))
          self.assertRegexpMatches(output, "10\.123\.3\.0/26.*via %s on .*RR_with_master_node.*AS65401" % (self.ips[2],))
        
        # Check connectivity from ToR to workload.
        self.red_pod_0_0.execute("ip addr add 10.123.0.1 dev lo")

        output = run("docker exec kind-node-tor ping -c3 10.123.0.1")
        self.assertRegexpMatches(output, "3 packets transmitted, 3 packets received")

class TestLocalBGPPeerRR(_TestLocalBGPPeer):

    # In the tests of this class we have BGP peers between the
    # cluster nodes (kind-control-plane, kind-worker, kind-worker2, kind-worker3, kind-control-plane acting as a RR) with ASNumber 64512
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
    #   A node specific peer is created to select the blue pod on kind-worker2 node.

    def setUp(self):
        self.set_topology(TopologyMode.RR)
        super(TestLocalBGPPeerRR, self).setUp() 

class TestLocalBGPPeerMesh(_TestLocalBGPPeer):

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
    #   A node specific peer is created to select the blue pod on kind-worker2 node.

    def setUp(self):
        self.set_topology(TopologyMode.MESH)
        super(TestLocalBGPPeerMesh, self).setUp() 

def stop_for_debug():
    # Touch debug file under projectcalico/calico/node to stop the process
    debug_file = "/code/stop-for-debug"
    last_log = None
    while os.path.exists(debug_file):
        if last_log is None or time.time() - last_log > 60:
            _log.info("stop-for-debug file exists. Sleeping...")
            last_log = time.time()
        time.sleep(1)

    _log.info("Debug file does not exist. Continuing...")
