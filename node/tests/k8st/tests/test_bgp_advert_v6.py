# Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
import json
import sys

from tests.k8st.test_base import TestBaseV6
from tests.k8st.utils.utils import start_external_node_with_bgp, \
        retry_until_success, run, curl, DiagsCollector, calicoctl, kubectl, node_info

_log = logging.getLogger(__name__)

attempts = 10

bird_conf = """
# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 64512;
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
  passive on; # Mesh is unidirectional, peer will connect to us.
}

protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}

protocol bgp Mesh_with_node_3 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}
"""

# BIRD config for an external node to peer with
# the in-cluster route reflector on kube-node-2.
bird_conf_rr = """
# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 64512;
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

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}
"""

class _TestBGPAdvertV6(TestBaseV6):

    def setUp(self):
        super(_TestBGPAdvertV6, self).setUp()

        # Create bgp test namespace
        self.ns = "bgp-test"
        self.create_namespace(self.ns)

        self.nodes, self.ipv4s, self.ipv6s = node_info()
        self.external_node_ip = start_external_node_with_bgp(
            "kube-node-extra",
            bird6_peer_config=self.get_bird_conf(),
        )

        # Enable debug logging
        self.update_ds_env("calico-node",
                           "kube-system",
                           {"BGP_LOGSEVERITYSCREEN": "debug"})

        # Establish BGPPeer from cluster nodes to node-extra
        calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: node-extra.peer%s
EOF
""" % self.get_extra_peer_spec())

    def tearDown(self):
        super(_TestBGPAdvertV6, self).tearDown()
        self.delete_and_confirm(self.ns, "ns")
        try:
            # Delete the extra node.
            run("docker rm -f kube-node-extra")
        except subprocess.CalledProcessError:
            pass

        # Delete BGPPeers.
        calicoctl("delete bgppeer node-extra.peer", allow_fail=True)
        calicoctl("delete bgppeer peer-with-rr", allow_fail=True)

        # Restore node-to-node mesh.
        calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata: {name: default}
spec:
  nodeToNodeMeshEnabled: true
  asNumber: 64512
EOF
""")

        # Remove node-2's route-reflector config.
        json_str = calicoctl("get node %s -o json" % self.nodes[2])
        node_dict = json.loads(json_str)
        node_dict['metadata']['labels'].pop('i-am-a-route-reflector', '')
        node_dict['spec']['bgp'].pop('routeReflectorClusterID', '')
        calicoctl("""apply -f - << EOF
%s
EOF
""" % json.dumps(node_dict))

    def get_svc_cluster_ip(self, svc, ns):
        return kubectl("get svc %s -n %s -o json | jq -r .spec.clusterIP" %
                       (svc, ns)).strip()

    def assert_ecmp_routes(self, dst, via):
        matchStr = dst + " proto bird metric 1024 pref medium"
        # sort ips and construct match string for ECMP routes.
        for ip in sorted(via):
            matchStr += "\n\tnexthop via %s dev eth0 weight 1 " % ip
        retry_until_success(lambda: self.assertIn(matchStr, self.get_routes()))

    def get_svc_host_ipv6(self, svc, ns):
        ipv4 = kubectl("get po -l app=%s -n %s -o json | jq -r .items[0].status.hostIP" %
                       (svc, ns)).strip()
        for i in range(len(self.ipv4s)):
            if ipv4 == self.ipv4s[i]:
                return self.ipv6s[i]
        assert False

    def add_svc_external_ips(self, svc, ns, ips):
        ipsStr = ','.join('"{0}"'.format(ip) for ip in ips)
        patchStr = "{\"spec\": {\"externalIPs\": [%s]}}" % (ipsStr)
        return kubectl("patch svc %s -n %s --patch '%s'" % (svc, ns, patchStr)).strip()


class TestBGPAdvertV6(_TestBGPAdvertV6):

    # In the tests of this class we have a full BGP mesh between the
    # cluster nodes (kube-control-plane, kube-node-1 and kube-node-2)
    # and the external node (kube-node-extra):
    #
    # - The full mesh between the cluster nodes is configured by
    #   nodeToNodeMeshEnabled: true.
    #
    # - The peerings from each cluster node to the external node are
    #   configured by self.get_extra_peer_spec().
    #
    # - The peerings from the external node to each cluster node are
    #   configured by self.get_bird_conf().

    def get_bird_conf(self):
        return bird_conf % (self.ipv6s[0], self.ipv6s[1],
                            self.ipv6s[2], self.ipv6s[3])

    def get_extra_peer_spec(self):
        return """
spec:
  peerIP: %s
  asNumber: 64512
""" % self.external_node_ip

    def test_cluster_ip_advertisement(self):
        """
        Runs the tests for service cluster IPv6 advertisement
        - Create both a Local and a Cluster type NodePort service with a single replica.
          - assert only local and cluster CIDR routes are advertised.
          - assert /128 routes are used, source IP is preserved.
        - Scale the Local NP service so it is running on multiple nodes, assert ECMP routing, source IP is preserved.
        - Delete both services, assert only cluster CIDR route is advertised.
        """
        with DiagsCollector():

            calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
  name: default
spec:
  serviceClusterIPs:
  - cidr: fd00:10:96::/112
EOF
""")

            # Assert that a route to the service IP range is present.
            retry_until_success(lambda: self.assertIn("fd00:10:96::/112", self.get_routes()))

            # Create both a Local and a Cluster type NodePort service with a single replica.
            local_svc = "nginx-local"
            cluster_svc = "nginx-cluster"
            self.deploy("gcr.io/kubernetes-e2e-test-images/test-webserver:1.0", local_svc, self.ns, 80, ipv6=True)
            self.deploy("gcr.io/kubernetes-e2e-test-images/test-webserver:1.0", cluster_svc, self.ns, 80, traffic_policy="Cluster", ipv6=True)
            self.wait_until_exists(local_svc, "svc", self.ns)
            self.wait_until_exists(cluster_svc, "svc", self.ns)

            # Get clusterIPs.
            local_svc_ip = self.get_svc_cluster_ip(local_svc, self.ns)
            cluster_svc_ip = self.get_svc_cluster_ip(cluster_svc, self.ns)

            # Wait for the deployments to roll out.
            self.wait_for_deployment(local_svc, self.ns)
            self.wait_for_deployment(cluster_svc, self.ns)

            # Assert that both nginx service can be curled from the external node.
            retry_until_success(curl, function_args=[local_svc_ip])
            retry_until_success(curl, function_args=[cluster_svc_ip])

            # Assert that local clusterIP is an advertised route and cluster clusterIP is not.
            retry_until_success(lambda: self.assertIn(local_svc_ip, self.get_routes()))
            retry_until_success(lambda: self.assertNotIn(cluster_svc_ip, self.get_routes()))

            # TODO: This assertion is actually incorrect. Kubernetes performs
            # SNAT on all traffic destined to a service ClusterIP that doesn't
            # originate from within the cluster's pod CIDR. This assertion
            # pass for External / LoadBalancer IPs, though.
            #
            # Create a network policy that only accepts traffic from the external node.
            # Applying this policy asserts that traffic is not being SNAT'd by kube-proxy
            # when it reaches the destination node.
            # kubectl("""apply -f - << EOF
# apiVersion: networking.k8s.io/v1
# kind: NetworkPolicy
# metadata:
  # name: allow-tcp-80-ex
  # namespace: bgp-test
# spec:
  # podSelector: {}
  # policyTypes:
  # - Ingress
  # ingress:
  # - from:
    # - ipBlock: { cidr: %s/128 }
    # ports:
    # - protocol: TCP
      # port: 80
# EOF
# """ % self.external_node_ip)

            # Connectivity to nginx-local should always succeed.
            for i in range(attempts):
              retry_until_success(curl, retries=200, wait_time=5, function_args=[local_svc_ip])

            # NOTE: Unlike in the IPv6 case (in test_bgp_advert.py) we cannot successfully test that
            # connectivity to nginx-cluster is load-balanced across all nodes (and hence, with the
            # above policy in place, will sometimes fail and sometimes succeed), because our current
            # observation is that Linux's IPv6 ECMP route choice does _not_ depend on source port,
            # even though it is documented as such when fib_multipath_hash_policy == 1.

            # Scale the local_svc to 4 replicas
            self.scale_deployment(local_svc, self.ns, 4)
            self.wait_for_deployment(local_svc, self.ns)
            self.assert_ecmp_routes(local_svc_ip, [self.ipv6s[1], self.ipv6s[2], self.ipv6s[3]])
            for i in range(attempts):
              retry_until_success(curl, function_args=[local_svc_ip])

            # Delete both services.
            self.delete_and_confirm(local_svc, "svc", self.ns)
            self.delete_and_confirm(cluster_svc, "svc", self.ns)

            # Assert that clusterIP is no longer an advertised route.
            retry_until_success(lambda: self.assertNotIn(local_svc_ip, self.get_routes()))

    def test_external_ip_advertisement(self):
        """
        Runs the tests for service external IPv6 advertisement
        """
        with DiagsCollector():

            # Whitelist two IP ranges for the external IPs we'll test with
            calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
  name: default
spec:
  serviceExternalIPs:
  - cidr: fd5f:1234:175:200::/112
  - cidr: fd5f:1234:200:255::/120
EOF
""")

            # Create both a Local and a Cluster type NodePort service with a single replica.
            local_svc = "nginx-local"
            cluster_svc = "nginx-cluster"
            self.deploy("gcr.io/kubernetes-e2e-test-images/test-webserver:1.0", local_svc, self.ns, 80, ipv6=True)
            self.deploy("gcr.io/kubernetes-e2e-test-images/test-webserver:1.0", cluster_svc, self.ns, 80, traffic_policy="Cluster", ipv6=True)
            self.wait_until_exists(local_svc, "svc", self.ns)
            self.wait_until_exists(cluster_svc, "svc", self.ns)

            # Get clusterIPs.
            local_svc_ip = self.get_svc_cluster_ip(local_svc, self.ns)
            cluster_svc_ip = self.get_svc_cluster_ip(cluster_svc, self.ns)

            # Wait for the deployments to roll out.
            self.wait_for_deployment(local_svc, self.ns)
            self.wait_for_deployment(cluster_svc, self.ns)

            # Assert that clusterIPs are not advertised.
            retry_until_success(lambda: self.assertNotIn(local_svc_ip, self.get_routes()))
            retry_until_success(lambda: self.assertNotIn(cluster_svc_ip, self.get_routes()))

            # Create a network policy that only accepts traffic from the external node.
            kubectl("""apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-tcp-80-ex
  namespace: bgp-test
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock: { cidr: %s/32 }
    ports:
    - protocol: TCP
      port: 80
EOF
""" % self.external_node_ip)

            # Get host IPs for the nginx pods.
            local_svc_host_ip = self.get_svc_host_ipv6(local_svc, self.ns)
            cluster_svc_host_ip = self.get_svc_host_ipv6(cluster_svc, self.ns)

            # Select an IP from each external IP CIDR.
            local_svc_external_ip = "fd5f:1234:175:200::1"
            cluster_svc_external_ip = "fd5f:1234:200:255::1"

            # Add external IPs to the two services.
            self.add_svc_external_ips(local_svc, self.ns, [local_svc_external_ip])
            self.add_svc_external_ips(cluster_svc, self.ns, [cluster_svc_external_ip])

            # Verify that external IPs for local service is advertised but not the cluster service.
            local_svc_externalips_route = "%s via %s" % (local_svc_external_ip, local_svc_host_ip)
            cluster_svc_externalips_route = "%s via %s" % (cluster_svc_external_ip, cluster_svc_host_ip)
            retry_until_success(lambda: self.assertIn(local_svc_externalips_route, self.get_routes()))
            retry_until_success(lambda: self.assertNotIn(cluster_svc_externalips_route, self.get_routes()))

            # Scale the local_svc to 4 replicas.
            self.scale_deployment(local_svc, self.ns, 4)
            self.wait_for_deployment(local_svc, self.ns)

            # Verify that we have ECMP routes for the external IP of the local service.
            retry_until_success(lambda: self.assert_ecmp_routes(local_svc_external_ip, [self.ipv6s[1], self.ipv6s[2], self.ipv6s[3]]))

            # Delete both services, assert only cluster CIDR route is advertised.
            self.delete_and_confirm(local_svc, "svc", self.ns)
            self.delete_and_confirm(cluster_svc, "svc", self.ns)

            # Assert that external IP is no longer an advertised route.
            retry_until_success(lambda: self.assertNotIn(local_svc_externalips_route, self.get_routes()))

    def test_many_services(self):
        """
        Creates a lot of IPv6 services quickly
        """
        with DiagsCollector():

            calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
  name: default
spec:
  serviceClusterIPs:
  - cidr: fd00:10:96::/112
EOF
""")

            # Assert that a route to the service IP range is present.
            retry_until_success(lambda: self.assertIn("fd00:10:96::/112", self.get_routes()))

            # Create a local service and deployment.
            local_svc = "nginx-local"
            self.deploy("gcr.io/kubernetes-e2e-test-images/test-webserver:1.0", local_svc, self.ns, 80, ipv6=True)
            self.wait_for_deployment(local_svc, self.ns)

            # Get clusterIPs.
            cluster_ips = []
            cluster_ips.append(self.get_svc_cluster_ip(local_svc, self.ns))

            # Create many more services which select this deployment.
            num_svc = 300
            for i in range(num_svc):
                name = "nginx-svc-%s" % i
                self.create_service(name, local_svc, self.ns, 80, ipv6=True)

            # Get all of their IPs.
            for i in range(num_svc):
                name = "nginx-svc-%s" % i
                cluster_ips.append(self.get_svc_cluster_ip(name, self.ns))

            # Assert they are all advertised to the other node. This should happen
            # quickly enough that by the time we have queried all services from
            # the k8s API, they should be programmed on the remote node.
            def check_routes_advertised():
                routes = self.get_routes()
                for cip in cluster_ips:
                    self.assertIn(cip, routes)
            retry_until_success(check_routes_advertised, retries=3, wait_time=5)

            # Scale to 0 replicas, assert all routes are removed.
            self.scale_deployment(local_svc, self.ns, 0)
            self.wait_for_deployment(local_svc, self.ns)
            def check_routes_gone():
                routes = self.get_routes()
                for cip in cluster_ips:
                    self.assertNotIn(cip, routes)
            retry_until_success(check_routes_gone, retries=10, wait_time=5)


class TestBGPAdvertV6RR(_TestBGPAdvertV6):

    # In the tests of this class, kube-node-2 acts as an RR, and all
    # the other nodes peer with it.  Here are the peerings that we
    # need for that:
    #
    #                                      RR
    # kube-master     kube-node-1     kube-node-2    kube-node-extra
    #  2001:20::8      2001:20::1      2001:20::2      2001:20::20
    #        |                |         | |    |         |
    #        |                +---------+ |    +---------+
    #        +----------------------------+   Peering -> is configured
    #           These peerings are            by get_extra_peer_spec().
    #           configured by BGPPeer         Peering <- is configured
    #           peer-with-rr                  in get_bird_conf().

    def get_bird_conf(self):
        return bird_conf_rr % self.ipv6s[2]

    def get_extra_peer_spec(self):
        return """
spec:
  node: %s
  peerIP: %s
  asNumber: 64512
""" % (self.nodes[2], self.external_node_ip)

    def test_rr(self):
        # Create ExternalTrafficPolicy Local service with one endpoint on node-1
        kubectl("""apply -f - << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-rr
  namespace: bgp-test
  labels:
    app: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
      run: nginx-rr
  template:
    metadata:
      labels:
        app: nginx
        run: nginx-rr
    spec:
      containers:
      - name: nginx-rr
        image: nginx:1.7.9
        ports:
        - containerPort: 80
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.io/hostname: %s
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-rr
  namespace: bgp-test
  labels:
    app: nginx
    run: nginx-rr
spec:
  ipFamilies:
  - IPv6
  externalIPs:
  - fd5f:1234:175:200::1
  ports:
  - port: 80
    targetPort: 80
  selector:
    app: nginx
    run: nginx-rr
  type: NodePort
  externalTrafficPolicy: Local
EOF
""" % self.nodes[1])

        calicoctl("get nodes -o yaml")
        calicoctl("get bgppeers -o yaml")
        calicoctl("get bgpconfigs -o yaml")

        # Update the node-2 to behave as a route-reflector
        json_str = calicoctl("get node %s -o json" % self.nodes[2])
        node_dict = json.loads(json_str)
        node_dict['metadata']['labels']['i-am-a-route-reflector'] = 'true'
        node_dict['spec']['bgp']['routeReflectorClusterID'] = '224.0.0.1'
        calicoctl("""apply -f - << EOF
%s
EOF
""" % json.dumps(node_dict))

        # Disable node-to-node mesh, add cluster and external IP CIDRs to
        # advertise, and configure BGP peering between the cluster nodes and the
        # RR.  (The BGP peering from the external node to the RR is included in
        # get_bird_conf() above.)
        calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
  name: default
spec:
  nodeToNodeMeshEnabled: false
  asNumber: 64512
  serviceClusterIPs:
  - cidr: fd00:10:96::/112
  serviceExternalIPs:
  - cidr: fd5f:1234:175:200::/112
EOF
""")

        calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata: {name: peer-with-rr}
spec:
  peerIP: %s
  asNumber: 64512
EOF
""" % self.ipv6s[2])
        svc_json = kubectl("get svc nginx-rr -n bgp-test -o json")
        svc_dict = json.loads(svc_json)
        cluster_ip = svc_dict['spec']['clusterIP']
        external_ip = svc_dict['spec']['externalIPs'][0]
        retry_until_success(lambda: self.assertIn(cluster_ip, self.get_routes()))
        retry_until_success(lambda: self.assertIn(external_ip, self.get_routes()))
