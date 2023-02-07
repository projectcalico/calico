# Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

import logging
import re

from tests.k8st.test_base import Container, Pod, TestBase
from tests.k8st.utils.utils import DiagsCollector, calicoctl, kubectl, run, retry_until_success, node_info, start_external_node_with_bgp, update_ds_env

_log = logging.getLogger(__name__)

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
protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}
"""

class TestBGPFilter(TestBase):
    def setUp(self):
        super(TestBGPFilter, self).setUp()

        # Create test namespace
        self.ns = "bgpfilter-test"
        self.create_namespace(self.ns)

        self.nodes, self.ips, self.ip6s = node_info()
        self.egress_node = self.nodes[1]
        self.egress_node_ip = self.ips[1]
        self.egress_node_ip6 = self.ip6s[1]
        self.external_node_ip = start_external_node_with_bgp(
            "kube-node-extra",
            bird_peer_config=self._get_bird_conf(),
        )
        self.external_node_ip6 = start_external_node_with_bgp(
            "kube-node-extra-v6",
            bird6_peer_config=self._get_bird_conf(ipv6=True),
        )

        kubectl("label node %s egress=true --overwrite" % self.egress_node)

        self.egress_calico_pod = self.get_calico_node_pod(self.egress_node)

        # Enable debug logging
        update_ds_env("calico-node",
                      "kube-system",
                      {"BGP_LOGSEVERITYSCREEN": "debug"})

        # Establish BGPPeer from cluster nodes to node-extra
        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: node-extra.peer
spec:
  peerIP: %s
  asNumber: 64512
  nodeSelector: "egress == 'true'"
EOF
""" % self.external_node_ip)

        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: node-extra-v6.peer
spec:
  peerIP: %s
  asNumber: 64512
  nodeSelector: "egress == 'true'"
EOF
""" % self.external_node_ip6)

    def tearDown(self):
        super(TestBGPFilter, self).tearDown()

        self.delete_and_confirm(self.ns, "ns")

        try:
            # Delete the extra node.
            run("docker rm -f kube-node-extra")
        except subprocess.CalledProcessError:
            pass

        try:
            # Delete the extra node.
            run("docker rm -f kube-node-extra-v6")
        except subprocess.CalledProcessError:
            pass

        # Delete BGPPeers.
        kubectl("delete bgppeer node-extra.peer", allow_fail=True)
        kubectl("delete bgppeer node-extra-v6.peer", allow_fail=True)

    def _get_bird_conf(self, ipv6=False):
        if ipv6:
            return bird_conf % (self.egress_node_ip6)

        return bird_conf % (self.egress_node_ip)

    def get_calico_node_pod(self, nodeName):
        """Get the calico-node pod name for a given kind node"""
        def fn():
            calicoPod = kubectl("-n kube-system get pods -o wide | grep calico-node | grep '%s '| cut -d' ' -f1" % nodeName)
            if calicoPod is None:
                raise Exception('calicoPod is None')
            return calicoPod.strip()
        calicoPod = retry_until_success(fn)
        return calicoPod

    def _check_route_in_cluster_bird(self, calicoPod, route, peerIP, ipv6=False, globalPeer=False, present=True):
        """Check that a route is present/not present in a (in-cluster) calico-node bird instance"""
        def fn():
            birdCmd = "birdcl6" if ipv6 else "birdcl"
            birdPeer = "Global_" if globalPeer else "Node_"
            birdPeer += peerIP.replace(".", "_").replace(":","_")
            routes = kubectl("exec -n kube-system %s -- %s show route protocol %s" % (calicoPod, birdCmd, birdPeer))
            result = re.search("%s *via %s on .* \[%s" % (re.escape(route), re.escape(peerIP), birdPeer), routes)
            if result is None and present:
                raise Exception('route not present when it should be')
            if result is not None and not present:
                raise Exception('route present when it should not be')
            return result
        result = retry_until_success(fn, wait_time=3)
        return result

    def _assert_route_present_in_cluster_bird(self, calicoPod, route, peerIP, ipv6=False, globalPeer=False):
        self._check_route_in_cluster_bird(calicoPod, route, peerIP, ipv6=ipv6, globalPeer=globalPeer, present=True)

    def _assert_route_not_present_in_cluster_bird(self, calicoPod, route, peerIP, ipv6=False, globalPeer=False):
        self._check_route_in_cluster_bird(calicoPod, route, peerIP, ipv6=ipv6, globalPeer=globalPeer, present=False)

    def _check_route_in_external_bird(self, birdContainer, birdPeer, routeRegex, peerIPRegex, ipv6=False, present=True):
        """Check that a route is present/not present in an external (plain docker container) bird instance"""
        def fn():
            birdCmd = "birdcl6" if ipv6 else "birdcl"
            routes = run("docker exec %s %s show route protocol %s" % (birdContainer, birdCmd, birdPeer))
            result = re.search("%s *via %s on .* \[%s" % (routeRegex, peerIPRegex, birdPeer), routes)
            if result is None and present:
                raise Exception('route not present when it should be')
            if result is not None and not present:
                raise Exception('route present when it should not be')
            return result
        result = retry_until_success(fn, wait_time=3)
        return result

    def _assert_route_present_in_external_bird(self, birdContainer, birdPeer, routeRegex, peerIPRegex, ipv6=False):
        self._check_route_in_external_bird(birdContainer, birdPeer, routeRegex, peerIPRegex, ipv6=ipv6, present=True)

    def _assert_route_not_present_in_external_bird(self, birdContainer, birdPeer, routeRegex, peerIPRegex, ipv6=False):
        self._check_route_in_external_bird(birdContainer, birdPeer, routeRegex, peerIPRegex, ipv6=ipv6, present=False)

    def _patch_peer_filters(self, peer, filters):
        """Patch BGPFilters in a BGPPeer"""
        filterStr = "\"" + "\", \"".join(filters) + "\"" if len(filters) > 0 else ""
        patchStr = "{\"spec\": {\"filters\": [%s]}}" % filterStr
        kubectl("patch bgppeer %s --patch '%s'" % (peer, patchStr))


    def _test_bgp_filter_basic(self, ipv4, ipv6):
        """Basic test case:
        - Add IPv4/IPv6 route to the external bird instance
        - Verify it is present in cluster bird instance (to validate import)
        - Verify that IPAM block from IP pool is present in external bird instance (to validate export)
        - Add BGPFilter with export reject rule and verify that route is no longer present in external bird instance
        - Add BGPFilter with import reject rule and verify that route is no longer present in cluster bird instance
        """
        with DiagsCollector():
            external_route_v4 = "10.111.111.0/24"
            cluster_route_regex_v4 = "192\.168\.\d+\.\d+/\d+"
            export_filter_cidr_v4 = "192.168.0.0/16"

            external_route_v6 = "fd00:1111:1111:1111::/64"
            cluster_route_regex_v6 = "fd00:10:244:.*/\d+"
            export_filter_cidr_v6 = "fd00:10:244::/64"

            # Add static route bird config to external node
            if ipv4:
                run("""cat <<EOF | docker exec -i kube-node-extra sh -c "cat > /etc/bird/static-route.conf"
protocol static static1 {
    route %s via %s;
    export all;
}
EOF
""" % (external_route_v4, self.external_node_ip))
                run("docker exec kube-node-extra birdcl configure")
                self.add_cleanup(lambda: run("docker exec kube-node-extra sh -c 'rm /etc/bird/static-route.conf; birdcl configure'"))
            if ipv6:
                run("""cat <<EOF | docker exec -i kube-node-extra-v6 sh -c "cat > /etc/bird6/static-route.conf"
protocol static static1 {
    route %s via %s;
    export all;
}
EOF
""" % (external_route_v6, self.external_node_ip6))
                run("docker exec kube-node-extra-v6 birdcl6 configure")
                self.add_cleanup(lambda: run("docker exec kube-node-extra-v6 sh -c 'rm /etc/bird6/static-route.conf; birdcl6 configure'"))

            # Check that the egress node (i.e., the cluster node that peers through BGP with the external bird instance) has the route advertised by the external bird instance
            if ipv4:
                self._assert_route_present_in_cluster_bird(self.egress_calico_pod, external_route_v4, self.external_node_ip)
            if ipv6:
                self._assert_route_present_in_cluster_bird(self.egress_calico_pod, external_route_v6, self.external_node_ip6, ipv6=True)

            # Check that the external bird instance has a route for an IPAM block from the default IP pool
            if ipv4:
                self._assert_route_present_in_external_bird("kube-node-extra", "Mesh_with_node_1", cluster_route_regex_v4, re.escape(self.egress_node_ip))
            if ipv6:
                # Use link-local address as 'via'
                self._assert_route_present_in_external_bird("kube-node-extra-v6", "Mesh_with_node_1", cluster_route_regex_v6, "fe80::.*", ipv6=True)

            # Add BGPFilter with export rule and check that the external bird instance no longer has the route for an IPAM block from the default IP pool
            if ipv4:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-export-1
spec:
  exportV4:
  - cidr: %s
    matchOperator: In
    action: Reject
EOF
""" % export_filter_cidr_v4)
                self._patch_peer_filters("node-extra.peer", ["test-filter-export-1"])

                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-export-1"))
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra.peer", []))

                self._assert_route_not_present_in_external_bird("kube-node-extra", "Mesh_with_node_1", cluster_route_regex_v4, re.escape(self.egress_node_ip))
            if ipv6:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-export-v6-1
spec:
  exportV6:
  - cidr: %s
    matchOperator: In
    action: Reject
EOF
""" % export_filter_cidr_v6)
                self._patch_peer_filters("node-extra-v6.peer", ["test-filter-export-v6-1"])

                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-export-v6-1"))
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra-v6.peer", []))

                # Use link-local address as 'via'
                self._assert_route_not_present_in_external_bird("kube-node-extra-v6", "Mesh_with_node_1", cluster_route_regex_v6, "fe80::.*", ipv6=True)

            # Add BGPFilter with import rule and check that the egress node no longer has the route advertised by the external bird instance
            if ipv4:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-1
spec:
  importV4:
  - cidr: %s
    matchOperator: Equal
    action: Reject
EOF
""" % external_route_v4)
                self._patch_peer_filters("node-extra.peer", ["test-filter-import-1"])

                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-1"))
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra.peer", []))

                self._assert_route_not_present_in_cluster_bird(self.egress_calico_pod, external_route_v4, self.external_node_ip)
            if ipv6:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-v6-1
spec:
  importV6:
  - cidr: %s
    matchOperator: Equal
    action: Reject
EOF
""" % external_route_v6)
                self._patch_peer_filters("node-extra-v6.peer", ["test-filter-import-v6-1"])

                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-v6-1"))
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra-v6.peer", []))

                self._assert_route_not_present_in_cluster_bird(self.egress_calico_pod, external_route_v6, self.external_node_ip6, ipv6=True)

    def _test_bgp_filter_ordering(self, ipv4, ipv6):
        """Test multiple rules per filter and multiple filters per peer, as well as
        exhaust matchOperators and actions"""
        with DiagsCollector():
            external_route_v4 = "10.111.111.0/24"
            cluster_route_regex_v4 = "192\.168\.\d+\.\d+/\d+"
            export_filter_cidr_v4 = "192.168.0.0/16"

            external_route_v6 = "fd00:1111:1111:1111::/64"
            cluster_route_regex_v6 = "fd00:10:244:.*/\d+"
            export_filter_cidr_v6 = "fd00:10:244::/64"

            # Add static route bird config
            if ipv4:
                run("""cat <<EOF | docker exec -i kube-node-extra sh -c "cat > /etc/bird/static-route.conf"
protocol static static1 {
    route %s via %s;
    export all;
}
EOF
""" % (external_route_v4, self.external_node_ip))
                run("docker exec kube-node-extra birdcl configure")
                self.add_cleanup(lambda: run("docker exec kube-node-extra sh -c 'rm /etc/bird/static-route.conf; birdcl configure'"))
            if ipv6:
                run("""cat <<EOF | docker exec -i kube-node-extra-v6 sh -c "cat > /etc/bird6/static-route.conf"
protocol static static1 {
    route %s via %s;
    export all;
}
EOF
""" % (external_route_v6, self.external_node_ip6))
                run("docker exec kube-node-extra-v6 birdcl6 configure")
                self.add_cleanup(lambda: run("docker exec kube-node-extra-v6 sh -c 'rm /etc/bird6/static-route.conf; birdcl6 configure'"))

            # Add filters with multiple rules that should result in the routes being accepted
            if ipv4:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-1
spec:
  importV4:
  - cidr: 10.111.0.0/16
    matchOperator: In
    action: Accept
  - cidr: 10.111.111.0/24
    matchOperator: Equal
    action: Reject
EOF
""")
                self._patch_peer_filters("node-extra.peer", ["test-filter-import-1"])
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra.peer", []))
                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-1"))
            if ipv6:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-v6-1
spec:
  importV6:
  - cidr: fd00:1111:1111::/48
    matchOperator: In
    action: Accept
  - cidr: fd00:1111:1111:1111::/64
    matchOperator: Equal
    action: Reject
EOF
""")
                self._patch_peer_filters("node-extra-v6.peer", ["test-filter-import-v6-1"])
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra-v6.peer", []))
                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-v6-1"))

            # Check that routes are present
            if ipv4:
                self._assert_route_present_in_cluster_bird(self.egress_calico_pod, external_route_v4, self.external_node_ip)
            if ipv6:
                self._assert_route_present_in_cluster_bird(self.egress_calico_pod, external_route_v6, self.external_node_ip6, ipv6=True)

            # Add additional filters with multiple rules that should result in the routes being rejected
            if ipv4:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-2
spec:
  importV4:
  - cidr: 10.111.0.0/16
    matchOperator: NotIn
    action: Accept
  - cidr: 10.111.111.0/24
    matchOperator: NotEqual
    action: Accept
  - cidr: 10.111.111.0/24
    matchOperator: Equal
    action: Reject
EOF
""")
                self._patch_peer_filters("node-extra.peer", ["test-filter-import-2", "test-filter-import-1"])
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra.peer", []))
                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-2"))
            if ipv6:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-v6-2
spec:
  importV6:
  - cidr: fd00:1111:1111::/48
    matchOperator: NotIn
    action: Accept
  - cidr: fd00:1111:1111:1111::/64
    matchOperator: NotEqual
    action: Accept
  - cidr: fd00:1111:1111:1111::/64
    matchOperator: Equal
    action: Reject
EOF
""")
                self._patch_peer_filters("node-extra-v6.peer", ["test-filter-import-v6-2", "test-filter-import-v6-1"])
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra-v6.peer", []))
                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-v6-2"))

            # Check that routes are no longer present
            if ipv4:
                self._assert_route_not_present_in_cluster_bird(self.egress_calico_pod, external_route_v4, self.external_node_ip)
            if ipv6:
                self._assert_route_not_present_in_cluster_bird(self.egress_calico_pod, external_route_v6, self.external_node_ip6, ipv6=True)

            # Add an additional filter with both IPv4 and IPv6 rules that should result in the routes being accepted
            if ipv4 and ipv6:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-v4-v6
spec:
  importV4:
  - cidr: 10.111.111.0/24
    matchOperator: Equal
    action: Accept
  - cidr: 10.111.0.0/16
    matchOperator: NotIn
    action: Accept
  - cidr: 10.111.111.0/24
    matchOperator: NotEqual
    action: Accept
  - cidr: 10.111.111.0/24
    matchOperator: Equal
    action: Reject
  importV6:
  - cidr: fd00:1111:1111:1111::/64
    matchOperator: Equal
    action: Accept
  - cidr: fd00:1111:1111::/48
    matchOperator: NotIn
    action: Accept
  - cidr: fd00:1111:1111:1111::/64
    matchOperator: NotEqual
    action: Accept
  - cidr: fd00:1111:1111:1111::/64
    matchOperator: Equal
    action: Reject
EOF
""")
                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-v4-v6"))

                self._patch_peer_filters("node-extra.peer", ["test-filter-import-v4-v6", "test-filter-import-2", "test-filter-import-1"])
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra.peer", []))

                self._patch_peer_filters("node-extra-v6.peer", ["test-filter-import-v4-v6", "test-filter-import-v6-2", "test-filter-import-v6-1"])
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra-v6.peer", []))

                # Check that routes are present
                self._assert_route_present_in_cluster_bird(self.egress_calico_pod, external_route_v4, self.external_node_ip)
                self._assert_route_present_in_cluster_bird(self.egress_calico_pod, external_route_v6, self.external_node_ip6, ipv6=True)

    def _test_bgp_filter_global_peer(self, ipv4, ipv6):
        """Test BGP import filters with global BGP peers"""
        with DiagsCollector():
            external_route_v4 = "10.111.111.0/24"
            cluster_route_regex_v4 = "192\.168\.\d+\.\d+/\d+"
            export_filter_cidr_v4 = "192.168.0.0/16"

            external_route_v6 = "fd00:1111:1111:1111::/64"
            cluster_route_regex_v6 = "fd00:10:244:.*/\d+"
            export_filter_cidr_v6 = "fd00:10:244::/64"

            # Add static route bird config
            if ipv4:
                run("""cat <<EOF | docker exec -i kube-node-extra sh -c "cat > /etc/bird/static-route.conf"
protocol static static1 {
    route %s via %s;
    export all;
}
EOF
""" % (external_route_v4, self.external_node_ip))
                run("docker exec kube-node-extra birdcl configure")
                self.add_cleanup(lambda: run("docker exec kube-node-extra sh -c 'rm /etc/bird/static-route.conf; birdcl configure'"))
            if ipv6:
                run("""cat <<EOF | docker exec -i kube-node-extra-v6 sh -c "cat > /etc/bird6/static-route.conf"
protocol static static1 {
    route %s via %s;
    export all;
}
EOF
""" % (external_route_v6, self.external_node_ip6))
                run("docker exec kube-node-extra-v6 birdcl6 configure")
                self.add_cleanup(lambda: run("docker exec kube-node-extra-v6 sh -c 'rm /etc/bird6/static-route.conf; birdcl6 configure'"))

            # Patch BGPPeer to make it global
            if ipv4:
                kubectl("patch bgppeer node-extra.peer --type json --patch '[{\"op\": \"remove\", \"path\": \"/spec/nodeSelector\"}]'")
                self.add_cleanup(lambda: kubectl("patch bgppeer node-extra.peer --patch '{\"spec\":{\"nodeSelector\":\"egress == \\\"true\\\"\"}}'"))
            if ipv6:
                kubectl("patch bgppeer node-extra-v6.peer --type json --patch '[{\"op\": \"remove\", \"path\": \"/spec/nodeSelector\"}]'")
                self.add_cleanup(lambda: kubectl("patch bgppeer node-extra-v6.peer --patch '{\"spec\":{\"nodeSelector\":\"egress == \\\"true\\\"\"}}'"))

            # Check that route is present
            if ipv4:
                self._assert_route_present_in_cluster_bird(self.egress_calico_pod, external_route_v4, self.external_node_ip, globalPeer=True)
            if ipv6:
                self._assert_route_present_in_cluster_bird(self.egress_calico_pod, external_route_v6, self.external_node_ip6, globalPeer=True, ipv6=True)

            # Add BGPFilter with import rule and check that the route is no longer present
            if ipv4:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-1
spec:
  importV4:
  - cidr: %s
    matchOperator: Equal
    action: Reject
EOF
""" % external_route_v4)
                self._patch_peer_filters("node-extra.peer", ["test-filter-import-1"])

                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-1"))
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra.peer", []))

                self._assert_route_not_present_in_cluster_bird(self.egress_calico_pod, external_route_v4, self.external_node_ip, globalPeer=True)
            if ipv6:
                kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-import-v6-1
spec:
  importV6:
  - cidr: %s
    matchOperator: Equal
    action: Reject
EOF
""" % external_route_v6)
                self._patch_peer_filters("node-extra-v6.peer", ["test-filter-import-v6-1"])

                self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-import-v6-1"))
                self.add_cleanup(lambda: self._patch_peer_filters("node-extra-v6.peer", []))

                self._assert_route_not_present_in_cluster_bird(self.egress_calico_pod, external_route_v6, self.external_node_ip6, globalPeer=True, ipv6=True)

    def test_bgp_filter_validation(self):
        with DiagsCollector():
            # Filter with various invalid fields
            output = kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-invalid-filter
spec:
  importV4:
  - cidr: 10.111.111.0/24
    matchOperator: notin
    action: accept
  - cidr: 10.222.222.0/24
    matchOperator: equal
    action: Retecj
  - cidr: fd00:1111:1111:1111::/64
    matchOperator: Equal
    action: Accept
  exportV4:
  - cidr: 10.111.111.0/24
    matchOperator: notin
    action: Accetp
  - cidr: 10.222.222.0/24
    matchOperator: in
    action: Accept
  - cidr: IPv4Address
    matchOperator: In
    action: Accept
  importV6:
  - cidr: fd00:1111:1111:1111::/64
    matchOperator: Eqaul
    action: accept
  - cidr: 10.111.111.0/24
    matchOperator: In
    action: Accept
  exportV6:
  - cidr: fd00:2222:2222:2222::/64
    matchOperator: notequal
    action: reject
  - cidr: ipv6Address
    matchOperator: Equal
    action: Reject
EOF
""", allow_fail=True, returnerr=True)

            if output is not None:
                output = output.strip()

            expectedOutput = """The BGPFilter "test-invalid-filter" is invalid: 
* MatchOperator: Invalid value: "notin": Reason: failed to validate Field: MatchOperator because of Tag: matchOperator 
* Action: Invalid value: "Accetp": Reason: failed to validate Field: Action because of Tag: filterAction 
* MatchOperator: Invalid value: "in": Reason: failed to validate Field: MatchOperator because of Tag: matchOperator 
* CIDR: Invalid value: "IPv4Address": Reason: failed to validate Field: CIDR because of Tag: netv4 
* Action: Invalid value: "accept": Reason: failed to validate Field: Action because of Tag: filterAction 
* MatchOperator: Invalid value: "equal": Reason: failed to validate Field: MatchOperator because of Tag: matchOperator 
* Action: Invalid value: "Retecj": Reason: failed to validate Field: Action because of Tag: filterAction 
* CIDR: Invalid value: "fd00:1111:1111:1111::/64": Reason: failed to validate Field: CIDR because of Tag: netv4 
* MatchOperator: Invalid value: "notequal": Reason: failed to validate Field: MatchOperator because of Tag: matchOperator 
* Action: Invalid value: "reject": Reason: failed to validate Field: Action because of Tag: filterAction 
* CIDR: Invalid value: "ipv6Address": Reason: failed to validate Field: CIDR because of Tag: netv6 
* MatchOperator: Invalid value: "Eqaul": Reason: failed to validate Field: MatchOperator because of Tag: matchOperator 
* CIDR: Invalid value: "10.111.111.0/24": Reason: failed to validate Field: CIDR because of Tag: netv6"""
            assert output == expectedOutput

    def test_bgp_filter_basic_v4(self):
        self._test_bgp_filter_basic(True, False)

    def test_bgp_filter_basic_v6(self):
        self._test_bgp_filter_basic(False, True)

    def test_bgp_filter_basic_v4v6(self):
        self._test_bgp_filter_basic(True, True)

    def test_bgp_filter_ordering_v4(self):
        self._test_bgp_filter_ordering(True, False)

    def test_bgp_filter_ordering_v6(self):
        self._test_bgp_filter_ordering(False, True)

    def test_bgp_filter_ordering_v4v6(self):
        self._test_bgp_filter_ordering(True, True)

    def test_bgp_filter_global_peer_v4(self):
        self._test_bgp_filter_global_peer(True, False)

    def test_bgp_filter_global_peer_v6(self):
        self._test_bgp_filter_global_peer(False, True)

    def test_bgp_filter_global_peer_v4v6(self):
        self._test_bgp_filter_global_peer(True, True)
