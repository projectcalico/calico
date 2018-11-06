# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
import subprocess
from time import sleep

from kubernetes import client, config

from tests.k8st.test_base import TestBase
from tests.k8st.utils.utils import start_external_node_with_bgp, retry_until_success

_log = logging.getLogger(__name__)
_log.setLevel(logging.INFO)


bird_conf = """
router id 10.192.0.5;

# Configure synchronization between routing tables and kernel.
protocol kernel {
  learn;             # Learn all alien routes from the kernel
  persist;           # Don't remove routes on bird shutdown
  scan time 2;       # Scan kernel routing table every 2 seconds
  import all;
        export all;
  graceful restart;  # Turn on graceful restart to reduce potential flaps in
                     # routes when reloading BIRD configuration.  With a full
                     # automatic mesh, there is no way to prevent BGP from
                     # flapping since multiple nodes update their BGP
                     # configuration at the same time, GR is not guaranteed to
                     # work correctly in this scenario.
  merge paths on;
}

# Watch interface up/down events.
protocol device {
  debug { states };
  scan time 2;    # Scan interfaces every 2 seconds
}

protocol direct {
  debug { states };
  interface -"cali*", "*"; # Exclude cali* but include everything else.
}

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
  source address 10.192.0.5;  # The local address we use for the TCP connection
  add paths on;
  graceful restart;  # See comment in kernel section about graceful restart.
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}

# ------------- Node-to-node mesh -------------
# For peer /host/kube-master/ip_addr_v4
protocol bgp Mesh_10_192_0_2 from bgp_template {
  neighbor 10.192.0.2 as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}


# For peer /host/kube-node-1/ip_addr_v4
protocol bgp Mesh_10_192_0_3 from bgp_template {
  neighbor 10.192.0.3 as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}

# For peer /host/kube-node-2/ip_addr_v4
protocol bgp Mesh_10_192_0_4 from bgp_template {
  neighbor 10.192.0.4 as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}
"""


class TestBGPAdvert(TestBase):
    def setUp(self):
        super(TestBGPAdvert, self).setUp()

        # Run tearDown in case anything was left up
        self.tearDown()

        start_external_node_with_bgp("kube-node-extra", bird_conf)

        # # Create nginx deployment and service
        self.create_service("nginx:1.7.9", "nginx", "bgp-test", 80)

        # set CALICO_STATIC_ROUTES=10.96.0.0/12
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.AppsV1Api(client.ApiClient())
        node_ds = api.read_namespaced_daemon_set("calico-node", "kube-system", exact=True, export=True)
        for container in node_ds.spec.template.spec.containers:
            if container.name == "calico-node":
                route_env_present = False
                for env in container.env:
                    if env.name == "CALICO_STATIC_ROUTES":
                        route_env_present = True
                if not route_env_present:
                    container.env.append({"name": "CALICO_STATIC_ROUTES", "value": "10.96.0.0/12", "value_from": None})
        api.replace_namespaced_daemon_set("calico-node", "kube-system", node_ds)
        sleep(3)
        retry_until_success(self.check_pod_status, retries=20, wait_time=3, function_args=["kube-system"])

        # # Establish BGPPeer from cluster nodes to node-extra using calicoctl
        subprocess.check_call("""kubectl exec -i -n kube-system calicoctl -- /calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: node-extra.peer
spec:
  peerIP: 10.192.0.5
  asNumber: 64512
EOF
""", shell=True)

    def tearDown(self):
        try:
            subprocess.check_call("docker rm -f kube-node-extra", shell=True)
        except subprocess.CalledProcessError:
            pass
        self.delete_and_confirm("bgp-test", "ns")

    def test_bgp_advert(self):
        """
        Test that BGP routes to services are exported over BGP
        """

        # # Test access to nginx svc from kube-node-extra

        def test():
            subprocess.check_call("docker exec kube-node-extra ip r", shell=True)
            # Assert that a route to the service IP range is present
            subprocess.check_call("docker exec kube-node-extra ip r | grep 10.96.0.0/12", shell=True)
            # Assert that the nginx service can be curled from the external node
            subprocess.check_call("docker exec kube-node-extra "
                                  "curl --connect-timeout 2 -m 3  "
                                  "$(kubectl get svc nginx -n bgp-test -o json | jq -r .spec.clusterIP)", shell=True)
        retry_until_success(test, retries=6, wait_time=10)
