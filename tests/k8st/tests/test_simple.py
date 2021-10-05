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
import subprocess
import time

from kubernetes import client

from tests.k8st.test_base import TestBase
from tests.k8st.utils.utils import retry_until_success, DiagsCollector, kubectl, node_info, run

_log = logging.getLogger(__name__)


class TestGracefulRestart(TestBase):

    def get_restart_node_pod_name(self):
        self.restart_pod_name = run("kubectl get po -n kube-system" +
                                    " -l k8s-app=calico-node" +
                                    " --field-selector status.podIP=" + self.restart_node_ip +
                                    " -o jsonpath='{.items[*].metadata.name}'")
        if self.restart_pod_name == "":
            raise Exception('pod name not found')

    def _test_restart_route_churn(self, num_repeats, restart_func, expect_churn):
        with DiagsCollector():

            # Get 2 worker node names, one to monitor routes and one
            # to have its calico-node restarted.  The first name
            # returned is always the master, so skip that.
            nodes, ips, _ = node_info()
            self.assertGreater(len(nodes), 2)
            monitor_node = nodes[1]
            self.restart_node = nodes[2]
            self.restart_node_ip = ips[2]

            # Start running ip monitor on the monitor node, to monitor
            # IPv4 route changes.  We use "fd00:10:244" to identify
            # and exclude IPv6 workload block routes like
            # fd00:10:244:0:1cc0:b1ac:ad47:e7c0/122.  These definitely
            # _do_ flap when the host of that block restarts, but it
            # is not yet clear why this is; specifically it is not yet
            # known if it indicates anything wrong with calico/node's
            # GR setup.  See
            # https://marc.info/?l=bird-users&m=158298182509702&w=2
            # for the mailing list discussion so far.
            run("docker exec -d %s sh -c 'stdbuf -oL ip -ts monitor route | stdbuf -oL grep -v fd00:10:244 > rmon.txt'" %
                monitor_node)

            # Find the name of the calico-node pod on the restart node.
            self.get_restart_node_pod_name()

            # Restart the calico-node several times, on the other node.
            for i in range(num_repeats):
                # Restart it.
                _log.info("Iteration %d: restart pod %s", i, self.restart_pod_name)
                restart_func(self)

            # Kill the ip monitor process.
            run("docker exec %s pkill ip" % monitor_node)

            # Dump the monitor output.
            monitor_output = run("docker exec %s cat rmon.txt" % monitor_node)

            if expect_churn:
                # Assert that it is not empty.
                self.assertNotEqual(monitor_output, "")
            else:
                # Assert that it is empty.
                self.assertEqual(monitor_output, "")

    def test_methodology(self):
        # Test the methodology here, by verifying that we _do_ observe
        # route churn if we kill BIRD with SIGTERM.
        def kill_bird(self):
            run("docker exec %s pkill bird" % self.restart_node)
            def check_bird_running():
                run("docker exec %s pgrep bird" % self.restart_node)
            retry_until_success(check_bird_running, retries=10, wait_time=1)
            time.sleep(5)

        # Expect non-GR behaviour, i.e. route churn.
        self._test_restart_route_churn(3, kill_bird, True)

    def test_graceful_restart(self):
        # Test that we do _not_ observe route churn when Kubernetes
        # deletes and restarts a pod.
        def delete_calico_node_pod(self):
            run("kubectl delete po %s -n kube-system" % self.restart_pod_name)

            # Wait until a replacement calico-node pod has been created.
            retry_until_success(self.get_restart_node_pod_name, retries=10, wait_time=1)

            # Wait until it is ready, before returning.
            run("kubectl wait po %s -n kube-system --timeout=2m --for=condition=ready" %
                self.restart_pod_name)

        # Expect GR behaviour, i.e. no route churn.
        self._test_restart_route_churn(8, delete_calico_node_pod, False)


class TestAllRunning(TestBase):
    def test_kubesystem_pods_running(self):
        with DiagsCollector():
            self.check_pod_status('kube-system')

    def test_default_pods_running(self):
        with DiagsCollector():
            self.check_pod_status('default')

    def test_calico_monitoring_pods_running(self):
        with DiagsCollector():
            self.check_pod_status('calico-monitoring')


class TestSimplePolicy(TestBase):
    def setUp(self):
        TestBase.setUp(self)
        self.create_namespace("policy-demo")
        self.deploy("nginx:1.7.9", "nginx", "policy-demo", 80)

        # Create two client pods that live for the duration of the
        # test.  We will use 'kubectl exec' to try wgets from these at
        # particular times.
        #
        # We do it this way - instead of one-shot pods that are
        # created, try wget, and then exit - because it takes a
        # relatively long time (7 seconds?) in this test setup for
        # Calico routing and policy to be set up correctly for a newly
        # created pod.  In particular it's possible that connection
        # from a just-created pod will fail because that pod's IP has
        # not yet propagated to the IP set for the ingress policy on
        # the server pod - which can confuse test code that is
        # expecting connection failure for some other reason.
        kubectl("run access -n policy-demo" +
                " --overrides='{\"metadata\": {\"annotations\": {\"cni.projectcalico.org/floatingIPs\":\"[\\\"195.160.168.193\\\", \\\"2001:67c:275c:ff::1\\\"]\"}}}' "
                " --image busybox --command /bin/sleep -- 3600")
        kubectl("run no-access -n policy-demo" +
                " --image busybox --command /bin/sleep -- 3600")
        kubectl("wait --timeout=2m --for=condition=available" +
                " deployment/nginx -n policy-demo")
        kubectl("wait --timeout=2m --for=condition=ready" +
                " pod/access -n policy-demo")
        kubectl("wait --timeout=2m --for=condition=ready" +
                " pod/no-access -n policy-demo")

    def tearDown(self):
        # Delete deployment
        kubectl("delete --grace-period 0 pod access -n policy-demo")
        kubectl("delete --grace-period 0 pod no-access -n policy-demo")
        self.delete_and_confirm("policy-demo", "ns")

    def test_simple_policy(self):
        with DiagsCollector():
            # Check we can talk to service.
            retry_until_success(self.can_connect, retries=10, wait_time=1, function_args=["access"])
            _log.info("Client 'access' connected to open service")
            retry_until_success(self.can_connect, retries=10, wait_time=1, function_args=["no-access"])
            _log.info("Client 'no-access' connected to open service")

            # Create default-deny policy
            policy = client.V1NetworkPolicy(
                metadata=client.V1ObjectMeta(
                    name="default-deny",
                    namespace="policy-demo"
                ),
                spec={
                    "podSelector": {
                        "matchLabels": {},
                    },
                }
            )
            client.NetworkingV1Api().create_namespaced_network_policy(
                body=policy,
                namespace="policy-demo",
            )
            _log.debug("Isolation policy created")

            # Check we cannot talk to service
            retry_until_success(self.cannot_connect, retries=10, wait_time=1, function_args=["access"])
            _log.info("Client 'access' failed to connect to isolated service")
            retry_until_success(self.cannot_connect, retries=10, wait_time=1, function_args=["no-access"])
            _log.info("Client 'no-access' failed to connect to isolated service")

            # Create allow policy
            policy = client.V1NetworkPolicy(
                metadata=client.V1ObjectMeta(
                    name="access-nginx",
                    namespace="policy-demo"
                ),
                spec={
                    'ingress': [{
                        'from': [{
                            'podSelector': {
                                'matchLabels': {
                                    'run': 'access'
                                }
                            }
                        }]
                    }],
                    'podSelector': {
                        'matchLabels': {
                            'app': 'nginx'
                        }
                    }
                }
            )
            client.NetworkingV1Api().create_namespaced_network_policy(
                body=policy,
                namespace="policy-demo",
            )
            _log.debug("Allow policy created.")

            # Check we can talk to service as 'access'
            retry_until_success(self.can_connect, retries=10, wait_time=1, function_args=["access"])
            _log.info("Client 'access' connected to protected service")

            # Check we cannot talk to service as 'no-access'
            retry_until_success(self.cannot_connect, retries=10, wait_time=1, function_args=["no-access"])
            _log.info("Client 'no-access' failed to connect to protected service")

    def can_connect(self, name):
        if not self.check_connected(name):
            _log.warning("'%s' failed to connect, when connection was expected", name)
            raise self.ConnectionError
        _log.info("'%s' connected, as expected", name)

    def cannot_connect(self, name):
        if self.check_connected(name):
            _log.warning("'%s' unexpectedly connected", name)
            raise self.ConnectionError
        _log.info("'%s' failed to connect, as expected", name)

    @staticmethod
    def check_connected(name):
        try:
            kubectl("exec " + name + " -n policy-demo" +
                    " -- /bin/wget -O /dev/null -q --timeout=1 nginx")
        except subprocess.CalledProcessError:
            _log.exception("Failed to wget from nginx service")
            return False
        _log.debug("Contacted service")
        return True

    class ConnectionError(Exception):
        pass
