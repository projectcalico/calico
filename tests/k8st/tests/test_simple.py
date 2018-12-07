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
from time import sleep

from kubernetes import client

from tests.k8st.test_base import TestBase
from tests.k8st.utils.utils import retry_until_success, run, DiagsCollector

_log = logging.getLogger(__name__)


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
        run("kubectl run --generator=run-pod/v1 access -n policy-demo" +
            " --image busybox --command /bin/sleep -- 3600")
        run("kubectl run --generator=run-pod/v1 no-access -n policy-demo" +
            " --image busybox --command /bin/sleep -- 3600")

    def tearDown(self):
        # Delete deployment
        run("kubectl delete --grace-period 0 pod access -n policy-demo")
        run("kubectl delete --grace-period 0 pod no-access -n policy-demo")
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
            client.ExtensionsV1beta1Api().create_namespaced_network_policy(
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
            client.ExtensionsV1beta1Api().create_namespaced_network_policy(
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
            run(("kubectl exec %s -n policy-demo" +
                 " -- /bin/wget -O /dev/null -q --timeout=1 nginx") % name)
        except subprocess.CalledProcessError:
            _log.exception("Failed to wget from nginx service")
            return False
        _log.debug("Contacted service")
        return True

    class ConnectionError(Exception):
        pass
