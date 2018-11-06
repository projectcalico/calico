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
from tests.k8st.utils.utils import retry_until_success

_log = logging.getLogger(__name__)


class TestAllRunning(TestBase):
    def test_kubesystem_pods_running(self):
        self.check_pod_status('kube-system')

    def test_default_pods_running(self):
        self.check_pod_status('default')

    def test_calico_monitoring_pods_running(self):
        self.check_pod_status('calico-monitoring')


class TestSimplePolicy(TestBase):
    def setUp(self):
        self.create_service("nginx:1.7.9", "nginx", "policy-demo", 80)

    def tearDown(self):
        # Delete deployment
        self.delete_and_confirm("policy-demo", "ns")

    def test_simple_policy(self):
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
        retry_until_success(self.cannot_connect, retries=10, wait_time=1, function_args=["access"])
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
            subprocess.check_call("kubectl run "
                                  "--namespace=policy-demo "
                                  "%s "
                                  "--restart Never "
                                  "--rm -i "
                                  "--image busybox "
                                  "--command /bin/wget "
                                  "-- -q --timeout=1 nginx" % name,
                                  shell=True)
        except subprocess.CalledProcessError:
            _log.debug("Failed to contact service")
            return False
        _log.debug("Contacted service")
        return True

    class ConnectionError(Exception):
        pass
