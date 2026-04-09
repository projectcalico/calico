# Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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
import re
from subprocess import CalledProcessError

from tests.k8st.test_base import TestBase
from tests.k8st.utils.utils import DiagsCollector, calicoctl, kubectl, exec_in_calico_node, run, retry_until_success, node_info, start_external_node_with_bgp, update_ds_env

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)


class TestReadiness(TestBase):
    def setUp(self):
        # Wait for all Calico pods to be ready.
        kubectl("wait --for=condition=Ready pods --all -n calico-system --timeout=120s")

    def tearDown(self):
        # Make sure nodes are healthy for next test.
        nodes, _, _ = node_info()
        for node in nodes:
            exec_in_calico_node(node, "sv start /etc/service/enabled/bird")
            exec_in_calico_node(node, "sv start /etc/service/enabled/bird6")
            exec_in_calico_node(node, "sv start /etc/service/enabled/confd")
            exec_in_calico_node(node, "sv start /etc/service/enabled/felix")

    def assert_readiness(self, node, flag, ready):
        if not ready:
            try:
                exec_in_calico_node(node, "/bin/calico-node -%s-ready" % flag)
            except CalledProcessError as e:
                _log.info("Got expected error: %s", e)
                return
            raise AssertionError("Expected %s not to be ready" % flag)

        exec_in_calico_node(node, "/bin/calico-node -%s-ready" % flag)

    def assert_liveness(self, node, flag, live):
        if not live:
            try:
                exec_in_calico_node(node, "/bin/calico-node -%s-live" % flag)
            except CalledProcessError as e:
                _log.info("Got expected error: %s", e)
                return
            raise AssertionError("Expected %s not to be live" % flag)

        exec_in_calico_node(node, "/bin/calico-node -%s-live" % flag)

    def test_readiness_bird_down(self):
        """
        Simulate bird service to be down.
        """
        nodes, _, _ = node_info()
        self.assert_readiness(nodes[0], "bird", True)
        exec_in_calico_node(nodes[0], "sv stop /etc/service/enabled/bird")
        self.assert_readiness(nodes[0], "bird", False)
        exec_in_calico_node(nodes[0], "sv start /etc/service/enabled/bird")

    def test_readiness_bird6_down(self):
        """
        Simulate bird6 service to be down.
        """
        nodes, _, _ = node_info()
        self.assert_readiness(nodes[0], "bird6", True)
        exec_in_calico_node(nodes[0], "sv stop /etc/service/enabled/bird6")
        self.assert_readiness(nodes[0], "bird6", False)
        exec_in_calico_node(nodes[0], "sv start /etc/service/enabled/bird6")

    def test_readiness_confd_down(self):
        """
        Simulate confd service to be down.
        """
        nodes, _, _ = node_info()
        self.assert_liveness(nodes[0], "bird", True)
        exec_in_calico_node(nodes[0], "sv stop /etc/service/enabled/confd")
        self.assert_liveness(nodes[0], "bird", False)
        exec_in_calico_node(nodes[0], "sv start /etc/service/enabled/confd")

    def test_felix_down(self):
        """
        Simulate felix service to be down.
        """
        nodes, _, _ = node_info()
        self.assert_readiness(nodes[0], "felix", True)
        exec_in_calico_node(nodes[0], "sv stop /etc/service/enabled/felix")
        self.assert_readiness(nodes[0], "felix", False)
        exec_in_calico_node(nodes[0], "sv start /etc/service/enabled/felix")
