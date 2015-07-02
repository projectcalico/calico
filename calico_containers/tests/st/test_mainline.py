# Copyright 2015 Metaswitch Networks
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
import unittest
import uuid

from test_base import TestBase
from tests.st.utils.docker_host import DockerHost


class TestMainline(TestBase):
    def run_mainline(self, ip1, ip2):
        """
        Setup two endpoints on one host and check connectivity.
        """
        # TODO dind=True is just to work around https://github.com/docker/docker/issues/14107
        with DockerHost('host', dind=True) as host:
            network = host.create_network(str(uuid.uuid4()))
            node1 = host.create_workload(str(uuid.uuid4()), network=network)
            node2 = host.create_workload(str(uuid.uuid4()), network=network)

            # Allow network to converge
            node1.assert_can_ping(node2.ip, retries=5)

            # Check connectivity.
            self.assert_connectivity([node1, node2])

            # Test calicoctl teardown commands.
            # TODO - move this to a different test.
            # host.execute("docker rm -f %s" % node1)
            # host.execute("docker rm -f %s" % node2)
            # host.calicoctl("pool remove 192.168.0.0/16")
            # host.calicoctl("node stop")

    def test_auto(self):
        """
        Run the test using auto assignment of IPs
        """
        self.run_mainline("auto", "auto")

    @unittest.skip("Docker Driver doesn't support static IP assignment yet.")
    def test_hardcoded_ip(self):
        """
        Run the test using hard coded IPV4 assignments.
        """
        self.run_mainline("192.168.1.1", "192.168.1.2")
