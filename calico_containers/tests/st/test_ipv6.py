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
from calico_containers.tests.st.utils.docker_host import DockerHost


class TestIpv6(TestBase):
    @unittest.skip("Workloads don't store an ipv6 address and this test is "
                   "only testing IPv4")
    def test_ipv6(self):
        """
        Test mainline functionality with IPv6 addresses.
        """
        # Use a UUID for net name so that independent runs of the test use
        # different names.  This helps in the case where etcd gets restarted
        # but Docker does not, since libnetwork will only create the network
        # if it doesn't exist.
        with DockerHost('host', dind=False) as host:

            network = host.create_network(str(uuid.uuid4()))

            # We use this image here because busybox doesn't have ping6.
            node1 = host.create_workload("node1", network=network,
                                         image="ubuntu:14.04")
            node2 = host.create_workload("node2", network=network,
                                         image="ubuntu:14.04")

            # Allow network to converge
            node1.assert_can_ping(node2.ip, retries=3)

            # Check connectivity.
            self.assert_connectivity([node1, node2])

