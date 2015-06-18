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
from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class TestIpv6(TestBase):
    def test_ipv6(self):
        """
        Test mainline functionality with IPv6 addresses.
        """
        host = DockerHost('host')

        ip1, ip2 = "fd80:24e2:f998:72d6::1:1", "fd80:24e2:f998:72d6::1:2"
        # We use this image here because busybox doesn't have ping6.
        node1 = host.create_workload("node1", ip=ip1, image="phusion/baseimage:0.9.16")
        node2 = host.create_workload("node2", ip=ip2, image="phusion/baseimage:0.9.16")

        # Configure the nodes with the same profiles.
        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add %s" % node1)
        host.calicoctl("profile TEST_GROUP member add %s" % node2)

        node1.assert_can_ping(ip2, retries=3)

        # Check connectivity.
        self.assert_connectivity([node1, node2])
