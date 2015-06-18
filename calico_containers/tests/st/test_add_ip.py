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


class TestAddIp(TestBase):
    def test_add_ip(self):
        """
        Test adding multiple IPs per workload.
        """
        host = DockerHost('host')

        ip11 = "192.168.1.1"
        ip12 = "192.168.1.2"
        ip21 = "192.168.2.1"
        ip22 = "192.168.2.2"
        ip31 = "192.168.3.1"

        node1 = host.create_workload("node1", ip11)
        node2 = host.create_workload("node2")
        host.calicoctl("container add %s %s --interface=hello" % (node2, ip12))

        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add %s" % node1)
        host.calicoctl("profile TEST_GROUP member add %s" % node2)

        node1.assert_can_ping(ip12, retries=3)

        # Add two more addresses to node1 and one more to node2
        host.calicoctl("container node1 ip add %s" % ip21)
        host.calicoctl("container node1 ip add %s" % ip31)

        host.calicoctl("container %s ip add %s --interface=hello" % (node2, ip22))

        node1.assert_can_ping(ip22)
        node2.assert_can_ping(ip11)
        node2.assert_can_ping(ip21)
        node2.assert_can_ping(ip31)

        # Now stop and restart node 1 and node 2.
        host.execute("docker stop %s" % node1, use_powerstrip=True)
        host.execute("docker stop %s" % node2, use_powerstrip=True)
        host.execute("docker start %s" % node1, use_powerstrip=True)
        host.execute("docker start %s" % node2, use_powerstrip=True)

        # Test pings between the IPs.
        node1.assert_can_ping(ip12, retries=3)
        node1.assert_can_ping(ip22)
        node2.assert_can_ping(ip11)
        node2.assert_can_ping(ip21)
        node2.assert_can_ping(ip31)

        # Now remove and check pings to the removed addresses no longer work.
        host.calicoctl("container %s ip remove %s" % (node1, ip21))
        host.calicoctl("container %s ip remove %s --interface=hello" % (node2, ip22))
        node1.assert_can_ping(ip12)
        node2.assert_can_ping(ip11)
        with self.assertRaises(ErrorReturnCode):
            node1.assert_can_ping(ip22)
        with self.assertRaises(ErrorReturnCode):
            node2.assert_can_ping(ip21)
        node2.assert_can_ping(ip31)

        # Check that we can't remove addresses twice
        with self.assertRaises(ErrorReturnCode):
            host.calicoctl("container %s ip remove %s" % (node1, ip21))
