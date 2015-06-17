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


class TestNoPowerstrip(TestBase):
    def test_no_powerstrip(self):
        """
        Test mainline functionality without using powerstrip.
        """
        host = DockerHost('host')

        host.calicoctl("profile add TEST_GROUP")

        # Remove the environment variable such that docker run does not utilize
        # powerstrip.
        node1 = host.create_workload("node1", use_powerstrip=False)
        node2 = host.create_workload("node2", use_powerstrip=False)

        # Attempt to configure the nodes with the same profiles.  This will fail
        # since we didn't use powerstrip to create the nodes.
        with self.assertRaises(ErrorReturnCode):
            host.calicoctl("profile TEST_GROUP member add %s" % node1)
        with self.assertRaises(ErrorReturnCode):
            host.calicoctl("profile TEST_GROUP member add %s" % node2)

        # Add the nodes to Calico networking.
        ip1, ip2 = "192.168.1.1", "192.168.1.2"
        host.calicoctl("container add %s %s" % (node1, ip1))
        host.calicoctl("container add %s %s" % (node2, ip2))

        # Now add the profiles.
        host.calicoctl("profile TEST_GROUP member add %s" % node1)
        host.calicoctl("profile TEST_GROUP member add %s" % node2)

        # Inspect the nodes (ensure this works without powerstrip)
        host.execute("docker inspect %s" % node1)
        host.execute("docker inspect %s" % node2)

        # Check it works
        node1.assert_can_ping(ip1, retries=3)
        node1.assert_can_ping(ip2)
        node2.assert_can_ping(ip1)
        node2.assert_can_ping(ip2)

        # Test the teardown commands
        host.calicoctl("profile remove TEST_GROUP")
        host.calicoctl("container remove %s" % node1)
        host.calicoctl("container remove %s" % node2)
        host.calicoctl("pool remove 192.168.0.0/16")
        host.calicoctl("node stop")
