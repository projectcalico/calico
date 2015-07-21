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

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.workload import NET_NONE


class TestNoOrchestratorMultiHost(TestBase):
    def test_multi_host(self):
        """
        Test mainline functionality without using an orchestrator plugin on
        multiple hosts.
        """
        with DockerHost('host1') as host1, DockerHost('host2') as host2:
            # TODO ipv6 too
            host1.calicoctl("profile add TEST_GROUP")

            # Use standard docker bridge networking for one and --net=none
            # for the other
            node1 = host1.create_workload("node1")
            node2 = host2.create_workload("node2", network=NET_NONE)

            # Add the nodes to Calico networking.
            host1.calicoctl("container add %s 192.168.1.1" % node1)
            host2.calicoctl("container add %s 192.168.1.2" % node2)

            # Get the endpoint IDs for the containers
            ep1 = host1.calicoctl("container %s endpoint-id show" % node1)
            ep2 = host2.calicoctl("container %s endpoint-id show" % node2)

            # Now add the profiles - one using set and one using append
            host1.calicoctl("endpoint %s profile set TEST_GROUP" % ep1)
            host2.calicoctl("endpoint %s profile append TEST_GROUP" % ep2)

            # TODO - assert on output of endpoint show and endpoint profile
            # show commands.

            # Check it works
            node1.assert_can_ping("192.168.1.2", retries=3)
            node2.assert_can_ping("192.168.1.1", retries=3)


            # Test the teardown commands
            host1.calicoctl("profile remove TEST_GROUP")
            host1.calicoctl("container remove %s" % node1)
            host2.calicoctl("container remove %s" % node2)
            host1.calicoctl("pool remove 192.168.0.0/16")
            host1.calicoctl("node stop")
            host2.calicoctl("node stop")
