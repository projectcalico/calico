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

from tests.st.test_base import TestBase, HOST_IPV6
from tests.st.utils.docker_host import DockerHost

class TestNoOrchestratorSingleHost(TestBase):
    def test_single_host_ipv4(self):
        """
        Test mainline functionality without using an orchestrator plugin
        """
        with DockerHost('host', dind=False) as host:
            host.calicoctl("profile add TEST_GROUP")

            # Create a workload on each host.
            workload1 = host.create_workload("workload1")
            workload2 = host.create_workload("workload2")

            # Add the nodes to Calico networking.
            host.calicoctl("container add %s 192.168.1.1" % workload1)
            host.calicoctl("container add %s 192.168.1.2" % workload2)

            # Now add the profiles - one using set and one using append
            host.calicoctl("container %s profile set TEST_GROUP" % workload1)
            host.calicoctl("container %s profile append TEST_GROUP" % workload2)

            # TODO - assert on output of endpoint show and endpoint profile
            # show commands.

            # Check it works
            workload1.assert_can_ping("192.168.1.2", retries=3)
            workload2.assert_can_ping("192.168.1.1", retries=3)

            # Test the teardown commands
            host.calicoctl("profile remove TEST_GROUP")
            host.calicoctl("container remove %s" % workload1)
            host.calicoctl("container remove %s" % workload2)
            host.calicoctl("pool remove 192.168.0.0/16")
            host.calicoctl("node stop")
            host.calicoctl("node remove")

    @unittest.skipUnless(HOST_IPV6, "Host does not have an IPv6 address")
    def test_single_host_ipv6(self):
        """
        Test mainline functionality without using an orchestrator plugin
        """
        with DockerHost('host', dind=False) as host:
            host.calicoctl("profile add TEST_GROUP")

            # Create a workload on each host.
            workload1 = host.create_workload("workload1")
            workload2 = host.create_workload("workload2")

            # Add the nodes to Calico networking.
            host.calicoctl("container add %s fd80:24e2:f998:72d6::1" % workload1)
            host.calicoctl("container add %s fd80:24e2:f998:72d6::2" % workload2)

            # Now add the profiles - one using set and one using append
            host.calicoctl("container %s profile set TEST_GROUP" % workload1)
            host.calicoctl("container %s profile append TEST_GROUP" % workload2)

            # # Check it works
            workload1.assert_can_ping("fd80:24e2:f998:72d6::2", retries=3)
            workload2.assert_can_ping("fd80:24e2:f998:72d6::1", retries=3)
