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
import re

from nose.plugins.attrib import attr

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.constants import (DEFAULT_IPV4_ADDR_1, DEFAULT_IPV4_ADDR_2,
                                      LARGE_AS_NUM)
from tests.st.utils.utils import check_bird_status

"""
Test "calicoctl bgp" and "calicoctl node bgp" commands.

Testing should be focused around the different topologies that we support.
    Mesh is covered (a little) by existing multi host tests (done)
    Single RR cluster  (done)
    AS per ToR
    AS per calico node

Test IPv4 and IPv6
Two threads to the testing:
    Function of the commands (which we already are testing) - see below
    BGP functionality in the different topologies

TODO - rework BGP tests.
"""


class TestGlobalPeers(TestBase):

    @attr('slow')
    def test_global_peers(self):
        """
        Test global BGP peer configuration.

        Test by turning off the mesh and configuring the mesh as
        a set of global peers.
        """
        with DockerHost('host1', start_calico=False) as host1, \
             DockerHost('host2', start_calico=False) as host2:

            # Start both hosts using specific AS numbers.
            host1.start_calico_node(as_num=LARGE_AS_NUM)
            host2.start_calico_node(as_num=LARGE_AS_NUM)

            # Create the network on host1, but it should be usable from all
            # hosts.
            workload_host1 = host1.create_workload("workload1")
            workload_host2 = host2.create_workload("workload2")

            # Create a profile to associate with both workloads
            host1.calicoctl("profile add TEST_GROUP")

            # Add the workloads to Calico networking
            host1.calicoctl("container add %s %s" % (workload_host1,
                                                     DEFAULT_IPV4_ADDR_1))
            host2.calicoctl("container add %s %s" % (workload_host2,
                                                     DEFAULT_IPV4_ADDR_2))

            # Now add the profiles - one using set and one using append
            host1.calicoctl("container %s profile set TEST_GROUP" % workload_host1)
            host2.calicoctl("container %s profile append TEST_GROUP" % workload_host2)

            # Allow network to converge
            workload_host1.assert_can_ping(DEFAULT_IPV4_ADDR_2, retries=10)

            # Turn the node-to-node mesh off and wait for connectivity to drop.
            host1.calicoctl("bgp node-mesh off")
            workload_host1.assert_cant_ping(DEFAULT_IPV4_ADDR_2, retries=10)

            # Configure global peers to explicitly set up a mesh.  This means
            # each node will try to peer with itself which will fail.
            host1.calicoctl("bgp peer add %s as %s" % (host2.ip, LARGE_AS_NUM))
            host1.calicoctl("bgp peer add %s as %s" % (host1.ip, LARGE_AS_NUM))

            # Allow network to converge
            workload_host1.assert_can_ping(DEFAULT_IPV4_ADDR_2, retries=10)

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[DEFAULT_IPV4_ADDR_1,
                                                      DEFAULT_IPV4_ADDR_2])

            # Check the BGP status on each host.  Connections from a node to
            # itself will be idle since this is invalid BGP configuration.
            check_bird_status(host1, [("global", host1.ip, "Idle"),
                                       ("global", host2.ip, "Established")])
            check_bird_status(host2, [("global", host1.ip, "Established"),
                                       ("global", host2.ip, "Idle")])
