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
from nose.plugins.attrib import attr

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.route_reflector import RouteReflectorCluster
from tests.st.utils.constants import (DEFAULT_IPV4_ADDR_1, DEFAULT_IPV4_ADDR_2,
                                      DEFAULT_IPV4_ADDR_3)

class TestRouteReflectorCluster(TestBase):

    @attr('slow')
    def test_route_reflector_cluster(self):
        """
        Run a multi-host test using a cluster of route reflectors and node
        specific peerings.
        """
        with DockerHost('host1') as host1, \
             DockerHost('host2') as host2, \
             DockerHost('host3') as host3, \
             RouteReflectorCluster(2, 2) as rrc:

            # Set the default AS number - as this is used by the RR mesh, and
            # turn off the node-to-node mesh (do this from any host).
            host1.calicoctl("bgp default-node-as 64513")
            host1.calicoctl("bgp node-mesh off")

            # Create a profile to associate with all workloads
            host1.calicoctl("profile add TEST_GROUP")

            workload_host1 = host1.create_workload("workload1")
            workload_host2 = host2.create_workload("workload2")
            workload_host3 = host3.create_workload("workload3")

            # Add containers to Calico
            host1.calicoctl("container add %s %s" % (workload_host1,
                                                     DEFAULT_IPV4_ADDR_1))
            host2.calicoctl("container add %s %s" % (workload_host2,
                                                     DEFAULT_IPV4_ADDR_2))
            host3.calicoctl("container add %s %s" % (workload_host3,
                                                     DEFAULT_IPV4_ADDR_3))

            # Now add the profiles
            host1.calicoctl("container %s profile set TEST_GROUP" % workload_host1)
            host2.calicoctl("container %s profile append TEST_GROUP" % workload_host2)
            host3.calicoctl("container %s profile append TEST_GROUP" % workload_host3)

            # Allow network to converge (which it won't)
            try:
                workload_host1.assert_can_ping(DEFAULT_IPV4_ADDR_2, retries=5)
            except AssertionError:
                pass
            else:
                raise AssertionError("Hosts can ping each other")
            workload_host1.assert_cant_ping(DEFAULT_IPV4_ADDR_3)
            workload_host2.assert_cant_ping(DEFAULT_IPV4_ADDR_3)

            # Set distributed peerings between the hosts, each host peering
            # with a different set of redundant route reflectors.
            for host in [host1, host2, host3]:
                for rr in rrc.get_redundancy_group():
                    host.calicoctl("node bgp peer add %s as 64513" % rr.ip)

            # Allow network to converge (which it now will).
            workload_host1.assert_can_ping(DEFAULT_IPV4_ADDR_2, retries=10)
            workload_host1.assert_can_ping(DEFAULT_IPV4_ADDR_3, retries=10)
            workload_host2.assert_can_ping(DEFAULT_IPV4_ADDR_3, retries=10)

            # And check connectivity in both directions.
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2,
                                                       workload_host3],
                                        ip_pass_list=[DEFAULT_IPV4_ADDR_1,
                                                      DEFAULT_IPV4_ADDR_2,
                                                      DEFAULT_IPV4_ADDR_3])

