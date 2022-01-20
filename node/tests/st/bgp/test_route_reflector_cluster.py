# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
from unittest import skip

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.route_reflector import RouteReflectorCluster

from .peer import create_bgp_peer
from tests.st.utils.utils import update_bgp_config

class TestRouteReflectorCluster(TestBase):

    def test_route_reflector_cluster_resilience(self):
        """
        Runs a cluster of route reflectors, brings one node down, and ensures that traffic still flows
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2, \
             RouteReflectorCluster(2, 1) as rrc:

            # Start both hosts using specific backends.
            host1.start_calico_node("--backend=bird")
            host2.start_calico_node("--backend=bird")
            update_bgp_config(host1, asNum=64513, nodeMesh=False)

            # Create a workload on each host in the same network.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1)
            workload_host2 = host2.create_workload("workload2", network=network1)

            # Assert no network connectivity
            self.assert_false(workload_host1.check_can_ping(workload_host2.ip, retries=5))

            # Peer the hosts with the route reflectors
            for host in [host1, host2]:
                for rr in rrc.get_redundancy_group():
                    create_bgp_peer(host, "node", rr.ip, 64513, metadata={'name': host.name + rr.name.lower()})

            # Assert network connectivity
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=10))
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip])
            # Bring down a node
            rrc.redundancy_groups[0][0].cleanup()

            # Assert that network is still connected
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=10))
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip])


    def _test_route_reflector_cluster(self, backend='bird'):
        """
        Run a multi-host test using a cluster of route reflectors and node
        specific peerings.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2, \
             DockerHost('host3',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host3, \
             RouteReflectorCluster(2, 2) as rrc:

            # Start both hosts using specific backends.
            host1.start_calico_node("--backend=%s" % backend)
            host2.start_calico_node("--backend=%s" % backend)
            host3.start_calico_node("--backend=%s" % backend)

            # Set the default AS number - as this is used by the RR mesh, and
            # turn off the node-to-node mesh (do this from any host).
            update_bgp_config(host1, asNum=64513, nodeMesh=False)

            # Create a workload on each host in the same network.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1)
            workload_host2 = host2.create_workload("workload2", network=network1)
            workload_host3 = host3.create_workload("workload3", network=network1)

            # Allow network to converge (which it won't)
            self.assert_false(workload_host1.check_can_ping(workload_host2.ip, retries=5))
            self.assert_true(workload_host1.check_cant_ping(workload_host3.ip))
            self.assert_true(workload_host2.check_cant_ping(workload_host3.ip))

            # Set distributed peerings between the hosts, each host peering
            # with a different set of redundant route reflectors.
            for host in [host1, host2, host3]:
                for rr in rrc.get_redundancy_group():
                    create_bgp_peer(host, "node", rr.ip, 64513, metadata={'name': host.name + rr.name.lower()})

            # Allow network to converge (which it now will).
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=20))
            self.assert_true(workload_host1.check_can_ping(workload_host3.ip, retries=20))
            self.assert_true(workload_host2.check_can_ping(workload_host3.ip, retries=20))

            # And check connectivity in both directions.
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2,
                                                       workload_host3],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip,
                                                      workload_host3.ip])

    @attr('slow')
    def test_bird_route_reflector_cluster(self):
        self._test_route_reflector_cluster(backend='bird')

TestRouteReflectorCluster.batchnumber = 3  # Adds a batch number for parallel testing
