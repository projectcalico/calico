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
from tests.st.utils.utils import update_bgp_config, check_bird_status, retry_until_success

from .peer import create_bgp_peer

class TestSingleRouteReflector(TestBase):

    @attr('slow')
    def _test_single_route_reflector(self, backend='bird', bgpconfig_as_num=64514, peer_as_num=64514):
        """
        Run a multi-host test using a single route reflector and global
        peering.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2, \
             RouteReflectorCluster(1, 1) as rrc:

            # Start both hosts using specific backends.
            host1.start_calico_node("--backend=%s" % backend)
            host2.start_calico_node("--backend=%s" % backend)

            # Set the default AS number - as this is used by the RR mesh, and
            # turn off the node-to-node mesh (do this from any host).
            update_bgp_config(host1, nodeMesh=False, asNum=bgpconfig_as_num)

            # Create a workload on each host in the same network.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1",
                                                   network=network1)
            workload_host2 = host2.create_workload("workload2",
                                                   network=network1)

            # Allow network to converge (which it won't)
            self.assert_false(workload_host1.check_can_ping(workload_host2.ip, retries=5))

            # Set global config telling all calico nodes to peer with the
            # route reflector.  This can be run from either host.
            rg = rrc.get_redundancy_group()
            assert len(rg) == 1
            create_bgp_peer(host1, "global", rg[0].ip, peer_as_num)

            # Allow network to converge (which it now will).
            retry_until_success(host1.assert_is_ready, retries=30, felix=False)
            retry_until_success(host2.assert_is_ready, retries=30, felix=False)
            check_bird_status(host1, [("global", rg[0].ip, "Established")])
            check_bird_status(host2, [("global", rg[0].ip, "Established")])
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=20))

            # And check connectivity in both directions.
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip])

    @attr('slow')
    def test_bird_single_route_reflector(self):
        self._test_single_route_reflector(backend='bird')

    @attr('slow')
    def test_bird_single_route_reflector_default_as(self):
        self._test_single_route_reflector(backend='bird', bgpconfig_as_num=None, peer_as_num=64512)

TestSingleRouteReflector.batchnumber = 1  # Adds a batch number for parallel testing
