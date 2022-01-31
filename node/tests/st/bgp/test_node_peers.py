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

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.constants import (DEFAULT_IPV4_ADDR_1, DEFAULT_IPV4_ADDR_2,
                                      DEFAULT_IPV4_POOL_CIDR, LARGE_AS_NUM)
from tests.st.utils.utils import check_bird_status, update_bgp_config

from .peer import create_bgp_peer
from unittest import skip

class TestNodePeers(TestBase):

    def _test_node_peers(self, backend='bird'):
        """
        Test per-node BGP peer configuration.

        Test by turning off the mesh and configuring the mesh as
        a set of per node peers.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2:

            # Start both hosts using specific AS numbers.
            host1.start_calico_node("--backend=%s --as=%s" % (backend, LARGE_AS_NUM))
            host2.start_calico_node("--backend=%s --as=%s" % (backend, LARGE_AS_NUM))

            # Create a network and a couple of workloads on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1,
                                                   ip=DEFAULT_IPV4_ADDR_1)
            workload_host2 = host2.create_workload("workload2", network=network1,
                                                   ip=DEFAULT_IPV4_ADDR_2)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(DEFAULT_IPV4_ADDR_2, retries=10))

            # Turn the node-to-node mesh off and wait for connectivity to drop.
            update_bgp_config(host1, nodeMesh=False)
            self.assert_true(workload_host1.check_cant_ping(DEFAULT_IPV4_ADDR_2, retries=10))

            # Configure node specific peers to explicitly set up a mesh.
            create_bgp_peer(host1, 'node', host2.ip, LARGE_AS_NUM, metadata={'name': "host1peer" })
            create_bgp_peer(host2, 'node', host1.ip, LARGE_AS_NUM, metadata={'name': "host2peer" })

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(DEFAULT_IPV4_ADDR_2, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[DEFAULT_IPV4_ADDR_1,
                                                      DEFAULT_IPV4_ADDR_2])

            # Check the BGP status on each host.
            check_bird_status(host1, [("node specific", host2.ip, "Established")])
            check_bird_status(host2, [("node specific", host1.ip, "Established")])

    @attr('slow')
    def test_bird_node_peers(self):
        self._test_node_peers(backend='bird')

TestNodePeers.batchnumber = 1  # Adds a batch number for parallel testing
