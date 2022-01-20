# Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
import logging
import yaml

from nose.plugins.attrib import attr
from multiprocessing.dummy import Pool as ThreadPool
from unittest import skip

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.route_reflector import RouteReflectorCluster
from tests.st.utils.utils import (
    check_bird_status,
    retry_until_success,
    update_bgp_config
)

from .peer import create_bgp_peer

logger = logging.getLogger(__name__)

class TestSwitchRouteReflector(TestBase):

    @attr('slow')
    def _test_switch_route_reflector(self, backend='bird', bgpconfig_as_num=64514, peer_as_num=64514):
        """
        Test that switching from node-to-node full mesh to route reflectors doesn't disrupt dataplane traffic if done as per
        https://projectcalico.docs.tigera.io/networking/bgp#change-from-node-to-node-mesh-to-route-reflectors-without-any-traffic-disruption
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2, \
             DockerHost('host3',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host3:

            # Start all hosts using specific backends.
            host1.start_calico_node("--backend=%s" % backend)
            host2.start_calico_node("--backend=%s" % backend)
            host3.start_calico_node("--backend=%s" % backend)

            # Create a workload on host1 and host2 in the same network.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1",
                                                   network=network1)
            workload_host2 = host2.create_workload("workload2",
                                                   network=network1)

            # Set the default AS number - as this is used by the RR mesh
            # (do this from any host).
            update_bgp_config(host1, asNum=bgpconfig_as_num)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=5))

            # Start checking ping continuously from host1's to host2's workloads
            # and vice-versa
            t1 = ThreadPool(1)
            ping1_result = t1.apply_async(workload_host1.check_can_ping_continuously,
                                         (workload_host2.ip,),
                                         {'timeout':60})
            t2 = ThreadPool(1)
            ping2_result = t2.apply_async(workload_host2.check_can_ping_continuously,
                                         (workload_host1.ip,),
                                         {'timeout':60})

            # Make host3 act as a route reflector.
            node3 = host3.calicoctl("get Node %s -o yaml" % host3.get_hostname())
            node3cfg = yaml.safe_load(node3)
            logger.info("host3 Node: %s", node3cfg)
            node3cfg['spec']['bgp']['routeReflectorClusterID'] = '224.0.0.3'
            node3cfg['metadata']['labels'] = {
                'routeReflectorClusterID': node3cfg['spec']['bgp']['routeReflectorClusterID'],
            }
            host3.add_resource(node3cfg)

            # Configure peerings - note, NOT a full mesh - from the
            # other nodes to the route reflector.
            host3.add_resource({
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'BGPPeer',
                'metadata': {
                    'name': 'rr-peerings',
                },
                'spec': {
                    'nodeSelector': '!has(routeReflectorClusterID)',
                    'peerSelector': 'has(routeReflectorClusterID)',
                },
            })

            # Wait until the peers' BGP session to the route reflector are
            # established
            retry_until_success(check_bird_status, 30, AssertionError,
                                host1, [("node specific", host3.ip, "Established")])
            retry_until_success(check_bird_status, 30, AssertionError,
                                host2, [("node specific", host3.ip, "Established")])

            # Turn off the node-to-node mesh (do this from any host).
            update_bgp_config(host3, nodeMesh=False)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=20))

            # Verify results of continuous ping from host1's to host2's workloads
            # and vice-versa
            t1.close()
            t1.join()
            logger.info("ping1_result: %s", str(ping1_result.get()))
            self.assert_true(ping1_result.get())
            t2.close()
            t2.join()
            logger.info("ping2_result: %s", str(ping2_result.get()))
            self.assert_true(ping2_result.get())

            # Check connectivity in both directions.
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip],
                                        retries=5)

    @attr('slow')
    def test_bird_switch_route_reflector(self):
        self._test_switch_route_reflector(backend='bird')

    @attr('slow')
    def test_bird_switch_route_reflector_default_as(self):
        self._test_switch_route_reflector(backend='bird', bgpconfig_as_num=None, peer_as_num=64512)

TestSwitchRouteReflector.batchnumber = 1  # Adds a batch number for parallel testing
