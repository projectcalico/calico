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
import logging
import yaml

from nose.plugins.attrib import attr
from unittest import skip

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.route_reflector import RouteReflectorCluster
from tests.st.utils.utils import update_bgp_config

from .peer import create_bgp_peer

logger = logging.getLogger(__name__)

class TestInternalRouteReflector(TestBase):

    @attr('slow')
    def _test_internal_route_reflector(self, backend='bird', bgpconfig_as_num=64514, peer_as_num=64514):
        """
        Run a multi-host test using an internal route reflector.
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

            # Set the default AS number - as this is used by the RR mesh, and
            # turn off the node-to-node mesh (do this from any host).
            update_bgp_config(host1, nodeMesh=False, asNum=bgpconfig_as_num)

            # Create a workload on each host in the same network.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1",
                                                   network=network1)
            workload_host2 = host2.create_workload("workload2",
                                                   network=network1)
            workload_host3 = host3.create_workload("workload3",
                                                   network=network1)

            # Allow network to converge (which it won't)
            self.assert_false(workload_host1.check_can_ping(workload_host2.ip, retries=5))

            # Make host2 act as a route reflector.
            node2 = host2.calicoctl("get Node %s -o yaml" % host2.get_hostname())
            node2cfg = yaml.safe_load(node2)
            logger.info("host2 Node: %s", node2cfg)
            node2cfg['spec']['bgp']['routeReflectorClusterID'] = '224.0.0.2'
            node2cfg['metadata']['labels'] = {
                'routeReflectorClusterID': node2cfg['spec']['bgp']['routeReflectorClusterID'],
            }
            host2.add_resource(node2cfg)

            # Configure peerings - note, NOT a full mesh - from the
            # other nodes to the route reflector.
            host2.add_resource({
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

            # Allow network to converge (which it now will).
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=20))

            # And check connectivity in both directions.
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2,
                                                       workload_host3],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip,
                                                      workload_host3.ip],
                                        retries=5)

    @attr('slow')
    def test_bird_internal_route_reflector(self):
        self._test_internal_route_reflector(backend='bird')

    @attr('slow')
    def test_bird_internal_route_reflector_default_as(self):
        self._test_internal_route_reflector(backend='bird', bgpconfig_as_num=None, peer_as_num=64512)

TestInternalRouteReflector.batchnumber = 1  # Adds a batch number for parallel testing
