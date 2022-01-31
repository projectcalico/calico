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
from tests.st.utils.constants import (DEFAULT_IPV4_ADDR_1, DEFAULT_IPV4_ADDR_2,
                                      DEFAULT_IPV4_POOL_CIDR, LARGE_AS_NUM)
from tests.st.utils.exceptions import CommandExecError
from tests.st.utils.utils import check_bird_status, update_bgp_config, \
        get_bgp_spec

class TestBGP(TestBase):

    def test_defaults(self):
        """
        Test default BGP configuration commands.
        """
        with DockerHost('host', start_calico=False, dind=False) as host:
            # As the v3 data model now stands, there is no way to query what
            # the default AS number is, in the absence of any resources.  Also,
            # if you create a BGPConfiguration resource that does not specify
            # an AS number, and then read it back, the output does not include
            # the default AS number.
            #
            # So we can't test the default AS number directly with calicoctl
            # operations.  We can of course test it indirectly: see
            # test_bird_single_route_reflector_default_as in
            # test_single_route_reflector.py.

            # Set the global-default AS number.
            update_bgp_config(host, asNum=12345)

            self.assertEquals(get_bgp_spec(host)['asNumber'], 12345)

            with self.assertRaises(CommandExecError):
                update_bgp_config(host, asNum=99999999999999999999999)
            with self.assertRaises(CommandExecError):
                update_bgp_config(host, asNum='abcde')

            # Check BGP mesh command
            if 'nodeToNodeMeshEnabled' in get_bgp_spec(host):
                self.assertEquals(get_bgp_spec(host)['nodeToNodeMeshEnabled'], True)

            update_bgp_config(host, nodeMesh=False)
            self.assertEquals(get_bgp_spec(host)['nodeToNodeMeshEnabled'], False)

            update_bgp_config(host, nodeMesh=True)
            self.assertEquals(get_bgp_spec(host)['nodeToNodeMeshEnabled'], True)

    @attr('slow')
    def _test_as_num(self, backend='bird'):
        """
        Test using different AS number for the node-to-node mesh.

        We run a multi-host test for this as we need to set up real BGP peers.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2:

            # Set the default AS number.
            update_bgp_config(host1, asNum=LARGE_AS_NUM)

            # Start host1 using the inherited AS, and host2 using a specified
            # AS (same as default).
            host1.start_calico_node("--backend=%s" % backend)
            host2.start_calico_node("--backend=%s --as=%s" % (backend, LARGE_AS_NUM))

            # Create a network and a couple of workloads on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1, ip=DEFAULT_IPV4_ADDR_1)
            workload_host2 = host2.create_workload("workload2", network=network1, ip=DEFAULT_IPV4_ADDR_2)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(DEFAULT_IPV4_ADDR_2, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[DEFAULT_IPV4_ADDR_1,
                                                      DEFAULT_IPV4_ADDR_2])

            # Check the BGP status on each host.
            check_bird_status(host1, [("node-to-node mesh", host2.ip, "Established")])
            check_bird_status(host2, [("node-to-node mesh", host1.ip, "Established")])

    @attr('slow')
    def test_bird_as_num(self):
        self._test_as_num(backend='bird')
