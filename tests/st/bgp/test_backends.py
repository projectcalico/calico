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
                                      DEFAULT_IPV4_ADDR_3,
                                      DEFAULT_IPV4_POOL_CIDR, LARGE_AS_NUM)
from tests.st.utils.utils import check_bird_status, update_bgp_config
from unittest import skip

# TODO: Add back when gobgp is updated to work with libcalico-go v3 api
@skip("Disabled until gobgp is updated with libcalico-go v3")
class TestBGPBackends(TestBase):

    @attr('slow')
    def test_bgp_backends(self):
        """
        Test using different BGP backends.

        We run a multi-host test for this to test peering between two gobgp
        backends and a single BIRD backend.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2, \
             DockerHost('host3',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=True) as host3:

            # Set the default AS number.
            update_bgp_config(host1, asNum=LARGE_AS_NUM)

            # Start host1 using the inherited AS, and host2 using a specified
            # AS (same as default).  These hosts use the gobgp backend, whereas
            # host3 uses BIRD.
            host1.start_calico_node("--backend=gobgp")
            host2.start_calico_node("--backend=gobgp --as=%s" % LARGE_AS_NUM)

            # Create a network and a couple of workloads on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1, ip=DEFAULT_IPV4_ADDR_1)
            workload_host2 = host2.create_workload("workload2", network=network1, ip=DEFAULT_IPV4_ADDR_2)
            workload_host3 = host3.create_workload("workload3", network=network1, ip=DEFAULT_IPV4_ADDR_3)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2,
                                                       workload_host3],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip,
                                                      workload_host3.ip])

            # Check the BGP status on the BIRD/GoBGP host.
            hosts = [host1, host2, host3]
            for target in hosts:
                expected = [("node-to-node mesh", h.ip, "Established") for h in hosts if h is not target]
                check_bird_status(target, expected)
