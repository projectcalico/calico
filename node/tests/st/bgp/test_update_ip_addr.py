# Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
import json
from nose.plugins.attrib import attr

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS

class TestUpdateIPAddress(TestBase):

    @attr('slow')
    def test_update_ip_address(self):
        """
        Test updating the IP address automatically updates and fixes the
        Bird BGP config.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2:

            # Start host1 and host2 using bogus IP addresses.  The nodes should
            # start although they won't be functional.
            host1.start_calico_node("--ip=1.2.3.4")
            host2.start_calico_node("--ip=2.3.4.5")

            # Create a network and a couple of workloads on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1)
            workload_host2 = host2.create_workload("workload2", network=network1)

            # Fix the node resources to have the correct IP addresses. BIRD
            # should automatically fix it's configuration and connectivity will
            # be established.
            self._fix_ip(host1)
            self._fix_ip(host2)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip])

    def _fix_ip(self, host):
        """
        Update the calico node resource to have the correct IP for the host.
        """
        noder = json.loads(host.calicoctl(
            "get node %s --output=json" % host.get_hostname()))
        noder["spec"]["bgp"]["ipv4Address"] = str(host.ip)
        host.writejson("new_data", noder)
        host.calicoctl("apply -f new_data")
