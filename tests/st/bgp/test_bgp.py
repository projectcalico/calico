# Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.
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
from subprocess import CalledProcessError

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.utils import check_bird_status, retry_until_success

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)


class TestReadiness(TestBase):
    def test_readiness(self):
        """
        A simple base case to check if calico/node becomes ready.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1:
            retry_until_success(host1.assert_is_ready, retries=30)

    def test_readiness_env_port(self):
        """
        A simple base case to check if calico/node becomes ready. Uses environment variable as port number.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS, start_calico=False) as host1:
            host1.start_calico_node(env_options="-e FELIX_HEALTHPORT=9032 -e FELIX_HEALTHENABLED=true")
            retry_until_success(host1.assert_is_ready, retries=30)

    def test_readiness_multihost(self):
        """
        A simple base case to check if calico/node becomes ready.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1, \
                DockerHost('host2',
                           additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host2:
            retry_until_success(host1.assert_is_ready, retries=30)
            retry_until_success(host2.assert_is_ready, retries=30)

    def test_liveness(self):
        """
        A simple base case to check if calico/node becomes live.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1:
            retry_until_success(host1.assert_is_live, retries=30)

    def test_liveness_env_port(self):
        """
        A simple base case to check if calico/node becomes live. Uses environment variable as port number.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS, start_calico=False) as host1:
            host1.start_calico_node(env_options="-e FELIX_HEALTHPORT=9011 -e FELIX_HEALTHENABLED=true")
            retry_until_success(host1.assert_is_live, retries=30)

    def test_liveness_multihost(self):
        """
        A simple base case to check if calico/node becomes live.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1, \
                DockerHost('host2',
                           additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host2:
            retry_until_success(host1.assert_is_live, retries=30)
            retry_until_success(host2.assert_is_live, retries=30)

    def test_not_ready_with_broken_felix(self):
        """
        Simulate a broken felix by turning off Felix's health endpoint.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS, start_calico=False) as host1:
            # Start node without felix healthcheck endpoint.
            host1.start_calico_node(env_options="-e FELIX_HEALTHENABLED=false")

            # Run readiness checks against felix
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: felix is not ready", host1.execute,
                               "docker exec calico-node /bin/calico-node -felix-ready")

    def test_not_ready_with_no_networking_and_broken_felix(self):
        """
        Check that we're still reporting broken felix even when calico networking (bird) is off.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS, start_calico=False) as host1:
            # Start node without felix healthcheck endpoint.
            host1.start_calico_node(env_options="-e FELIX_HEALTHENABLED=false -e CALICO_NETWORKING_BACKEND=none")

            # Run readiness checks against felix
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: felix is not ready", host1.execute,
                               "docker exec calico-node /bin/calico-node -felix-ready")

    def test_bird_readiness(self):
        """
        Test readiness when BGP connections are severed.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1, \
                DockerHost('host2',
                           additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host2:
            retry_until_success(host1.assert_is_ready, retries=30)
            retry_until_success(host2.assert_is_ready, retries=30)

            # Create a network and a couple of workloads on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1)
            workload_host2 = host2.create_workload("workload2", network=network1)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip])

            # Block bgp connectivity between hosts
            host1.execute("iptables -t raw -I PREROUTING  -p tcp -m multiport --dport 179 -j DROP")
            host2.execute("iptables -t raw -I PREROUTING -p tcp -m multiport --dport 179 -j DROP")
            host1.execute("docker exec -it calico-node pkill -9 bird")
            host2.execute("docker exec -it calico-node pkill -9 bird")

            # Check that the readiness script is reporting 'not ready'
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: BIRD is not ready: BGP not established with",
                                    host1.execute, "docker exec calico-node /bin/calico-node -bird-ready -felix-ready")
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: BIRD is not ready: BGP not established with",
                                    host1.execute, "docker exec calico-node /bin/calico-node -bird-ready -felix-ready")

            # Restore connectivity
            host1.execute("iptables -t raw -D PREROUTING -p tcp -m multiport --dports 179 -j DROP")
            host2.execute("iptables -t raw -D PREROUTING -p tcp -m multiport --dports 179 -j DROP")

            _log.debug('check connected and retry until "Established"')
            retry_until_success(host1.assert_is_ready, retries=30)
            retry_until_success(host2.assert_is_ready, retries=30)
            check_bird_status(host1, [("node-to-node mesh", host2.ip, "Established")])
            check_bird_status(host2, [("node-to-node mesh", host1.ip, "Established")])
