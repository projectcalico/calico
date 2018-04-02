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
    def test_felix_readiness(self):
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS, start_calico=False) as host1:
            # Start node without felix healthcheck endpoint.
            host1.start_calico_node(env_options="-e FELIX_HEALTHENABLED=false")
            retry_until_success(host1.check_readiness, retries=10)

            # Trick the readiness script into thinking felix is reporting health when it isn't, so that we can
            # trigger the readiness script to try and hit felix, when felix isn't running on that endpoint yet.
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: felix is not ready", host1.execute,
                               "docker exec -e FELIX_HEALTHENABLED=true calico-node /sbin/check_readiness")

    def test_bgp_established(self):
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1, \
                DockerHost('host2',
                           additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host2:
            retry_until_success(host1.check_readiness, retries=10)
            retry_until_success(host2.check_readiness, retries=10)

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

            # Check the BGP status on the BIRD/GoBGP host.
            def check_connected():
                for target in [host1, host2]:
                    expected = [("node-to-node mesh", h.ip, "Established") for h in [host1, host2] if h is not target]
                    _log.debug("expected : %s", expected)
                    check_bird_status(target, expected)

            # Block bgp connectivity between hosts
            host1.execute("iptables -t raw -I PREROUTING  -p tcp -m multiport --dport 179 -j DROP")
            host2.execute("iptables -t raw -I PREROUTING -p tcp -m multiport --dport 179 -j DROP")
            host1.execute("docker exec -it calico-node pkill -9 bird")
            host2.execute("docker exec -it calico-node pkill -9 bird")

            # Check that the readiness script is reporting 'not ready'
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: BGP not established with",
                                    host1.check_readiness)
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: BGP not established with",
                                    host2.check_readiness)

            # Restore connectivity
            host1.execute("iptables -t raw -D PREROUTING -p tcp -m multiport --dports 179 -j DROP")
            host2.execute("iptables -t raw -D PREROUTING -p tcp -m multiport --dports 179 -j DROP")

            _log.debug('check connected and retry until "Established"')
            retry_until_success(host1.check_readiness, retries=10)
            retry_until_success(host2.check_readiness, retries=10)
            retry_until_success(check_connected, retries=20, ex_class=Exception)
