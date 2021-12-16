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
import re
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

    def test_liveness_bird_down(self):
        """
        Simulate bird service to be down.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1:
            retry_until_success(host1.assert_is_ready, retries=30)
            host1.execute("docker exec -it calico-node sv stop /etc/service/enabled/bird")

            # Check that the readiness script is reporting 'not ready'
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: bird/confd is not live: Service bird is not running.",
                                host1.execute, "docker exec calico-node /bin/calico-node -bird-live")

    def test_liveness_bird_confd_down(self):
        """
        Simulate confd service to be down for bird
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1:
            retry_until_success(host1.assert_is_ready, retries=30)
            host1.execute("docker exec -it calico-node sv stop /etc/service/enabled/confd")

            # Check that the readiness script is reporting 'not ready'
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: bird/confd is not live: Service confd is not running.",
                                    host1.execute, "docker exec calico-node /bin/calico-node -bird-live")

    def test_liveness_bird6_down(self):
        """
        Simulate bird6 service to be down.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1:
            retry_until_success(host1.assert_is_ready, retries=30)
            host1.execute("docker exec -it calico-node sv stop /etc/service/enabled/bird6")

            # Check that the readiness script is reporting 'not ready'
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: bird6/confd is not live: Service bird6 is not running.",
                                    host1.execute, "docker exec calico-node /bin/calico-node -bird6-live")

    def test_liveness_bird6_confd_down(self):
        """
        Simulate confd service to be down for bird6
        """
        with DockerHost('host1',
                    additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1:
            retry_until_success(host1.assert_is_ready, retries=30)
            host1.execute("docker exec -it calico-node sv stop /etc/service/enabled/confd")

            # Check that the readiness script is reporting 'not ready'
            self.assertRaisesRegexp(CalledProcessError, "calico/node is not ready: bird/confd is not live: Service confd is not running.",
                                host1.execute, "docker exec calico-node /bin/calico-node -bird-live")

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
            host1.execute("docker exec -it calico-node sv kill bird")
            host2.execute("docker exec -it calico-node sv kill bird")

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

class TestDisableBGPExport(TestBase):
    def test_disable_bgp_export(self):
        """
        Verify that disableBGPExport in an IP pool makes bird not export it correctly.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS) as host2:

            # Wait until both hosts are ready
            retry_until_success(host1.assert_is_ready, retries=30)
            retry_until_success(host2.assert_is_ready, retries=30)

            # Create IPPool pool1 with disableBGPExport=true
            pool1 = {'apiVersion': 'projectcalico.org/v3',
                        'kind': 'IPPool',
                        'metadata': {'name': 'ippool-name-1'},
                        'spec': {'cidr': '192.168.1.0/24',
                                 'ipipMode': 'Always',
                                 'disableBGPExport': True},
                        }
            host1.writejson("pool1.json", pool1)
            host1.calicoctl("create -f pool1.json")

            # Create IPPool pool2 with explicit disableBGPExport=false
            pool2 = {'apiVersion': 'projectcalico.org/v3',
                        'kind': 'IPPool',
                        'metadata': {'name': 'ippool-name-2'},
                        'spec': {'cidr': '192.168.2.0/24',
                                 'ipipMode': 'Always',
                                 'disableBGPExport': False},
                        }
            host1.writejson("pool2.json", pool2)
            host1.calicoctl("create -f pool2.json")

            # Create IPPool pool3 with no disableBGPExport (false is the default)
            pool3 = {'apiVersion': 'projectcalico.org/v3',
                        'kind': 'IPPool',
                        'metadata': {'name': 'ippool-name-3'},
                        'spec': {'cidr': '192.168.3.0/24',
                                 'ipipMode': 'Always'},
                        }
            host1.writejson("pool3.json", pool3)
            host1.calicoctl("create -f pool3.json")

            # Create one workload on each IP pool
            network1 = host1.create_network("subnet1")
            workload1 = host1.create_workload("workload1", network=network1,
                                              ip='192.168.1.1')
            workload2 = host1.create_workload("workload2", network=network1,
                                              ip='192.168.2.1')
            workload3 = host1.create_workload("workload3", network=network1,
                                              ip='192.168.3.1')

            # host2's name in host1's bird cfg is Mesh_xxx_xxx_xxx_xxx (based on its IP address)
            nameHost2 = 'Mesh_' + host2.ip.replace('.', '_')

            def _get_re_from_pool(pool):
                """
                Get a regex for blocks in 'birdcl show route' output from an
                IP pool CIDR
                """
                no_mask = pool.rsplit('/', 1)[0]
                no_last_octet = no_mask.rsplit('.', 1)[0]
                regex = re.escape(no_last_octet) + r'\.\d{1,3}/\d{1,2}\s+blackhole'
                return regex

            # Verify that pool2 and pool3 are exported and pool1 is not
            output = host1.execute("docker exec calico-node birdcl show route export %s" % nameHost2)
            for pool in [ '192.168.2.0/24', '192.168.3.0/24' ]:
                self.assertRegexpMatches(output, _get_re_from_pool(pool),
                                         "pool '%s' should be present in 'birdcl show route export' output" % pool)
            for pool in [ '192.168.1.0/24' ]:
                self.assertNotRegexpMatches(output, _get_re_from_pool(pool),
                                            "pool '%s' should not be present in 'birdcl show route export' output" % pool)

            # Verify that pool1 is filtered from being exported and pool2 and pool3 are not
            output = host1.execute("docker exec calico-node birdcl show route noexport %s" % nameHost2)
            for pool in [ '192.168.1.0/24' ]:
                self.assertRegexpMatches(output, _get_re_from_pool(pool),
                                         "pool '%s' should be present in 'birdcl show route noexport' output" % pool)
            for pool in [ '192.168.2.0/24', '192.168.3.0/24' ]:
                self.assertNotRegexpMatches(output, _get_re_from_pool(pool),
                                            "pool '%s' should not be present in 'birdcl show route noexport' output" % pool)
