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

from nose.plugins.attrib import attr
from nose_parameterized import parameterized

from tests.st.test_base import TestBase
from tests.st.utils.constants import (LARGE_AS_NUM)
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.utils import check_bird_status, \
    retry_until_success

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)


class TestNodeStatusResilience(TestBase):
    @parameterized.expand([
        (2, 'bird'),
        (0, 'calico-bgp-daemon')
    ])
    @attr('slow')
    def test_node_status_resilience(self, test_host, pid_name):
        """
        Test that newly restarted BGP backend processes consistently
        transition to an Established state.

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
            host1.calicoctl("config set asNumber %s" % LARGE_AS_NUM)

            # Start host1 using the inherited AS, and host2 using a specified
            # AS (same as default).  These hosts use the gobgp backend, whereas
            # host3 uses BIRD.
            host1.start_calico_node("--backend=gobgp")
            host2.start_calico_node("--backend=gobgp --as=%s" % LARGE_AS_NUM)

            # Create a network and a couple of workloads on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1)
            workload_host2 = host2.create_workload("workload2", network=network1)
            workload_host3 = host3.create_workload("workload3", network=network1)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(workload_host2.ip, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2,
                                                       workload_host3],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip,
                                                      workload_host3.ip])

            hosts = [host1, host2, host3]
            workloads = [workload_host1, workload_host2, workload_host3]

            _log.debug("==== docker exec -it calico-node ps -a  ====")
            _log.debug(hosts[test_host].execute("docker exec -it calico-node ps -a"))

            # Check the BGP status on the BIRD/GoBGP host.
            def check_connected():
                for target in hosts:
                    expected = [("node-to-node mesh", h.ip, "Established") for h in hosts if h is not target]
                    _log.debug("expected : %s", expected)
                    check_bird_status(target, expected)

            def delete_workload(host, host_workload):
                host.calicoctl("ipam release --ip=%s" % host_workload.ip)
                host.execute("docker rm -f %s" % host_workload.name)
                host.workloads.remove(host_workload)

            def pid_parse(pid_str):
                if '\r\n' in pid_str:
                    pid_list = pid_str.split('\r\n')
                    return pid_list
                else:
                    return [pid_str]

            iterations = 3
            for iteration in range(1, iterations+1):
                _log.debug("Iteration %s", iteration)
                _log.debug("Host under test: %s", hosts[test_host].name)
                _log.debug("Identify and pkill process: %s", pid_name)

                pre_pkill = hosts[test_host].execute("docker exec -it calico-node pgrep %s" % pid_name)
                pre_pkill_list = pid_parse(pre_pkill)
                _log.debug("Pre pkill list: %s", pre_pkill_list)

                hosts[test_host].execute("docker exec -it calico-node pkill %s" % pid_name)

                _log.debug('check connected and retry until "Established"')
                retry_until_success(check_connected, retries=20, ex_class=Exception)

                post_pkill = hosts[test_host].execute("docker exec -it calico-node pgrep %s" % pid_name)
                post_pkill_list = pid_parse(post_pkill)
                _log.debug("Post pkill list: %s", post_pkill_list)

                assert pre_pkill_list != post_pkill_list, "The pids should not be the same after pkill"

                new_workloads = []
                for workload in workloads:
                    new_workload = "%s_%s" % (workload, iteration)
                    new_workloads.append(new_workload)

                # create new workloads
                index = 0
                for new_workload in new_workloads:
                    new_workload = hosts[index].create_workload(new_workload, network=network1)
                    _log.debug("host: %s and workload: %s", hosts[index].name, new_workload.name)

                    # Wait for the workload to be networked.
                    self.assert_true(new_workload.check_can_ping(workload_host3.ip, retries=10))

                    # Check connectivity in both directions
                    self.assert_ip_connectivity(workload_list=[workload_host1,
                                                               workload_host2,
                                                               workload_host3,
                                                               new_workload],
                                                ip_pass_list=[workload_host1.ip,
                                                              workload_host2.ip,
                                                              workload_host3.ip,
                                                              new_workload.ip])
                    delete_workload(hosts[index], new_workload)
                    index += 1

TestNodeStatusResilience.batchnumber = 2  # Adds a batch number for parallel testing
