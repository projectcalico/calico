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
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.utils import ETCD_CA, ETCD_CERT, \
    ETCD_KEY, ETCD_HOSTNAME_SSL, ETCD_SCHEME, get_ip
from tests.st.utils.exceptions import CommandExecError

if ETCD_SCHEME == "https":
    ADDITIONAL_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " \
                                "--cluster-store-opt kv.cacertfile=%s " \
                                "--cluster-store-opt kv.certfile=%s " \
                                "--cluster-store-opt kv.keyfile=%s " % \
                                (ETCD_HOSTNAME_SSL, ETCD_CA, ETCD_CERT,
                                 ETCD_KEY)
else:
    ADDITIONAL_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " % \
                                get_ip()

class TestAutodetection(TestBase):

    @attr('slow')
    def test_autodetection(self):
        """
        Test using different IP autodetection methods.

        We run a multi-host test for this to test explicit selection of
        "first-found" and also "interface" and "can-reach" detection methods.
        """
        with DockerHost('host1',
                        additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                        start_calico=False) as host2, \
             DockerHost('host3',
                        additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                        start_calico=False) as host3:

            # Start the node on host1 using first-found auto-detection
            # method.
            host1.start_calico_node(
                "--ip=autodetect --ip-autodetection-method=first-found")

            # Attempt to start the node on host2 using can-reach auto-detection
            # method using a bogus DNS name.  This should fail.
            try:
                host2.start_calico_node(
                    "--ip=autodetect --ip-autodetection-method=can-reach=XXX.YYY.ZZZ.XXX")
            except CommandExecError:
                pass
            else:
                raise AssertionError("Command expected to fail but did not")

            # Start the node on host2 using can-reach auto-detection method
            # using the IP address of host1.  This should succeed.
            host2.start_calico_node(
                "--ip=autodetect --ip-autodetection-method=can-reach=" + host1.ip)

            # Attempt to start the node on host3 using interface auto-detection
            # method using a bogus interface name.  This should fail.
            try:
                host3.start_calico_node(
                    "--ip=autodetect --ip-autodetection-method=interface=BogusInterface")
            except CommandExecError:
                pass
            else:
                raise AssertionError("Command expected to fail but did not")

            # Start the node on host2 using can-reach auto-detection method
            # using the IP address of host1.  This should succeed.
            host3.start_calico_node(
                "--ip=autodetect --ip-autodetection-method=interface=eth0")

            # Create a network and a workload on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1", network=network1)
            workload_host2 = host2.create_workload("workload2", network=network1)
            workload_host3 = host3.create_workload("workload3", network=network1)

            # Allow network to converge
            self.assert_true(workload_host1.check_can_ping(workload_host3.ip, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2,
                                                       workload_host3],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip,
                                                      workload_host3.ip])
