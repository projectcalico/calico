# Copyright 2015 Metaswitch Networks
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
import unittest

from tests.st.test_base import TestBase, HOST_IPV6
from tests.st.utils.docker_host import DockerHost

"""
Test the calicoctl container <CONTAINER> ip add/remove commands w/ auto-assign

Tests the use of (libcalico) pycalico.ipam.IPAMClient.auto_assign_ips
within calicoctl container ip add.
"""


class TestAutoAssignIp(TestBase):
    def __init__(self, *args, **kwargs):
        super(TestAutoAssignIp, self).__init__(*args, **kwargs)

        self.DEFAULT_IPV4_POOL = "192.168.0.0/16"
        self.DEFAULT_IPV6_POOL = "fd80:24e2:f998:72d6::/64"

    def _setup_env(self, host, count=2, ip="ipv4", profile="TEST"):
        workloads = []

        host.calicoctl("profile add {0}".format(profile))
        for x in xrange(count):
            workloads.append(host.create_workload("workload" + str(x)))
            host.calicoctl("container add {0} {1}".format(workloads[x], ip))
            host.calicoctl("container {0} profile set {1}".format(
                workloads[x], profile))

        return workloads

    def test_add_autoassigned_ipv4(self):
        """
        Test "calicoctl container add <container> ipv4"
        """
        with DockerHost('host', dind=False) as host:
            # Test that auto-assiging IPv4 addresses gives what we expect
            workloads = self._setup_env(host, count=2, ip="ipv4")

            workloads[0].assert_can_ping("192.168.0.1", retries=3)
            workloads[1].assert_can_ping("192.168.0.0", retries=3)

            host.calicoctl("container remove {0}".format("workload0"))
            host.calicoctl("container remove {0}".format("workload1"))

            host.remove_workloads()

            # Test that recreating returns the next two IPs (IPs are not
            # reassigned automatically unless we have run out of IPs).
            workloads = self._setup_env(host, count=2, ip="ipv4")

            workloads[0].assert_can_ping("192.168.0.3", retries=3)
            workloads[1].assert_can_ping("192.168.0.2", retries=3)

    @unittest.skipUnless(HOST_IPV6, "Host does not have an IPv6 address")
    def test_add_autoassigned_ipv6(self):
        """
        Test "calicoctl container add <container> ipv6"
        """
        with DockerHost('host', dind=False) as host:
            # Test that auto-assiging IPv4 addresses gives what we expect
            workloads = self._setup_env(host, count=2, ip="ipv6")

            workloads[0].assert_can_ping("fd80:24e2:f998:72d6::1", retries=3)
            workloads[1].assert_can_ping("fd80:24e2:f998:72d6::", retries=3)

            host.calicoctl("container remove {0}".format("workload0"))
            host.calicoctl("container remove {0}".format("workload1"))

            host.remove_workloads()

            # Test that recreating returns the next two IPs (IPs are not
            # reassigned automatically unless we have run out of IPs).
            workloads = self._setup_env(host, count=2, ip="ipv6")

            workloads[0].assert_can_ping("fd80:24e2:f998:72d6::3", retries=3)
            workloads[1].assert_can_ping("fd80:24e2:f998:72d6::2", retries=3)

    def test_add_autoassigned_pool_ipv4(self):
        """
        Test "calicoctl container add <container> <IPv4 CIDR>"
        (192.168.0.0/16)
        """
        with DockerHost('host', dind=False) as host:
            # Test that auto-assiging IPv4 addresses gives what we expect
            workloads = self._setup_env(host, count=2,
                                        ip=self.DEFAULT_IPV4_POOL)

            workloads[0].assert_can_ping("192.168.0.1", retries=3)
            workloads[1].assert_can_ping("192.168.0.0", retries=3)

    @unittest.skipUnless(HOST_IPV6, "Host does not have an IPv6 address")
    def test_add_autoassigned_pool_ipv6(self):
        """
        Test "calicoctl container add <container> <IPv6 CIDR>"
        (fd80:24e2:f998:72d6::/64)
        """
        with DockerHost('host', dind=False) as host:
            # Test that auto-assiging IPv6 addresses gives what we expect
            workloads = self._setup_env(host, count=2,
                                        ip=self.DEFAULT_IPV6_POOL)

            workloads[0].assert_can_ping("fd80:24e2:f998:72d6::1", retries=3)
            workloads[1].assert_can_ping("fd80:24e2:f998:72d6::", retries=3)
