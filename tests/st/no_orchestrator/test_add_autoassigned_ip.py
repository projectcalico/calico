# Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
import re
import unittest

from netaddr import IPNetwork, IPAddress

from tests.st.test_base import TestBase, HOST_IPV6
from tests.st.utils.docker_host import DockerHost

"""
Test the calicoctl container <CONTAINER> ip add/remove commands w/ auto-assign

Tests the use of (libcalico) pycalico.ipam.IPAMClient.auto_assign_ips
within calicoctl container ip add.
"""

IP_RE = re.compile("IP (.*) added to .*")


class TestAutoAssignIp(TestBase):
    def __init__(self, *args, **kwargs):
        super(TestAutoAssignIp, self).__init__(*args, **kwargs)

        self.DEFAULT_IPV4_POOL = IPNetwork("192.168.0.0/16")
        self.DEFAULT_IPV6_POOL = IPNetwork("fd80:24e2:f998:72d6::/64")

    def _setup_env(self, host, count=2, ip="ipv4", profile="TEST"):
        workloads = []

        host.calicoctl("profile add {0}".format(profile))
        for x in xrange(count):
            workload = host.create_workload("workload" + str(x))
            output = host.calicoctl("container add {0} {1}".format(workload, str(ip)))
            host.calicoctl("container {0} profile set {1}".format(
                workload, profile))
            # Set the workload IP from the calicoctl output.
            ip_search = IP_RE.search(output)
            workload.ip = ip_search.group(1)
            workloads.append(workload)
        return workloads

    def test_add_autoassigned_ipv4(self):
        """
        Test "calicoctl container add <container> ipv4"
        """
        self._test_add_autoassigned(version=4)

    @unittest.skipUnless(HOST_IPV6, "Host does not have an IPv6 address")
    def test_add_autoassigned_ipv6(self):
        """
        Test "calicoctl container add <container> ipv6"
        """
        self._test_add_autoassigned(version=6)

    def _test_add_autoassigned(self, version):
        """
        Test "calicoctl container add <container> ipv<version>"
        """
        with DockerHost('host', dind=False) as host:
            # Test that auto-assiging IPv4 addresses gives what we expect
            ip = "ipv" + str(version)
            workloads = self._setup_env(host, count=2, ip=ip)

            # IPs are assigned sequentially from the selected block.
            first_ip = IPAddress(workloads[0].ip)
            assert first_ip.version == version
            assert IPAddress(workloads[1].ip) == first_ip + 1, \
                "Assigned %s, expected %s" % (workloads[1].ip, first_ip + 1)

            # Test each workload can ping the other
            workloads[0].assert_can_ping(workloads[1].ip, retries=3)
            workloads[1].assert_can_ping(workloads[0].ip, retries=3)

            host.calicoctl("container remove {0}".format("workload0"))
            host.calicoctl("container remove {0}".format("workload1"))

            host.remove_workloads()

            # Test that recreating returns the next two IPs (IPs are not
            # reassigned automatically unless we have run out of IPs).
            workloads = self._setup_env(host, count=2, ip=ip)
            assert IPAddress(workloads[0].ip) == first_ip + 2, \
                "Assigned %s, expected %s" % (workloads[0].ip, first_ip + 2)
            assert IPAddress(workloads[1].ip) == first_ip + 3, \
                "Assigned %s, expected %s" % (workloads[1].ip, first_ip + 3)

            # Test each workload can ping the other
            workloads[0].assert_can_ping(workloads[1].ip, retries=3)
            workloads[1].assert_can_ping(workloads[0].ip, retries=3)

    def test_add_autoassigned_pool_ipv4(self):
        """
        Test "calicoctl container add <container> <IPv4 CIDR>"
        (192.168.0.0/16)
        """
        self._test_add_autoassigned_pool(self.DEFAULT_IPV4_POOL)

    @unittest.skipUnless(HOST_IPV6, "Host does not have an IPv6 address")
    def test_add_autoassigned_pool_ipv6(self):
        """
        Test "calicoctl container add <container> <IPv6 CIDR>"
        (fd80:24e2:f998:72d6::/64)
        """
        self._test_add_autoassigned_pool(self.DEFAULT_IPV6_POOL)

    def _test_add_autoassigned_pool(self, pool):
        """
        Test "calicoctl container add <container> <pool>"
        """
        with DockerHost('host', dind=False) as host:
            # Test that auto-assigning IPv6 addresses gives what we expect
            workloads = self._setup_env(host, count=2, ip=pool)

            assert IPAddress(workloads[0].ip) in pool, \
                "Assigned %s not in %s" % (workloads[0].ip, pool)
            assert IPAddress(workloads[1].ip) in pool, \
                "Assigned %s not in %s" % (workloads[1].ip, pool)

            workloads[0].assert_can_ping(workloads[1].ip, retries=3)
            workloads[1].assert_can_ping(workloads[0].ip, retries=3)
