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
from sh import ErrorReturnCode_1
from functools import partial

from test_base import TestBase
from docker_host import DockerHost


class TestDuplicateIps(TestBase):
    def test_duplicate_ips(self):
        """
        Start two workloads with the same IP on different hosts. Make sure they
        can be reached from all places even after one of them is deleted.
        """
        host1 = DockerHost('host1')
        host2 = DockerHost('host2')
        host3 = DockerHost('host3')

        # Set up three workloads on three hosts
        workload1 = host1.create_workload("workload1", "192.168.1.1")
        workload2 = host2.create_workload("workload2", "192.168.1.2")
        workload3 = host3.create_workload("workload3", "192.168.1.3")

        # Set up the workloads with duplicate IPs
        dup_ip = "192.168.1.4"
        dup1 = host1.create_workload("dup1", dup_ip)
        dup2 = host2.create_workload("dup2", dup_ip)

        host1.calicoctl("profile add TEST_PROFILE")

        # Add everyone to the same profile
        host1.calicoctl("profile TEST_PROFILE member add %s" % workload1)
        host1.calicoctl("profile TEST_PROFILE member add %s" % dup1)
        host2.calicoctl("profile TEST_PROFILE member add %s" % workload2)
        host2.calicoctl("profile TEST_PROFILE member add %s" % dup2)
        host3.calicoctl("profile TEST_PROFILE member add %s" % workload3)

        # Check for standard connectivity
        workload1.assert_can_ping(dup_ip, retries=3)
        workload2.assert_can_ping(dup_ip, retries=3)
        workload3.assert_can_ping(dup_ip, retries=3)

        # Delete one of the duplciates.
        host2.execute("docker rm -f dup2")

        # Check standard connectivity still works.
        workload1.assert_can_ping(dup_ip, retries=3)
        workload2.assert_can_ping(dup_ip, retries=3)
        workload3.assert_can_ping(dup_ip, retries=3)
