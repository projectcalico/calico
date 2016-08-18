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

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.utils import get_ip
from tests.st.utils.workload import NET_NONE


class TestNoOrchMultiHostOverrideHostname(TestBase):

    def test_multi_host_override_hostname(self):
        """
        Test override of hostname works.
        """
        with DockerHost('host1', override_hostname=True) as host1, \
             DockerHost('host2', start_calico=False, override_hostname=True) as host2:
            # Start calico manually on host2
            host2.start_calico_node_with_docker()

            # Use standard docker bridge networking for one and --net=none
            # for the other
            workload1 = host1.create_workload("workload1")
            workload2 = host2.create_workload("workload2", network=NET_NONE)

            # Add the nodes to Calico networking.
            host1.calicoctl("container add %s 192.168.1.1" % workload1)
            host2.calicoctl("container add %s 192.168.1.2" % workload2)

            # Now add the profiles - one using set and one using append
            host1.calicoctl("profile add TEST_GROUP")
            host1.calicoctl("container %s profile set TEST_GROUP" % workload1)
            host2.calicoctl("container %s profile append TEST_GROUP" % workload2)

            # Check it works
            workload1.assert_can_ping("192.168.1.2", retries=3)
            workload2.assert_can_ping("192.168.1.1", retries=3)

            # Check the hostnames configured in etcd are the overridden ones.
            hostnames = self.get_endpoint_hostnames(host1)
            self.assertEqual(len(hostnames), 2)
            self.assertIn(host1.override_hostname, hostnames)
            self.assertIn(host2.override_hostname, hostnames)

    def get_endpoint_hostnames(self, host):
        """
        Return a list of hosts with endpoints.
        :param host:
        :return:  A list of host names.
        """
        hostnames = []
        output = host.calicoctl("endpoint show")
        data = False
        for line in output.split("\n"):
            # Columns are separated by |
            cols = map(str.strip, line.strip().split("|"))

            if len(cols) == 6:
                # Table is bordered with |, so first and last columns are blank.
                assert not cols[0]
                assert not cols[5]

                # Data appears after the heading.  The Hostname should be the first
                # actual column of data (i.e. cols[1])
                if not data:
                    assert cols[1] == "Hostname"
                    data = True
                else:
                    assert cols[1]
                    hostnames.append(cols[1])

        return hostnames