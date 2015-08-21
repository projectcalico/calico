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
from subprocess import CalledProcessError
from unittest import skip

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost

"""
Test the calicoctl container <CONTAINER> ip add/remove commands.

Tests the edge cases that aren't already covered by the mainline tests.
"""


class TestAddIp(TestBase):
    @skip("Not written yet")
    def test_add_remove_ip_with_interface(self):
        """
        Test the --interface option to calicoctl container <CONTAINER> ip
        add/remove <IP>
        """
        pass

    def test_add_ip(self):
        """
        Test adding multiple IPs per workload.
        """
        # TODO - split this up into multiple tests
        # TODO - add IPv6 testing here too
        with DockerHost('host') as host:
            # host.execute("docker run --net=calico:test -tid"
            #              " --name=workload1 busybox")
            # ip11 = host.execute("docker inspect --format "
            #                     "'{{ .NetworkSettings.IPAddress }}' "
            #                     "workload1").rstrip()
            ip11 = "192.168.1.1"
            ip12 = "192.168.1.2"
            ip21 = "192.168.2.1"
            ip22 = "192.168.2.2"
            ip31 = "192.168.3.1"

            workload1 = host.create_workload("workload1")
            host.calicoctl("container add %s %s" % (workload1, ip11))
            workload2 = host.create_workload("workload2")
            host.calicoctl("container add %s %s --interface=hello" %
                           (workload2, ip12))

            host.calicoctl("profile add TEST_GROUP")
            host.calicoctl("container %s profile set TEST_GROUP " % workload1)
            host.calicoctl("container %s profile set TEST_GROUP " % workload2)

            workload1.assert_can_ping(ip12, retries=3)

            # Add two more addresses to workload1 and one more to workload2
            host.calicoctl("container %s ip add %s" % (workload1, ip21))
            host.calicoctl("container %s ip add %s" % (workload1, ip31))

            host.calicoctl("container %s ip add %s --interface=hello" %
                           (workload2, ip22))

            workload1.assert_can_ping(ip22)
            workload2.assert_can_ping(ip11)
            workload2.assert_can_ping(ip21)
            workload2.assert_can_ping(ip31)

            #TODO Need to allow containers to be re-added to Calico networking
            """
            # Now stop and restart node 1 and node 2.
            host.execute("docker stop %s" % workload1)
            host.execute("docker stop %s" % workload2)
            host.execute("docker start %s" % workload1)
            host.execute("docker start %s" % workload2)

            # Test pings between the IPs.
            workload1.assert_can_ping(ip12, retries=10)
            workload1.assert_can_ping(ip22)
            workload2.assert_can_ping(ip11)
            workload2.assert_can_ping(ip21)
            workload2.assert_can_ping(ip31)

            # Now remove and check can't ping the removed addresses.
            host.calicoctl("container %s ip remove %s" % (workload1, ip21))
            host.calicoctl("container %s ip remove %s --interface=hello" %
                           (workload2, ip22))
            workload1.assert_can_ping(ip12)
            workload2.assert_can_ping(ip11)
            with self.assertRaises(CalledProcessError):
                workload1.assert_can_ping(ip22)
            with self.assertRaises(CalledProcessError):
                workload2.assert_can_ping(ip21)
            workload2.assert_can_ping(ip31)

            # Check that we can't remove addresses twice
            with self.assertRaises(CalledProcessError):
                host.calicoctl("container %s ip remove %s" % (workload1, ip21))
            """