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
import uuid

from nose.plugins.attrib import attr

from test_base import TestBase
from calico_containers.tests.st.utils.docker_host import (DockerHost,
                                                          CommandExecError)
from calico_containers.tests.st.utils.utils import retry_until_success
from functools import partial

class TestBGPConfig(TestBase):

    @attr('slow')
    def test_defaults(self):
        """
        Test default BGP configuration commands.
        """
        with DockerHost('host', start_calico=False, dind=False) as host:
            # Check default AS command
            self.assertEquals(host.calicoctl("default-node-as"), "64511")
            host.calicoctl("default-node-as 12345")
            self.assertEquals(host.calicoctl("default-node-as"), "12345")
            with self.assertRaises(CommandExecError):
                host.calicoctl("default-node-as 99999999999999999999999")
            with self.assertRaises(CommandExecError):
                host.calicoctl("default-node-as abcde")

            # Check BGP mesh command
            self.assertEquals(host.calicoctl("bgp-node-mesh"), "on")
            host.calicoctl("bgp-node-mesh off")
            self.assertEquals(host.calicoctl("bgp-node-mesh"), "off")
            host.calicoctl("bgp-node-mesh on")
            self.assertEquals(host.calicoctl("bgp-node-mesh"), "on")

    @attr('new')
    def test_three_host_different_as_num(self):
        """
        Test using different AS number for the node-to-node mesh.

        We run a multi-host test for this as we need to set up real BGP peers.
        """
        with DockerHost('host1', start_calico=False) as host1, \
             DockerHost('host2', start_calico=False) as host2, \
             DockerHost('host3', start_calico=False) as host3:

            # Set the default AS number.
            host1.calicoctl("default-node-as 64512")

            # Start host1 using the inherited AS, and host2 using a specified
            # AS (same as default), and host3 with a completely different AS.
            host1.start_calico_node()
            host1.assert_driver_up()
            host2.start_calico_node(as_num="64512")
            host2.assert_driver_up()
            host3.start_calico_node(as_num="23456")
            host3.assert_driver_up()

            # Create the network on host1, but it should be usable from all
            # hosts.
            net = host1.create_network(str(uuid.uuid4()))

            workload_host1 = host1.create_workload("workload1", network=net)
            workload_host2 = host2.create_workload("workload2", network=net)
            workload_host3 = host3.create_workload("workload3", network=net)

            # Allow network to converge
            workload_host1.assert_can_ping(workload_host2.ip, retries=10)

            # And check connectivity in both directions.
            self.assert_connectivity(pass_list=[workload_host1,
                                                workload_host2],
                                     fail_list=[workload_host3])



            #with DockerHost('host', start_calico=False, dind=False) as host:
            # Spin up calicoctl specifying an AS number.
            #host2 = DockerHost('host2', as_num=64512)
            #
            # # Add some peers
            # examples = [
            #     ["1.2.3.4", 4],
            #     ["aa:cc::ff", 6],
            # ]
            # for [peer, version] in examples:
            #     host2.calicoctl("node bgppeer add %s as 12345" % peer)
            #     self.assertIn(peer, host2.calicoctl("node bgppeer show").stdout.rstrip())
            #     self.assertIn(peer, host2.calicoctl("node bgppeer show --ipv%s" % version).stdout.rstrip())
            #     self.assertNotIn(peer, host2.calicoctl("node bgppeer show --ipv%s" % self.ip_not(version)).stdout.rstrip())
            #     host2.calicoctl("node bgppeer remove %s" % peer)
            #     self.assertNotIn(peer, host2.calicoctl("node bgppeer show").stdout.rstrip())
            #     with self.assertRaises(ErrorReturnCode_1):
            #         host2.calicoctl("node bgppeer remove %s" % peer)
