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
from test_base import TestBase
from calico_containers.tests.st.utils.docker_host import DockerHost
import unittest
import uuid

class MultiHostMainline(TestBase):

    def run_multi_host(self):
        """
        Run a mainline multi-host test.

        Almost identical in function to the vagrant coreOS demo.

        Create two hosts, a single network, one workload on each host and
        ping between them.
        """
        with DockerHost('host1') as host1, DockerHost('host2') as host2:
            # Create the network on host1, but it should be usable from all
            # hosts.
            net = host1.create_network(str(uuid.uuid4()))

            workload_host1 = host1.create_workload("workload1", network=net)
            workload_host2 = host2.create_workload("workload2", network=net)

            # Allow network to converge
            workload_host1.assert_can_ping(workload_host2.ip, retries=5)

            # And check connectivity in both directions.
            self.assert_connectivity(pass_list=[workload_host1,
                                                workload_host2])


    def test_multi_host(self):
        self.run_multi_host()

    # def test_multi_host_default_as(self):
    #     self.run_multi_host(default_as=64512)
    #
    # def test_multi_host_per_node_as(self):
    #     self.run_multi_host(per_node_as=64513)
    #
    # def test_multi_host_default_and_per_node_as(self):
    #     self.run_multi_host(default_as=64514, per_node_as=64515)

# @unittest.skip("Libnetwork doesn't support multi-host yet.")
#     def run_multi_host(self, default_as=None, per_node_as=None):
#         """
#         Run a mainline multi-host test.
#
#         Almost identical in function to the vagrant coreOS demo.
#
#         Create two hosts, a single network, one workload on each host and
#         ping between them.
#         """
#         with DockerHost('host1') as host1, DockerHost('host2') as host2:
#
#             net135 = host1.create_network(str(uuid.uuid4()))
#             net2 = host1.create_network(str(uuid.uuid4()))
#             net4 = host1.create_network(str(uuid.uuid4()))
#
#             workload1 = host1.create_workload("workload1", network=net135)
#             workload2 = host1.create_workload("workload2", network=net2)
#             workload3 = host1.create_workload("workload3", network=net135)
#
#             workload4 = host2.create_workload("workload4", network=net4)
#             workload5 = host2.create_workload("workload5", network=net135)
#
#             self.assert_connectivity(pass_list=[workload1,
#                                                 workload3,
#                                                 workload5],
#                                      fail_list=[workload2,
#                                                 workload4])
#
#             self.assert_connectivity(pass_list=[workload2],
#                                      fail_list=[workload1,
#                                                 workload3,
#                                                 workload4,
#                                                 workload5])
#
#             self.assert_connectivity(pass_list=[workload4],
#                                      fail_list=[workload1,
#                                                 workload2,
#                                                 workload3,
#                                                 workload5])
#             host1 = DockerHost('host1', as_num=per_node_as)
#             host2 = DockerHost('host2', as_num=per_node_as)
#
#             if default_as:
#                 host1.calicoctl("default-node-as 12345")
#
#             ip1 = "192.168.1.1"
#             ip2 = "192.168.1.2"
#             ip3 = "192.168.1.3"
#             ip4 = "192.168.1.4"
#             ip5 = "192.168.1.5"
#
#             workload1 = host1.create_workload("workload1", ip1)
#             workload2 = host1.create_workload("workload2", ip2)
#             workload3 = host1.create_workload("workload3", ip3)
#
#             workload4 = host2.create_workload("workload4", ip4)
#             workload5 = host2.create_workload("workload5", ip5)
#
#             host1.calicoctl("profile add PROF_1_3_5")
#             host1.calicoctl("profile add PROF_2")
#             host1.calicoctl("profile add PROF_4")
#
#             host1.calicoctl("profile PROF_1_3_5 member add %s" % workload1)
#             host1.calicoctl("profile PROF_2 member add %s" % workload2)
#             host1.calicoctl("profile PROF_1_3_5 member add %s" % workload3)
#
#             host2.calicoctl("profile PROF_4 member add %s" % workload4)
#             host2.calicoctl("profile PROF_1_3_5 member add %s" % workload5)
#
#             self.assert_connectivity(pass_list=[workload1, workload3, workload5],
#                                      fail_list=[workload2, workload4])
#
#             self.assert_connectivity(pass_list=[workload2],
#                                      fail_list=[workload1, workload3, workload4, workload5])
#
#             self.assert_connectivity(pass_list=[workload4],
#                                      fail_list=[workload1, workload2, workload3, workload5])
