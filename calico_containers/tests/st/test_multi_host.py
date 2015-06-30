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

from test_base import TestBase
from calico_containers.tests.st.utils.docker_host import DockerHost

class MultiHostMainline(TestBase):

    def test_multi_host(self):
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
