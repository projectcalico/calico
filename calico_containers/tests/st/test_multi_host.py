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
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.exceptions import CommandExecError


class MultiHostMainline(TestBase):

    def test_multi_host(self):
        """
        Run a mainline multi-host test.

        Because multihost tests are slow to setup, this tests most mainline
        functionality in a single test.

        Create two hosts, a single network, one workload on each host and
        ping between them.
        """
        with DockerHost('host1') as host1, DockerHost('host2') as host2:
            # Create the network on host1, but it should be usable from all
            # hosts.
            network = host1.create_network(str(uuid.uuid4()))
            # TODO Assert that the network can be seen on host2

            # Check that autocreating a service for the existing network, when
            # starting a container works. Create a container on each host and
            # check that pings work.
            # TODO To make things harder, we should be able to create a
            # network using the UUID, but that doesn't work...
            #docker run --tty --interactive --detach --name workload2 --publish-service=a5accd88-869e-4149-8031-87af7c20318a.966204b315e55324148888e3808f6b4bf079a15f572142a69d4dab745bac7783 busybox
            #Error response from daemon: Cannot start container 11e8089573d188399487b1b490c1a786260dbd7cb33ec3b7817ea87528935b3f: Interface name 966204b315e55324148888e3808f6b4bf079a15f572142a69d4dab745bac7783 too long

            workload_host1 = host1.create_workload("workload1",
                                                   service="workload1",
                                                   network=network)
            # Precreate the service name on host1, before attaching it on
            # host 2.
            host1.execute("docker service publish workload2.%s" % network.name)
            workload_host2 = host2.create_workload("workload2",
                                                   service="workload2",
                                                   network=network)
            workload_host1.assert_can_ping(workload_host2.ip, retries=5)
            self.assert_connectivity(pass_list=[workload_host1,
                                                workload_host2])
            # Ping using service names
            workload_host1.execute("ping -c 1 -W 1 workload2")
            workload_host2.execute("ping -c 1 -W 1 workload1")

            # Test deleting the network. It will fail if there are any
            # endpoints connected still.
            self.assertRaises(CommandExecError, network.delete)

            # Remove the workloads, so the endpoints can be unpubloshed, then
            # the delete should succeed.
            host1.remove_workloads()
            host2.remove_workloads()

            host1.execute("docker service unpublish workload1.%s" % network)
            host1.execute("docker service unpublish workload2.%s" % network)
            network.delete()

            # TODO Would like to assert that there are no errors in the logs...
