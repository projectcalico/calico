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

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost


class TestMainline(TestBase):
    def test_mainline(self):
        """
        Setup two endpoints on one host and check connectivity then teardown.
        """
        # TODO - add in IPv6 as part of this flow.
        with DockerHost('host', dind=False) as host:
            network = host.create_network(str(uuid.uuid4()))
            node1 = host.create_workload(str(uuid.uuid4()), network=network)
            node2 = host.create_workload(str(uuid.uuid4()), network=network)

            # TODO - assert on output of endpoint show and endpoint profile
            # show commands.

            # Allow network to converge
            node1.assert_can_ping(node2.ip, retries=5)

            # Check connectivity.
            self.assert_connectivity([node1, node2])

            # Test calicoctl teardown commands.
            # TODO - detach ("leave") the endpoints - (assert can't ping and
            #  endpoints are removed from calicoctl)
            # TODO - unpublish the endpoints - (assert IPs are released)
            # TODO - remove the network - (assert profile is removed)
            # TODO - Remove this calico node

