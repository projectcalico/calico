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
from functools import partial
from subprocess import CalledProcessError

from calico_containers.tests.st.utils.utils import retry_until_success
from calico_containers.tests.st.utils.workload import NET_NONE
from test_base import TestBase
from calico_containers.tests.st.utils.docker_host import DockerHost


class TestAddContainer(TestBase):
    def test_add_container(self):
        """
        Test adding container to calico networking after it exists.
        """
        with DockerHost('host', dind=False) as host:
            # Create a container with --net=none, add a calico interface to
            # it then check felix programs a route.
            node = host.create_workload("node", network=NET_NONE)
            host.calicoctl("container add %s 192.168.1.1" % node)

            # Create the profile, get the endpoint IDs for the containers and
            # add the profile to the endpoint so felix will pick it up.
            host.calicoctl("profile add TEST_GROUP")
            ep = host.calicoctl("container %s endpoint-id show" % node).strip()
            host.calicoctl("endpoint %s profile set TEST_GROUP" % ep)

            # Wait for felix to program down the route.
            check_route = partial(host.execute,
                                  "ip route | grep '192\.168\.1\.1'")
            retry_until_success(check_route, ex_class=CalledProcessError)
