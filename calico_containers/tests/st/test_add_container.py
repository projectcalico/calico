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
from sh import ErrorReturnCode
from functools import partial

from test_base import TestBase
from docker_host import DockerHost
from utils import retry_until_success


class TestAddContainer(TestBase):
    def test_add_container(self):
        """
        Test adding container to calico networking after it exists.
        """
        host = DockerHost('host')

        node = host.create_workload("node")

        # Use the `container add` command instead of passing a CALICO_IP on
        # container creation. Note this no longer needs DOCKER_HOST specified.
        host.calicoctl("container add %s 192.168.1.1" % node.name)

        host.calicoctl("profile add TEST_GROUP")
        host.calicoctl("profile TEST_GROUP member add %s" % node.name)

        # Wait for felix to program down the route.
        check_route = partial(host.execute, "ip route | grep '192\.168\.1\.1'")
        retry_until_success(check_route, ex_class=ErrorReturnCode)
