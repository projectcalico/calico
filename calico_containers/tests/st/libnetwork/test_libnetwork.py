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
from unittest import skip

from tests.st.test_base import TestBase


class LibnetworkTests(TestBase):

    @skip("Not written yet")
    def test_moving_endpoints(self):
        """
        Test moving endpoints between hosts and containers.
        """
        # with DockerHost('host1') as host1, DockerHost('host2') as host2:
        #     pass
        # Using docker service attach/detach publish/unpublish ls/info
        pass

    @skip("Not written yet")
    def test_endpoint_ids(self):
        """
        Test that endpoint ID provided by docker service publish can be used
        with calicoctl endpoint commands.
        """
        pass
