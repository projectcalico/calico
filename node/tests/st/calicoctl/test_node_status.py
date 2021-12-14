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
from tests.st.utils.exceptions import CommandExecError
from tests.st.utils.utils import retry_until_success

"""
Test calicoctl status

Most of the status output is checked by the BGP tests, so this module just
contains a simple return code check.
"""

class TestNodeStatus(TestBase):
    def test_node_status(self):
        """
        Test that the status command can be executed.
        """
        with DockerHost('host', dind=False, start_calico=True) as host:
            def node_status():
                host.calicoctl("node status")
            retry_until_success(node_status, retries=10, ex_class=Exception)

    def test_node_status_fails(self):
        """
        Test that the status command fails when calico node is not running
        """
        with DockerHost('host', dind=False, start_calico=False) as host:
            try:
                host.calicoctl("node status")
            except CommandExecError as e:
                self.assertEquals(e.returncode, 1)
                self.assertEquals(e.output,
                                  "Calico process is not running.\n")
            else:
                raise AssertionError("'calicoctl node status' did not exit"
                                     " with code 1 when node was not running")
