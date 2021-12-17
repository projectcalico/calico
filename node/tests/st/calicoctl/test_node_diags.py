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

"""
Test calicoctl diags.

It's worth testing that the command can be executed. It's debatable whether
it's worth testing the upload.

We're not trying to assert on the contents of the diags package.

TODO We could check that the file is actually written (and doesn't just appear
in the output) and is a decent size.
TODO We could check collecting diags when calico-node is actually running.
"""


class TestNodeDiags(TestBase):
    def test_node_diags(self):
        """
        Test that the diags command successfully creates a tar.gz file.
        """
        with DockerHost('host', dind=False, start_calico=False) as host:
            results = host.calicoctl("node diags")
            self.assertIn(".tar.gz", results)
