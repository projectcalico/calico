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
from nose.plugins.attrib import attr

from test_base import TestBase
from tests.st.utils.docker_host import DockerHost


class TestDiags(TestBase):
    @attr('slow')
    def test_diags(self):
        """
        Test that the diags command successfully uploads the diags file.
        """
        with DockerHost('host', start_calico=False) as host:
            results = host.calicoctl("diags")
            self.assertIn(".tar.gz", results)
