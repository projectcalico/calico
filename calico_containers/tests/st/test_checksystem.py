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
from tests.st.utils.docker_host import DockerHost

"""
Test calicoctl checksystem

It's worth doing a simple return code check. Anything more is going to be
difficult given the environmental requirements.

The --fix command is already executed as part of the tests (in the Makefile)
"""


class TestCheckSystem(TestBase):
    def test_checksystem(self):
        """
        Test that the checksystem command can be executed.
        """
        with DockerHost('host', dind=False, start_calico=False) as host:
            host.calicoctl("checksystem")
