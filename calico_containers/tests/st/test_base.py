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
from subprocess import CalledProcessError
import subprocess
from unittest import TestCase
from calico_containers.tests.st.utils.utils import get_ip
import logging

logging.getLogger('sh').setLevel('INFO')

class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """
    def setUp(self):
        """
        Clean up before every test.
        """
        self.ip = get_ip()
        # Delete /calico if it exists. This ensures each test has an empty data
        # store at start of day.
        subprocess.check_output(
            "curl -sL http://%s:2379/v2/keys/calico?recursive=true -XDELETE"
            % self.ip, shell=True)

    def assert_connectivity(self, pass_list, fail_list=None):
        """
        Assert partial connectivity graphs between workloads.

        :param pass_list: Every workload in this list should be able to ping
        every other workload in this list.
        :param fail_list: Every workload in pass_list should *not* be able to
        ping each workload in this list. Interconnectivity is not checked
        *within* the fail_list.
        """
        if fail_list is None:
            fail_list = []
        for source in pass_list:
            for dest in pass_list:
                source.assert_can_ping(dest.ip)
            for dest in fail_list:
                source.assert_cant_ping(dest.ip)
