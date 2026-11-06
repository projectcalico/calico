# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
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

import logging
from unittest import mock

import netaddr

import calicotest.openstack.basetest as basetest

_log = logging.getLogger(__name__)


class TestPingFunctions(basetest.TestBase):
    @classmethod
    def setUpClass(cls):
        super(TestPingFunctions, cls).setUpClass()
        security_group_one = [mock_vm("1.2.3.4"), mock_vm("1.2.3.5")]
        security_group_two = [mock_vm("2.2.3.4"), mock_vm("2.2.3.5")]
        cls._security_groups = [security_group_one, security_group_two]

    def test_check_mutual_connectivity(self):
        """
        Gives the check_mutual_connectivity function sets of vms to ping,
        and checks that the outcome is as expected.
        :return:
        """
        self.ping = mock.create_autospec(self.ping)
        self.ping.side_effect = self.mock_ping

        pass_list, fail_list = self._security_groups
        self.check_mutual_connectivity(pass_list, fail_list)

        try:
            self.check_mutual_connectivity(pass_list + fail_list, retries=0)
            self.assertFalse(
                True,
                "TestBase.ping incorrectly did not throw "
                "an exception on failing pings that were"
                "meant to succeed",
            )
        except self.failureException:
            _log.info(
                "TestBase.ping correctly noticed failing pings that were meant to fail"
            )
        try:
            self.check_mutual_connectivity(pass_list, pass_list, retries=0)
            self.assertFalse(
                True,
                "TestBase.ping incorrectly did not throw "
                "an exception on successful pings that were"
                "meant to fail",
            )
        except self.failureException:
            _log.info(
                "TestBase.ping correctly noticed successful pings that "
                "were meant to fail"
            )

    def mock_ping(self, vm, dest_ip, num_bytes):
        """
        A function to mock out the ping function of TestBase.
        Returns True if the vm and ip given both are from the same security
        group define in this class, False otherwise.
        :param vm: The vm which will ping
        :param dest_ip: The target ip to ping
        :param num_bytes: The number of bytes to ping with. Since we don't
            actually ping anything, this doesn't affect anything. Needed to
            match the argument signature of the original ping(...) function.
        """
        _log.debug("Mocking ping call")
        for sec_group in self._security_groups:
            if vm in sec_group and any(
                ip == dest_ip for vm in sec_group for ip in vm.get_all_addresses()
            ):
                return True
        return False


TestPingFunctions.unit_test = True


def mock_vm(ip):
    """
    Creates a mock vm, which will act as if it owns the given ip
    :param ip:
    """
    vm = mock.MagicMock()
    vm.get_all_addresses.return_value = [netaddr.IPAddress(ip)]
    vm.name = ip
    return vm
