# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

"""
Minimal test that DNS resolution works from inside an Ubuntu VM.
"""

import logging

from calicotest.openstack.basetest import LOGS_IGNORE_ALL_TESTS
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology
from calicotest.settings import IPV6_WITH_APPS

_log = logging.getLogger(__name__)


class TestVmDns(Topology):
    """
    Verify that an Ubuntu VM can resolve DNS names.
    """

    IGNORE_LOGS_LIST = LOGS_IGNORE_ALL_TESTS

    @classmethod
    def setUpClass(cls):
        super(TestVmDns, cls).setUpClass()
        cls.node1 = LAYOUT.compute_nodes[0]
        cls.vm = cls.create_vm(
            availability_zone=cls.zonify(cls.node1),
            image=IPV6_WITH_APPS,
            ubuntu_speedup_sudo=True,
        )
        cls.vms = [cls.vm]

    @classmethod
    def tearDownClass(cls):
        for vm in cls.vms:
            cls.delete_vm(vm.name)
        super(TestVmDns, cls).tearDownClass()

    def test_dns_resolution(self):
        """
        Verify that the VM can resolve a well-known DNS name.
        """
        # First check what resolv.conf looks like, for diagnostics.
        result = self.vm.execute("cat /etc/resolv.conf")
        _log.info("resolv.conf:\n%s", result.stdout)

        # Try to resolve a well-known name.
        result = self.vm.execute("nslookup archive.ubuntu.com")
        _log.info("nslookup output:\n%s", result.stdout)
        if result.return_code != 0:
            _log.warning("nslookup stderr:\n%s", result.stderr)
        assert result.return_code == 0, "DNS resolution failed for archive.ubuntu.com"
