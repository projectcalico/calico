# Copyright (c) 2014-2026 Tigera, Inc. All rights reserved.
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

from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology

_log = logging.getLogger(__name__)


class TestVmActions(Topology):
    """
    Sets up VMs in the same tenant, network, security
    group and across all hosts.
    """

    def setUp(self):
        super(TestVmActions, self).setUp()
        _log.info("Running %s.setUp", self.id())
        # Setup 3 VMs per test.  We pick one VM to apply actions to and use the
        # others for connectivity checks.
        self.vms = []
        num_vms = 3
        vm_threads = []
        for i in range(num_vms):
            # Deal the VMs out over the available compute nodes
            index = i % len(LAYOUT.compute_nodes)
            node = LAYOUT.compute_nodes[index]
            vm_threads.append(self.create_vm_parallel(availability_zone=node))

        for vm_thread in vm_threads:
            self.vms.append(vm_thread.join())

    def tearDown(self):
        _log.info("Running %s.tearDown", self.id())
        for vm in self.vms:
            self.delete_vm(vm.name)
        super(TestVmActions, self).tearDown()

    def test_vm_pause_unpause(self):
        """
        Check that pause (and unpause) works.
        """
        vm = self.vms.pop()
        vm.wait_for_state("ACTIVE")
        vm.pause()
        vm.wait_for_state("PAUSED")
        self.check_mutual_connectivity(self.vms, fail_list=[vm], retries=1)

        vm.unpause()
        vm.wait_for_state("ACTIVE")

        # Give the VM a few seconds to come up
        self.vms.append(vm)
        self.check_mutual_connectivity(pass_list=self.vms)

    def test_suspend_resume(self):
        """
        Checks that suspend-resume works.
        """
        vm = self.vms.pop()
        vm.wait_for_state("ACTIVE", retries=30)
        vm.suspend()
        vm.wait_for_state("SUSPENDED", retries=30)
        self.check_mutual_connectivity(self.vms, fail_list=[vm], retries=1)

        vm.resume()
        vm.wait_for_state("ACTIVE")
        # Give the VM a few seconds to come up
        self.vms.append(vm)
        self.check_mutual_connectivity(pass_list=self.vms)

    def test_reboot_soft_nova(self):
        """
        Triggers a soft reboot via nova.
        """
        vm = self.vms[-1]
        vm.wait_for_state("ACTIVE", retries=30)
        vm.reboot()
        vm.wait_for_state("REBOOT")
        # Wait to allow VM to reboot.
        vm.wait_for_state("ACTIVE", retries=300)
        # Wait for VM to allow ssh.
        retry_until_success(
            vm.connect, retries=2, context_string="TestVmActions.test_reboot_soft_nova"
        )
        self.check_mutual_connectivity(pass_list=self.vms)

    def test_reboot_hard_nova(self):
        """
        Triggers a hard reboot via nova.
        """
        vm = self.vms[-1]
        vm.wait_for_state("ACTIVE")
        vm.reboot(reboot_type="HARD")
        # Wait to allow VM to reboot.
        vm.wait_for_state("ACTIVE", retries=75)
        # Wait for VM to allow ssh.
        retry_until_success(
            vm.connect, retries=2, context_string="TestVmActions.test_reboot_hard_nova"
        )

        self.check_mutual_connectivity(pass_list=self.vms)

    def test_reboot_vm(self):
        """
        Triggers a reboot via the VM's CLI.
        """
        vm = self.vms[-1]
        vm.wait_for_state("ACTIVE", retries=30)
        vm.execute("sudo reboot")
        vm.wait_for_state("ACTIVE", retries=30)
        vm.restarted()
        # Wait to allow VM to reboot.
        retry_until_success(
            vm.connect, retries=2, context_string="TestVmActions.test_reboot_vm"
        )
        self.check_mutual_connectivity(pass_list=self.vms)

    def test_rebuild_vm(self):
        """
        Triggers a rebuild via Nova.
        """
        vm = self.vms[-1]
        vm.wait_for_state("ACTIVE", retries=30)
        vm.rebuild()
        vm.wait_for_state("REBUILD", retries=60)
        vm.wait_for_state("ACTIVE", retries=300)

        # Wait to allow rebuilt VM to boot.
        retry_until_success(
            vm.connect, retries=2, context_string="TestVmActions.test_rebuild_vm"
        )
        self.check_mutual_connectivity(pass_list=self.vms)
