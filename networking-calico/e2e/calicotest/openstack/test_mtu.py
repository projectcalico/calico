# Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
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

import functools
import logging

from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology
from calicotest.settings import Network

_log = logging.getLogger(__name__)

MTU_NET = Network("mtu-net", "100.15.32.0/24", None)


class TestMTU(Topology):
    """
    Create VM A, check MTU 1500, check connection.

    Create dedicated Neutron network, MTU not specified.

    Create VM B on dedicated network, check MTU 1500, check connection.

    Change MTU on dedicated network to 1400.

    Create VM C on dedicated network, check MTU 1400, check connection.

    Change MTU on dedicated network to 1499.

    Hard-reboot VM B, check MTU 1499, check connection.

    Live-migrate VM C, check MTU 1400, check connection.

    Hard-reboot VM C, check MTU 1499, check connection.
    """

    def setUp(self):
        super(TestMTU, self).setUp()
        _log.info("Running %s.setUp", self.id())

        # Create dedicated Neutron network, MTU not specified.
        self.mtu_net_id = self.create_network(MTU_NET.name, cidr=MTU_NET.cidr)
        self.vms = []

    def tearDown(self):
        _log.info("Running %s.tearDown", self.id())
        for vm in self.vms:
            self.delete_vm(vm.name)
        retry_until_success(
            functools.partial(self.delete_network, MTU_NET.name),
            context_string="TestMTU.tearDown",
        )
        super(TestMTU, self).tearDown()

    def hard_reboot(self, vm):
        vm.wait_for_state("ACTIVE")
        vm.reboot(reboot_type="HARD")
        # Wait to allow VM to reboot.
        vm.wait_for_state("ACTIVE", retries=75)
        # Wait for VM to allow ssh.
        retry_until_success(vm.connect, retries=2, context_string="TestMTU.hard_reboot")

    def change_dedicated_mtu(self, mtu):
        neutron = self.controller.tenants["admin"].neutron
        neutron.update_network(self.mtu_net_id, {"network": {"mtu": mtu}})

    def check_mtu(self, vm, expected_mtu):
        result = vm.execute("ip l show dev eth0")
        self.assertEqual(result.return_code, 0)
        words = result.stdout.split()
        self.assertGreater(len(words), 0)
        found_mtu = False
        for ii in range(len(words) - 1):
            if words[ii] == "mtu":
                self.assertEqual(int(words[ii + 1]), expected_mtu)
            found_mtu = True
            break
        self.assertTrue(found_mtu)

    def test_mtu(self):
        """
        Test MTU variation.
        """
        # Create VM A on standard network.
        vma_thread = self.create_vm_parallel()

        # Create VM B on dedicated network.
        vmb_thread = self.create_vm_parallel(networks=[MTU_NET.name])

        # Wait for VMs.
        vma = vma_thread.join()
        self.vms.append(vma)
        vmb = vmb_thread.join()
        self.vms.append(vmb)

        # Check VM A MTU 1500.
        self.check_mtu(vma, 1500)

        # Check VM B MTU 1500.
        self.check_mtu(vmb, 1500)

        # Check connectivity.
        self.check_mutual_connectivity(pass_list=self.vms)

        # Change MTU on dedicated network to 1400.
        self.change_dedicated_mtu(1400)

        # Create VM C on dedicated network, check MTU 1400.
        vmc_thread = self.create_vm_parallel(
            networks=[MTU_NET.name],
            availability_zone=self.zonify(LAYOUT.compute_nodes[1]),
        )
        vmc = vmc_thread.join()
        self.vms.append(vmc)
        self.check_mtu(vmc, 1400)

        # Check connectivity.
        self.check_mutual_connectivity(pass_list=self.vms)

        # Change MTU on dedicated network to 1499.
        self.change_dedicated_mtu(1499)

        # Hard-reboot VM B, check MTU 1499.
        self.hard_reboot(vmb)
        self.check_mtu(vmb, 1499)

        # Check connectivity.
        self.check_mutual_connectivity(pass_list=self.vms)

        # Live-migrate VM C, check MTU 1400.
        vmc.live_migrate(
            self.zonify(LAYOUT.compute_nodes[2]),
            block_migration=False,
            disk_over_commit=False,
        )
        vmc.wait_for_state("ACTIVE", wait_time=5, retries=15)
        self.check_mtu(vmc, 1400)

        # Hard-reboot VM C, check MTU 1499.
        self.hard_reboot(vmc)
        self.check_mtu(vmc, 1499)

        # Check connectivity.
        self.check_mutual_connectivity(pass_list=self.vms)
