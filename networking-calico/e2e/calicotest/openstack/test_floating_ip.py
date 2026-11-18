# Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
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

from calicotest.common.ssh import SSH
from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import TopologyBasicFloatingIPs
from calicotest.settings import CIRROS

_log = logging.getLogger(__name__)


class TestFloatingIPs(TopologyBasicFloatingIPs):
    """
    Sets up VMs in the same tenant, network and security group on
    all hosts and checks they can all connect to each other.
    """

    def test_floating_ip(self):
        self.check_mutual_connectivity(pass_list=self.vms)

        # Identify the port that we will add a floating IP to.
        target_vm = self.vms[0]
        target_vm_fixed_ip = str(target_vm.get_ip_addr_list()[0])
        target_vm_port = self.get_port(target_vm_fixed_ip)
        _log.info(
            "Floating IP target=%s IP=%s port=%s",
            target_vm,
            target_vm_fixed_ip,
            target_vm_port,
        )

        # Add a floating IP address to the first VM.
        neutron = self.controller.tenants["admin"].neutron
        req = {
            "floatingip": {
                "floating_network_id": self.float_net,
                "port_id": target_vm_port["id"],
            }
        }
        rsp = neutron.create_floatingip(req)
        _log.info("Floating IP creation rsp=%s", rsp)
        floating_ip_addr = rsp["floatingip"]["floating_ip_address"]

        # Check that all VMs can ping the floating IP.
        for vm in self.vms:
            retry_until_success(
                functools.partial(self.assert_can_ping, vm, floating_ip_addr)
            )

        # Check that the test node can connect to the floating IP.
        ssh = SSH(
            floating_ip_addr,
            CIRROS.username,
            CIRROS.password,
            desc="cirros-via-floating-ip",
        )
        ssh.connect()
        ssh.execute("/sbin/ifconfig")
        ssh.disconnect()

        # Check that the target VM's host can ping the floating IP.
        LAYOUT.compute_nodes[0].execute("ping -c 1 %s" % floating_ip_addr)
