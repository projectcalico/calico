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

import functools
import logging
import time

import netaddr

from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology
from calicotest.settings import DEFAULT_NET_NAME, IPV4_ONLY

_log = logging.getLogger(__name__)


class TestMultipleInterfaces(Topology):
    """Test the multiple interfaces topology with one security group."""

    @classmethod
    def setUpClass(cls):
        """
        We set up an A-frame network of three VMs. One leg is on demo-net. The
        other leg is on network2. The middle VM has two interfaces, one for
        each network.
        """
        super(TestMultipleInterfaces, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)

        cls.create_network(IPV4_ONLY.name, cidr=IPV4_ONLY.cidr)

        # Check both inter-node and intra-node connectivity.
        node0 = LAYOUT.compute_nodes[0]
        net1_vm_thread = cls.create_vm_parallel(availability_zone=node0)

        node1 = LAYOUT.compute_nodes[1]
        net2_vm_thread = cls.create_vm_parallel(
            availability_zone=node1, networks=[IPV4_ONLY.name]
        )

        vm_both_thread = cls.create_vm_parallel(availability_zone=node0)

        # Wait for threads to complete and store the created VMs
        cls.net1_vm = net1_vm_thread.join()
        cls.net2_vm = net2_vm_thread.join()
        cls.vm_both = vm_both_thread.join()

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        cls.delete_vm(cls.net2_vm.name)
        cls.delete_vm(cls.vm_both.name)
        cls.delete_vm(cls.net1_vm.name)
        # The test creates a port, then attaches it to a VM.  Deleting the VM doesn't
        # delete this port, because Nova only deletes the ports that it created itself.
        # In this case, the network can't be deleted because there is a port using it.
        # So first delete any stray ports on this network.
        cls.controller.tenants["admin"].delete_ports(IPV4_ONLY.name)
        retry_until_success(
            functools.partial(cls.delete_network, IPV4_ONLY.name),
            context_string="TestMultipleInterfaces.tearDownClass",
        )
        super(TestMultipleInterfaces, cls).tearDownClass()

    def test_multiple_interfaces(self):
        """
        Test that a VM with interfaces on two networks has connectivity.
        """

        self.vm_both.add_interface(IPV4_ONLY.name)

        # Because vm_both has two interfaces, it has two addresses.
        net1_addr = self.vm_both.get_ip_addr(version=4, network=DEFAULT_NET_NAME)
        net2_addr = self.vm_both.get_ip_addr(version=4, network=IPV4_ONLY.name)

        # Because all VMs are in the same security group, pinging between any
        # pair should succeed.
        can_ping = [
            [self.net1_vm, net1_addr],
            [self.net2_vm, net2_addr],
            [self.net2_vm, self.net1_vm.get_ip_addr()],
            [self.net1_vm, self.net2_vm.get_ip_addr()],
            # Leave these out for now because reverse path forwarding prevents
            # us from reliably SSHing into vm_both.
            # [self.vm_both, self.net1_vm.get_ip_addr()],
            # [self.vm_both, self.net2_vm.get_ip_addr()],
            # Leave these out for now because reverse path forwarding drops the
            # return ping.
            # [self.net1_vm, net2_addr],
            # [self.net2_vm, net1_addr],
        ]
        for source, dest in can_ping:
            ping = functools.partial(self.assert_can_ping, source, dest)
            context = "TestMultipleInterfaces.test_multiple_interfaces(%s, %s, %s)" % (
                self.assert_can_ping,
                source,
                dest,
            )
            retry_until_success(ping, context_string=context)


class TestMultipleInterfacesSecGroups(Topology):
    """
    Test the multiple interfaces topology where VMs on a network are also in a
    security group for that network.
    """

    @classmethod
    def setUpClass(cls):
        """
        We set up an A-frame network of three VMs. One leg is on demo-net. The
        other leg is on network2. The middle VM has two interfaces, one for
        each network.
        """
        super(TestMultipleInterfacesSecGroups, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)

        cls.create_network(IPV4_ONLY.name, cidr=IPV4_ONLY.cidr)

        cls.SEC_GROUP_1 = "group1"
        cls.create_security_group(cls.SEC_GROUP_1)
        cls.add_ssh_rule(cls.SEC_GROUP_1)
        cls.add_group_ping_rule(cls.SEC_GROUP_1)

        cls.SEC_GROUP_2 = "group2"
        cls.create_security_group(cls.SEC_GROUP_2)
        cls.add_ssh_rule(cls.SEC_GROUP_2)
        cls.add_group_ping_rule(cls.SEC_GROUP_2)

        node0 = LAYOUT.compute_nodes[0]
        net1_vm_thread = cls.create_vm_parallel(
            availability_zone=node0, security_groups=cls.SEC_GROUP_1
        )

        node1 = LAYOUT.compute_nodes[1]
        net2_vm_thread = cls.create_vm_parallel(
            availability_zone=node1,
            networks=[IPV4_ONLY.name],
            security_groups=cls.SEC_GROUP_2,
        )

        vm_both_thread = cls.create_vm_parallel(
            availability_zone=node0, security_groups=cls.SEC_GROUP_1
        )

        # Wait for threads to complete and store the created VMs
        cls.net1_vm = net1_vm_thread.join()
        cls.net2_vm = net2_vm_thread.join()
        cls.vm_both = vm_both_thread.join()

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)

        cls.delete_vm(cls.net2_vm.name)
        cls.delete_vm(cls.vm_both.name)
        cls.delete_vm(cls.net1_vm.name)
        # Can't delete while VMs are using
        cls.controller.tenants["admin"].delete_ports(IPV4_ONLY.name)
        retry_until_success(
            functools.partial(cls.delete_network, IPV4_ONLY.name),
            context_string="TestMultipleInterfacesSecGroups.tearDownClass",
        )
        super(TestMultipleInterfacesSecGroups, cls).tearDownClass()

    def test_multiple_interfaces_and_sec_groups(self):
        """
        Test that a VM with interfaces on two networks and corresponding
        security groups has the expected connectivity.
        """

        self.vm_both.add_interface(IPV4_ONLY.name, sec_groups=[self.SEC_GROUP_2])

        # Because vm_both has two interfaces, it has two addresses.
        net1_addr = self.vm_both.get_ip_addr(version=4, network=DEFAULT_NET_NAME)
        net2_addr = self.vm_both.get_ip_addr(version=4, network=IPV4_ONLY.name)

        # VMs should be able to ping the interface of vm_both that is on their network.
        can_ping = [
            [self.net1_vm, net1_addr],
            [self.net2_vm, net2_addr],
            # Leave these out for now because reverse path forwarding prevents
            # us from reliably SSHing into vm_both.
            # [self.vm_both, self.net1_vm.get_ip_addr()],
            # [self.vm_both, self.net2_vm.get_ip_addr()],
        ]
        for source, dest in can_ping:
            ping = functools.partial(self.assert_can_ping, source, dest)
            context = (
                "TestMultipleInterfacesSecGroups."
                "test_multiple_interfaces_and_sec_groups(%s, %s, %s)"
                % (self.assert_can_ping, source, dest)
            )
            retry_until_success(ping, context_string=context)

        # ... but *not* the interface of vm_both that isn't on their network.
        # (Nor each other)
        cant_ping = [
            [self.net2_vm, self.net1_vm.get_ip_addr()],
            [self.net1_vm, self.net2_vm.get_ip_addr()],
            [self.net1_vm, net2_addr],
            [self.net2_vm, net1_addr],
        ]
        for source, dest in cant_ping:
            # These are not retried because they should *never* allow a ping.
            with self.assertRaises(AssertionError):
                self.assert_can_ping(source, dest)


class TestFlapInterfaces(Topology):
    """
    Test that when an interface is flapped, Calico reestablishes connection
    across it.
    """

    @classmethod
    def setUpClass(cls):
        """Set up three VMs, two on one host and one on another."""
        super(TestFlapInterfaces, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        cls.vms = []

        vm_threads = []
        node0 = LAYOUT.compute_nodes[0]
        vm_threads.append(cls.create_vm_parallel(availability_zone=node0))
        vm_threads.append(cls.create_vm_parallel(availability_zone=node0))

        node1 = LAYOUT.compute_nodes[1]
        vm_threads.append(cls.create_vm_parallel(availability_zone=node1))

        for vm_thread in vm_threads:
            cls.vms.append(vm_thread.join())

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in cls.vms:
            cls.delete_vm(vm.name)
        # Can't delete network while VMs are using it
        super(TestFlapInterfaces, cls).tearDownClass()

    def test_ifdown_interface(self):
        """
        Test that when a VM runs ifdown & ifup on its interface, Calico
        reestablishes connection.
        """
        vm = self.vms[0]
        ip = netaddr.IPAddress(list(vm.vm.addresses.values())[0][0]["addr"])
        vm.execute("ip l")
        vm.execute("ip a")
        _log.info("Bringing down eth0 of VM %s", ip)
        # We know this is eth0 by manual inspection
        down_up = (
            "sleep 30s && sudo ip l set eth0 down && sleep 60s && "
            "sudo ip l set eth0 up > /tmp/toggleif 2>&1"
        )
        result = vm.execute("nohup sh -lc '%s' &" % down_up)
        if result.return_code:
            raise RuntimeError("Command failed: %s" % result)

        # Sleep for 30s
        _log.info("Pause 30s waiting for ifdown")
        time.sleep(30)

        # Make sure it went down
        _log.info("Check ping connectivity is failing")
        check = functools.partial(self.assert_cannot_ping, self.vms[1], ip)
        retry_until_success(
            check, retries=10, context_string="TestFlapInterfaces.test_ifdown_interface"
        )

        # Sleep for 60s to wait for the ifup command to be issued.
        _log.info("Pause 60s waiting for ifup")
        time.sleep(60)

        # Although the VM has not actually been restarted, we call restarted
        # to reconnect the SSH session.
        _log.info("Flag VM as restarted (to reconnect SSH session)")
        vm.restarted()

        # Make sure it came back up again
        _log.info("Check ping connectivity is working")
        self.check_mutual_connectivity(pass_list=self.vms, retries=5)

    def test_detach_interface(self):
        """
        Test openstack flapping an interface.
        """
        vm = self.vms[0]
        interfaces = vm.vm.interface_list()
        port_id = interfaces[0].port_id
        _log.info("About to detach port %s from vm %s", port_id, vm)

        vm.vm.interface_detach(port_id=port_id)

        # Wait until the interface is really gone.
        def interface_gone():
            interfaces = vm.vm.interface_list()
            _log.info("interfaces = %r", interfaces)
            assert not interfaces

        retry_until_success(interface_gone, retries=10, wait_time=5)

        _log.info("Detached port; checking connectivity")
        self.check_mutual_connectivity(pass_list=self.vms[1:], fail_list=[vm])

        net_id = vm.tenant.networks[DEFAULT_NET_NAME]
        _log.info(
            "About to re-attach port %s to vm %s (net ID %s)", port_id, vm, net_id
        )
        vm.vm.interface_attach(port_id=None, net_id=net_id, fixed_ip=None)

        _log.info("Rebooting VM")
        vm.reboot(reboot_type="HARD")
        # Wait to allow VM to reboot.
        vm.wait_for_state("ACTIVE", retries=75)

        _log.info("Re-checking connectivity")
        self.check_mutual_connectivity(pass_list=self.vms)
