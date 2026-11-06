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

from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology
from calicotest.settings import IPV6_WITH_APPS


_log = logging.getLogger(__name__)


class TestSpoofing(Topology):
    """
    Test whether Calico stops simple IP/MAC address spoofing attempts
    """

    TCPDUMP_FILE_NAME = "snoop.cap"
    security_group = None

    @classmethod
    def setUpClass(cls):
        """
        Set up the VMs and add to appropriate security groups
        We create three VMs on one security group:
        spoofed_vm: A VM which we will attempt to spoof.
        target_vm: A VM which we will attempt to contact.
        neighbor_vm: A VM which we use to test allowed pings to target_vm
        And one vm on a separate security group:
        spoofing_vm: A VM which we will use for spoofing
        """
        _log.info("Running %s.setUpClass", cls.__name__)
        super(TestSpoofing, cls).setUpClass()

        _log.info("Creating security group: group2")
        cls.security_group = cls.create_security_group("group2")
        cls.add_ssh_rule("group2")
        cls.add_group_ping_rule("group2")

        # Turn off RPF on compute hosts (so that we're testing our rules,
        # not the kernel's own)
        for node in LAYOUT.compute_nodes:
            node.execute("sudo sysctl net.ipv4.conf.all.rp_filter=0")
            node.execute("sudo sysctl net.ipv4.conf.default.rp_filter=0")

        # Create two vms in the default security group
        node = LAYOUT.compute_nodes[0]
        _log.info("Creating 2 VMs on %s", node)
        spoofed_vm_thread = cls.create_vm_parallel(availability_zone=node)
        neighbor_vm_thread = cls.create_vm_parallel(
            availability_zone=node, image=IPV6_WITH_APPS, ubuntu_speedup_sudo=True
        )

        node = LAYOUT.compute_nodes[0]
        _log.info("Creating spoofing VM on %s", node)
        spoofing_vm_thread = cls.create_vm_parallel(
            availability_zone=node,
            security_groups="group2",
            image=IPV6_WITH_APPS,
            ubuntu_speedup_sudo=True,
        )

        node = LAYOUT.compute_nodes[1]
        _log.info("Creating target VM on %s", node)
        target_vm_thread = cls.create_vm_parallel(
            availability_zone=node, image=IPV6_WITH_APPS, ubuntu_speedup_sudo=True
        )

        # Wait for the threads to complete and store the created VMs
        cls.spoofed_vm = spoofed_vm_thread.join()
        cls.neighbor_vm = neighbor_vm_thread.join()
        cls.spoofing_vm = spoofing_vm_thread.join()
        cls.target_vm = target_vm_thread.join()

        _log.debug("spoofing VM ip: %s", cls.spoofing_vm.get_ip_addr().format())
        _log.debug("spoofed VM ip : %s", cls.spoofed_vm.get_ip_addr().format())
        _log.debug("neighbor VM ip: %s", cls.neighbor_vm.get_ip_addr().format())
        _log.debug("target VM ip  : %s", cls.target_vm.get_ip_addr().format())

    @classmethod
    def tearDownClass(cls):
        """
        Tear down the VMs and remove the security groups.
        """
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in list(cls.controller.tenants["admin"].vms.keys()):
            cls.delete_vm(vm)

        # Can't delete Sec group while VMs are using it, so give the VMs time
        # to disappear
        neutron = cls.controller.tenants["admin"].neutron
        retry_until_success(
            functools.partial(neutron.delete_security_group, cls.security_group["id"]),
            retries=30,
            context_string="TestSpoofing.tearDownClass",
        )
        super(TestSpoofing, cls).tearDownClass()

    def test_ip_spoofing_nat(self):
        """
        Test if we can get away with ip spoofing using guest NAT rules to
        spoof.
        We have two security groups, and attempt to get one VM to ping a VM
        in a different security group (which it should not be able to).
        We copy the address of a VM in the other security group, and modify
        outgoing traffic on spoofing vm to have the ip of spoofed_vm.
        We set tcpdump running on target_vm, attempt to ping it and check if
        any packets are received, and as a sanity test, we attempt the same
        thing with neighbor vm and check it can connect.
        """
        # Change ip to that of the VM we are spoofing
        original_ip = self.spoofing_vm.get_ip_addr().format()
        spoofed_ip = self.spoofed_vm.get_ip_addr().format()
        self.spoofing_vm.change_advertised_ip(spoofed_ip)

        # Set up receiver to monitor if it receives pings, and then start pings
        self.run_tcpdump(self.target_vm, 20)
        target_ip = self.target_vm.get_ip_addr().format()
        # Without the next line, the ping can succeed before tcpdump is
        # watching, causing test to fail.
        time.sleep(5)
        self.assert_can_ping(self.neighbor_vm, target_ip)
        self.assert_cannot_ping(self.spoofing_vm, target_ip)

        # Wait for tcpdump to output, then check if results are as expected,
        # the spoofed ping did not get through and the non-spoofed ping got
        # through and had a response
        time.sleep(20)
        self.assertEqual(
            self.check_tcpdump_file(self.target_vm, spoofed_ip),
            0,
            msg="Test Failure - spoof packets seen at target!",
        )
        neighbor_ip = self.neighbor_vm.get_ip_addr().format()
        self.assertEqual(
            self.check_tcpdump_file(self.target_vm, neighbor_ip),
            2,
            msg="Test Failure - neighbour could not ping target",
        )
        # Clean up
        self.spoofing_vm.change_advertised_ip(original_ip)

    def test_ip_spoofing_assigned(self):
        """
        Test if we can get away with ip spoofing using an IP assigned on the
        guest interface.
        We have two security groups, and attempt to get one VM to ping a VM
        in a different security group (which it should not be able to).
        We copy the address of a VM in the other security group, and modify
        outgoing traffic on spoofing vm to have the ip of spoofed_vm.
        We set tcpdump running on target_vm, attempt to ping it and check if
        any packets are received, and as a sanity test, we attempt the same
        thing with neighbor vm and check it can connect.
        """
        # Change ip to that of the VM we are spoofing
        spoofed_ip = self.spoofed_vm.get_ip_addr().format()
        self.spoofing_vm.execute("sudo ip addr add %s/32 dev eth0" % spoofed_ip)

        # Set up receiver to monitor if it receives pings, and then start pings
        self.run_tcpdump(self.target_vm, 20)
        target_ip = self.target_vm.get_ip_addr().format()
        # Without the next line, the ping can succeed before tcpdump is
        # watching, causing test to fail.
        time.sleep(5)
        self.assert_can_ping(self.neighbor_vm, target_ip)
        self.spoofing_vm.execute("ping -c 1 -I %s %s" % (spoofed_ip, target_ip))

        # Wait for tcpdump to output, then check if results are as expected,
        # the spoofed ping did not get through and the non-spoofed ping got
        # through and had a response
        time.sleep(20)
        self.assertEqual(
            self.check_tcpdump_file(self.target_vm, spoofed_ip),
            0,
            msg="Test Failure - spoof packets seen at target!",
        )
        neighbor_ip = self.neighbor_vm.get_ip_addr().format()
        self.assertEqual(
            self.check_tcpdump_file(self.target_vm, neighbor_ip),
            2,
            msg="Test Failure - neighbour could not ping target",
        )
        # Leave the VM the way we found it.

        self.spoofing_vm.execute("sudo ip addr del %s/32 dev eth0" % spoofed_ip)

    def test_ip6_spoofing_assigned(self):
        """
        Test if we can get away with ip spoofing using an IP assigned on the
        guest interface.
        We have two security groups, and attempt to get one VM to ping a VM
        in a different security group (which it should not be able to).
        We copy the address of a VM in the other security group, and modify
        outgoing traffic on spoofing vm to have the ip of spoofed_vm.
        We set tcpdump running on target_vm, attempt to ping it and check if
        any packets are received, and as a sanity test, we attempt the same
        thing with neighbor vm and check it can connect.
        """

        # Change ip to that of the VM we are spoofing
        spoofed_ip = self.spoofed_vm.get_ip_addr(version=6).format()
        self.spoofing_vm.execute("sudo ip -6 addr add %s/128 dev eth0" % spoofed_ip)

        # Set up receiver to monitor if it receives pings, and then start pings
        self.run_tcpdump(self.target_vm, 20)
        target_ip = self.target_vm.get_ip_addr(version=6).format()
        # Without the next line, the ping can succeed before tcpdump is
        # watching, causing test to fail.
        time.sleep(5)
        # Ping 10 times to ensure that packet loss doesn't cause
        # spurious failures
        for _ in range(10):
            self.assert_can_ping(self.neighbor_vm, target_ip)
        # And now wait until the tcpdump has finished and check that the
        # tcpdump file shows that some packets got through
        neighbor_ip = self.neighbor_vm.get_ip_addr(version=6).format()
        # We need to do this repeatedly for a while because the tcpdump
        # file gets buffered and this check fails until it is written.
        retry_until_success(
            self.check_neighbor_got_through, retries=15, function_args=(neighbor_ip,)
        )

        # Now try again with the spoofing VM
        self.run_tcpdump(self.target_vm, 20)
        time.sleep(5)
        # This command sends 10 pings to avoid packet loss giving us
        # false positives.
        self.spoofing_vm.execute("ping6 -c 10 -I %s %s" % (spoofed_ip, target_ip))

        # Wait for tcpdump to output, then check that the spoofed packets
        # didn't get through
        # We do this in a loop repeatedly just in case the tcpdump
        # file has been buffered...
        for _ in range(15):
            self.check_spoof_not_got_through(spoofed_ip)
            time.sleep(1)

        # Leave the VM the way we found it.
        self.spoofing_vm.execute("sudo ip addr del %s/128 dev eth0" % spoofed_ip)

    def check_neighbor_got_through(self, neighbor_ip):
        self.assertTrue(
            self.check_tcpdump_file(self.target_vm, neighbor_ip) >= 2,
            msg="Test Failure - neighbour could not ping target",
        )

    def check_spoof_not_got_through(self, spoofed_ip):
        self.assertEqual(
            self.check_tcpdump_file(self.target_vm, spoofed_ip),
            0,
            msg="Test Failure - spoof packets seen at target!",
        )

    def test_udp_spoofing(self):
        """
        Test that a VM cannot inject packets into a UDP stream set up by
        another VM on the same host.

        To set up a UDP session (as far as conntrack is concerned), we need to have
        sent a UDP packet to a port and had a UDP packet in reply from that port.
        See http://www.iptables.info/en/connection-state.html

        We could set up a pretend UDP service on the target VM with nc,
        but we don't have to because our IPV6 images already have
        asterisk (a SIP server) installed on them (as used in
        test_applications.py).

        What we're doing here is crafting a SIP OPTIONS request by
        putting text into a file. We later cat that file into a UDP
        packet and send it to the Asterisk server on the target, which
        replies and bingo - we have a UDP connection.

        A SIP OPTIONS request is a SIP message between 2 peers asking
        about what SIP options the other end supports. It has the side
        effect of telling you that the other end is up and working and
        that you have network connectivity in both directions - like
        a SIP version of ping - which is what it often gets used for.
        https://www.packetizer.com/in/q122.html

        :return: None.
        """
        # Note that this test uses the *neighbor* VM as the spoofed VM.
        # In this test we need it to be running Ubuntu and we don't
        # have space on the test hosts for the spoofed VM to also run
        # Ubuntu (it runs cirros)
        spoofed_ip = self.neighbor_vm.get_ip_addr().format()
        target_ip = self.target_vm.get_ip_addr().format()

        # Add the spoofed IP to eth0 on the spoofing VM
        self.spoofing_vm.execute("sudo ip addr add %s/32 dev eth0" % spoofed_ip)

        # Assemble a SIP OPTIONS request file on both source VMs
        make_options_file = (
            "cat >> options.txt <<EOF\n"
            "OPTIONS sip:1234@{dest}:5060 SIP/2.0\n"
            "Via: SIP/2.0/UDP {source}:5061;"
            "branch=z9hG4bK.5457a176;rport;alias\n"
            "From: sip:sipsak@{source}:5061;tag=7a0027fb\n"
            "To: sip:1234@{dest}:5060\n"
            "Call-ID: 2046830587@{source}\n"
            "CSeq: 1 OPTIONS\n"
            "Contact: sip:sipsak@{source}:5061\n"
            "Content-Length: 0\n"
            "Max-Forwards: 70\n"
            "User-Agent: sipsak 0.9.6\n"
            "Accept: text/plain\n"
            "EOF\n"
        ).format(source=spoofed_ip, dest=target_ip)
        self.neighbor_vm.execute(make_options_file)
        self.spoofing_vm.execute(make_options_file)

        # These commands send on port 5061 because asterisk is already
        # running on 5060 of our ubuntu VMs.
        send_cmd = (
            "cat options.txt | "
            "nc -w 1 -u -p 5061 -s {source} {dest} 5060 "
            "2>&1 & disown".format(source=spoofed_ip, dest=target_ip)
        )

        # Set up receiver to monitor if it receives pings (timing out
        # after 20 seconds) and then start sending packets.
        self.run_tcpdump(self.target_vm, 20, proto="port 5060")
        # Without the next line, the send can succeed before tcpdump is
        # watching, causing test to fail.
        time.sleep(5)
        # Send packets from the spoofed VM (which sets up a conntrack rule)
        self.neighbor_vm.execute(send_cmd)
        # Attempt to send packets from the spoofing VM
        self.spoofing_vm.execute(send_cmd)
        # Wait for tcpdump to output, then check if results are as expected,
        # the spoofed ping did not get through and the non-spoofed ping got
        # through and had a response
        time.sleep(20)
        # If it all worked, we should only see 2 packets on the target -
        # to and from the original VM (and none from the spoofing VM)
        num_packets = self.check_tcpdump_file(self.target_vm, spoofed_ip)
        self.assertEqual(
            num_packets,
            2,
            msg="Test Failure - saw %s packets at target - expected exactly 2."
            % num_packets,
        )

        # Leave the VM the way we found it.
        self.spoofing_vm.execute("sudo ip addr del %s/32 dev eth0" % spoofed_ip)

    @classmethod
    def run_tcpdump(cls, vm, run_time, proto="icmp or icmp6"):
        """
        This will run tcpdump on the selected VM, filtering to output
        any pings from the given IP to file.  It runs for a set amount
        of time and then quits (in order that it writes to file at a
        known time rather than keeping output in buffer).
        :param vm:
        :param run_time: The time in seconds to run tcpdump for
        :param proto: protocol string to pass to tcpdump
        :return:
        """
        # Flags on this command set snooping on any interface (-i any),
        # suppressing some protocol info (-q), using IPs rather than
        # FQDNs (-n), don't buffer the output (-l)
        command = "sudo timeout %s tcpdump -qnl -i any %s > %s 2>&1 & disown" % (
            run_time,
            proto,
            cls.TCPDUMP_FILE_NAME,
        )
        vm.execute(command)

    @classmethod
    def check_tcpdump_file(cls, vm, ip_addr):
        """
        Looks at the output of a previous tcpdump run and returns
        the number of packets seen to/from ip_addr.
        :return:
        """
        _log.info("looking for ip %s in tcpdump file" % ip_addr)

        # Look for the IP address followed by a space, a colon or a dot, so as not to
        # accidentally match a different IP address that has `ip_addr` as a prefix.  For
        # example, "10.28.1.25" when we are looking for "10.28.1.2".  Here's an example
        # of the tcpdump output that we are grepping in:
        #
        # 11:23:44.349027 IP 10.28.3.140 > 10.28.1.25: ICMP echo request, id 1612, ...
        # 11:23:44.349199 IP 10.28.1.25 > 10.28.3.140: ICMP echo reply, id 1612, ...
        #
        # Following dot is needed for the UDP case, which looks like this:
        #
        # 11:25:52.858695 IP 10.28.3.140.5061 > 10.28.1.25.5060: UDP, length 351
        # 11:25:52.861021 IP 10.28.1.25.5060 > 10.28.3.140.5061: UDP, length 488
        command = "grep '%s[ :.]' %s | wc -l" % (ip_addr, cls.TCPDUMP_FILE_NAME)
        result = vm.execute(command)
        _log.debug("check_tcpdump_file output: %s ", result)
        _log.debug(
            "Full tcpdump file: %s", vm.execute("cat %s" % cls.TCPDUMP_FILE_NAME).stdout
        )
        _log.info("found %s instances in tcpdump file" % int(result.stdout))
        return int(result.stdout)
