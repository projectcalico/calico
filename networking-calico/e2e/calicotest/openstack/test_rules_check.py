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
import random
import struct
import time

from scapy.all import conf, ICMP, IP, Raw, send, sr1, TCP, UDP
from scapy.layers.inet import in4_chksum

from calicotest.common.testutils import retry_until_success
from calicotest.openstack.topology import TopologyUbuntuVm

_log = logging.getLogger(__name__)


class TestRules(TopologyUbuntuVm):
    @classmethod
    def setUpClass(cls):
        # Set up a background process on a target vm recording incoming
        # packets, then wait a bit for this to get started
        # We increase rule quotas as we will be creating lots of rules
        super(TestRules, cls).setUpClass()
        cls.controller.update_neutron_quota(security_group_rule=30)
        cls.controller.update_nova_quota(security_group_rules=30)
        cls.target_vm = cls.ubuntu_vm
        cls.target_ip = str(cls.target_vm.get_ip_addr())
        # This file will be a running output of all packets received on this
        # vm from the ip the test suite is running on
        cls.output_file = "TestRulesTcpdump.txt"
        # -A means we should get the payloads included in the file
        cls.target_vm.execute(
            "sudo tcpdump -Al -i "
            "any src {source_ip} > {output_file} "
            "2>&1 & disown".format(source_ip=cls.my_ipv4, output_file=cls.output_file)
        )
        # Wait for tcpdump to be ready to catch packets
        time.sleep(5)
        # Resynch scapy's routing. If the testing node is using bird, the
        # routes will have changed, and scapy's routes will not be current.
        conf.route.resync()

    def setUp(self):
        super(TestRules, self).setUp()

        # Needed due to conntrack bug which causes test_established_connection
        # to fail - we are waiting long enough such previous ICMP connections
        # are no longer viewed as established - this was causing this test
        # to fail when run the previous test had (and then deleted) a relevant
        # security rule
        # This sleep can be removed when test_established_connection passes
        _log.info("Sleeping for 30s to allow connection to no longer be established")
        time.sleep(30)

    def test_wildcard_protocol_rule(self):
        """
        Send IPv4 packets, each one claiming to contain a different protocol,
        and check that none of them reach the VM.  Then add a wildcard security
        rule allowing all protocols, and resend the packets, checking that this
        time they arrive.
        """
        # TODO This fails if protocol rules failed and left rules in SG.
        # Need to remove in teardown. (Same for all other tests in this class)

        allowed_protocols = []
        blocked_protocols = list(range(0, 256))
        id_string = "FvWildcardRule"

        _log.info("Checking no protocols can reach %s", self.target_vm.name)
        self.check_protocol_connectivity(
            self.target_vm, allowed_protocols, blocked_protocols, id_string
        )

        _log.info(
            "Adding wildcard rule to allow all protocols to be sent from"
            " this machine to %s",
            self.target_vm.name,
        )
        self.add_rule(self.UBUNTU_GROUPNAME, cidr=self.my_ipv4 + "/32")
        allowed_protocols = list(range(0, 255))
        # Remove SCTP (132) and UDPlite (136): our packets for these carry no valid
        # protocol header, and on Ubuntu they get dropped (whereas GRE packets,
        # equally header-less, get through).
        allowed_protocols.remove(132)
        allowed_protocols.remove(136)
        # remove ICMPv6 (58), as it doesn't make sense as an IPv4
        # packet, and gets dropped by our rule for ctstate invalid.
        allowed_protocols.remove(58)

        blocked_protocols = ()

        _log.info("Checking that all packets got through as expected")
        self.check_protocol_connectivity(
            self.target_vm, allowed_protocols, blocked_protocols, id_string
        )

        _log.info("Removing wildcard rule")
        self.delete_rule(self.UBUNTU_GROUPNAME, cidr=self.my_ipv4 + "/32")

    def test_protocol_rules(self):
        """
        We randomly pick a certain subset of protocols to be allowed to a VM,
        and check that these and only these get through after adding the
        appropriate security group rule
        """
        # TODO work out how to send valid GRE and UDPlite packets.

        # These are the IPv4 protocols that had names in Neutron's security group API
        # in Pike.  We used to test all of 1-255, but in Pike that API rejected rules
        # for protocol numbers without names, such as 4 (IP-in-IP), so we cut the test
        # down to the named ones.  Neutron has accepted any protocol number since Queens
        # (and the fix was backported to Pike), but we still test only these protocols.
        # See https://bugs.launchpad.net/neutron/+bug/1716045.
        blocked_protocols = [1, 2, 6, 8, 17, 33, 46, 47, 50, 51, 89, 112, 113, 132, 136]

        # Remove SCTP (132) and UDPlite (136): our packets for these carry no valid
        # protocol header, and on Ubuntu they get dropped even when allowed.
        blocked_protocols.remove(132)
        blocked_protocols.remove(136)

        allowed_protocols = []
        id_string = "FvProtocolRules"

        _log.info("Adding rules for random set of protocols")
        for _ in range(0, 10):
            protocol = random.choice(blocked_protocols)
            _log.info("Adding rule allowing protocol %s", protocol)
            self.add_rule(
                self.UBUNTU_GROUPNAME, proto=str(protocol), cidr=self.my_ipv4 + "/32"
            )
            blocked_protocols.remove(protocol)
            allowed_protocols.append(protocol)

        _log.info("Checking only allowed protocols can reach the VM")
        self.check_protocol_connectivity(
            self.target_vm, allowed_protocols, blocked_protocols, id_string
        )

        _log.info("Cleaning up by deleting all protocol rules")
        for protocol in allowed_protocols:
            _log.debug("Deleting rule for protocol %s", protocol)
            self.delete_rule(
                self.UBUNTU_GROUPNAME, proto=str(protocol), cidr=self.my_ipv4 + "/32"
            )

    def test_port_rules(self):
        """
        Sets up rules for filtering tcp and udp packets based on port numbers,
        and then tests packets within this range and around that range reach/
        don't reach the VM as expected
        """

        # Note the port 22 will always be open, for sshing, so avoid testing it
        test_range = random.randint(1, 10)
        rule_range = random.randint(0, 10)
        port_min = random.randint(22 + test_range + 1, 65535 - test_range - rule_range)
        port_max = port_min + rule_range
        allowed_ports = list(range(port_min, port_max + 1))
        blocked_ports = list(range(port_min - test_range, port_min)) + list(
            range(port_max + 1, port_max + test_range)
        )

        id_string = "FVport"

        _log.info(
            "Adding security rules for tcp and udp for ports {min} to {max}".format(
                min=port_min, max=port_max
            )
        )
        self.add_rule(
            self.UBUNTU_GROUPNAME, "udp", port_min, port_max, self.my_ipv4 + "/32"
        )
        self.add_rule(
            self.UBUNTU_GROUPNAME, "tcp", port_min, port_max, self.my_ipv4 + "/32"
        )

        _log.info(
            "Sending packets for each port from {first_port} to {last_port}".format(
                first_port=blocked_ports[0], last_port=blocked_ports[-1]
            )
        )
        packets = []
        allowed_ids = []
        blocked_ids = []
        for port in allowed_ports + blocked_ports:
            id_udp = id_string + "udp" + str(port)
            packets.append(
                IP(proto="udp", dst=self.target_ip) / UDP(dport=port) / id_udp
            )
            id_tcp = id_string + "tcp" + str(port)
            packets.append(
                IP(proto="tcp", dst=self.target_ip) / TCP(dport=port) / id_tcp
            )
            if port in allowed_ports:
                allowed_ids.extend([id_udp, id_tcp])
            if port in blocked_ports:
                blocked_ports.extend(([id_udp, id_tcp]))
        send(packets)

        _log.info("Checking that precisely the expected packets reached the VM")
        retry_until_success(
            self.check_packets_arrived,
            function_args=[allowed_ids, blocked_ids, self.target_vm, self.output_file],
            retries=30,
        )

        _log.info("Removing the port rules")
        self.delete_rule(
            self.UBUNTU_GROUPNAME, "udp", port_min, port_max, self.my_ipv4 + "/32"
        )
        self.delete_rule(
            self.UBUNTU_GROUPNAME, "tcp", port_min, port_max, self.my_ipv4 + "/32"
        )

    def test_icmp_filtering(self):
        """
        We check that we can filter on ICMP types using security rules.
        Note this only performs a test on a very limited subset of ICMP types -
        the rest get rejected in naive tests for being invalid (e.g. you can't
        just send an echo reply, unless you have already received an echo
        request)
        """
        # Needed due to conntrack bug which causes test_established_connection
        # to fail - we are waiting long enough such previous ICMP connections
        # are no longer viewed as established - this was causing this test
        # to fail when run the previous test had (and then deleted) a relevant
        # security rule
        # This sleep can be removed when test_established_connection passes

        _log.info("Sleeping for 30s to allow connection to no longer be established")
        time.sleep(30)

        # These are the only types we can easily test
        icmp_types = [8, 13, 15, 17]
        icmp_success_type = random.choice(icmp_types)
        id_string = "ICMPtest"

        _log.info(
            "Adding rule allowing ICMP type {type}".format(type=icmp_success_type)
        )
        self.add_rule(
            self.UBUNTU_GROUPNAME, "icmp", icmp_success_type, cidr=self.my_ipv4 + "/32"
        )
        # Allow time for Felix to propagate rule before testing
        time.sleep(2)

        _log.info("Sending packets testing ICMP rule")
        packets = []
        allowed_ids = []
        blocked_ids = []
        for icmp_type in icmp_types:
            type_string = id_string + "type" + str(icmp_type)
            if icmp_type == icmp_success_type:
                allowed_ids.append(type_string)
            else:
                blocked_ids.append(type_string)
            packets.append(IP(dst=self.target_ip) / ICMP(type=icmp_type) / type_string)
        send(packets)

        # Allow time for Felix to propagate rules before testing
        time.sleep(2)
        _log.info("Checking that precisely the expected packets reached the VM")
        retry_until_success(
            self.check_packets_arrived,
            function_args=[allowed_ids, blocked_ids, self.target_vm, self.output_file],
            retries=30,
        )

        _log.info("Deleting ICMP rule")
        self.delete_rule(
            self.UBUNTU_GROUPNAME, "icmp", icmp_success_type, cidr=self.my_ipv4 + "/32"
        )

    def check_protocol_connectivity(self, target_vm, successes, failures, id_string):
        """
        Asserts that IP packets containing the protocols defined in
        successes can be sent from the machine running this script to the
        target_vm, and that those in failures cannot
        :param target_vm: The vm we will send packets to
        :param successes: An iterable containing protocol numbers that are
                          allowed to reach the target vm
        :param failures: An iterable containing protocol numbers that aren't
                         allowed to reach the target vm
        :param id_string: Used to identify packets being sent - if multiple
                          tests are run on the same vm then this should be
                          different each time.
        """
        # Allow time for Felix to propagate rules before testing
        time.sleep(2)

        packets = self.return_packet_per_protocol(id_string, self.target_ip)

        # IP is generally unreliable, and we occasionally see this test class
        # failing and claiming that a particular packet did not get through.
        # Send multiple times to be more sure.
        for _ in range(20):
            _log.info("Sending packets")
            send(packets)

        def check_packets_arrived():
            _log.info("(re)Checking if the expected packets got through")
            all_ok = True
            bad_msg = ""
            for protocol in successes:
                if not self.packet_received(
                    target_vm, self.output_file, id_string + str(protocol)
                ):
                    all_ok = False
                    bad_msg = bad_msg + " -" + str(protocol)
                    _log.warning(
                        "Packet of protocol {protocol} not received on {vm} "
                        "as expected".format(protocol=protocol, vm=target_vm.name)
                    )
            for protocol in failures:
                if self.packet_received(
                    target_vm, self.output_file, id_string + str(protocol)
                ):
                    all_ok = False
                    bad_msg = bad_msg + " +" + str(protocol)
                    _log.warning(
                        "Packet of protocol {protocol} received on {vm} "
                        "but should not have been".format(
                            protocol=protocol, vm=target_vm.name
                        )
                    )
            self.assertTrue(all_ok, "Wrongly handled protocols:" + bad_msg)

        # Note: it does not make sense to call check_packets_arrived more than
        # once here; all it does is grep through a file.
        check_packets_arrived()
        _log.info("All protocol packets arrived or got blocked as expected")

    def packet_received(self, vm, file_name, id_string):
        """
        Checks on the given vm if a file contains details of a packet,
        searching for id_string which was in included in the packet payload.
        """
        # Dollar matches end of line, to differentiate between 1 and 11 say
        _log.info("Checking if packet was received")
        return_code = vm.execute(
            "grep '{id_string}$' {file}".format(file=file_name, id_string=id_string)
        ).return_code
        # A return of 0 means that grep successfully found the id_string
        return return_code == 0

    def can_ping(self, ip, timeout=2):
        """
        Sends a ping request to the given IP and returns True if we receive a
        response in the number of seconds given by timeout, False otherwise
        """
        # ICMP type 8 is ping
        _log.debug("Sending ping request to %s", str(ip))
        ping = IP(dst=ip) / ICMP(type=8)
        response = sr1(ping, timeout=timeout)
        if response:
            _log.debug("Can ping {ip}".format(ip=ip))
            return True
        _log.debug("Cannot ping {ip}".format(ip=ip))
        return False

    def check_packets_arrived(self, allowed_ids, blocked_ids, target_vm, output_file):
        """
        SSHs into the target vm
        Looks in the given filename, which should be outputting packets
        from tcpdump and checks that the strings in success_ids are present
        (e.g. in the payload of the packets) and that the strings in
        fail_ids are not
        """
        _log.info("(re)Checking if the expected packets got through")
        for cur_id in allowed_ids:
            self.assertTrue(
                self.packet_received(target_vm, output_file, cur_id),
                "Packet with id {id} not received on {vm} as expected".format(
                    id=cur_id, vm=target_vm.name
                ),
            )
        for cur_id in blocked_ids:
            self.assertFalse(
                self.packet_received(target_vm, output_file, cur_id),
                "Packet with id {id} received on {vm} but should not have".format(
                    id=cur_id, vm=target_vm.name
                ),
            )

    def return_packet_per_protocol(self, id_string, target_ip):
        """
        Returns one IPv4 packet per IPv4 protocol.  ICMP, TCP and UDP have
        the corresponding layer 2 packet inside.  All will be addressed to the
        target_ip, and have the id_string in the payload
        :param id_string: A string to identify these packets
        :param target_ip: The IP to address the packets to
        """
        packets = []

        for protocol in range(0, 256):
            payload = id_string + str(protocol)
            packets.append(IP(proto=protocol, dst=str(target_ip)) / payload)
        # IP packets claiming to contain ICMP, TCP or UDP seemed to be getting
        # dropped if they had no payload, so add the layer 2 wrapper inside
        for protocol in (1, 6, 17):
            packets[protocol].remove_payload()
        packets[1] = packets[1] / ICMP() / (id_string + "1")
        packets[6] = packets[6] / TCP() / (id_string + "6")
        packets[17] = packets[17] / UDP() / (id_string + "17")

        # Kernels before 6.17 track DCCP, and conntrack marks a header-less DCCP packet
        # INVALID, which Felix then drops even when a rule allows it.  (DCCP has been
        # deprecated in Linux since 6.4 and was removed in 6.16, with the conntrack
        # support being removed in 6.17.)
        packets[33].remove_payload()
        packets[33] = packets[33] / Raw(dccp_request(packets[33], id_string + "33"))
        return packets


def dccp_request(ip, payload):
    """
    Returns a DCCP Request segment carrying payload, with a valid checksum for the
    given IP header.  (Scapy has no DCCP layer.)
    """

    # Ports, data offset (5 words), CCVal/CsCov, checksum, type Request with 48-bit
    # sequence numbers, reserved, sequence number, service code.
    segment = struct.pack(
        "!HHBBHBB6sI", 33333, 5001, 5, 0, 0, 0x01, 0, (1).to_bytes(6, "big"), 0
    )
    segment += payload.encode()
    checksum = in4_chksum(33, ip, segment)
    return segment[:6] + struct.pack("!H", checksum) + segment[8:]
