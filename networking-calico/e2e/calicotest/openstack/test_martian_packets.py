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
import time

import netaddr

from calicotest.openstack.config import LAYOUT
from calicotest.settings import SCAPY_DPKG_PATH, SEND_PACKET_SCRIPT
from calicotest.openstack.topology import TopologyTwoUbuntuVms

_log = logging.getLogger(__name__)


class TestMartianPackets(TopologyTwoUbuntuVms):
    @classmethod
    def setUpClass(cls):
        super(TestMartianPackets, cls).setUpClass()
        cls.source_vm = cls.vms[0]
        cls.target_vm = cls.vms[1]

        # Turn off RPF on compute hosts (so that we're testing our rules,
        # not the kernel's own)
        for node in LAYOUT.compute_nodes:
            node.execute("sudo sysctl net.ipv4.conf.all.rp_filter=0")
            node.execute("sudo sysctl net.ipv4.conf.default.rp_filter=0")

        _log.info("Installing Scapy on Ubuntu VM")
        cls.source_vm.install_dpkg_from_test_rig(SCAPY_DPKG_PATH)
        _log.info("Setting up tcpdump on receiving vm")
        cls.output_file_name = "snoop.cap"
        cls.target_vm.set_up_tcpdump(cls.output_file_name)
        _log.info("Copying across scapy scripts")
        cls.packet_script_path = "send_packets.py"
        cls.source_vm.ssh.send_file(SEND_PACKET_SCRIPT, cls.packet_script_path)

    @classmethod
    def tearDownClass(cls):
        # Turn RPF back on on compute hosts
        for node in LAYOUT.compute_nodes:
            node.execute("sudo sysctl net.ipv4.conf.all.rp_filter=1")
            node.execute("sudo sysctl net.ipv4.conf.default.rp_filter=1")
        super(TestMartianPackets, cls).tearDownClass()

    def test_packets_arriving(self):
        """
        Test that packets sent with Martian source IPs don't arrive at a VM,
        but check that standard ping connectivity does still work
        """
        # A list of packets with dubious sources - these were taken from
        # https://en.wikipedia.org/wiki/Martian_packet

        martians = [
            netaddr.IPNetwork("0.0.0.0/8"),
            netaddr.IPNetwork("10.0.0.0/8"),
            netaddr.IPNetwork("100.64.0.0/10"),
            netaddr.IPNetwork("127.0.0.0/8"),
            netaddr.IPNetwork("169.254.0.0/16"),
            netaddr.IPNetwork("172.16.0.0/12"),
            netaddr.IPNetwork("192.0.0.0/24"),
            netaddr.IPNetwork("192.0.2.0/24"),
            netaddr.IPNetwork("192.168.0.0/16"),
            netaddr.IPNetwork("198.18.0.0/15"),
            netaddr.IPNetwork("198.51.100.0/24"),
            netaddr.IPNetwork("203.0.113.0/24"),
            netaddr.IPNetwork("224.0.0.0/4"),
            netaddr.IPNetwork("240.0.0.0/4"),
            netaddr.IPNetwork("255.255.255.255/32"),
        ]

        # Test the endpoints of each subnetwork plus a random member
        ips_to_test = [
            ip
            for subnet in martians
            for ip in [subnet[0], subnet[-1], random.choice(subnet)]
        ]

        target_ip = str(self.target_vm.get_ip_addr())
        source_ip = str(self.source_vm.get_ip_addr())
        martian_id_string = "MartianPacketsArriving"
        id_string = "PingPacketsArriving"

        _log.info("Sending packets with Martian source ips")
        # In both cases we send as the payload the relevant ID string,
        # followed by the source IP we are using
        for ip in ips_to_test:
            self.source_vm.execute(
                "sudo python "
                + self.packet_script_path
                + " "
                + str(ip)
                + " "
                + target_ip
                + " "
                + martian_id_string
                + str(ip)
            )
        self.source_vm.execute(
            "sudo python "
            + self.packet_script_path
            + " "
            + source_ip
            + " "
            + target_ip
            + " "
            + id_string
            + source_ip
        )

        _log.info("Sleep for two seconds to allow tcpdump to process")
        time.sleep(2)
        _log.info("Checking that packets arrived/didn't arrive as expected")
        self.assertFalse(
            self.target_vm.packet_received(martian_id_string),
            "Martian packets arrived at destination, from the following IPs:"
            + str(self.target_vm.packet_ids_received(martian_id_string)),
        )
        self.assertTrue(
            self.target_vm.packet_received(id_string),
            "Standard ping packet failed to reach VM",
        )
