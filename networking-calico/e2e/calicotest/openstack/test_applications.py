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
from subprocess import check_call
from urllib.request import urlopen

from calicotest.common.osutils import check_dependency
from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology
from calicotest.settings import IPV6_WITH_APPS

_log = logging.getLogger(__name__)


class TestApplications(Topology):
    """
    Test generally sane behavior of network by running client applications on
    VM instances.
    """

    @classmethod
    def setUpClass(cls):
        super(TestApplications, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        # Setup a VM using an image with our applications installed

        # Set up a security group and add rules so we can ping and log in
        cls.GROUPNAME = "application"
        cls.security_group = cls.create_security_group(cls.GROUPNAME)
        cls.add_ssh_rule(cls.GROUPNAME)
        cls.add_group_ping_rule(cls.GROUPNAME)

        # Add rules for http and SIP to the VM
        cls.add_rule(cls.GROUPNAME, "tcp", 80, 80, cls.my_ipv4 + "/32")
        cls.add_rule(cls.GROUPNAME, "udp", 5060, 5060, cls.my_ipv4 + "/32")

        # These tests assume the OpenStack deployment has the IPv6 image
        # installed, and that this image has Asterisk and Apache configured
        # on it.
        cls.node = LAYOUT.compute_nodes[0]
        cls.vm = cls.create_vm(
            availability_zone=cls.zonify(cls.node),
            image=IPV6_WITH_APPS,
            security_groups=cls.GROUPNAME,
        )
        cls.vm_ip = cls.vm.get_ip_addr(4)

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        cls.delete_vm(cls.vm.name)

        # Deleting the VM should cause all its conntrack entries to be cleaned
        # up by felix.
        cls._assert_conntrack_entries_not_present()

        neutron = cls.controller.tenants["admin"].neutron
        retry_until_success(
            functools.partial(neutron.delete_security_group, cls.security_group["id"]),
            retries=30,
            context_string="TestApplications.tearDownClass",
        )
        super(TestApplications, cls).tearDownClass()

    def test_web_server(self):
        """
        Test that web server can send and receive requests over Calico network.

        Apache2 is installed on the VM, this test GETs the default page.
        """
        vm_ip = self.vm.get_ip_addr(4)
        check = functools.partial(urlopen, "http://%s" % vm_ip)
        retry_until_success(
            check, retries=60, context_string="TestApplications.test_web_server"
        )
        # Contacting the VM should generate conntrack entries.
        self._assert_conntrack_entries_present()

    def test_sip_ping(self):
        """
        Tests UDP to and from a VM, by sending an OPTIONS message to the VoIP
        server as a crude SIP 'ping'.

        Asterisk is installed on the test image.  Extension 1234 is configured
        to respond to an OPTIONS request.

        Requires that sipsak be installed on the machine running the tests
        (install with 'apt-get install sipsak')
        """
        check_dependency("sipsak")

        vm_ip = self.vm.get_ip_addr(4)
        command = "sipsak -s sip:1234@%s:5060" % vm_ip
        check = functools.partial(check_call, command, shell=True)
        retry_until_success(
            check, retries=60, context_string="TestApplications.test_sip_ping"
        )
        # Contacting the VM should generate conntrack entries.
        self._assert_conntrack_entries_present()

    @classmethod
    def _assert_conntrack_entries_present(cls):
        rc, stdout, stderr = cls.node.execute("sudo conntrack -L | grep %s" % cls.vm_ip)
        assert str(cls.vm_ip) in stdout

    @classmethod
    def _assert_conntrack_entries_not_present(cls):
        def check_conntrack_removed():
            rc, stdout, stderr = cls.node.execute(
                "sudo conntrack -L | grep %s" % cls.vm_ip
            )
            assert str(cls.vm_ip) not in stdout

        # Check the entries are gone.
        retry_until_success(
            check_conntrack_removed,
            retries=10,
            context_string="TestApplications.tearDownClass",
        )
