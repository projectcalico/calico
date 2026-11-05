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

from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology
from calicotest.settings import (
    IPV4_ONLY,
    IPV6_WITH_APPS,
    IPV_BOTH,
)

_log = logging.getLogger(__name__)


class TestIpv4(Topology):
    """
    Set up a simple IPv4-only network with inter- and intra-host connectivity.
    """

    @classmethod
    def setUpClass(cls):
        super(TestIpv4, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        cls.vms = []

        cls.create_network(IPV4_ONLY.name, cidr=IPV4_ONLY.cidr)

        vm_threads = []
        for node in LAYOUT.compute_nodes:
            vm_threads.append(
                cls.create_vm_parallel(
                    availability_zone=node, networks=[IPV4_ONLY.name]
                )
            )
        node = LAYOUT.compute_nodes[0]
        vm_threads.append(
            cls.create_vm_parallel(availability_zone=node, networks=[IPV4_ONLY.name])
        )

        for vm_thread in vm_threads:
            cls.vms.append(vm_thread.join())

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in cls.vms:
            cls.delete_vm(vm.name)
        retry_until_success(
            functools.partial(cls.delete_network, IPV4_ONLY.name),
            context_string="TestIpv4.tearDownClass",
        )
        super(TestIpv4, cls).tearDownClass()

    def test_ipv4_only(self):
        """
        Test that Calico can run on an IPv4-only network.
        """
        self.check_mutual_connectivity(self.vms, ipv4=True, ipv6=False)


class TestIpvBoth(Topology):
    """
    Set up a simple IPv4+IPv6 network with inter- and intra-host connectivity.
    """

    @classmethod
    def setUpClass(cls):
        super(TestIpvBoth, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)

        cls.create_network(IPV_BOTH.name, cidr=IPV_BOTH.cidr, cidr_v6=IPV_BOTH.cidr_v6)

        cls.vms = []

        # Check both inter-node and intra-node connectivity.
        _log.info("Creating VMs with IPv4 and IPv6 networking")
        vm_threads = []
        for node in LAYOUT.compute_nodes:
            vm_threads.append(
                cls.create_vm_parallel(
                    availability_zone=node,
                    image=IPV6_WITH_APPS,
                    networks=[IPV_BOTH.name],
                )
            )
        node = LAYOUT.compute_nodes[0]
        vm_threads.append(
            cls.create_vm_parallel(
                availability_zone=node, image=IPV6_WITH_APPS, networks=[IPV_BOTH.name]
            )
        )

        for vm_thread in vm_threads:
            cls.vms.append(vm_thread.join())

        # It can take a while for the VM to be ready to connect.  Keep trying
        # until all VMs are connected.
        _log.info("Connect SSH sessions to VMs using IPv4 and IPv6")
        retry_until_success(
            cls._connect_vm_ssh, retries=5, context_string="TestIpvBoth.setUpClass"
        )

    @classmethod
    def _connect_vm_ssh(cls):
        """
        Connect to the VMs over SSH.

        If a VM is already connected, the connection is a no-op, so this method
        can be called multiple times.
        """
        for vm in cls.vms:
            vm.connect()

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in cls.vms:
            cls.delete_vm(vm.name)
        retry_until_success(
            functools.partial(cls.delete_network, IPV_BOTH.name),
            context_string="TestIpvBoth.tearDownClass",
        )
        super(TestIpvBoth, cls).tearDownClass()

    def test_ipv4_and_ipv6(self):
        """Check mainline connectivity of both IPv4 and IPv6 networking."""
        _log.info("Test IPv4 and IPv6 connectivity between VMs")
        self.check_mutual_connectivity(self.vms, ipv4=True, ipv6=True)
