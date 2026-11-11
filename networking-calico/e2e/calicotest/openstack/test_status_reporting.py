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
from calicotest.openstack.basetest import LOGS_IGNORE_GR_EXPECTED_LOGS
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology
from calicotest.openstack.vm import VmErrorState, WrongState

_log = logging.getLogger(__name__)


class TestStatusReporting(Topology):
    """
    Test status reporting of calico per-host component (aka Felix).
    """

    IGNORE_LOGS_LIST = LOGS_IGNORE_GR_EXPECTED_LOGS + [
        "Failed to bind port",
    ]

    @classmethod
    def setUpClass(cls):
        super(TestStatusReporting, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        cls.vms = []

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        # make sure felix is running on all hosts
        for test_node in LAYOUT.compute_nodes:
            test_node.execute("sudo service calico-felix start")

        # clear out any left over VMs
        for vm in cls.vms:
            cls.delete_vm(vm.name)

        super(TestStatusReporting, cls).tearDownClass()

    def setUp(self):
        pass

    def test_felix_status_reporting(self):
        """
        Test felix service status is reported correctly and that VMs are not
        scheduled on compute hosts where Felix is not up.
        :return: None.
        """
        self.assert_felix_agent_up()

        # Stop felix on a compute host
        test_node = LAYOUT.compute_nodes[1]
        _log.info("Stopping felix on %s", test_node)
        test_node.execute("sudo service calico-felix stop")

        # Check that that felix is reported as down in a reasonable time
        _log.info("Wait up to 100s for felix to be reported DOWN")
        hostname = test_node.fqdn.split(".")[0]
        retry_until_success(
            self.check_service_status,
            retries=100,
            function_args=(hostname, "calico-felix", False),
        )

        _log.info("Check that VM creation fails on that node")
        # Attempt to schedule a VM on that compute host - check it
        # fails
        try:
            self.vms.append(self.create_vm(availability_zone=test_node))
        except (WrongState, VmErrorState):
            _log.info("Success - could not create VM when felix is down")
        else:
            msg = "Failed - could successfully create VM when felix is down"
            _log.info(msg)
            self.fail(msg)

        # Start felix again on the compute host
        _log.info("Restarting felix on %s", test_node)
        test_node.execute("sudo service calico-felix start")

        # Check felix service is reported as up within 30 seconds
        _log.info("Wait up to 30s for felix to be reported UP")
        retry_until_success(
            self.check_service_status,
            retries=30,
            function_args=(hostname, "calico-felix", True),
        )

        # Schedule a VM on that compute host - check it works and has
        # connectivity to other VMs
        _log.info("Attempting to create a VM now felix is back up")
        self.vms.append(self.create_vm(availability_zone=test_node))
        _log.info("Success - created VM")


class _TestEpStatusReportingBase(Topology):
    """
    Test status reporting of network endpoints.
    """

    IGNORE_LOGS_LIST = LOGS_IGNORE_GR_EXPECTED_LOGS + [
        "Marking the ports it was managing as in-error.",
        "Dummy iptables-restore, returning exit code 1",
        "Non-retryable iptables-restore failure. RC=1",
        "Non-retryable error from a combined batch",
        "FailedSystemCall('iptables-restore',",
        "Failed to bind port",
        "Failed to program chains",
        "iptables-restore failed",
    ]

    @classmethod
    def setUpClass(cls):
        super(_TestEpStatusReportingBase, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        # Pick a node to test on
        cls.test_node = LAYOUT.compute_nodes[1]
        cls.vms = []
        cls.vms.append(cls.create_vm(availability_zone=cls.test_node))
        cls.vms.append(cls.create_vm(availability_zone=cls.test_node))

        # Create another security group for the tests to use
        cls.groupname = "alternative_group"
        cls.security_group = cls.create_security_group(cls.groupname)
        cls.add_ssh_rule(cls.groupname)
        cls.add_group_ping_rule(cls.groupname)

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)

        # clear out any left over VMs
        for vm in cls.vms:
            cls.delete_vm(vm.name)

        # Delete the security group we created
        neutron = cls.controller.tenants["admin"].neutron
        retry_until_success(
            functools.partial(neutron.delete_security_group, cls.security_group["id"]),
            retries=30,
            context_string="TestApplications.tearDownClass",
        )

        super(_TestEpStatusReportingBase, cls).tearDownClass()

    def setUp(self):
        # Deliberately does not chain to the superclass, matching the
        # behaviour this method has always had.
        pass

    def tearDown(self):
        self.restart_felix_and_wait(self.test_node, waittime=0)

        # make sure felix is running on all hosts
        for node in LAYOUT.compute_nodes:
            _log.info("Ensuring calico-felix is started on %s", node)
            node.execute("sudo service calico-felix start")
        super(_TestEpStatusReportingBase, self).tearDown()

    @staticmethod
    def restart_felix_and_wait(host, waittime=40):
        _log.info("Restarting felix on host: %s", host)
        host.execute("sudo service calico-felix restart")
        _log.info(
            "Sleeping for %ss to allow Felix to complete startup processing",
            waittime,
        )
        time.sleep(waittime)

    def add_ip_to_port(self, port, subnet_id, ip=None):
        neutron = self.controller.tenants["admin"].neutron
        fixed_ips = port["fixed_ips"]
        if ip:
            fixed_ips.append({"subnet_id": subnet_id, "ip_address": ip})
        else:
            fixed_ips.append({"subnet_id": subnet_id})
        neutron.update_port(port["id"], {"port": {"fixed_ips": fixed_ips}})

    def get_subnet_id(self, port, ip):
        subnet_id = None
        for addr in port["fixed_ips"]:
            if addr["ip_address"] == ip:
                subnet_id = addr["subnet_id"]
                break

        # Check we actually found it
        assert subnet_id is not None, "Couldn't find an address with IP %s" % ip
        return subnet_id

    def change_port_admin_state(self, port, admin_up):
        """
        Changes the port's admin state.
        :param port: The neutron port object to modify
        :param admin_up: (boolean) Whether the port should be up.
        """
        neutron = self.controller.tenants["admin"].neutron
        neutron.update_port(port["id"], {"port": {"admin_state_up": admin_up}})


class TestEndpointStatusReporting(_TestEpStatusReportingBase):
    def test_ep_status_reporting(self):
        """
        Stop felix on the test_node, then check that the port status of a VM on
        that node stays ACTIVE.  Calico stopped marking ports in error when
        Felix goes down in v3.1.1: a Felix that is not running reports nothing,
        which must not be read as the port having failed.
        :return: None
        """

        # We want to find the port with the IP address of our VM.
        vm_ip = str(self.vms[0].get_ip_addr())
        self.check_port_status(vm_ip, "ACTIVE")
        _log.info("Port appears to be ACTIVE")

        # Great - so we have an active port.  Now we stop felix on the host and
        # check that the status stays ACTIVE rather than degrading to 'ERROR'.
        _log.info("Stopping felix on %s", self.test_node)
        self.test_node.execute("sudo service calico-felix stop")

        for _ in range(30):
            self.check_port_status(vm_ip, "ACTIVE")

        # Start felix again on the compute host
        _log.info("Restarting felix on %s", self.test_node)
        self.test_node.execute("sudo service calico-felix start")

        # And check that Felix coming back up leaves the port ACTIVE too, so
        # that a passing run means the status held throughout rather than
        # merely ending up right.
        _log.info("Check port is still reported ACTIVE")
        retry_until_success(self.check_port_status, function_args=(vm_ip, "ACTIVE"))
        _log.info("State == ACTIVE, Success!")

    def test_port_up_down(self):
        """
        Check that port status changes when the tap interface is down
        and that setting ports admin-down results in them actually being
        taken down.
        """
        self.take_port_up_down(restart_felix=False)

    def test_restart_port_up_down(self):
        """
        Check that port status changes when the tap interface is down after
        having restarted felix.  We had a bug previously where Felix would
        not report a port down if it had been up when felix started.
        """
        self.take_port_up_down(restart_felix=True)

    def take_port_up_down(self, restart_felix):
        my_vm = self.vms[0]
        test_vm = self.vms[1]
        # VM may have >1 port, but we don't care - just grab the first one
        vm_ip = str(my_vm.get_ip_addr_list()[0])

        # find the node that this VM lives on
        my_node = None
        for node in LAYOUT.compute_nodes:
            if my_vm.availability_zone.zoneName in node.fqdn:
                my_node = node
                break
        assert my_node is not None, "Couldn't find the host for VM %s" % my_vm

        _log.info("Check that VM port is currently ACTIVE")
        retry_until_success(self.check_port_status, function_args=(vm_ip, "ACTIVE"))

        if restart_felix:
            self.restart_felix_and_wait(my_node)

        # Take tap interface down
        tap_name = "tap%s" % self.get_port(vm_ip)["id"][0:11]
        status, stdout, stderr = my_node.execute("sudo ifconfig %s down" % tap_name)
        self.assertEqual(
            status,
            0,
            msg="Attempt to set interface %s down failed.  Stdout/stderr: [%s]/[%s]"
            % (tap_name, stdout, stderr),
        )

        # check port state is down in Neutron
        _log.info("Wait up to 10s for port to be reported as DOWN")
        retry_until_success(self.check_port_status, function_args=(vm_ip, "DOWN"))
        _log.info("State == DOWN, as expected")

        # Add an IP address to the VM interface
        vm_port = self.get_port(vm_ip)
        self.add_ip_to_port(vm_port, self.get_subnet_id(vm_port, vm_ip))

        # Bring port up
        my_node.execute("sudo ifconfig %s up" % tap_name)
        self.assertEqual(
            status,
            0,
            msg="Attempt to set interface %s up failed.  Stdout/stderr: [%s]/[%s]"
            % (tap_name, stdout, stderr),
        )

        # Check port is up and new IP is added.
        _log.info("Wait up to 10s for port to be reported as ACTIVE")
        retry_until_success(self.check_port_status, function_args=(vm_ip, "ACTIVE"))
        _log.info("State == ACTIVE, as expected")

        # Set port down in Horizon
        vm_port = self.get_port(vm_ip)
        self.change_port_admin_state(vm_port, admin_up=False)

        # check you cannot ping the VM from another VM
        retry_until_success(
            self.do_ping_check, function_args=([], test_vm, [], [my_vm])
        )

        # Set port up
        self.change_port_admin_state(vm_port, admin_up=True)

        # check you can ping the VM from another VM
        retry_until_success(
            self.do_ping_check, function_args=([], test_vm, [my_vm], [])
        )
