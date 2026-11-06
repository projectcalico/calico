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
import random

from calicotest import settings
from calicotest.common.testutils import retry_until_success
from calicotest.openstack.basetest import LOGS_IGNORE_ALL_TESTS
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology, Topology2SecurityGroups

_log = logging.getLogger(__name__)


class TestBasicSecurityGroups(Topology2SecurityGroups):
    """
    The base class sets up VMs in the same tenant and network, across 2
    security groups and all hosts.
    """

    def test_security_group_connectivity(self):
        """
        Check that VMs within a security group can ping each other, but not VMs
        in other security groups.
        """
        self.default_check_connectivity()

    def test_egress_filtering(self):
        """
        Uses the basic topology with two security groups, default and group2
        Adds ingress rules so that they can receive pings from each other, but
        removes egress rules from group2 so that group2 cannot send messages.
        Checks group2 cannot ping internally or externally.
        Adds egress ping rule from group2 to group2, and tests pinging works.
        Adds egress ping rule from group2 to default, and checks it works.
        Removes these two rules and checks group2 can no longer ping anyone.
        Sets the system back to normal and checks standard connectivity
        """

        # Make it so that the ingress rules allow group2 to ping itself and the
        # security group, but remove the egress rules so that it can't
        # currently ping anyone.
        self.delete_group_default_egress_rules("group2")
        self.add_group_ping_rule("default", "group2")
        self.add_group_ping_rule("group2", "default")
        self.check_mutual_connectivity(
            [self.group2[0]], self.default_group + [self.group2[1], self.group2[2]]
        )

        # Allow group2 to ping group2
        self.add_egress_group_ping_rule("group2", "group2")
        self.check_mutual_connectivity(self.group2, self.default_group)

        # Allow group2 to ping default
        self.add_egress_group_ping_rule("group2", "default")
        self.check_mutual_connectivity(self.group2 + self.default_group)

        # Remove rules and test that again we can't ping anyone
        self.delete_egress_group_ping_rule("group2", "default")
        self.delete_egress_group_ping_rule("group2", "group2")
        self.check_mutual_connectivity(
            [self.group2[0]], self.default_group + [self.group2[1], self.group2[2]]
        )

        # Return to starting state and check we are where we think we are
        self.delete_group_ping_rule("default", "group2")
        self.delete_group_ping_rule("group2", "default")
        self.add_group_default_egress_rules("group2")
        self.default_check_connectivity()

    def test_add_delete_group_rule(self):
        """
        Add/delete group rules and test connectivity (short run).

        Check that when we add a rule to allow VMs in different security groups
        to ping each other, that it actually works.
        """
        self._add_delete_group_rule()

    def _add_delete_group_rule(self):
        """
        Check that when we add a rule to allow VMs in different security groups
        to ping each other, that it actually works.
        """

        def add_rules():
            """Add rules to allow pings between groups"""
            self.add_group_ping_rule("default", "group2")
            self.add_group_ping_rule("group2", "default")

        def remove_rules():
            """Remove rules to disallow pings between groups"""
            self.delete_group_ping_rule("default", "group2")
            self.delete_group_ping_rule("group2", "default")

        def check_conn_between_groups():
            """Check connectivity between groups when rules are added"""
            try:
                self.check_mutual_connectivity(
                    pass_list=self.default_group + self.group2
                )
            except Exception:
                # If pinging fails, remove the rules to get us back to the
                # starting conditions and re-raise the exception.
                remove_rules()
                raise

        # Run a simple test with and without the rules
        _log.info("Perform test with rules added to connect groups")
        add_rules()
        check_conn_between_groups()
        _log.info("Perform test with rules removed to disconnect groups")
        remove_rules()
        self.default_check_connectivity()

        # Now fire off multiple adds and deletes with a variety of flips.  We perform
        # each set twice to get us back to the default starting conditions.

        _log.info("Perform test while flipping rules")
        added = False
        for flips in [4, 11, 20]:
            for _iters in range(2):
                _log.info("Flipping rules %s times", flips)
                for _flip in range(flips):
                    if added:
                        remove_rules()
                    else:
                        add_rules()
                    added = not added
                if added:
                    check_conn_between_groups()
                else:
                    self.default_check_connectivity()

        # We should be back to the default starting conditions.
        self.default_check_connectivity()

    def test_add_remove_group(self):
        """
        Add/remove group from VM to connect/disconnect two sets of VMs (short).

        Check that when we add and remove a security group to a VM after
        creation, things get updated as expected.
        """

        self._add_remove_group()

    def _add_remove_group(self):
        """
        Check that when we add and remove a security group to a VM after
        creation, things get updated as expected.
        """
        # Create a VM in group 1 and add group 2 to it - so this VM will span
        # both groups.
        node = random.choice(LAYOUT.compute_nodes)
        test_vm = self.create_vm(availability_zone=node)
        self.other_vms.append(test_vm)

        def add_security_group():
            """Add security group to test_vm so in both groups"""
            test_vm.add_security_group(self.security_group["name"])

        def remove_security_group():
            """Remove security group from test_vm so only in group1"""
            test_vm.remove_security_group(self.security_group["name"])

        def check_conn_group1_only():
            """Check test_vm can only contact group 1"""
            self.check_mutual_connectivity(
                pass_list=self.default_group + [test_vm], fail_list=self.group2
            )
            self.check_mutual_connectivity(
                pass_list=self.group2, fail_list=self.default_group + [test_vm]
            )

        def check_conn_both_groups():
            """Check test_vm can contact both groups"""
            self.default_check_connectivity()
            self.check_mutual_connectivity(pass_list=self.default_group + [test_vm])
            self.check_mutual_connectivity(pass_list=self.group2 + [test_vm])

        # Perform simple add / delete testing at first.
        _log.info("Perform test with group added so VM in both groups")
        add_security_group()
        check_conn_both_groups()
        _log.info("Perform test with group removed so VM in one groups")
        remove_security_group()
        check_conn_group1_only()

        # Now fire off multiple adds and deletes with a variety of flips.  We perform
        # each set twice to get us back to the default starting conditions.

        _log.info("Perform test flipping VM in and out of group")
        added = False
        for flips in [4, 11, 20]:
            for _iters in range(2):
                _log.info("Flipping group %s times", flips)
                for _flip in range(flips):
                    if added:
                        remove_security_group()
                    else:
                        add_security_group()
                    added = not added
                if added:
                    check_conn_both_groups()
                else:
                    check_conn_group1_only()

        # We should be back to the default starting conditions.
        self.default_check_connectivity()


class TestLargeSecurityGroup(Topology):
    """
    Test use of a large security group.
    """

    # This test adds a lot of security group rules, using the
    # OpenStack API, and that propagates through to the Neutron driver
    # adding a lot of corresponding Calico data to the etcd datastore.
    # If a dense group of writes by the Neutron driver coincides with
    # a Felix trying to refresh its active status report, the latter
    # can take longer than the 2s allowed by
    # https://github.com/projectcalico/felix/blob/master/daemon/daemon.go#L861,
    # and then Felix/libcalico-go emits the following ERROR log.
    #
    # It's not actually harmful, unless it happens 3 times in a row,
    # because Felix tries to refresh its status every 30s, with a TTL
    # of 90s.
    IGNORE_LOGS_LIST = LOGS_IGNORE_ALL_TESTS + [
        "Failed to grant a lease error=context deadline exceeded",
    ]

    @classmethod
    def setUpClass(cls):
        """
        Setup a security group with a large number of rules, a set of
        VMs spanning the compute nodes belonging to this security group, and
        a set of VMs belonging to a different security group.
        """
        super(TestLargeSecurityGroup, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        cls.vms = []
        cls.control_vms = []
        cls.GROUPNAME = "biggroup"

        # Increase the quota for security group rules
        total_quota = (
            settings.OPENSTACK_DEF_RULES + settings.OPENSTACK_MAX_RULES_IN_TEST
        )
        cls.controller.update_neutron_quota(security_group_rule=total_quota)
        cls.controller.update_nova_quota(security_group_rules=total_quota)

        # Set up a security group and add a rule so we can log in
        cls.security_group = cls.create_security_group(cls.GROUPNAME)
        cls.add_ssh_rule(cls.GROUPNAME)
        cls.add_group_ping_rule(cls.GROUPNAME)

        # Put lots of rules into that group.  If we hit an exception, make sure
        # we delete the group since it group prevent other tests working.  We
        # don't need ot update our cache since we'll be deleting the whole
        # group after.
        try:
            cls.add_cidr_rules(
                cls.GROUPNAME,
                "tcp",
                80,
                80,
                [
                    "10.253.%d.%d/32" % (ii / 255, (ii % 255) + 1)
                    for ii in range(settings.OPENSTACK_MAX_RULES_IN_TEST)
                ],
                update_cache=False,
            )
        except Exception:
            _log.exception("Hit exception adding rules")
            neutron = cls.controller.tenants["admin"].neutron
            neutron.delete_security_group(cls.security_group["id"])
            raise

        _log.info("Created large security group")

        # Setup a VM on each host in the large security group
        # And another pair on one of the hosts
        # So that we check both inter-host and intra-host connectivity.
        vm_threads = []
        for node in LAYOUT.compute_nodes:
            vm_threads.append(
                cls.create_vm_parallel(
                    availability_zone=node, security_groups=cls.GROUPNAME
                )
            )

        node = LAYOUT.compute_nodes[0]
        vm_threads.append(
            cls.create_vm_parallel(
                availability_zone=node, security_groups=cls.GROUPNAME
            )
        )

        # Create a 'control group VM' which should fail connectivity checks to
        # the VMs with the large rule-set
        control_vm_thread = cls.create_vm_parallel(availability_zone=node)

        # Wait for the threads to complete and store the created VMs
        for vm_thread in vm_threads:
            cls.vms.append(vm_thread.join())
        cls.control_vms.append(control_vm_thread.join())

    @classmethod
    def tearDownClass(cls):
        """
        Tear down the VMs and remove the large security group.
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
            context_string="TestLargeSecurityGroup.tearDownClass",
        )
        super(TestLargeSecurityGroup, cls).tearDownClass()

    def test_large_security_group(self):
        """
        Check mutual connectivity between the VMs within a large security grp.
        """
        self.check_mutual_connectivity(pass_list=self.vms, fail_list=self.control_vms)


class TestManySecurityGroups(Topology):
    """
    Test behaviour with a large number of security groups.
    """

    @classmethod
    def setUpClass(cls):
        """
        Set up a large number of security groups, and a set of VMs belonging
        to an arbitrary security group.
        """
        super(TestManySecurityGroups, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)

        # Increase the quota for number of security groups
        total_quota = (
            settings.OPENSTACK_DEF_GROUPS + settings.OPENSTACK_MAX_GROUPS_IN_TEST
        )
        cls.controller.update_neutron_quota(security_group=total_quota)
        cls.controller.update_nova_quota(security_groups=total_quota)

        # Also need to increate the quota for rules since we are creating
        # rules for each group.  A new group has 2 rules plus we create
        # another 3 for each group (ICMP + 2 SSH).
        rules_quota = max(total_quota * 5, settings.OPENSTACK_DEF_RULES)
        cls.controller.update_neutron_quota(security_group_rule=rules_quota)
        cls.controller.update_nova_quota(security_group_rules=rules_quota)

        cls.vms = []
        cls.control_vms = []

        # Set up a large number of security groups and add rules so we can log
        # in and ping between them.
        cls.security_groups = []
        for ii in range(settings.OPENSTACK_MAX_GROUPS_IN_TEST):
            gp_name = "group-%.3d" % ii
            sg = cls.create_security_group(gp_name)
            cls.add_ssh_rule(gp_name)
            cls.add_group_ping_rule(gp_name)
            cls.security_groups.append(sg)

        # Create another security group with a no-ping rule.
        gp_name = "group-no-ping"
        cls.security_group_no_ping = cls.create_security_group(gp_name)
        cls.add_ssh_rule(gp_name)
        cls.security_groups.append(cls.security_group_no_ping)

        # Setup a VM on each host with all of the ping-able security groups.
        sgs = [sg["name"] for sg in cls.security_groups]
        _log.info("SGs for VM: %s", sgs)
        ping_vm_threads = []
        for node in LAYOUT.compute_nodes:
            ping_vm_threads.append(
                cls.create_vm_parallel(availability_zone=node, security_groups=sgs)
            )

        # Choose a node at random to add a couple more VMs to test intra-host
        # connectivity and to test non-pingability.
        node = random.choice(LAYOUT.compute_nodes)
        no_ping_vm_thread = cls.create_vm_parallel(
            availability_zone=node,
            security_groups=sgs + [cls.security_group_no_ping["name"]],
        )

        # Create a 'control group VM' using just the security group that has
        # no ping-ability.
        control_vm_thread = cls.create_vm_parallel(
            availability_zone=node, security_groups=cls.security_group_no_ping["name"]
        )

        # Wait for the threads to complete and store the created VMs
        for ping_vm_thread in ping_vm_threads:
            new_ping_vm = ping_vm_thread.join()
            for sg in cls.security_groups[1:]:
                new_ping_vm.add_security_group(sg["name"])
            cls.vms.append(new_ping_vm)

        new_no_ping_vm = no_ping_vm_thread.join()
        cls.vms.append(new_no_ping_vm)

        new_control_vm = control_vm_thread.join()
        cls.control_vms.append(new_control_vm)

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in list(cls.controller.tenants["admin"].vms.keys()):
            cls.delete_vm(vm)

        neutron = cls.controller.tenants["admin"].neutron

        # Delete the security groups.  Note that you can't delete them while
        # they are referenced by the VMs.
        def delete_groups():
            for ii in range(len(cls.security_groups)):
                neutron.delete_security_group(cls.security_groups[0]["id"])
                cls.security_groups.pop(0)

        retry_until_success(
            delete_groups,
            retries=60,
            context_string="TestManySecurityGroups.tearDownClass",
        )

        super(TestManySecurityGroups, cls).tearDownClass()

    def test_many_security_groups(self):
        """
        Test behaviour with a large number of security groups.

        Check VMs with larges numbers of groups assigned can ping other VMs in
        shared groups for which the group rules allow.
        """
        self.check_mutual_connectivity(pass_list=self.vms, fail_list=self.control_vms)
