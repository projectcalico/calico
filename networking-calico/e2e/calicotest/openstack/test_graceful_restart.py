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
import json
import logging
import threading
import time

from calicotest import settings
from calicotest.common import datamodel_v3
from calicotest.common import logutils
from calicotest.common.testutils import retry_until_success
from calicotest.openstack.basetest import LOGS_IGNORE_ALL_TESTS
from calicotest.openstack.basetest import LOGS_IGNORE_GR_EXPECTED_LOGS
from calicotest.openstack.config import LAYOUT, IPERF_PATH
from calicotest.openstack.topology import Topology
from calicotest.openstack.topology import Topology2SecurityGroupsUbuntu
from calicotest.openstack.udp_stream import UdpStream

_log = logging.getLogger(__name__)


class DatastoreNotReadyException(Exception):
    pass


class TestGracefulRestart(Topology2SecurityGroupsUbuntu):
    """
    Test that Calico can deal well with various services failing/restarting
    """

    IGNORE_LOGS_LIST = LOGS_IGNORE_GR_EXPECTED_LOGS
    compute_host_to_test = None
    # Naming some of VMs in our topology for ease of reference
    ubuntu_vm_one = None
    ubuntu_vm_two = None
    cirros_vm_one = None
    cirros_vm_two = None

    @classmethod
    def setUpClass(cls):
        # Turn on Felix debug logs for these tests.  Felix restarts to apply that,
        # which takes a few seconds.  We do it before the super() call because that
        # call creates security groups and then VMs in them, and Tenant.create_vm
        # waits 30s before creating a VM in a security group less than 30s old.  So
        # Felix's restart overlaps that wait, and is done well before the VMs exist.
        _log.info("Turning on Felix debug logs")
        logutils.set_felix_log_level("DEBUG")
        super(TestGracefulRestart, cls).setUpClass()
        # Install iperf on two of the Ubuntu machines
        cls.ubuntu_vm_one = cls.default_group[0]
        cls.ubuntu_vm_two = cls.default_group[1]
        cls.cirros_vm_one = cls.group2[0]
        cls.cirros_vm_two = cls.group2[1]
        cls.ubuntu_vm_one.install_dpkg_from_test_rig(IPERF_PATH)
        cls.ubuntu_vm_two.install_dpkg_from_test_rig(IPERF_PATH)
        cls.compute_host_to_test = cls.get_nth_compute_node(n=0)
        cls.second_compute_host = cls.get_nth_compute_node(n=1)

    @classmethod
    def tearDownClass(cls):
        super(TestGracefulRestart, cls).tearDownClass()
        cls.compute_host_to_test.start_felix()

        # We need to wait before moving onto the next test until Felix has
        # restarted, and we can detect that by looking at PIDs.  So get the
        # PIDs now.
        pids = LAYOUT.compute_nodes[0].get_pids("calico-felix")
        _log.info("Felix PIDs before LogSeverityFile change: %s", pids)

        # Turn off Felix debug logs
        _log.info("Turning off Felix debug logs")
        logutils.set_felix_log_level(None)

        def felix_has_new_pids():
            new_pids = LAYOUT.compute_nodes[0].get_pids("calico-felix")
            _log.info("Felix PIDs now: %s", new_pids)
            assert new_pids
            assert all(p not in pids for p in new_pids)

        # Wait until Felix is running with different PIDs.
        retry_until_success(
            felix_has_new_pids,
            retries=5,
            context_string="TestGracefulRestart.tearDownClass",
        )

    def tearDown(self):
        _log.info("Restart felix in case the test didn't")
        self.compute_host_to_test.start_felix()

    def test_graceful_restart_basic(self):
        """
        Test that Calico can handle various parts restarting
        :return:
        """
        self.default_check_connectivity()
        self.graceful_restart_check()
        self.default_check_connectivity()

    def test_delete_vm(self):
        """
        Run the standard graceful restart test, but check that deleting vms
        whilst services are down has succeeded by the resync.
        To do this we add two vms before the start, to later delete.
        :return:
        """

        _log.info("Adding two vms to delete during test")
        number_of_vms_at_start = len(self.controller.get_vms())
        self.add_vm_to_default_group()
        self.add_vm_to_default_group()
        self.default_check_connectivity()
        self.graceful_restart_check(
            [
                self.remove_last_vm_from_default_group,
                self.remove_last_vm_from_default_group,
            ]
        )
        number_of_vms_at_end = len(self.controller.get_vms())
        self.assertEqual(
            number_of_vms_at_start,
            number_of_vms_at_end,
            msg="VMs were not successfully deleted",
        )

    def test_migrate_vm(self):
        """
        Run the standard graceful restart test, but check that migrating vms
        whilst services are down has succeeded by the resync
        We wait for VMs to be migrated before continuing testing, as some
        downtime is expected, even for live migrate (about 1s)
        :return:
        """
        assert (
            len(LAYOUT.compute_nodes) >= 3
        ), "Require 3 compute nodes for migration testing"

        def migrate_vm_to_node(vm, node):
            """
            Helper function, that moves the given vm to the given node,
            and keeps attempting for a while if this does not work first time,
            then waits for the vm to be active before returning.
            It may require a few tries to migrate somewhere if the memory is
            being freed up.  The number of retries just needs to be long
            enough for the system to sort itself out, and then do the
            migration.
            :return:
            """
            _log.info("Migrating vm")
            target_zone = self.zonify(node)
            migrate = functools.partial(vm.live_migrate, target_zone)
            retry_until_success(
                migrate,
                60,
                context_string="TestGracefulRestart.test_migrate_vm.migrate_vm_to_node",
            )
            vm.wait_for_state("ACTIVE", 20)

        def migrate_first_vm():
            """
            Moves ubuntu node which starts on node 0 to node 2
            """
            migrate_vm_to_node(self.ubuntu_vm_one, LAYOUT.compute_nodes[2])

        def migrate_second_vm():
            """
            Moves a CirrOS VM that starts on node 1 to node 0.
            """
            migrate_vm_to_node(self.cirros_vm_two, LAYOUT.compute_nodes[0])

        def migrate_second_vm_back():
            migrate_vm_to_node(self.cirros_vm_two, LAYOUT.compute_nodes[1])

        def migrate_first_vm_back():
            migrate_vm_to_node(self.ubuntu_vm_one, LAYOUT.compute_nodes[0])

        self.default_check_connectivity()
        self.graceful_restart_check([migrate_first_vm, migrate_second_vm])
        self.default_check_connectivity()

        # Return to original state - migrate in parallel to save time
        threads = [
            threading.Thread(target=migrate_first_vm_back),
            threading.Thread(target=migrate_second_vm_back),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def test_add_rules(self):
        """
        Tests we can add security group rules whilst services are down
        :return:
        """

        def add_ping_rule_default_group_to_group2():
            _log.info("Allow default sec group to ping group2")
            self.add_group_ping_rule("default", "group2")

        def add_ping_rule_group2_to_default_group():
            _log.info("Allow group2 to ping default sec group")
            self.add_group_ping_rule("group2", "default")

        self.default_check_connectivity()
        try:
            self.graceful_restart_check(
                [
                    add_ping_rule_default_group_to_group2,
                    add_ping_rule_group2_to_default_group,
                ]
            )
            self.check_mutual_connectivity(
                pass_list=self.default_group + self.group2,
            )
        finally:
            _log.info("Remove intra-group ping rules")
            self.delete_group_ping_rule("group2", "default")
            self.delete_group_ping_rule("default", "group2")

    def test_add_security_groups(self):
        """
        Tests that adding vms to security groups works when services are down
        We keep track of what security groups vms are in so that we can check
        that our view of the world matches what OpenStack tells us.
        :return:
        """

        def add_ubuntu_vm_one_to_group2():
            _log.info("Add ubuntu_vm_one to security group 2")
            self.ubuntu_vm_one.add_security_group(self.security_group["name"])
            self.group2.append(self.ubuntu_vm_one)

        def add_ubuntu_vm_two_to_group2():
            _log.info("Add ubuntu_vm_two to security group 2")
            self.ubuntu_vm_two.add_security_group(self.security_group["name"])
            self.group2.append(self.ubuntu_vm_two)

        self.default_check_connectivity()
        self.graceful_restart_check(
            [add_ubuntu_vm_one_to_group2, add_ubuntu_vm_two_to_group2]
        )
        self.check_mutual_connectivity(self.default_group)
        self.check_mutual_connectivity(self.group2)
        # Return to original state
        _log.info("Remove ubuntu vms from security group 2")
        self.ubuntu_vm_one.remove_security_group(self.security_group["name"])
        self.ubuntu_vm_two.remove_security_group(self.security_group["name"])
        self.group2.remove(self.ubuntu_vm_one)
        self.group2.remove(self.ubuntu_vm_two)

    def test_add_and_remove_security_groups(self):
        """
        Tests that adding and removing security groups whilst services are
        down works as expected
        :return:
        """

        def add_and_remove_security_groups_1():
            self.ubuntu_vm_one.add_security_group(self.security_group["name"])
            self.ubuntu_vm_two.add_security_group(self.security_group["name"])
            self.ubuntu_vm_one.remove_security_group(self.security_group["name"])

        def add_and_remove_security_groups_2():
            self.ubuntu_vm_one.add_security_group(self.security_group["name"])
            self.ubuntu_vm_two.remove_security_group(self.security_group["name"])
            self.ubuntu_vm_one.remove_security_group(self.security_group["name"])

        self.default_check_connectivity()
        self.graceful_restart_check(
            [add_and_remove_security_groups_1, add_and_remove_security_groups_2]
        )
        self.default_check_connectivity()

    def test_replace_security_groups(self):
        """
        Tests that we can replace the security group on a vm whilst services
        are down
        We keep track of what security groups we think the vms are in, so that
        we can compare our idea of the world with OpenStack's.
        :return:
        """

        def add_cirros_vm_one_to_default_group():
            _log.info("Adding cirros_vm_one to default security group")
            default_id = self.controller.tenants["admin"].security_groups["default"][
                "id"
            ]
            self.cirros_vm_one.add_security_group(default_id)
            self.default_group.append(self.cirros_vm_one)

        def remove_cirros_vm_one_from_default_group():
            _log.info("Removing cirros_vm_one from default security group")
            default_id = self.controller.tenants["admin"].security_groups["default"][
                "id"
            ]
            self.cirros_vm_one.remove_security_group(default_id)
            self.default_group.remove(self.cirros_vm_one)

        def remove_cirros_vm_one_from_group2():
            _log.info("Removing cirros_vm_one from security group 2")
            self.cirros_vm_one.remove_security_group(self.security_group["name"])
            self.group2.remove(self.cirros_vm_one)

        self.default_check_connectivity()
        self.graceful_restart_check(
            [add_cirros_vm_one_to_default_group, remove_cirros_vm_one_from_group2]
        )
        self.default_check_connectivity()
        # Return to initial state
        self.cirros_vm_one.add_security_group(self.security_group["name"])
        self.group2.append(self.cirros_vm_one)
        remove_cirros_vm_one_from_default_group()

    def add_vm_to_default_group(self):
        self.default_group.append(
            self.create_vm(availability_zone=self.compute_host_to_test)
        )

    def remove_last_vm_from_default_group(self):
        """
        Deletes the last VM from group one both in Horizon, and in our record.
        :return:
        """
        vm_to_remove = self.default_group[-1]
        self.delete_vm(vm_to_remove.name)
        self.default_group.pop()

    def graceful_restart_check(self, test_actions=[lambda: True]):
        """
        For each given test action:
        - Check basic connectivity i.e. group1 can ping group1, group2 can ping
          group2 and they cannot ping each other.
        - Stop Felix, and check that basic connectivity persists.
        - Execute the test action.
        - Restart Felix, and check that basic connectivity persists.
        - Check basic connectivity again.
        """
        for test_action in test_actions:

            _log.info("Test connectivity stopping felix")
            self.check_connectivity_across_action(
                self.compute_host_to_test, self.compute_host_to_test.stop_felix
            )

            _log.info("Execute test action")
            test_action()

            _log.info("Test connectivity restarting felix")
            self.check_connectivity_across_action(
                self.compute_host_to_test, self.compute_host_to_test.start_felix
            )

        _log.info("Test waiting for datastore ready")
        self.check_connectivity_across_action(
            self.compute_host_to_test,
            functools.partial(
                self.wait_and_assert_datastore_ready, self.compute_host_to_test
            ),
        )

    @staticmethod
    def wait_and_assert_datastore_ready(etcd_node, seconds_to_wait=5):
        """
        Waits for the time given for etcd to sync up -
        checks for the ready flag
        :return:
        """
        for _ in range(0, seconds_to_wait):
            try:
                cluster_info = datamodel_v3.get("ClusterInformation", "default")
                if cluster_info[datamodel_v3.DATASTORE_READY]:
                    return
            except Exception:
                pass
            time.sleep(1)
        raise DatastoreNotReadyException()

    @classmethod
    def get_nth_compute_node(cls, n=0):
        """
        Returns a compute node
        :return:
        """
        compute_node = LAYOUT.compute_nodes[n]
        return compute_node

    def check_connectivity_across_action(self, compute_host, action):
        """
        Checks that an SSH connection and UDP stream are preserved across the
        given action, and that we don't leak rules.

        Set up ssh connection to a vm
        Set up UDP stream between two vms
        Check how many rules are on our compute_host
        Perform the given action
        Check our ssh connection still up
        Check that the number of rules is same as before
        Check that the UDP stream was still going after the action, and
        that it delivered successfully
        :param compute_host: The compute host which our action is affecting
        :param action: The action we are testing - this should be a function
        :return:
        """
        # Set up tests
        self.ubuntu_vm_one.connect()
        number_of_rules_before = compute_host.get_number_of_rules()
        stream = UdpStream(self.ubuntu_vm_one, self.ubuntu_vm_two)
        stream.start_stream()

        action()

        # First check ssh is still up - otherwise all other checks will fail
        self.assertTrue(
            self.ubuntu_vm_one.ssh.still_connected,
            msg="The action disconnected our ssh connection",
        )
        # Need to make sure stream carried on until after the action finished
        self.assertFalse(
            stream.stream_finished(), msg="The UdpStream finished before the action"
        )
        number_of_rules_after = compute_host.get_number_of_rules()
        if number_of_rules_before != number_of_rules_after:
            _log.info(
                "The number of rules on the compute host before the action "
                "{number_before} and the number after was {number_after}. "
                "This could indicate rule leakage but may well be "
                "expected".format(
                    number_before=number_of_rules_before,
                    number_after=number_of_rules_after,
                )
            )
        self.assertTrue(
            stream.wait_for_stream_to_finish(), msg="The UDP stream did not complete"
        )
        self.assertTrue(
            stream.completed_successfully(), msg="The UDP stream suffered packet loss"
        )


class TestCompaction(Topology):

    # See https://bugs.launchpad.net/oslo.messaging/+bug/1450336
    # "oslo.messaging log useless error on application exit".
    IGNORE_LOGS_LIST = LOGS_IGNORE_ALL_TESTS + [
        "Failed to consume message from queue",
    ]

    @classmethod
    def setUpClass(cls):
        super(TestCompaction, cls).setUpClass()
        # store off ETCD_COMPACTION_PERIOD_MINS
        status, cls.original_compaction_period, _ = cls.controller.execute(
            "sudo crudini --get /etc/neutron/neutron.conf "
            "calico etcd_compaction_period_mins"
        )
        if status != 0:
            cls.original_compaction_period = None
        # store off ETCD_COMPACTION_MIN_REVISIONS
        status, cls.original_compaction_revs, _ = cls.controller.execute(
            "sudo crudini --get /etc/neutron/neutron.conf "
            "calico etcd_compaction_min_revisions"
        )
        if status != 0:
            cls.original_compaction_revs = None

        # set ETCD_COMPACTION_PERIOD = 1m
        cls.controller.execute(
            "sudo crudini --set /etc/neutron/neutron.conf "
            "calico etcd_compaction_period_mins 1"
        )
        # set ETCD_COMPACTION_MIN_REVISIONS = 50
        cls.controller.execute(
            "sudo crudini --set /etc/neutron/neutron.conf "
            "calico etcd_compaction_min_revisions 50"
        )

        # restart neutron server to allow settings to take effect
        cls.controller.execute("sudo service neutron-server restart")

    @classmethod
    def tearDownClass(cls):
        super(TestCompaction, cls).tearDownClass()
        # restore ETCD_COMPACTION_PERIOD_MINS
        if cls.original_compaction_period is None:
            cls.controller.execute(
                "sudo crudini --del /etc/neutron/neutron.conf "
                "calico etcd_compaction_period_mins"
            )
        else:
            cls.controller.execute(
                "sudo crudini --set /etc/neutron/neutron.conf "
                "calico etcd_compaction_period_mins %s"
                % cls.original_compaction_period
            )

        # restore ETCD_COMPACTION_MIN_REVISIONS
        if cls.original_compaction_revs is None:
            cls.controller.execute(
                "sudo crudini --del /etc/neutron/neutron.conf "
                "calico etcd_compaction_min_revisions"
            )
        else:
            cls.controller.execute(
                "sudo crudini --set /etc/neutron/neutron.conf "
                "calico etcd_compaction_min_revisions %s"
                % cls.original_compaction_revs
            )

        # restart neutron server to allow settings to take effect
        cls.controller.execute("sudo service neutron-server restart")

        # Ensure we leave a little time for the Neutron server to come up
        # again, before the next test.
        time.sleep(10)

    def test_compaction(self):
        # find and store off original compaction point
        origin_compact_point = self.find_compaction_rev()

        # write ready flag 51 times
        cluster_info = datamodel_v3.get("ClusterInformation", "default")
        for i in range(50):
            datamodel_v3.put("ClusterInformation", "default", cluster_info)

        def check_compaction():
            # find new current compaction point
            new_compact_point = self.find_compaction_rev()

            _log.info(
                "\nOriginal compaction rev: %s\nNew compaction rev     : %s",
                origin_compact_point,
                new_compact_point,
            )

            # assert that new current compaction point is > original compaction point
            assert new_compact_point > origin_compact_point

        # Allow a bit more than 2 minutes for a compaction to occur.
        #
        # The master Neutron server considers compaction when it becomes master, which
        # is soon after the restart in setUpClass, and then every
        # etcd_compaction_period_mins, which setUpClass sets to 1.  Each time, it only
        # compacts if its compaction trigger key has expired.  Whenever it writes that
        # key, it gives it a lease of etcd_compaction_period_mins.  So:
        #
        # - If the trigger key has already expired - for example, because an earlier
        #   run of this test wrote it with a 1 minute lease - the first check compacts,
        #   within seconds of the restart.
        #
        # - If the key still has a lease from the default 60 minute period, as on a
        #   recently installed cluster, the first check rewrites it with a 1 minute
        #   lease, and does not compact.  The second check, a minute later, normally
        #   finds that the key has gone, and compacts.  But that check and the expiry
        #   of the lease are both due a minute after the first check, so the second
        #   check can find the lease on the verge of expiring - logging "Compaction
        #   trigger TTL is -1", for example - and not compact.  Then the third check
        #   compacts, about 2 minutes after the restart.
        #
        # (Before Calico v3.32, networking-calico considered compaction during its
        # periodic resync, every 60s, so the timing was the same.)
        retry_until_success(
            check_compaction,
            retries=8,
            wait_time=16,
            context_string="Waiting for networking-calico to compact etcd",
        )

    def get_current_revision(self):
        # Attempt to grab any key - this won't work, but the header
        # contains the info we want.
        _, stdout, _ = self.controller.execute(
            settings.ETCDCTL_V3 + " get mykey -w=json"
        )
        data = json.loads(stdout)
        return data["header"]["revision"]

    def find_compaction_rev(self):
        current_rev = self.get_current_revision()
        # Binary chop current rev to find last compaction point
        compacted_rev = 0
        interval = current_rev - compacted_rev

        def check_rev(rev):
            rc, _, _ = self.controller.execute(
                settings.ETCDCTL_V3 + " get mykey --rev=%d" % rev
            )
            return rc

        while interval > 1:
            new_rev = (interval // 2) + compacted_rev
            _log.debug(
                "Compact point between %s and %s.  Trying rev: %s",
                compacted_rev,
                current_rev,
                new_rev,
            )
            status = check_rev(new_rev)
            if status == 0:
                current_rev = new_rev
            else:
                compacted_rev = new_rev
            interval = current_rev - compacted_rev

        # Final check that current_rev still works, in case a further
        # compaction has happened during this search.  (If it did, the
        # current_rev would still be kinda valid, in that it would lie between
        # the previous compaction point and the latest compaction point.  But
        # really we want to return an actual compaction point here.)
        retry = False
        if check_rev(current_rev) != 0:
            retry = True

        # If we need to retry, do so...
        if retry:
            _log.info("Failed check of compaction rev - retrying")
            current_rev = self.find_compaction_rev()

        return current_rev
