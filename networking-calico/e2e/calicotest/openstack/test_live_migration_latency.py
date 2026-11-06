# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

"""
Tests that live migration maintains connectivity with minimal
disruption.  Uses Ubuntu VMs and measures the connectivity gap during
migration, asserting it is under 2 seconds.
"""

import logging
import re
import time

from calicotest.common.testutils import ThreadWithReturn
from calicotest.openstack.basetest import LOGS_IGNORE_ALL_TESTS
from calicotest.openstack.config import LAYOUT, IPERF_PATH
from calicotest.openstack.topology import Topology
from calicotest.settings import IPV6_WITH_APPS

_log = logging.getLogger(__name__)

LOGS_IGNORE_LIVE_MIGRATION = LOGS_IGNORE_ALL_TESTS + [
    "RTNETLINK answers: Network is down",
]

# Maximum acceptable connectivity gap during live migration, in seconds.
MAX_MIGRATION_GAP_SECS = 2


class LiveMigrationLatency(Topology):
    """
    Base class for live migration latency tests.  Creates two Ubuntu
    VMs on different compute nodes: a "traffic client" that stays put,
    and a "migrating VM" that will be live-migrated.
    """

    IGNORE_LOGS_LIST = LOGS_IGNORE_LIVE_MIGRATION

    @classmethod
    def setUpClass(cls):
        super(LiveMigrationLatency, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)

        assert (
            len(LAYOUT.compute_nodes) >= 3
        ), "Require 3 compute nodes for migration testing"

        cls.node1 = LAYOUT.compute_nodes[0]
        cls.node2 = LAYOUT.compute_nodes[1]
        cls.node3 = LAYOUT.compute_nodes[2]

        # Create Ubuntu VMs in parallel.  The traffic client goes on
        # node1 (which won't be involved in migration).  The migrating
        # VM goes on node2 and will be migrated to node3.
        client_thread = cls.create_vm_parallel(
            availability_zone=cls.zonify(cls.node1),
            image=IPV6_WITH_APPS,
            ubuntu_speedup_sudo=True,
        )
        migrate_thread = cls.create_vm_parallel(
            availability_zone=cls.zonify(cls.node2),
            image=IPV6_WITH_APPS,
            ubuntu_speedup_sudo=True,
        )

        cls.client_vm = client_thread.join()
        cls.migrate_vm = migrate_thread.join()
        cls.vms = [cls.client_vm, cls.migrate_vm]

        # Put node3 in the same availability zone as node2 so
        # migration between them is allowed.
        cls.controller.tenants["admin"].update_aggregate(
            cls.zonify(cls.node3),
            availability_zone=cls.zonify(cls.node2),
        )

        # Install iperf (v2) on both VMs via the pre-built dpkg.
        # The VMs don't have internet access so we can't apt-get.
        for vm in cls.vms:
            vm.install_dpkg_from_test_rig(IPERF_PATH)

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in cls.vms:
            cls.delete_vm(vm.name)
        super(LiveMigrationLatency, cls).tearDownClass()

    def _migration_target(self):
        """
        Return a node to migrate migrate_vm to.  Picks a node that
        is not the VM's current host (and not node1, which hosts the
        client VM).
        """
        self.migrate_vm.vm.get()
        current_host = getattr(
            self.migrate_vm.vm,
            "OS-EXT-SRV-ATTR:host",
            None,
        )
        _log.info("migrate_vm is currently on %s", current_host)
        for node in [self.node2, self.node3]:
            if self.zonify(node) != current_host:
                return node
        raise RuntimeError(
            "Could not find migration target; VM is on %s" % current_host
        )

    def _measure_ping_gap(self, client_vm, target_ip, duration, interval=0.2):
        """
        Run ping from client_vm to target_ip for the given duration,
        in a background thread.  Returns a ThreadWithReturn whose
        join() yields the SSHResult.  The caller should trigger
        migration while this is running, then join() to get the
        results.

        Parse the ping output afterwards with _parse_ping_gap().
        """

        def run_ping():
            return client_vm.execute(
                "ping -i %s -w %d %s" % (interval, duration, target_ip)
            )

        thread = ThreadWithReturn(target=run_ping)
        thread.start()
        return thread

    def _parse_ping_gap(self, ping_output, interval=0.2):
        """
        Parse ping output and find the longest gap between
        consecutive successful replies.

        Ping output lines look like:
          64 bytes from 10.28.0.5: icmp_seq=1 ttl=64 time=1.23 ms

        We look at icmp_seq numbers to find the longest run of
        missing sequence numbers, then multiply by the interval to
        get the gap duration.
        """
        seq_numbers = []
        for line in ping_output.splitlines():
            match = re.search(r"icmp_seq=(\d+)", line)
            if match:
                seq_numbers.append(int(match.group(1)))

        if len(seq_numbers) < 2:
            _log.warning("Too few ping responses to measure gap")
            return 0

        # Find the largest gap between consecutive received
        # sequence numbers.
        max_gap_seqs = 0
        for i in range(1, len(seq_numbers)):
            gap = seq_numbers[i] - seq_numbers[i - 1] - 1
            max_gap_seqs = max(max_gap_seqs, gap)

        gap_secs = max_gap_seqs * interval
        return gap_secs


class TestLiveMigrationConnectivity(LiveMigrationLatency):
    """
    Verify that connectivity survives live migration with a gap
    under MAX_MIGRATION_GAP_SECS, and that a TCP connection
    (iperf) survives the migration.
    """

    def test_connectivity_gap(self):
        """
        Run a continuous ping from the client VM to the migrating VM
        during live migration.  Verify the gap is under 2 seconds.
        """
        self.check_mutual_connectivity(self.vms)

        target_ip = self.migrate_vm.get_ip_addr()

        # Start pinging in a background thread.
        ping_thread = self._measure_ping_gap(
            self.client_vm,
            target_ip,
            duration=120,
            interval=0.2,
        )

        # Give ping a few seconds to start.
        time.sleep(3)

        # Trigger live migration and wait for it to complete.
        target = self._migration_target()
        _log.info("Live-migrating %s to %s", self.migrate_vm.name, target.fqdn)
        self.migrate_vm.live_migrate(
            self.zonify(target),
            block_migration=False,
            disk_over_commit=False,
        )
        self.migrate_vm.wait_for_state(
            "ACTIVE",
            retries=self.migrate_vm.image.active_time,
        )
        _log.info("Migration complete")

        # Let ping run a bit longer post-migration, then stop it.
        time.sleep(10)
        self.client_vm.execute("pkill ping || true")
        ping_result = ping_thread.join()

        _log.info("ping return code: %s", ping_result.return_code)
        _log.debug("ping output:\n%s", ping_result.stdout[-2000:])

        gap = self._parse_ping_gap(ping_result.stdout, interval=0.2)
        _log.info("Measured connectivity gap: %.1f seconds", gap)
        assert (
            gap <= MAX_MIGRATION_GAP_SECS
        ), "Connectivity gap %.1fs exceeds maximum %ds" % (gap, MAX_MIGRATION_GAP_SECS)

        self.check_mutual_connectivity(self.vms)

    def test_tcp_survives_migration(self):
        """
        Establish an iperf TCP stream between the client VM and the
        migrating VM, then live-migrate the server VM and verify the
        TCP connection survives.
        """
        self.check_mutual_connectivity(self.vms)

        server_ip = self.migrate_vm.get_ip_addr()

        # Start iperf server on the migrating VM.  Redirect output and
        # use nohup so the SSH channel closes promptly.
        self.migrate_vm.execute("pkill iperf || true")
        self.migrate_vm.execute("nohup iperf -s </dev/null >/dev/null 2>&1 &")
        time.sleep(1)

        # Run iperf client in a background thread.
        def run_iperf():
            return self.client_vm.execute("iperf -c %s -t 120 -i 1" % server_ip)

        iperf_thread = ThreadWithReturn(target=run_iperf)
        iperf_thread.start()
        time.sleep(5)

        # Trigger live migration.
        target = self._migration_target()
        _log.info("Live-migrating %s to %s", self.migrate_vm.name, target.fqdn)
        self.migrate_vm.live_migrate(
            self.zonify(target),
            block_migration=False,
            disk_over_commit=False,
        )
        self.migrate_vm.wait_for_state(
            "ACTIVE",
            retries=self.migrate_vm.image.active_time,
        )
        _log.info("Migration complete")

        # Let iperf run a bit longer, then stop server.
        time.sleep(10)
        self.migrate_vm.execute("pkill iperf || true")
        iperf_result = iperf_thread.join()

        _log.info("iperf return code: %s", iperf_result.return_code)
        _log.debug("iperf output:\n%s", iperf_result.stdout[-2000:])

        # iperf exits 0 if the connection completed successfully.
        # A broken TCP connection would cause a non-zero exit.
        assert (
            iperf_result.return_code == 0
        ), "iperf exited with error — TCP connection was broken"

        self.check_mutual_connectivity(self.vms)


class TestLiveMigrationRouteMetrics(LiveMigrationLatency):
    """
    Verify that route metrics transition correctly during and after
    live migration: elevated priority during migration, normal
    priority after the TimeWait period.
    """

    def _get_route_metric(self, node, vm_ip):
        """
        Get the route metric for a VM IP on a compute node.
        Returns the metric as an integer, or None if no route found.
        """
        node.connect()
        result = node.execute("ip route show %s" % vm_ip)
        # Example output: "10.28.0.5 dev tap12345 proto 80 metric 1024"
        match = re.search(r"metric\s+(\d+)", result.stdout)
        if match:
            return int(match.group(1))
        return None

    def test_route_metric_transitions(self):
        """
        After migration, the route metric on the destination node
        should be elevated (512), then revert to normal (1024) after
        the TimeWait period (~30s).
        """
        self.check_mutual_connectivity(self.vms)

        vm_ip = self.migrate_vm.get_ip_addr()

        target = self._migration_target()
        _log.info("Live-migrating %s to %s", self.migrate_vm.name, target.fqdn)
        self.migrate_vm.live_migrate(
            self.zonify(target),
            block_migration=False,
            disk_over_commit=False,
        )
        self.migrate_vm.wait_for_state(
            "ACTIVE",
            retries=self.migrate_vm.image.active_time,
        )
        _log.info("Migration complete")

        # Check the route metric on the destination node immediately after
        # migration.  It should be elevated (default 512).  Note, the higher
        # priority metric is configured by the IPv4ElevatedRoutePriority
        # field in FelixConfiguration.
        metric = self._get_route_metric(target, vm_ip)
        _log.info("Route metric immediately after migration: %s", metric)
        assert metric is not None, "No route for %s on destination node" % vm_ip
        assert metric < 1024, "Route metric %d is not elevated after migration" % metric

        # Wait for TimeWait to expire and check the metric reverts.  Note,
        # "TimeWait" here means the time for which we continue advertising a
        # route at higher priority after a successful migration, so that the
        # rest of the nearby network routes correctly to the new host.  This
        # time is configured by the LiveMigrationRouteConvergenceTime field
        # in FelixConfiguration, defaulting to 30s.  The normal priority
        # route metric is configured by the IPv4NormalRoutePriority field in
        # FelixConfiguration.
        _log.info("Waiting 40s for TimeWait to expire...")
        time.sleep(40)
        metric = self._get_route_metric(target, vm_ip)
        _log.info("Route metric after TimeWait: %s", metric)
        assert metric == 1024, (
            "Route metric %d did not revert to normal (1024)" % metric
        )

        self.check_mutual_connectivity(self.vms)


class TestRapidSequentialMigration(LiveMigrationLatency):
    """
    Verify that connectivity survives rapid sequential migrations.
    """

    def test_rapid_migration_a_b_a(self):
        """
        Migrate A→B then immediately B→A while running a continuous
        ping.  Verify the connection survives both migrations with
        acceptable gaps.
        """
        self.check_mutual_connectivity(self.vms)

        target_ip = self.migrate_vm.get_ip_addr()

        ping_thread = self._measure_ping_gap(
            self.client_vm,
            target_ip,
            duration=180,
            interval=0.2,
        )
        time.sleep(3)

        # First migration.
        target1 = self._migration_target()
        _log.info("Migration 1: -> %s", target1.fqdn)
        self.migrate_vm.live_migrate(
            self.zonify(target1),
            block_migration=False,
            disk_over_commit=False,
        )
        self.migrate_vm.wait_for_state(
            "ACTIVE",
            retries=self.migrate_vm.image.active_time,
        )
        _log.info("Migration 1 complete")

        # Immediately migrate back.
        target2 = self._migration_target()
        _log.info("Migration 2: -> %s", target2.fqdn)
        self.migrate_vm.live_migrate(
            self.zonify(target2),
            block_migration=False,
            disk_over_commit=False,
        )
        self.migrate_vm.wait_for_state(
            "ACTIVE",
            retries=self.migrate_vm.image.active_time,
        )
        _log.info("Migration 2 complete")

        # Let ping run a bit longer to confirm stability.
        time.sleep(10)
        self.client_vm.execute("pkill ping || true")
        ping_result = ping_thread.join()

        _log.info("ping return code: %s", ping_result.return_code)

        gap = self._parse_ping_gap(ping_result.stdout, interval=0.2)
        _log.info("Measured max connectivity gap: %.1f seconds", gap)
        # Allow slightly more for two migrations.
        assert (
            gap <= MAX_MIGRATION_GAP_SECS * 2
        ), "Connectivity gap %.1fs exceeds maximum %ds for 2 migrations" % (
            gap,
            MAX_MIGRATION_GAP_SECS * 2,
        )

        self.check_mutual_connectivity(self.vms)
