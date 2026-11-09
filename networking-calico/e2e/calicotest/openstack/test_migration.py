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
import os
import subprocess
import time

from calicotest.common.ssh import SSH
from calicotest.common.testutils import ThreadWithReturn
from calicotest.openstack.basetest import LOGS_IGNORE_ALL_TESTS
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology
from calicotest.settings import CIRROS, LOCAL_DIAGS_DIR

_log = logging.getLogger(__name__)

# Per-test diagnostic artefacts (pcaps, conntrack event logs, /proc/net
# snapshots, ss snapshots, VM console log) are written under the standard
# calicotest LOCAL_DIAGS_DIR ("diags" relative to the test working
# directory).  One subdirectory per test run, suffixed with a timestamp so
# reruns don't clobber each other.


class Migration(Topology):
    """
    Superclass for setting up migration tests.
    """

    IGNORE_LOGS_LIST = LOGS_IGNORE_ALL_TESTS

    @classmethod
    def setUpClass(cls):
        super(Migration, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)

        # This topology requires at least three compute nodes.  We configure
        # two nodes in the same availability zone as migration moves a guest
        # between nodes in the same zone.
        assert (
            len(LAYOUT.compute_nodes) >= 3
        ), "Require 3 compute nodes for migration testing"

        cls.node1 = LAYOUT.compute_nodes[0]
        cls.node2 = LAYOUT.compute_nodes[1]
        cls.node3 = LAYOUT.compute_nodes[2]
        vm1_thread = cls.create_vm_parallel(availability_zone=cls.zonify(cls.node1))
        vm2_thread = cls.create_vm_parallel(availability_zone=cls.zonify(cls.node2))

        # Wait for the threads to complete and store the created VMs
        cls.vm1 = vm1_thread.join()
        cls.vm2 = vm2_thread.join()
        cls.vms = [cls.vm1, cls.vm2]

        # Change the availability zone of compute node 3 to be the
        # same as compute node 2.  cls.vm2 has been created on node 2
        # and migration will be to node 3.
        cls.controller.tenants["admin"].update_aggregate(
            cls.zonify(cls.node3), availability_zone=cls.zonify(cls.node2)
        )

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in cls.vms:
            cls.delete_vm(vm.name)
        super(Migration, cls).tearDownClass()


class TestNonLiveMigration(Migration):
    """
    Test that VMs remain communicable after moving to a new host.
    """

    def test_non_live_migration(self):
        """
        Test a stopped VM reestablishes communications after moving hosts.
        """
        # Verify connectivity before we attempt migration
        _log.debug("Verify connectivity before migration")
        self.check_mutual_connectivity(self.vms)

        # Migrate the VM and re-check connectivity.
        _log.info("Migrate now: %r", self.vm2)
        self.vm2.migrate()
        self.check_mutual_connectivity(self.vms)


class _LiveMigrationDiagnostics(object):
    """Per-test diagnostic capture for the live-migration tests.

    Always-on (runs whether the test passes or fails) so the capture
    machinery itself can be validated without needing to reproduce the
    rare RST.  All artefacts land in LOCAL_DIAGS_DIR/<test-id>-<timestamp>/.

    What gets captured:
      - tcpdump on the test rig and on every compute node, filtered to
        the migrating VM's IP, written as pcap.
      - `conntrack -E` event log on every compute node.
      - Periodic `ss` snapshot of the test rig's TCP socket to the VM,
        sampled twice a second.
      - /proc/net/snmp and /proc/net/netstat on each host, before and
        after the test (so MIB counter deltas can be computed by hand).
      - Cirros console log at the end (best-effort).

    Remote commands and file pulls all go through the existing
    paramiko-based Node abstraction (node.execute / node.get_file), so
    we inherit its host/key/username handling and don't have to
    duplicate it.  Long-running captures are started via
    `nohup … & echo $!` so node.execute() returns the PID immediately
    after the remote shell backgrounds the command.  stop() then
    SIGTERMs each captured PID via another node.execute().
    """

    def __init__(self, test_self):
        self.test = test_self
        # get_ip_addr returns a netaddr.IPAddress; force to str so it can be
        # used directly as an argv element (Popen rejects non-str/bytes args)
        # as well as interpolated into shell strings.
        self.vm_ip = str(test_self.vm2.get_ip_addr())
        ts = time.strftime("%Y%m%d-%H%M%S")
        safe_id = test_self.id().replace(":", "_").replace("/", "_")
        self.dir = os.path.join(LOCAL_DIAGS_DIR, f"{safe_id}-{ts}")
        os.makedirs(self.dir, exist_ok=True)
        self._bg = []  # local subprocess captures: (name, Popen, [files])
        self._remote_bg = []  # remote nohup captures: (name, node, pid)
        self._to_pull = []  # files to scp back: (node, remote_path, local_basename)
        # The set of compute nodes to capture on.  Use Node objects so we
        # pick up whatever the cluster layout tells us, not a hardcoded list.
        self.computes = [
            (f"compute{i + 1}", node) for i, node in enumerate(LAYOUT.compute_nodes[:3])
        ]

    # ----- entry / exit -----------------------------------------------------

    def start(self):
        _log.info("=== Diags directory: %s ===", self.dir)
        self._snapshot_round("before")
        self._start_local_pcap()
        for label, node in self.computes:
            self._start_remote_pcap(label, node)
            self._start_remote_conntrack_events(label, node)
        self._start_local_ss_loop()

    def stop(self):
        # Stop captures first so their output files are flushed before
        # we read or copy them.  Local first, then remote.
        for name, p, fhs in self._bg:
            try:
                p.terminate()
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _log.warning("%s did not exit on TERM; killing", name)
                p.kill()
                p.wait()
            except Exception as e:
                _log.warning("Error stopping %s: %s", name, e)
            for f in fhs:
                try:
                    f.close()
                except Exception:
                    pass
            _log.info("Stopped %s (rc=%s)", name, p.returncode)

        for name, node, pid in self._remote_bg:
            self._stop_remote_one(name, node, pid)

        for node, remote_path, local_basename in self._to_pull:
            self._pull(node, remote_path, local_basename)

        self._snapshot_round("after")
        self._dump_console_log()

        try:
            files = sorted(os.listdir(self.dir))
            _log.info(
                "=== Diags collected in %s ===\n  %s", self.dir, "\n  ".join(files)
            )
        except Exception as e:
            _log.warning("Could not list diags directory %s: %s", self.dir, e)

    # ----- background captures ---------------------------------------------

    def _start_local_pcap(self):
        path = os.path.join(self.dir, "test-node.pcap")
        # -U flushes per-packet; -s 0 captures full frame; "host VM_IP" keeps the file
        # small.  calicotest/scripts/run-test.sh runs us under sudo so we should already
        # be root, but fall back to "sudo -n" if not.
        argv = [
            "tcpdump",
            "-n",
            "-s",
            "0",
            "-U",
            "-i",
            "any",
            "-w",
            path,
            "host",
            self.vm_ip,
        ]
        if os.geteuid() != 0:
            argv = ["sudo", "-n"] + argv
        self._start_bg("pcap-test-node", argv)

    def _start_remote_pcap(self, label, node):
        # tcpdump writes packets to `remote` itself via -w.  Crucially we
        # do NOT do a shell-level "> remote" here: that would have the
        # (unprivileged) shell pre-open the file, and tcpdump's drop to
        # the unprivileged "tcpdump" user (default on Debian/Ubuntu)
        # would then fail to reopen it via -w with "Permission denied".
        # Instead, discard tcpdump's own stdout/stderr; only its pcap
        # output (via -w) is interesting.
        remote = f"/tmp/diags-{label}-{int(time.time())}.pcap"
        self._start_remote_capture(
            name=f"pcap-{label}",
            node=node,
            command=(
                f"sudo -n tcpdump -n -s 0 -U -i any -w {remote} "
                f"host {self.vm_ip} > /dev/null 2>&1"
            ),
            remote_file=remote,
            local_basename=f"{label}.pcap",
        )

    def _start_remote_conntrack_events(self, label, node):
        # conntrack -E prints to its stdout; redirect at the shell level
        # so the (unprivileged) shell creates the file and conntrack
        # (under sudo) writes through the inherited fd.  File ownership
        # doesn't matter because the fd is already open by the time
        # privileges change.
        remote = f"/tmp/diags-conntrack-{label}-{int(time.time())}.log"
        self._start_remote_capture(
            name=f"conntrack-{label}",
            node=node,
            command=f"sudo -n conntrack -E -o timestamp,id -p tcp > {remote} 2>&1",
            remote_file=remote,
            local_basename=f"conntrack-{label}.log",
        )

    def _start_remote_capture(self, name, node, command, remote_file, local_basename):
        """Run `command` in the background on `node`.  The caller is
        responsible for `command` handling its own stdout/stderr (tcpdump
        uses -w; conntrack uses shell `>`) — see callers for why a
        one-size redirect in this helper doesn't work.

        We add nohup (so the backgrounded process survives the shell
        exit), a /dev/null stdin redirect (so the SSH server can close
        the channel), and `& echo $!` so node.execute() returns
        immediately with the PID.  The PID is captured into
        self._remote_bg so stop() can SIGTERM it; the file is queued for
        SFTP at stop() under `local_basename`.
        """
        full_cmd = f"nohup {command} < /dev/null & echo $!"
        _log.info("Starting remote %s on %s", name, node.fqdn)
        try:
            result = node.execute(full_cmd)
        except Exception as e:
            _log.warning("Failed to start %s on %s: %s", name, node.fqdn, e)
            return
        if result.return_code != 0:
            _log.warning(
                "Remote %s on %s exited rc=%s stderr=%r",
                name,
                node.fqdn,
                result.return_code,
                result.stderr,
            )
            return
        try:
            pid = int(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            _log.warning("Could not parse PID for %s from %r", name, result.stdout)
            return
        self._remote_bg.append((name, node, pid))
        self._to_pull.append((node, remote_file, local_basename))

    def _stop_remote_one(self, name, node, pid):
        """SIGTERM the remote process; wait up to 1s; SIGKILL if still alive."""
        try:
            node.execute(
                f"sudo -n kill -TERM {pid} 2>/dev/null; "
                "for i in 1 2 3 4 5; do "
                "  sleep 0.2; "
                f"  kill -0 {pid} 2>/dev/null || break; "
                "done; "
                f"sudo -n kill -KILL {pid} 2>/dev/null; true"
            )
        except Exception as e:
            _log.warning(
                "Failed to stop %s (pid=%s) on %s: %s", name, pid, node.fqdn, e
            )
            return
        _log.info("Stopped remote %s (pid=%s) on %s", name, pid, node.fqdn)

    def _start_local_ss_loop(self):
        path = os.path.join(self.dir, "ss-test-node.log")
        # Sample twice a second.  ss output for a single dst is small
        # (sub-kB) so even ~minute-long tests produce a manageable log.
        # Note: redirect must be on the compound statement; "exec while"
        # is a bash syntax error.
        script = (
            "while true; do "
            "  printf -- '--- %s ---\\n' \"$(date '+%s.%N %Y-%m-%dT%H:%M:%S.%6N')\"; "
            f"  ss --tcp --extended --info --options dst {self.vm_ip}; "
            "  sleep 0.5; "
            f"done > {path} 2>&1"
        )
        self._start_bg("ss-test-node", ["bash", "-c", script])

    def _start_bg(self, name, cmd):
        # Redirect both stdout and stderr to per-process files in the diags
        # dir, so even silent failures (binary not found, sudo refused,
        # remote command bad-syntax, etc.) leave evidence.  Polling
        # immediately after Popen catches commands that die before doing
        # anything useful.
        out_path = os.path.join(self.dir, f"{name}.stdout")
        err_path = os.path.join(self.dir, f"{name}.stderr")
        _log.info("Starting background %s: %r (stderr -> %s)", name, cmd, err_path)
        out_f = open(out_path, "wb")
        err_f = open(err_path, "wb")
        try:
            p = subprocess.Popen(
                cmd,
                stdout=out_f,
                stderr=err_f,
                start_new_session=True,
            )
        except Exception as e:
            _log.warning("Failed to start %s: %s", name, e)
            out_f.close()
            err_f.close()
            return
        self._bg.append((name, p, [out_f, err_f]))
        # Give the process a moment to either start producing output or
        # die.  Anything that exits in 100ms is broken at startup.
        time.sleep(0.1)
        rc = p.poll()
        if rc is not None:
            _log.warning(
                "Background %s exited immediately with rc=%s; "
                "see %s and %s for details",
                name,
                rc,
                out_path,
                err_path,
            )

    # ----- snapshots -------------------------------------------------------

    def _snapshot_round(self, when):
        """Capture /proc/net/snmp and /proc/net/netstat on every host."""
        # Test rig
        for proc_file in ("snmp", "netstat"):
            out_path = os.path.join(self.dir, f"proc-{proc_file}-test-node-{when}.txt")
            self._snapshot_local(out_path, ["cat", f"/proc/net/{proc_file}"])
        # Each compute
        for label, node in self.computes:
            for proc_file in ("snmp", "netstat"):
                out_path = os.path.join(
                    self.dir, f"proc-{proc_file}-{label}-{when}.txt"
                )
                self._snapshot_node(node, out_path, f"cat /proc/net/{proc_file}")

    def _snapshot_local(self, out_path, argv):
        try:
            r = subprocess.run(argv, capture_output=True, timeout=15)
            with open(out_path, "wb") as f:
                f.write(r.stdout)
                if r.stderr:
                    f.write(b"\n--- stderr ---\n")
                    f.write(r.stderr)
            _log.info("Snapshot %r -> %s", argv, out_path)
        except Exception as e:
            _log.warning("Snapshot %r failed: %s", argv, e)

    def _snapshot_node(self, node, out_path, remote_cmd):
        try:
            result = node.execute(remote_cmd)
            with open(out_path, "wb") as f:
                f.write(result.stdout.encode("utf-8", errors="replace"))
                if result.stderr:
                    f.write(b"\n--- stderr ---\n")
                    f.write(result.stderr.encode("utf-8", errors="replace"))
            _log.info("Snapshot %s on %s -> %s", remote_cmd, node.fqdn, out_path)
        except Exception as e:
            _log.warning("Snapshot %s on %s failed: %s", remote_cmd, node.fqdn, e)

    # ----- pulling artefacts back ------------------------------------------

    def _pull(self, node, remote_path, local_basename):
        local_path = os.path.join(self.dir, local_basename)
        try:
            node.get_file(remote_path, local_path)
            _log.info("Pulled %s:%s -> %s", node.fqdn, remote_path, local_path)
        except Exception as e:
            _log.warning("Failed to pull %s:%s: %s", node.fqdn, remote_path, e)
            return
        # Best-effort cleanup of the remote file.
        try:
            node.execute(f"sudo -n rm -f {remote_path}")
        except Exception as e:
            _log.warning("rm of %s on %s failed: %s", remote_path, node.fqdn, e)

    # ----- console log -----------------------------------------------------

    def _dump_console_log(self):
        try:
            # Some nova versions return empty when length is unspecified;
            # ask for a generous tail explicitly.
            console = self.test.vm2.vm.get_console_output(length=10000)
        except Exception as e:
            _log.warning("Could not fetch VM console log: %s", e)
            return
        path = os.path.join(self.dir, "vm-console.log")
        text = console or ""
        if not text:
            _log.warning("VM console log came back empty")
        try:
            with open(path, "w") as f:
                f.write(text)
            _log.info("Wrote VM console log (%d bytes) -> %s", len(text), path)
        except Exception as e:
            _log.warning("Could not write VM console log to %s: %s", path, e)


class TestLiveMigration(Migration):
    """
    Test that VMs remain communicable after moving to a new host.
    """

    def setUp(self):
        super(TestLiveMigration, self).setUp()
        self._diags = None
        try:
            self._diags = _LiveMigrationDiagnostics(self)
            self._diags.start()
        except Exception as e:
            _log.warning("Failed to set up diagnostics: %s", e)

    def tearDown(self):
        try:
            if self._diags is not None:
                self._diags.stop()
        except Exception as e:
            _log.warning("Failed to tear down diagnostics: %s", e)
        super(TestLiveMigration, self).tearDown()

    def test_live_migration(self):
        """
        Test a working VM retains communication after moving hosts.
        """
        # Verify connectivity before we attempt migration status
        _log.debug("Verify connectivity before migration")
        self.check_mutual_connectivity(self.vms)

        # Run an SSH connection to the VM while it is migrating, so
        # that we can check that the SSH connection continues working.
        # If the connection fails, ssh.execute() will raise an
        # exception, which the main thread will see when it calls
        # ssh_thread.join() below.
        #
        # Probe cadence and post-migration observation length are
        # independent knobs:
        #   - probe interval (50 ms) needs to be tight enough to land a
        #     segment inside the qemu stop-and-copy window;
        #   - observation length (3 s) gives BGP convergence and any
        #     post-migration TCP anomalies time to surface before we
        #     declare success.
        probe_interval_s = 0.05
        observe_after_migration_s = 3.0
        migration_done_at = None

        def ssh_to_migrating_vm():
            ssh = SSH(
                self.vm2.get_ip_addr(),
                CIRROS.username,
                CIRROS.password,
                desc="cirros-during-live-migration",
            )
            ssh.connect()
            _log.info("SSH connected to migrating VM")
            while True:
                _ = ssh.execute("date")
                if (
                    migration_done_at is not None
                    and time.monotonic() - migration_done_at
                    >= observe_after_migration_s
                ):
                    break
                time.sleep(probe_interval_s)

        ssh_thread = ThreadWithReturn(target=ssh_to_migrating_vm)
        ssh_thread.start()

        # We zonify the node to effectively get the "hostname" of the node.
        # OpenStack uses the short hostname rather than the FQDN which seems
        # to differ from what is displayed in the UI.
        _log.info("Live migrate VM %r to node3", self.vm2)
        try:
            self.vm2.live_migrate(
                self.zonify(self.node3), block_migration=False, disk_over_commit=False
            )
        # Ensure that the SSH thread finishes even if live_migrate(...) throws an
        # exception.
        finally:
            migration_done_at = time.monotonic()
            ssh_thread.join()

        # Recheck connectivity.
        self.check_mutual_connectivity(self.vms)
