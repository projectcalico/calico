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

from calicotest.common import logutils
from calicotest.common.testutils import retry_until_success
from calicotest.openstack.basetest import LOGS_IGNORE_GR_EXPECTED_LOGS
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import Topology

_log = logging.getLogger(__name__)


class TestConcurrentResync(Topology):
    """
    Test that Felix restarts cleanly, with a new and stable PID, after it is killed
    and after a config change that it can only apply by restarting.
    """

    IGNORE_LOGS_LIST = LOGS_IGNORE_GR_EXPECTED_LOGS + [
        "SocketClosed",
        "Socket closed by other end.",
        "Driver process died with RC",
        "Reader thread shutting down",
    ]

    @classmethod
    def setUpClass(cls):
        super(TestConcurrentResync, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        cls.test_node = LAYOUT.compute_nodes[0]
        cls.original_log_level = logutils.get_felix_log_level()

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        logutils.set_felix_log_level(cls.original_log_level)
        super(TestConcurrentResync, cls).tearDownClass()

    def setUp(self):
        pass

    def test_terminate_felix(self):
        """
        Test that Felix restarts after being sent SIGTERM.
        """
        _log.info("Killing Felix")
        self.run_command_and_check("sudo pkill --signal TERM calico-felix")

    def test_kill_kill_felix(self):
        """
        Test that Felix restarts after being sent SIGKILL.
        """
        _log.info("Killing Felix")
        self.run_command_and_check("sudo pkill -9 calico-felix")

    def test_change_config(self):
        """
        Test that when config (held in etcd) is changed, Felix restarts to take the
        new settings.
        """

        # Go round twice, toggling the LogSeverityFile setting so that
        # we end up in the same state we started in
        if self.original_log_level is None:
            log_setting_exists = False
        else:
            log_setting_exists = True
        for _ in range(2):
            if log_setting_exists:
                _log.info("Deleting LogSeverityFile")
                old_felix_pid = self.get_pid()
                logutils.set_felix_log_level(None)
                log_setting_exists = False
                self.check_felix_restart(old_felix_pid)
            else:
                _log.info("Setting LogSeverityFile to DEBUG")
                old_felix_pid = self.get_pid()
                logutils.set_felix_log_level("DEBUG")
                log_setting_exists = True
                self.check_felix_restart(old_felix_pid)
                retry_until_success(self.check_for_debug_logs)

    def get_pid(self):
        # Even when nothing should be changing, Felix periodically queries the
        # state of the local data path - routing, iptables etc. - so that it
        # can check that this matches what it should be (according to the
        # current etcd data), and these queries involve fork/exec to run shell
        # commands.  Hence there are windows (between each fork and the
        # corresponding exec) in which there can appear to be 2 Felix
        # processes, instead of the usual 1.  (And in practice those windows
        # are quite large when running on systems using QEMU, as on GCE and
        # AWS.)
        #
        # Therefore we retry getting Felix's PID, and checking that there is just 1
        # Felix, up to 5 times.
        return retry_until_success(self._get_pid, retries=5)

    def _get_pid(self):
        felix_pids = self.test_node.get_pids("calico-felix")
        _log.debug("Felix PIDs: %s", felix_pids)
        self.assertEqual(
            len(felix_pids),
            1,
            msg="Expected number of felix pids to be 1, got: %s %s"
            % (len(felix_pids), felix_pids),
        )
        return felix_pids[0]

    def check_pid_changed(self, old_felix_pid):
        # Check that the PID has changed.  i.e. felix has restarted.
        _log.info("Checking that felix has restarted with different PID")
        new_felix_pid = self.get_pid()
        self.assertNotEqual(
            old_felix_pid, new_felix_pid, msg="Felix PID should have changed"
        )

        # Then check that the PID is stable.  I.e. felix isn't in a crash loop.
        _log.info("Checking that new PID is stable")
        time.sleep(5)
        self.assertEqual(new_felix_pid, self.get_pid())

    def run_command_and_check(self, command):
        old_felix_pid = self.get_pid()
        _log.info("Running command %s on %s", command, self.test_node.fqdn)
        self.test_node.execute(command)
        self.check_felix_restart(old_felix_pid)

    def check_felix_restart(self, old_felix_pid):
        # Give the old Felix a moment to exit before we start checking for the new
        # one.  The checks are retried in any case.
        time.sleep(1)
        check = functools.partial(self.check_pid_changed, old_felix_pid)
        retry_until_success(check)

    def check_for_debug_logs(self):
        """
        Checks for the presence of debug logging in /var/log/calico/felix.log
        """
        _log.info("Checking for DEBUG logs in felix.log")
        command = "tail -100 /var/log/calico/felix.log"
        _, stdout, stderr = self.test_node.execute(command)
        if stderr:
            _log.warning("Hit error %s when running: %s", stderr, command)
        self.assertIn("[DEBUG]", stdout, msg="No debug logs found in felix.log")
        _log.info("Found DEBUG logs.")
