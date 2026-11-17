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

import atexit
import logging
import os
import re
import shutil
import subprocess
import threading
import time

import netaddr

from calicotest import settings
from calicotest.common.log_analyzer import LogAnalyzer
from calicotest.common.osutils import ensure_dir_exists
from calicotest.common.testutils import log_banner
from calicotest.common.testutils import retry_until_success, TestWithHooks
from calicotest.openstack.config import LAYOUT

_log = logging.getLogger(__name__)

# Regex to match the diags filename in calico-diags output.
DIAGS_RE = re.compile('Diags saved to \\"(.*)\\" and compressed to \\"(.*)\\"')

# Regex to match felix log entries.  Notes:
# - Golang timestamps use '.' vs Python's ',' for separating milliseconds.
#   Hence, we match with a regex '.' (any character) rather than '\\.'.
# - Python log entries have a PID and TID [123/456], whereas Golang logs only
#   have a PID.
FELIX_LOG_FORMAT = (
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).\d{0,3} "
    r"\[(?P<loglevel>\w+)\]"
    r"\[(?P<pid>\d+)(/\d+)?\] "
    r"(?P<logtext>.*)"
)

NEUTRON_LOG_FORMAT = (
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r".\d{0,3} (?P<pid>\d+) "
    r"(?P<loglevel>\w+) "
    r"(?P<logtext>.*)"
)
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# The diags files are known to produce certain spurious logs.  Ignore these
# logs in the file.
LOGS_IGNORE_ALL_TESTS = [
    "IOError: [Errno 2]",
    "IOError: [Errno 19]",
    "IOError: [Errno 22]",
    "Deadlock found when trying to get lock; try restarting transaction",
    # From python-etcd, whenever a request fails.  Our code will make its own
    # logs if the error is unexpected.
    "Request to server http://localhost:4001 failed",
    "StaleDataError: UPDATE statement on table 'ports' expected to update 1 row(s); 0",
    "AMQP server on ",
    "dhcp_agent_fanout",
    # Neutron can generate DB transactions that fail, and when that happens the
    # Neutron server log can contain errors like this:
    #
    # ERROR oslo_db.sqlalchemy.exc_filters
    # [req-44d559ca-cd8f-4b39-92bc-5dd882169c10
    # 64af4a68f0cf4533874fb7070ca59263 dcc158bac9d645bdb7d7a641d73f0d4c -
    # default default] DBAPIError exception wrapped from
    # (pymysql.err.InternalError) (1305, u'SAVEPOINT sa_savepoint_3 does not
    # exist') [SQL: u'ROLLBACK TO SAVEPOINT sa_savepoint_3']: InternalError:
    # (1305, u'SAVEPOINT sa_savepoint_3 does not exist')
    #
    # What has happened is that the mysql server rolls back itself, and Neutron
    # also asks for a rollback but the savepoint is no longer available
    # (https://bugs.launchpad.net/neutron/+bug/1590298).  Neutron now handles
    # this as a retriable condition, but we still get the traceback in the log,
    # so we have to ignore it here.
    "oslo_db.sqlalchemy.exc_filters",
    # The Noble version of sqlalchemy emits ERROR logs about "do not call blocking
    # functions from the mainloop", but they do not appear to cause any real problem.
    # We will fix these eventually, either by improving our DB access coding, or by
    # removing use of eventlet, but for now it is unhelpful to have tests failing for
    # this reason, as that can obscure more important issues.
    "sqlalchemy.pool.impl.QueuePool",
]

LOGS_IGNORE_GR_EXPECTED_LOGS = LOGS_IGNORE_ALL_TESTS + [
    "Connection to etcd failed, will retry.",
    "Failed to delete chain felix",
    "KeyNotFound: Key not found",
    "Failed to report status for",
    "DB exception wrapped",
    "EtcdConnectionFailed: Connection to etcd failed due to MaxRetryError",
    "Socket closed by other end",
    "etcd cluster is unavailable or misconfigured",
    "Broken pipe",
    "Felix must exit",
    "Felix must be restarted",
    "Failed to read from front-end socket",
    "Dataplane driver process stopped",
    "failed to check in",
    # golang-dp-driver: log emitted when an os.exec() is canceled due to SIGTERM.
    "signal: terminated",
    # Since 2.1.0, Felix's managed shutdown logs that it's exiting.
    "Exiting",
]

# How often each ignore-list entry has matched an error log during this run, so that
# we can report at the end which entries matched nothing and so may be obsolete.
# Maps each entry to a dict from test class name to the number of error logs that
# the entry matched in that class's logs.  A class whose logs were checked with the
# entry in effect, but where it matched nothing, has a count of 0.
_ignore_list_matches = {}


@atexit.register
def _report_ignore_list_matches():
    """
    At the end of the run, log how often each ignore-list entry matched, and in
    particular which entries never matched.  Each line starts with
    "IGNORED-LOG-UNUSED:" or "IGNORED-LOG-USED:", so that these lines are easy to
    find in a CI job's log.

    An entry that matched nothing in one run is not necessarily obsolete, because
    some errors are only logged intermittently.  So this is input for a human
    decision, ideally comparing several runs.
    """
    if not _ignore_list_matches:
        return
    log_banner("IGNORE-LIST USAGE")
    for entry, matches_by_class in sorted(_ignore_list_matches.items()):
        total = sum(matches_by_class.values())
        if total == 0:
            _log.info(
                "IGNORED-LOG-UNUSED: %r (in effect for %d test classes)",
                entry,
                len(matches_by_class),
            )
        else:
            _log.info(
                "IGNORED-LOG-USED: %r matched %d error logs (%s)",
                entry,
                total,
                ", ".join(
                    "%s: %d" % (cls_name, n)
                    for cls_name, n in sorted(matches_by_class.items())
                    if n
                ),
            )


# Port that netcat will use to connect to on the listening machine.
NETCAT_PORT = 2389

# How long to run each netcat process, in seconds. Must be an integer. Testing
# show that 1 is too low a value to work consistently.
NETCAT_TIMEOUT = 2

# The amount of times we should attempt to run netcat if it's already running or
# is waiting for the listener to be created.
NETCAT_RETRIES = 50

# The message to attempt to send via netcat. Will be repeated NETCAT_MSG_AMOUNT,
# to trying to 'type' too much into the command line.
NETCAT_MSG = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor"
    " incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis"
    " nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
    " Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore"
    " eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt"
    " in culpa qui officia deserunt mollit anim id est laborum."
)

# The amount of times to repeat NETCAT_MSG in each message. Increase this to
# send longer messages, don't just lengthen NETCAT_MSG by some large amount, as
# else the commands will grow too long to type.
NETCAT_MSG_AMOUNT = 4


class TestBase(TestWithHooks):

    IGNORE_LOGS_LIST = LOGS_IGNORE_ALL_TESTS
    """
    Which list of logs to ignore when checking logs at the end of a test.

    A sub class may change this to a different list if known actions result
    in certain error logs that can be ignored.
    """

    log_analyzers = None

    @classmethod
    def setUpClass(cls):
        """
        Setup the class data common to this test suite.

        This just sets up any log analyzers that are used to check if any
        errors are raised during the test suite.

        Note that we do the log analysis at the test suite level because most
        of the interesting setup and teardown is at the class scope.
        """
        cls.log_analyzers = []

        # Add a log analyzer to look at the neutron server logs on the control
        # node, and log analyzers to each compute node to look at the felix
        # logs.
        cls.log_analyzers.append(
            LogAnalyzer(
                LAYOUT.control_node,
                LAYOUT.neutron_log_file,
                NEUTRON_LOG_FORMAT,
                TIMESTAMP_FORMAT,
                continuation_level="TRACE",
            )
        )
        for node in LAYOUT.compute_nodes:
            cls.log_analyzers.append(
                LogAnalyzer(
                    node, LAYOUT.felix_log_file, FELIX_LOG_FORMAT, TIMESTAMP_FORMAT
                )
            )

    @classmethod
    def tearDownClass(cls):
        """
        Common teardown processing.

        This just checks any logs generated during the test suite to ensure
        no errors were raised during any of the tests.
        """
        cls.check_logs_for_exceptions()

        log_banner("TEST TEAR DOWN COMPLETE: %s", cls.__name__)

    @classmethod
    def check_logs_for_exceptions(cls):
        """
        Check the logs for any error level logs and raises an exception if
        any are found.
        """
        _log.info("Checking logs for exceptions")
        for entry in cls.IGNORE_LOGS_LIST:
            _ignore_list_matches.setdefault(entry, {}).setdefault(cls.__name__, 0)
        hit_errors = False
        detail = ""
        for la in cls.log_analyzers:
            _log.debug("Analyzing logs from %s on %s", la.filename, la.ssh.fqdn)
            errors = la.get_latest_logs(logfilter=cls.log_filter_in_errors)
            if errors:
                hit_errors = True
                detail += (
                    "***** Start of errors in logs from %s on %s *****\n\n%s\n\n"
                    % (
                        la.filename,
                        la.ssh.fqdn,
                        "\n\n".join(map(str, errors)),
                    )
                )
                detail += "****** End of errors in logs from %s on %s ******\n\n" % (
                    la.filename,
                    la.ssh.fqdn,
                )
        if hit_errors:
            _log.error("%s", detail)
            cls.on_failure()

        assert not hit_errors, "Test failed due to errors in logs\n\n" + detail

    @classmethod
    def log_filter_in_errors(cls, log):
        """
        Return the log filter function used for filtering logs to leave behind
        just the error logs that will cause a test to fail.

        :return: True if the log is being filtered (i.e. is NOT an error log),
         otherwise returns False (it is an error log).

        Error logs that match any of the text in IGNORE_LOGS_LIST are ignored.
        """
        is_error = log.level in {"ERROR", "PANIC", "FATAL", "CRITICAL"}

        # ... unless the error message matches any of the text in our list of
        # known misbehaving logs.  Check every entry, rather than stopping at the
        # first match, so that _ignore_list_matches counts all the entries that
        # match.
        if is_error:
            matched = [txt for txt in set(cls.IGNORE_LOGS_LIST) if txt in log.msg]
            for txt in matched:
                by_class = _ignore_list_matches.setdefault(txt, {})
                by_class[cls.__name__] = by_class.get(cls.__name__, 0) + 1
            is_error = not matched

        return not is_error

    @classmethod
    def on_failure(cls, test_id=None):
        """
        If a test fails, collect diagnostics by running diags.sh from the
        calico repo on each host.
        """
        _log.info("Gathering diagnostics from failure")

        if test_id is None:
            test_id = cls.__name__

        ensure_dir_exists(settings.LOCAL_DIAGS_DIR)

        # Gather from every region's control + computes, so that multi-
        # region tests' failures get diags from all hosts and not just
        # the primary region's.  The per-region dicts are populated for
        # both single-region (one entry each) and multi-region setups.
        nodes = []
        for region, control in LAYOUT.control_node_by_region.items():
            nodes.append(control)
            nodes.extend(LAYOUT.compute_nodes_by_region.get(region, []))
        collected = []
        for node in nodes:
            try:
                local_file = cls.gather_diags_for_node(node, test_id)
                if local_file:
                    collected.append(local_file)
            except Exception:
                _log.exception("Failed to run calico-diags")
        _log.info("Finished gathering diagnostics from failure")
        cls.repack_diags(collected, test_id)

    @classmethod
    def repack_diags(cls, tarfiles, test_id):
        """
        Unpack per-node diags tarfiles, fix permissions so non-root
        users can read them, repack into a single archive, and clean
        up intermediaries.
        """
        if not tarfiles:
            _log.info("No diags tarfiles to repack")
            return

        diags_dir = settings.LOCAL_DIAGS_DIR
        combined_dir = os.path.join(diags_dir, test_id)
        os.makedirs(combined_dir, exist_ok=True)

        try:
            for tarfile in tarfiles:
                _log.info("Unpacking %s", tarfile)
                subprocess.run(
                    ["tar", "xf", tarfile, "-C", combined_dir],
                    check=True,
                )

            # Fix permissions so non-root users can read everything.
            subprocess.run(
                ["chmod", "-R", "a+rX", combined_dir],
                check=True,
            )

            # Repack into a single archive.
            combined_tar = os.path.join(diags_dir, "%s.tar.xz" % test_id)
            subprocess.run(
                ["tar", "-Jcf", combined_tar, "-C", diags_dir, test_id],
                check=True,
            )
            _log.info("Combined diags saved to %s", combined_tar)

            # Clean up per-node tarfiles now that repacking succeeded.
            for tarfile in tarfiles:
                try:
                    os.remove(tarfile)
                except OSError:
                    pass
        except Exception:
            _log.exception("Failed to repack diags")
        finally:
            # Always clean up the unpacked directory.
            shutil.rmtree(combined_dir, ignore_errors=True)

    @classmethod
    def gather_diags_for_node(cls, node, test_id):
        """
        Gather diagnostics from the specified node and gather the diags (using
        a filename based on the test and host).

        :param node: The node to gather diagnostics from
        :param test_id: Identifier used in the output filename.
        :returns: The local filename of the downloaded tarfile.
        """
        with node:
            results = node.execute(
                "ETCDCTL_V3='%s' sudo -E calico-diags" % settings.ETCDCTL_V3
            )
            if results.return_code:
                raise Exception(
                    "Error gathering diags:\nrc=%s\nstdout=%s\nstderr=%s"
                    % (results.return_code, results.stdout, results.stderr)
                )

            output_match = DIAGS_RE.search(results.stdout)
            if not output_match:
                raise Exception(
                    "No diags files declared:\nrc=%s\nstdout=%s\nstderr=%s"
                    % (results.return_code, results.stdout, results.stderr)
                )

            # Download the tar archive.
            output_dir = output_match.group(1)
            output_tar = output_match.group(2)

            if not output_dir:
                raise Exception("Diags output directory is blank")
            if not output_tar:
                raise Exception("Diags output tar is blank")

            filename = "%s.%s.tar.xz" % (test_id, node.vmname)
            local_filename = os.path.join(settings.LOCAL_DIAGS_DIR, filename)
            node.get_file(output_tar, local_filename)
            _log.debug("Downloaded diags to %s", local_filename)

            # Diags downloaded, now delete them.  Sanity check that the output
            # dir does not have a leading file separator (it should be a
            # relative path and we don't want to delete the file system
            # accidentally)
            if "*" in output_tar:
                raise Exception("Output tar contains a *")
            node.execute("sudo rm %s" % output_tar)
            if not output_dir.startswith(os.path.sep + "tmp" + os.path.sep):
                raise Exception(
                    "Output directory from diags script MUST start with /tmp/"
                )
            if "*" in output_dir:
                raise Exception("Output dir contains a *")
            node.execute("sudo rm -r %s" % output_dir)

            return local_filename

    def check_mutual_connectivity(
        self,
        pass_list,
        fail_list=None,
        retries=10,
        ipv4=True,
        ipv6=False,
        traffic="ping",
        source_list=None,
    ):
        """
        Checks connectivity (or lack thereof) between VMs

        Throws an exception if a VM cannot contact one it should be able to or
        if a VM can contact one it should not be able to.

        :param pass_list: A list of VMs that VMs in source_list should be able
                          to ping.
        :param fail_list: A list of VMs that VMs in source_list should not be
                          able to ping.
        :param ipv4:      Whether to test using IPv4
        :param ipv6:      Whether to test using IPv6
        :param traffic:   Whether to test using a ping or tcp traffic. Allowable
                          values are 'ping' or 'tcp'.
        :param source_list: A list of VMs to send pings from.  Defaults to
                          pass_list.
        """
        source_list = source_list or pass_list
        fail_list = fail_list or []

        def check_all():
            _log.info("(re)running parallel ping tests...")
            failures = []
            threads = []
            if traffic == "tcp":
                test_func = self.do_tcp_check
            elif traffic == "ping":
                test_func = self.do_ping_check
            else:
                raise ValueError("traffic argument was neither 'tcp' nor 'ping'")
            for vm in source_list:
                thread = threading.Thread(
                    target=test_func,
                    args=[failures, vm, pass_list, fail_list, ipv4, ipv6],
                )
                thread.daemon = True
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()
            self.assertFalse(failures, msg="Some failures: %s" % sorted(failures))

        retry_until_success(
            check_all,
            retries=retries,
            context_string="TestBase.check_mutual_connectivity",
        )

    def do_ping_check(
        self, failures, vm, pass_list, fail_list, ipv4=True, ipv6=False, num_bytes=56
    ):
        """
        Attempts to ping from the given vm, asserting that the pings to all
        those vms in pass_list succeed, and all those in the fail_list fail
        :param failures: A list to which we will append results of each ping
                         that gives an unexpected result
        :param vm: The vm to ping from
        :param pass_list: A list of VMs that should be pingable
        :param fail_list: A list of VMs that should not be pingable
        :param ipv4: Whether to test using IPv4
        :param ipv6: Whether to test using IPv6
        :param num_bytes: The number of bytes to ping with. Defaults to 56,
            which is the default for the ping command.
        :return:
        """
        try:
            for dest in pass_list:
                if dest == vm:
                    continue
                for ip in dest.get_all_addresses():
                    if (ip.version == 4 and ipv4) or (ip.version == 6 and ipv6):
                        can_ping = self.ping(vm=vm, dest_ip=ip, num_bytes=num_bytes)
                        _log.info(
                            "%s -> to %s (%s): %s",
                            vm.name,
                            dest.name,
                            ip,
                            (
                                "CAN PING (EXPECTED)"
                                if can_ping
                                else "CANNOT PING (WRONG)"
                            ),
                        )
                        if not can_ping:
                            failures.append(
                                "%s cannot ping %s (%s)" % (vm.name, dest.name, ip)
                            )
            for dest in fail_list:
                for ip in dest.get_all_addresses():
                    if (ip.version == 4 and ipv4) or (ip.version == 6 and ipv6):
                        can_ping = self.ping(vm=vm, dest_ip=ip, num_bytes=num_bytes)
                        _log.info(
                            "%s -/> to %s (%s): %s",
                            vm.name,
                            dest.name,
                            ip,
                            (
                                "CAN PING (WRONG)"
                                if can_ping
                                else "CANNOT PING (EXPECTED)"
                            ),
                        )
                        if can_ping:
                            failures.append(
                                "%s unexpectedly can ping %s (%s)"
                                % (vm.name, dest.name, ip)
                            )
        except BaseException as e:
            _log.exception("Failure in ping worker thread")
            failures.append("Failure in ping worker thread %r" % e)
            raise

    def check_connectivity_of_vms_with_targets(
        self, vms_with_targets, current_vms, retries=10, ipv4=True, ipv6=False
    ):
        """
        Given a list of the vms in our current setup, and details of which vms
        are allowed to ping which, we test each of these pings in turn to
        ensure all work as expected.  Assumes vms can ping themselves.
        :param vms_with_targets: A dictionary, the keys are vms we should use
                                 to ping, the values vms that that vms should
                                 be able to ping
        :param current_vms: All vms in our current setup
        :param retries: Number of tries to attempt the test before giving up
        :param ipv4: Whether we should perform our pings over ipv4
        :param ipv6: Whether we should perform our pings over ipv6
        :return:
        """

        def ping_all():
            _log.info("(re)running parallel ping tests...")
            failures = []
            threads = []
            for this_vm in vms_with_targets:
                pass_list = vms_with_targets[this_vm]
                fail_list = [
                    vm
                    for vm in current_vms
                    if vm not in pass_list and vm is not this_vm
                ]
                thread = threading.Thread(
                    target=self.do_ping_check,
                    args=[failures, this_vm, pass_list, fail_list, ipv4, ipv6],
                )
                thread.daemon = True
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()
            self.assertFalse(failures, msg="Some failures: %s" % sorted(failures))

        retry_until_success(
            ping_all,
            retries=retries,
            context_string="TestBase.check_connectivity_of_vms_with_targets",
        )

    def assert_can_ping(self, vm, dest_ip):
        """
        Assert that a VM can ping a given IP address. Shells out to the
        standard ping command, and and raises AssertionError if the return code
        is not zero.

        :param vm: The VM from which to ping. Is an instance of class Vm.
        :param dest_ip: The IP to attempt to ping. May be IPv4 or IPv6.
        """
        can_ping = self.ping(vm, dest_ip)

        # Note that this assumes that the VM only has one network
        src_ip = netaddr.IPAddress(list(vm.vm.addresses.values())[0][0]["addr"])
        self.assertTrue(
            can_ping,
            msg="Failed to ping from %s/%s to %s." % (vm.name, src_ip, dest_ip),
        )
        _log.debug("Successfully pinged from %s to %s.", src_ip, dest_ip)

    def assert_cannot_ping(self, vm, dest_ip):
        """
        Assert that a VM cannot ping a given IP address. Shells out to the
        standard ping command.

        :param vm: The VM from which to ping. Is an instance of class Vm.
        :param dest_ip: The IP to attempt to ping. May be IPv4 or IPv6.
        """
        can_ping = self.ping(vm, dest_ip)

        # Note that this assumes that the VM only has one network
        src_ip = netaddr.IPAddress(list(vm.vm.addresses.values())[0][0]["addr"])
        self.assertFalse(
            can_ping,
            msg="Unexpectedly can ping from %s/%s to %s." % (vm.name, src_ip, dest_ip),
        )
        _log.debug("Successfully pinged from %s to %s.", src_ip, dest_ip)

    # Any changes to the functionality or argument signature of this function
    # should be duplicated in fv_unit_tests/test_basetest_units.py:
    # TestPingFunctions.mock_ping(...)
    def ping(self, vm, dest_ip, num_bytes=56):
        """
        Return whether the given VM can ping the given IP.

        Shells out to the standard ping command.

        :param vm: The VM from which to ping. Is an instance of class Vm.
        :param dest_ip: The IP to attempt to ping. May be IPv4 or IPv6.
        :param num_bytes: The number of bytes to ping with. Defaults to 56,
            which is the default for the ping command.
        :returns True if the VM can ping that IP address, False if not.
        """
        dest_ip = netaddr.IPAddress(dest_ip)  # This is idempotent.
        self.assertEqual(vm.get_current_status(), "ACTIVE")

        command = "{{cmd}} -c 1 -s {bytes} -W 2 {ip}".format(
            bytes=num_bytes, ip=dest_ip
        )
        if dest_ip.version == 4:
            command = command.format(cmd="ping")
        elif dest_ip.version == 6:
            command = command.format(cmd="ping6")
        else:
            raise RuntimeError("Invalid IP format.")

        result = vm.execute(command)
        return result.return_code == 0

    def do_tcp_check(self, failures, vm, pass_list, fail_list, ipv4=True, ipv6=False):
        """
        Attempts to send tcp traffic from the given vm, asserting that the
        traffic to all those vms in pass_list succeed, and all those in the
        fail_list fail.
        :param failures: A list to which we will append results of each tcp
                         attempt that gives an unexpected result
        :param vm: The vm to send tpc traffic from
        :param pass_list: A list of VMs that should be reachable
        :param fail_list: A list of VMs that should not be reachable
        :param ipv4: Whether to test using IPv4
        :param ipv6: Whether to test using IPv6
        :return:
        """
        if ipv6:
            _log.warning(
                "TCP connectivity requested with IPv6, but this is not"
                "supported. Use IPv4 instead."
            )
        if not ipv4:
            _log.warning(
                "TCP connectivity requested without specifying IPv4. "
                "(Only IPv4 is supported)"
            )
        else:
            try:
                for dest in pass_list:
                    if dest == vm:
                        continue
                    for ip in dest.get_all_addresses():
                        if ip.version == 4:
                            can_tcp = self.check_tcp(
                                vm_sender=vm, vm_listen=dest, vm_listen_ip=ip
                            )
                            _log.info(
                                "%s --> to %s (%s): %s",
                                vm.name,
                                dest.name,
                                ip,
                                (
                                    "CAN TCP (EXPECTED)"
                                    if can_tcp
                                    else "CANNOT TCP (WRONG)"
                                ),
                            )
                            if not can_tcp:
                                failures.append("%s cannot tcp %s" % (vm.name, ip))
                for dest in fail_list:
                    for ip in dest.get_all_addresses():
                        if ip.version == 4:
                            can_tcp = self.check_tcp(
                                vm_sender=vm, vm_listen=dest, vm_listen_ip=ip
                            )
                            _log.info(
                                "%s -/> to %s (%s): %s",
                                vm.name,
                                dest.name,
                                ip,
                                (
                                    "CAN TCP (WRONG)"
                                    if can_tcp
                                    else "CANNOT TCP (EXPECTED)"
                                ),
                            )
                            if can_tcp:
                                failures.append(
                                    "%s unexpectedly can tcp %s" % (vm.name, ip)
                                )
            except BaseException as e:
                _log.exception("Failure in tcp worker thread")
                failures.append("Failure in tcp worker thread %r" % e)
                raise

    def check_tcp(self, vm_sender, vm_listen, vm_listen_ip):
        """
        Return whether vm_sender can pass tcp traffic to the vm_listen.

        Shells out to the standard netcat command.

        :param vm_sender: The VM from which to send tcp traffic. It is an
            instance of class Vm.
        :param vm_listen: The VM on which to receive tcp traffic. It is an
            instance of class Vm.
        :param vm_listen_ip: The IP of vm_listen. Should be IPv4.
        :returns True if vm_sender can pass tcp traffic to vm_listen, False if
            not.
        """
        # A list that the result from the netcat listener will store its result
        # in. Implemented as such so that we can get data back from the thread
        # it is in.
        return_val = [None]
        # Run netcat on the listener (i.e. receiver)
        thread_listen = threading.Thread(
            target=self.netcat_listener, args=[vm_listen, return_val]
        )
        thread_listen.daemon = True
        thread_listen.start()

        # Make sure that the thread's started.
        timeout = time.time() + 1
        while not thread_listen.is_alive():
            if time.time() > timeout:
                return False

        # Run netcat on the sender
        self.netcat_sender(vm_sender, vm_listen_ip)
        # Wait for a response
        thread_listen.join()
        # Did we get the response we were expecting?
        return (NETCAT_MSG + "\n") * NETCAT_MSG_AMOUNT == return_val[0]

    def netcat_listener(self, vm, return_val):
        """
        Sets up a netcat listener on the specified VM. Will return whatever it
        hears.
        :param vm: The VM to listen on. It is an instance of class Vm.
        :param return_val: A list we'll set our return value in.
        :return:
        """
        self.assertEqual(vm.get_current_status(), "ACTIVE")

        for _ in range(NETCAT_RETRIES):
            # Briefly run netcat and get a response.
            command = "nc -l -w {timeout} -p {port}".format(
                timeout=NETCAT_TIMEOUT, port=NETCAT_PORT
            )
            result = vm.execute(command)
            if "bind" in result.stderr:
                # We might already have netcat running, so wait for for the
                # previous instance to terminate. The error message we get for
                # already having a netcat running is 'nc: bind: Address already
                # in use'.
                time.sleep(0.1)
            else:
                break

        return_val[0] = result.stdout

    def netcat_sender(self, vm, dest_ip):
        """
        Sets up a netcat sender on the specified VM, sending a message to the
        specified IP.
        :param vm: The VM to send from. It is an instance of class Vm.
        :param dest_ip: The IP address to send to. May be IPv4 or IPv6
        :return:
        """
        dest_ip = netaddr.IPAddress(dest_ip)  # This is idempotent.
        self.assertEqual(vm.get_current_status(), "ACTIVE")

        for _ in range(NETCAT_MSG_AMOUNT):
            vm.execute("echo '{msg}' >> temp_file".format(msg=NETCAT_MSG))

        for _ in range(NETCAT_RETRIES):
            # Send our message via netcat.

            command = "cat temp_file | nc -w {timeout} {ip} {port}".format(
                timeout=NETCAT_TIMEOUT, ip=dest_ip, port=NETCAT_PORT
            )
            result = vm.execute(command)

            if "refused" in result.stderr:
                # If the listener hasn't been set up yet. The error message we
                # get for this is 'nc: can't connect to remote host (<address>):
                # Connection refused'.
                time.sleep(0.1)
            else:
                break

        vm.execute("rm -f temp_file")

    def assert_open_ports(self, nodes, expected_ports):
        """Checks that each node in nodes has the expected ports open.

        :param nodes: list of Node objects.
        :param expected_ports: list of nmap style port specs, e.g. "22/tcp".
        """
        for node in nodes:
            ports_to_scan = {"0-1024", 8080, 8088, 8888, 9090, 8090, 8775, 9091, 16509}
            # Add any additional port numbers that we need to cover
            # expected_ports.
            for p in expected_ports:
                port_num = int(p.split("/")[0])
                if port_num > 1024 and port_num not in ports_to_scan:
                    ports_to_scan.add(port_num)
            ports_to_scan = {str(p) for p in ports_to_scan}
            output = subprocess.check_output(
                [
                    "sudo",
                    "nmap",
                    "-T4",  # Go fast
                    "-sS",  # Scan TCP with SYN packets.
                    # No -sU.  Every caller's expected_ports is TCP-only, so
                    # the UDP half can never satisfy an assertion -- it can
                    # only break one.  Once a host endpoint policy is in
                    # place the nodes silently drop UDP, so nmap reports
                    # ~1000 ports as "open|filtered", which --open includes
                    # and the regex below matches as open.  It is also
                    # ruinously slow: unanswered UDP probes hit ICMP rate
                    # limiting, taking tens of minutes per host.
                    "-Pn",  # Skip ping, which may be blocked.
                    # Limit the ports scanned or it takes too long.
                    "-p%s" % ",".join([str(s) for s in sorted(ports_to_scan)]),
                    "--open",  # Only list open ports.
                    node.get_ipv4(),
                ]
            )
            output = output.decode("utf-8")
            _log.info("nmap output for host %s:\n%s" % (node, output))
            open_ports = set()
            for line in output.splitlines():
                # nmap output looks like this:
                # <some fluff>
                # PORT    STATE         SERVICE
                # 22/tcp  open          ssh
                # 111/tcp open          rpcbind
                # 179/tcp open          bgp
                m = re.match(r"^(\d+/\S+)\s+open.*", line)
                if m:
                    port = m.group(1)
                    open_ports.add(port)
            _log.info("Open ports on node %s: %s", node, open_ports)
            self.assertEqual(
                set(expected_ports),
                open_ports,
                "Unexpected ports open on node %s\nExpected: %r\nActual:   %r"
                % (node, expected_ports, open_ports),
            )

    def restart_bird(self):
        for node in LAYOUT.compute_nodes:
            result = node.execute("sudo service bird restart")
            if result.return_code != 0:
                result2 = node.execute("sudo systemctl restart bird")
                if result2.return_code != 0:
                    self.fail(
                        "Failed to restart BIRD: \n"
                        "Result of service restart: %r\n"
                        "Result of systemctl restart: %r" % (result, result2)
                    )

    def assert_node_can_ping_other_node(self, node_1, node_2):
        rc, stdout, stderr = node_1.execute("ping -c 1 -W 2 %s" % node_2.get_ipv4())
        self.assertEqual(rc, 0)

    def assert_node_cannot_ping_other_node(self, node_1, node_2):
        rc, stdout, stderr = node_1.execute("ping -c 1 -W 2 %s" % node_2.get_ipv4())
        self.assertNotEqual(rc, 0)


TestBase.fv_test = True  # By default all OpenStack tests are FV tests
