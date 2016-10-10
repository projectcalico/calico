# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
felix.futils
~~~~~~~~~~~~

Felix utilities.
"""
import collections
import functools
import hashlib
import inspect
import logging
import os
import re
import sys
import types
import gc
import urllib3
from datetime import datetime
import gevent.lock
from gevent import subprocess
from gevent.subprocess import Popen, check_output, CalledProcessError
import tempfile
import pkg_resources
from posix_spawn import posix_spawnp, FileActions
from prometheus_client import Gauge

try:
    import resource
except ImportError:
    resource = None

from collections import namedtuple

CommandOutput = namedtuple('CommandOutput', ['stdout', 'stderr'])

# Logger
_log = logging.getLogger(__name__)
stat_log = logging.getLogger("calico.stats")

# Flag to indicate "IP v4" or "IP v6"; format that can be printed in logs.
IPV4 = "IPv4"
IPV6 = "IPv6"
IP_TYPES = [IPV4, IPV6]
IP_VERSIONS = [4, 6]
IP_TYPE_TO_VERSION = {IPV4: 4, IPV6: 6}

SHORTENED_PREFIX = "_"

# Semaphore used to limit the number of concurrent shell-outs.  Prevents us
# from using an unbounded number of file handles for stdin/out/err handling.
# Tuning: <10 seemed noticeably worse 20-200 hovered around the same.  Chose
# a value at low end of that range to limit our impact on the system.
MAX_CONCURRENT_CALLS = 32
_call_semaphore = gevent.lock.Semaphore(MAX_CONCURRENT_CALLS)

DEFAULT_TRUNC_LENGTH = 1000


class FailedSystemCall(Exception):
    def __init__(self,
                 message="Failed system call",
                 args="<unknown>",
                 retcode="<unknown>",
                 stdout="<unknown>",
                 stderr="<unknown>",
                 input=None):
        super(FailedSystemCall, self).__init__(message)
        self.message = message
        self.args = args
        self.retcode = retcode
        self.stdout = stdout
        self.stderr = stderr
        self.input = input

    def __str__(self):
        return ("%s (retcode : %s, args : %s)\n"
                "  stdout  : %s\n"
                "  stderr  : %s\n"
                "  input  : %s\n" %
                (self.message, self.retcode, self.args,
                 safe_truncate(self.stdout),
                 safe_truncate(self.stderr),
                 safe_truncate(self.input)))


def safe_truncate(s, max_len=DEFAULT_TRUNC_LENGTH):
    if s is None:
        return s
    if not isinstance(s, basestring):
        s = str(s)
    snip = "...<snip>..."
    if len(s) > max_len:
        s = s[:(max_len+1)//2] + snip + s[-(max_len//2):]
    return s


def call_silent(args):
    """
    Wrapper round subprocess_call that discards all of the output to both
    stdout and stderr. *args* must be a list.

    Returns the return code of the system call.
    """
    try:
        check_call(args)
        return 0
    except FailedSystemCall as e:
        return e.retcode

if getattr(sys, "frozen", False):
    # Running as a pyinstaller frozen executable.  The gevent version check
    # will fail, but we know we're running with a new version so it's OK to
    # skip it.
    gevent_version = None  # pragma: no cover
else:
    gevent_version = pkg_resources.get_distribution("gevent").parsed_version


class SpawnedProcess(Popen):
    """
    Version of gevent's Popen implementation that uses posix_spawn
    instead of fork().

    This is much more efficient in a large process because it avoids
    the overhead of copying the memory-management tables, which
    blocks the entire process.
    """

    if (gevent_version is not None and
            gevent_version < pkg_resources.parse_version("1.1a1")):
        # gevent 1.0.
        def _execute_child(self, args, executable, preexec_fn, close_fds,
                           cwd, env, universal_newlines,
                           startupinfo, creationflags, shell,
                           p2cread, p2cwrite,
                           c2pread, c2pwrite,
                           errread, errwrite):
            self.__execute_child(args, executable, preexec_fn, close_fds,
                                 cwd, env, universal_newlines,
                                 startupinfo, creationflags, shell,
                                 p2cread, p2cwrite,
                                 c2pread, c2pwrite,
                                 errread, errwrite)
    else:
        # gevent 1.1 changed the API slightly.
        def _execute_child(self, args, executable, preexec_fn, close_fds,
                           pass_fds, cwd, env, universal_newlines,
                           startupinfo, creationflags, shell,
                           p2cread, p2cwrite,
                           c2pread, c2pwrite,
                           errread, errwrite,
                           restore_signals, start_new_session):
            assert not pass_fds
            assert not start_new_session
            self.__execute_child(args, executable, preexec_fn, close_fds,
                                 cwd, env, universal_newlines,
                                 startupinfo, creationflags, shell,
                                 p2cread, p2cwrite,
                                 c2pread, c2pwrite,
                                 errread, errwrite)

    def __execute_child(self, args, executable, preexec_fn, close_fds,
                        cwd, env, universal_newlines,
                        startupinfo, creationflags, shell,
                        p2cread, p2cwrite,
                        c2pread, c2pwrite,
                        errread, errwrite):
        """
        Executes the program using posix_spawn().

        This is based on the method from the superclass but the
        posix_spawn API forces a number of changes.  In particular:

        * When using fork() FDs are manipulated in the child process
          after the fork, but before the program is exec()ed.  With
          posix_spawn() this is done by passing a data-structure to
          the posix_spawn() call, which describes the FD manipulations
          to perform.

        * The fork() version waits until after the fork before
          unsetting the non-blocking flag on the FDs that the child
          has inherited.  In the posix_spawn() version, we cannot
          do that after the fork so we dup the FDs in advance and
          unset the flag on the duped FD, which we then pass to the
          child.
        """

        if preexec_fn is not None:
            raise NotImplementedError("preexec_fn not supported")
        if close_fds:
            raise NotImplementedError("close_fds not implemented")
        if cwd:
            raise NotImplementedError("cwd not implemented")  # pragma: no cover
        if universal_newlines:
            raise NotImplementedError()  # pragma: no cover
        assert startupinfo is None and creationflags == 0

        _log.debug("Pipes: p2c %s, %s; c2p %s, %s; err %s, %s",
                   p2cread, p2cwrite,
                   c2pread, c2pwrite,
                   errread, errwrite)

        if isinstance(args, types.StringTypes):
            args = [args]
        else:
            args = [a.encode("ascii") for a in args]

        if shell:
            args = ["/bin/sh", "-c"] + args
            if executable:
                args[0] = executable

        if executable is None:
            executable = args[0]

        self._loop.install_sigchld()

        # The FileActions object is an ordered list of FD operations for
        # posix_spawn to do in the child process before it execs the new
        # program.
        file_actions = FileActions()

        # In the child, close parent's pipe ends.
        if p2cwrite is not None:
            file_actions.add_close(p2cwrite)
        if c2pread is not None:
            file_actions.add_close(c2pread)
        if errread is not None:
            file_actions.add_close(errread)

        # When duping fds, if there arises a situation where one of the fds
        # is either 0, 1 or 2, it is possible that it is overwritten (#12607).
        fds_to_close_in_parent = []
        if c2pwrite == 0:
            c2pwrite = os.dup(c2pwrite)
            fds_to_close_in_parent.append(c2pwrite)
        if errwrite == 0 or errwrite == 1:
            errwrite = os.dup(errwrite)
            fds_to_close_in_parent.append(errwrite)

        # Dup stdin/out/err FDs in child.
        def _dup2(dup_from, dup_to):
            if dup_from is None:
                # Pass through the existing FD.
                dup_from = dup_to
            # Need to take a dup so we can remove the non-blocking flag
            a_dup = os.dup(dup_from)
            _log.debug("Duped %s as %s", dup_from, a_dup)
            fds_to_close_in_parent.append(a_dup)
            self._remove_nonblock_flag(a_dup)
            file_actions.add_dup2(a_dup, dup_to)
        _dup2(p2cread, 0)
        _dup2(c2pwrite, 1)
        _dup2(errwrite, 2)

        # Close pipe fds in the child.  Make sure we don't close the same fd
        # more than once, or standard fds.
        for fd in set([p2cread, c2pwrite, errwrite]):
            if fd > 2:
                file_actions.add_close(fd)

        gc_was_enabled = gc.isenabled()
        # FIXME Does this bug apply to posix_spawn version?
        try:
            # Disable gc to avoid bug where gc -> file_dealloc ->
            # write to stderr -> hang.  http://bugs.python.org/issue1336
            gc.disable()
            self.pid = posix_spawnp(
                executable,
                args,
                file_actions=file_actions,
                env=env,
            )
        except:
            if gc_was_enabled:
                gc.enable()
            raise
        finally:
            for fd in fds_to_close_in_parent:
                os.close(fd)

        # Capture the SIGCHILD.
        self._watcher = self._loop.child(self.pid)
        self._watcher.start(self._on_child, self._watcher)

        if gc_was_enabled:
            gc.enable()

        # Close the Child's pipe ends in the parent.
        if p2cread is not None and p2cwrite is not None:
            os.close(p2cread)
        if c2pwrite is not None and c2pread is not None:
            os.close(c2pwrite)
        if errwrite is not None and errread is not None:
            os.close(errwrite)


# Check that our Popen subclass correctly overrides the superclass method, in
# case upstream change the API.
_popen_exc_args = inspect.getargspec(Popen._execute_child)
_our_exc_args = inspect.getargspec(SpawnedProcess._execute_child)
assert _popen_exc_args == _our_exc_args, "SpawnedProcess._execute_child " \
                                         "does not correctly override " \
                                         "Popen._execute_child"


def check_call(args, input_str=None):
    """
    Substitute for the subprocess.check_call function. It has the following
    useful characteristics.

    - If the return code is non-zero, it throws an exception on error (and
      expects the caller to handle it). That exception contains the command
      output.
    - It returns a tuple with stdout and stderr.

    :raises FailedSystemCall: if the return code of the subprocess is non-zero.
    :raises OSError: if, for example, there is a read error on stdout/err.
    """
    _log.debug("Calling out to system: %s.  %s/%s concurrent calls",
               args,
               MAX_CONCURRENT_CALLS - _call_semaphore.counter,
               MAX_CONCURRENT_CALLS)

    stdin = subprocess.PIPE if input_str is not None else None

    with _call_semaphore:
        proc = SpawnedProcess(args,
                              stdin=stdin,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=input_str)

    retcode = proc.returncode
    _log.debug("Process finished with RC=%s: %s.", retcode, args)
    if retcode:
        raise FailedSystemCall("Failed system call",
                               args, retcode, stdout, stderr, input=input_str)

    return CommandOutput(stdout, stderr)


def multi_call(ops):
    """
    Issue multiple ops, all of which must succeed.
    """
    _log.debug("Calling out to system : %s", ops)

    fd, name = tempfile.mkstemp(text=True)
    f = os.fdopen(fd, "w")
    f.write("set -e\n")
    cmds = [ " ".join(op) + "\n" for op in ops ]
    for cmd in cmds:
        # We echo every command before running it for diagnosability
        f.write("echo Executing : " + cmd)
        f.write(cmd)

    f.close()

    check_call(["bash", name])
    os.remove(name)

def hex(string):
    """
    Convert a string to hex.
    """
    return string.encode('hex')


def net_to_ip(net_or_ip):
    return net_or_ip.split("/")[0]


def uniquely_shorten(string, length):
    """
    Take a string and deterministically shorten it to at most length
    characters. Tries to return the input string unaltered unless it would
    potentially conflict with a shortened result.  Shortened results are
    formed by applying a secure hash to the input and truncating it to length.
    """

    if len(string) <= length and not (len(string) == length and
                                      string.startswith(SHORTENED_PREFIX)):
        return string

    h = hashlib.sha256()
    h.update("%s " % length)
    h.update(string)
    hash_text = h.hexdigest()

    return SHORTENED_PREFIX + hash_text[:length-len(SHORTENED_PREFIX)]


_registered_diags = []


def register_diags(name, fn):
    _registered_diags.append((name, fn))


def sanitize_name(name):
    return re.sub(r'[^a-zA-Z0-9]', '_', name)


class StatCounter(object):
    def __init__(self, name):
        self.name = name
        self.stats = collections.defaultdict(lambda: 0)
        # We duplicate the stats to Prometheus gauges.
        self.prom_gauges = {}
        register_diags(name, self._dump)

    def increment(self, stat, by=1):
        self.stats[stat] += by
        # Update the associated Prometheus gauge.
        if stat not in self.prom_gauges:
            gauge = Gauge(sanitize_name("felix_" + self.name + " " + stat),
                          "%s: %s" % (self.name, stat))
            self.prom_gauges[stat] = gauge
        else:
            gauge = self.prom_gauges[stat]
        gauge.inc(by)

    def _dump(self, log):
        stats_copy = self.stats.items()
        for name, stat in sorted(stats_copy):
            log.info("%s: %s", name, stat)


def register_process_statistics():
    """
    Called once to register a stats handler for process-specific information.
    """
    if resource is None:
        _log.warning(
            'Unable to import resource module, memory diags not available'
        )
        return

    rusage_fields = [
        ('Execution time in user mode (seconds)', 'ru_utime'),
        ('Execution time in kernel mode (seconds)', 'ru_stime'),
        ('Maximum Resident Set Size (KB)', 'ru_maxrss'),
        ('Soft page faults', 'ru_minflt'),
        ('Hard page faults', 'ru_majflt'),
        ('Input events', 'ru_inblock'),
        ('Output events', 'ru_oublock'),
        ('Voluntary context switches', 'ru_nvcsw'),
        ('Involuntary context switches', 'ru_nivcsw'),
    ]

    def dump(log):
        process = resource.getrusage(resource.RUSAGE_SELF)
        for name, field in rusage_fields:
            data = getattr(process, field, 'None')
            log.info('%s: %s', name, data)

    register_diags('Process Statistics', dump)


def dump_diags():
    """
    Dump diagnostics to the log.
    """
    try:
        stat_log.info("=== DIAGNOSTICS ===")
        for name, diags_function in _registered_diags:
            stat_log.info("--- %s ---", name)
            diags_function(stat_log)
        stat_log.info("=== END OF DIAGNOSTICS ===")
    except Exception:
        # We don't want to take down the process we're trying to diagnose...
        try:
            stat_log.exception("Failed to dump diagnostics")
        except Exception:
            pass


def logging_exceptions(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except:
            _log.exception("Exception in wrapped function %s", fn)
            raise
    return wrapped


def iso_utc_timestamp():
    """
    :return: Current (wall clock) UTC timestamp in ISO-8601 "Z" format.
    """
    time_now = datetime.utcnow()
    time_formatted = time_now.replace(microsecond=0).isoformat() + 'Z'
    return time_formatted


def find_set_bits(mask):
    """Generates an integer for each set bit in the input.

    - The integer is the value of the relevant bit (as opposed to, say,
      its position).
    - Bits are returned in least to most significant order.

    :param int mask: The mask to choose bits from.
    """
    while mask > 0:
        next_mask = mask & (mask - 1)
        yield mask - next_mask
        mask = next_mask


def detect_ipv6_supported():
    """Checks whether we can support IPv6 on this host.

    :returns tuple[bool,str]: supported, reason for lack of support or None.
    """
    if not os.path.exists("/proc/sys/net/ipv6"):
        return False, "/proc/sys/net/ipv6 is missing (IPv6 compiled out?)"
    try:
        check_call(["which", "ip6tables"])
    except FailedSystemCall:
        return False, ("ip6tables not installed; Calico IPv6 support requires "
                       "Linux kernel v3.3 or above and ip6tables v1.4.14 or "
                       "above.")

    # Check for the existence of the IPv6 NAT table.
    try:
        check_call(["ip6tables-save", "--table", "nat"])
    except FailedSystemCall:
        return False, "Failed to load IPv6 NAT table"

    try:
        # Use -C, which checks for a particular rule.  We don't expect the rule
        # to exist but iptables will give us a distinctive error if the
        # rpfilter module is missing.
        proc = Popen(["ip6tables", "-C", "FORWARD", "-m", "rpfilter"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if "Couldn't load match" in err:
            return False, (
                "ip6tables is missing required rpfilter match module; "
                "Calico IPv6 support requires Linux kernel v3.3 or "
                "above and ip6tables v1.4.14 or above."
            )
    except OSError:
        return False, "Failed to execute ip6tables"
    return True, None


def check_command_deps():
    """Checks for the presence of our prerequisite commands such as iptables
    and conntrack.

    :raises SystemExit if commands are missing."""
    _log.info("Checking for iptables")
    try:
        ipt_version = check_output(["iptables", "--version"])
    except (CalledProcessError, OSError):
        _log.critical("Failed to execute iptables; Calico requires iptables "
                      "to be installed.")
        sys.exit(1)
    else:
        _log.info("iptables version: %s", ipt_version)

    _log.info("Checking for iptables-save")
    try:
        check_call(["which", "iptables-save"])
    except (FailedSystemCall, OSError):
        _log.critical("Failed to find iptables-save; Calico requires "
                      "iptables-save to be installed.")
        sys.exit(1)

    _log.info("Checking for iptables-restore")
    try:
        check_call(["which", "iptables-restore"])
    except (FailedSystemCall, OSError):
        _log.critical("Failed to find iptables-restore; Calico requires "
                      "iptables-restore to be installed.")
        sys.exit(1)

    _log.info("Checking for ipset")
    try:
        ipset_version = check_output(["ipset", "--version"])
    except (CalledProcessError, OSError):
        _log.critical("Failed to execute ipset; Calico requires ipset "
                      "to be installed.")
        sys.exit(1)
    else:
        _log.info("ipset version: %s", ipset_version)

    _log.info("Checking for conntrack")
    try:
        conntrack_version = check_output(["conntrack", "--version"])
    except (CalledProcessError, OSError):
        _log.critical("Failed to execute conntrack; Calico requires conntrack "
                      "to be installed.")
        sys.exit(1)
    else:
        _log.info("conntrack version: %s", conntrack_version)


def find_longest_prefix(strs):
    """Finds the longest common prefix of the given input strings.
    :param list[str]|set[str] strs: Input strings.
    :returns the longest common prefix, or None if the input list is empty."""
    longest_prefix = None
    for iface in strs:
        if longest_prefix is None:
            longest_prefix = iface
        elif not iface.startswith(longest_prefix):
            shared_len = min(len(longest_prefix), len(iface))
            i = 0
            for i in xrange(shared_len):
                p_char = longest_prefix[i]
                i_char = iface[i]
                if p_char != i_char:
                    longest_prefix = iface[:i]
                    break
            else:
                longest_prefix = longest_prefix[:shared_len]
    return longest_prefix


def report_usage_and_get_warnings(calico_version, hostname, cluster_guid, cluster_size, cluster_type):
    """Reports the cluster's guid, size and version to projectcalico.org.
    Logs out of date calico versions, to the standard log file.
    Logs warnings returned by the usage server. The warnings might including warning
    if using a version of Calico that is no longer supported

    :param calico_version: the calico version
    :param hostname: the agent's hostname
    :param cluster_guid: the unique cluster identifier
    :param cluster_size: the number of felix instances
    :cluster_type: the type of cluster
    """
    _log.info("report_usage_and_get_warnings calico_version=%s, hostname=%s, guid=%s, size=%s, cluster_type=%s", calico_version, hostname, cluster_guid, cluster_size, cluster_type)
    try:
        url = 'https://usage.projectcalico.org/UsageCheck/calicoVersionCheck'

        urllib3.disable_warnings()
        http = urllib3.PoolManager()
        fields = {
            'version': calico_version,
            'hostname': hostname,
            'guid': cluster_guid,
            'size': cluster_size,
            'cluster_type': cluster_type
        }
        # Exponential backoff retry
        # http://urllib3.readthedocs.io/en/latest/reference/urllib3.util.html#module-urllib3.util.retry
        # Note this retry is not required to prevent thundering herd, because the jitter takes care of that
        # It is simply an additional retry in case of dropped or lost connections.
        retries = urllib3.util.retry.Retry(connect=5, read=5, redirect=5, backoff_factor=1.0)

        # Send the Usage Report to projectcalico.org
        r = http.request('GET', url, fields=fields, retries=retries)
        reply = r.data.decode('utf-8')
        _log.info("usage_report status=%s, reply=%s", r.status, reply)
    except Exception:
        _log.exception("Exception in usage_report")
