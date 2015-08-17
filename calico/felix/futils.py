# -*- coding: utf-8 -*-

# Copyright (c) 2014, 2015 Metaswitch Networks
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
import logging
import os
from types import StringTypes
import types
import gc
import gevent.lock
from gevent import subprocess
from gevent.subprocess import Popen
import tempfile
import time
from posix_spawn import posix_spawnp, FileActions

try:
    import resource
except ImportError:
    resource = None

from collections import namedtuple

CommandOutput = namedtuple('CommandOutput', ['stdout', 'stderr'])

# Logger
log = logging.getLogger(__name__)
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


class FailedSystemCall(Exception):
    def __init__(self, message, args, retcode, stdout, stderr, input=None):
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
                 self.stdout, self.stderr, self.input))


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


class SpawnedProcess(Popen):
    def _execute_child(self, args, executable, preexec_fn, close_fds,
                       cwd, env, universal_newlines,
                       startupinfo, creationflags, shell,
                       p2cread, p2cwrite,
                       c2pread, c2pwrite,
                       errread, errwrite):
        """Execute program (POSIX version)"""

        if preexec_fn is not None:
            raise NotImplementedError("preexec_fn not supported")
        if close_fds:
            raise NotImplementedError("close_fds not implemented")
        if cwd:
            raise NotImplementedError("cwd not implemented")
        if universal_newlines:
            raise NotImplementedError()
        assert startupinfo is None and creationflags == 0

        log.debug("Pipes: p2c %s, %s; c2p %s, %s; err %s, %s",
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

        file_actions = FileActions()
        # Close parent's pipe ends
        if p2cwrite is not None:
            file_actions.add_close(p2cwrite)
        if c2pread is not None:
            file_actions.add_close(c2pread)
        if errread is not None:
            file_actions.add_close(errread)

        # When duping fds, if there arises a situation
        # where one of the fds is either 0, 1 or 2, it
        # is possible that it is overwritten (#12607).
        fds_to_close_in_parent = []
        if c2pwrite == 0:
            c2pwrite = os.dup(c2pwrite)
            fds_to_close_in_parent.append(c2pwrite)
        if errwrite == 0 or errwrite == 1:
            errwrite = os.dup(errwrite)
            fds_to_close_in_parent.append(errwrite)

        # Dup fds for child
        def _dup2(a, b):
            if a is None:
                a = b
            # Need to take a dup so we can remove the non-blocking flag
            a_dup = os.dup(a)
            log.debug("Duped %s as %s", a, a_dup)
            fds_to_close_in_parent.append(a_dup)
            self._remove_nonblock_flag(a_dup)
            file_actions.add_dup2(a_dup, b)
        _dup2(p2cread, 0)
        _dup2(c2pwrite, 1)
        _dup2(errwrite, 2)

        # Close pipe fds.  Make sure we don't close the
        # same fd more than once, or standard fds.
        closed = set([None])
        for fd in [p2cread, c2pwrite, errwrite]:
            if fd not in closed and fd > 2:
                file_actions.add_close(fd)
                closed.add(fd)

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

        # Parent
        self._watcher = self._loop.child(self.pid)
        self._watcher.start(self._on_child, self._watcher)

        if gc_was_enabled:
            gc.enable()

        if p2cread is not None and p2cwrite is not None:
            os.close(p2cread)
        if c2pwrite is not None and c2pread is not None:
            os.close(c2pwrite)
        if errwrite is not None and errread is not None:
            os.close(errwrite)


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
    log.debug("Calling out to system : %s.  %s/%s concurrent calls",
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
    if retcode:
        raise FailedSystemCall("Failed system call",
                               args, retcode, stdout, stderr, input=input_str)

    return CommandOutput(stdout, stderr)


def multi_call(ops):
    """
    Issue multiple ops, all of which must succeed.
    """
    log.debug("Calling out to system : %s" % ops)

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


class StatCounter(object):
    def __init__(self, name):
        self.name = name
        self.stats = collections.defaultdict(lambda: 0)
        register_diags(name, self._dump)

    def increment(self, stat, by=1):
        self.stats[stat] += by

    def _dump(self, log):
        stats_copy = self.stats.items()
        for name, stat in sorted(stats_copy):
            log.info("%s: %s", name, stat)


def register_process_statistics():
    """
    Called once to register a stats handler for process-specific information.
    """
    if resource is None:
        log.warning(
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
            log.exception("Exception in wrapped function %s", fn)
            raise
    return wrapped


def intern_dict(d, fields_to_intern=None):
    """
    Return a copy of the input dict where all its string/unicode keys
    are interned, optionally interning some of its values too.

    Caveat: assumes that it is safe to convert the keys and interned values
    to str by calling .encode("utf8") on each string.

    :param dict[StringTypes,...] d: Input dict.
    :param set[StringTypes] fields_to_intern: set of field names whose values
        should also be interned.
    :return: new dict with interned keys/values.
    """
    fields_to_intern = fields_to_intern or set()
    out = {}
    for k, v in d.iteritems():
        # We can't intern unicode strings, as returned by etcd but all our
        # keys should be ASCII anyway.  Use the utf8 encoding just in case.
        k = intern(k.encode("utf8"))
        if k in fields_to_intern:
            if isinstance(v, StringTypes):
                v = intern(v.encode("utf8"))
            elif isinstance(v, list):
                v = intern_list(v)
        out[k] = v
    return out


def intern_list(l):
    """
    Returns a new list with interned versions of the input list's contents.

    Non-strings are copied to the new list verbatim.  Returned strings are
    encoded using .encode("utf8").
    """
    out = []
    for item in l:
        if isinstance(item, StringTypes):
            item = intern(item.encode("utf8"))
        out.append(item)
    return out
