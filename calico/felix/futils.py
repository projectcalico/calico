# -*- coding: utf-8 -*-

# Copyright (c) 2014 Metaswitch Networks
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
import logging
import os
import re
import subprocess
import tempfile
import time

from collections import namedtuple
CommandOutput = namedtuple('CommandOutput', ['stdout', 'stderr'])

# Logger
log = logging.getLogger(__name__)

# Flag to indicate "IP v4" or "IP v6"; format that can be printed in logs.
IPV4 = "IPv4"
IPV6 = "IPv6"


class FailedSystemCall(Exception):
    def __init__(self, message, args, retcode, stdout, stderr):
        super(FailedSystemCall, self).__init__(message)
        self.args = args
        self.retcode = retcode
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        return ("%s (retcode : %s, args : %s)\n"
                "  stdout  : %s\n"
                "  stderr  : %s\n" %
                (self.message, self.retcode, self.args, self.stdout, self.stderr))


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
        
def check_call(args):
    """
    Substitute for the subprocess.check_call funtion. It has the following useful
    characteristics.

    - If the return code is non-zero, it throws an exception on error (and
      expects the caller to handle it). That exception contains the command
      output.
    - It returns a tuple with stdout and stderr.

    If the command supplied does not exist, then an OSError is thrown.
    """
    log.debug("Calling out to system : %s" % args)

    proc = subprocess.Popen(args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    retcode = proc.returncode
    if retcode:
        raise FailedSystemCall("Failed system call", args, retcode, stdout, stderr)

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


def time_ms():
    """
    Return the time in ms. We use this rather than directly calling time.time
    mostly because it makes it easier to mock out for test purposes.
    """
    return(int(time.time() * 1000))
