# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
import json
import logging
import os
import re
import socket
import sys
from subprocess import CalledProcessError
from subprocess import check_output, STDOUT

import termios

from tests.st.utils.exceptions import CommandExecError

LOCAL_IP_ENV = "MY_IP"
LOCAL_IPv6_ENV = "MY_IPv6"
logger = logging.getLogger(__name__)

ETCD_SCHEME = os.environ.get("ETCD_SCHEME", "http")
ETCD_CA = os.environ.get("ETCD_CA_CERT_FILE", "")
ETCD_CERT = os.environ.get("ETCD_CERT_FILE", "")
ETCD_KEY = os.environ.get("ETCD_KEY_FILE", "")
ETCD_HOSTNAME_SSL = "etcd-authority-ssl"

"""
Compile Regexes
"""
# Splits into groups that start w/ no whitespace and contain all lines below
# that start w/ whitespace
INTERFACE_SPLIT_RE = re.compile(r'(\d+:.*(?:\n\s+.*)+)')
# Grabs interface name
IFACE_RE = re.compile(r'^\d+: (\S+):')
# Grabs v4 addresses
IPV4_RE = re.compile(r'inet ((?:\d+\.){3}\d+)/\d+')
# Grabs v6 addresses
IPV6_RE = re.compile(r'inet6 ([a-fA-F\d:]+)/\d{1,3}')


def calicoctl(command):
    """
    Convenience function for abstracting away calling the calicoctl
    command.

    Raises a CommandExecError() if the command returns a non-zero
    return code.

    :param command:  The calicoctl command line parms as a single string.
    :return: The output from the command with leading and trailing
    whitespace removed.
    """
    calicoctl = os.environ.get("CALICOCTL", "/code/dist/calicoctl")

    if ETCD_SCHEME == "https":
        etcd_auth = "%s:2379" % ETCD_HOSTNAME_SSL
    else:
        etcd_auth = "%s:2379" % get_ip()
    # Export the environment, in case the command has multiple parts, e.g.
    # use of | or ;
    #
    # Pass in all etcd params, the values will be empty if not set anyway
    calicoctl = "export ETCD_AUTHORITY=%s; " \
                "export ETCD_SCHEME=%s; " \
                "export ETCD_CA_CERT_FILE=%s; " \
                "export ETCD_CERT_FILE=%s; " \
                "export ETCD_KEY_FILE=%s; %s" % \
                (etcd_auth, ETCD_SCHEME, ETCD_CA, ETCD_CERT, ETCD_KEY,
                 calicoctl)

    return log_and_run(calicoctl + " " + command)


def get_ip(v6=False):
    """
    Return a string of the IP of the hosts interface.
    Try to get the local IP from the environment variables.  This allows
    testers to specify the IP address in cases where there is more than one
    configured IP address for the test system.
    """
    env = LOCAL_IPv6_ENV if v6 else LOCAL_IP_ENV
    ip = os.environ.get(env)
    if not ip:
        logger.debug("%s not set; try to auto detect IP.", env)
        socket_type = socket.AF_INET6 if v6 else socket.AF_INET
        s = socket.socket(socket_type, socket.SOCK_DGRAM)
        remote_ip = "2001:4860:4860::8888" if v6 else "8.8.8.8"
        s.connect((remote_ip, 0))
        ip = s.getsockname()[0]
        s.close()
    else:
        logger.debug("Got local IP from %s=%s", env, ip)

    return ip


# Some of the commands we execute like to mess with the TTY configuration, which can break the
# output formatting. As a wrokaround, save off the terminal settings and restore them after
# each command.
_term_settings = termios.tcgetattr(sys.stdin.fileno())


def log_and_run(command, raise_exception_on_failure=True):
    def log_output(results):
        if results is None:
            logger.info("  # <no output>")

        lines = results.split("\n")
        for line in lines:
            logger.info("  # %s", line.rstrip())

    try:
        logger.info("%s", command)
        try:
            results = check_output(command, shell=True, stderr=STDOUT).rstrip()
        finally:
            # Restore terminal settings in case the command we ran manipulated them.  Note:
            # under concurrent access, this is still not a perfect solution since another thread's
            # child process may break the settings again before we log below.
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _term_settings)
        log_output(results)
        return results
    except CalledProcessError as e:
        # Wrap the original exception with one that gives a better error
        # message (including command output).
        logger.info("  # Return code: %s", e.returncode)
        log_output(e.output)
        if raise_exception_on_failure:
            raise CommandExecError(e)

def curl_etcd(path, options=None, recursive=True, ip=None):
    """
    Perform a curl to etcd, returning JSON decoded response.
    :param path:  The key path to query
    :param options:  Additional options to include in the curl
    :param recursive:  Whether we want recursive query or not
    :return:  The JSON decoded response.
    """
    if options is None:
        options = []
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        rc = check_output(
            "curl --cacert %s --cert %s --key %s "
            "-sL https://%s:2379/v2/keys/%s?recursive=%s %s"
            % (ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL,
               path, str(recursive).lower(), " ".join(options)),
            shell=True)
    else:
        rc = check_output(
            "curl -sL http://%s:2379/v2/keys/%s?recursive=%s %s"
            % (ip, path, str(recursive).lower(), " ".join(options)),
            shell=True)

    return json.loads(rc.strip())

def wipe_etcd(ip):
    # Delete /calico if it exists. This ensures each test has an empty data
    # store at start of day.
    curl_etcd("calico", options=["-XDELETE"], ip=ip)

    # Disable Usage Reporting to usage.projectcalico.org
    # We want to avoid polluting analytics data with unit test noise
    curl_etcd("calico/v1/config/UsageReportingEnabled",
                   options=["-XPUT -d value=False"], ip=ip)
