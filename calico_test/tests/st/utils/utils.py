# Copyright 2015 Metaswitch Networks
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
import socket
from time import sleep
import os
import pdb
from subprocess import check_output, STDOUT
from subprocess import CalledProcessError
from exceptions import CommandExecError
import re
import json
from pycalico.util import get_host_ips

LOCAL_IP_ENV = "MY_IP"
LOCAL_IPv6_ENV = "MY_IPv6"
logger = logging.getLogger(__name__)

ETCD_SCHEME = os.environ.get("ETCD_SCHEME", "http")
ETCD_CA = os.environ.get("ETCD_CA_CERT_FILE", "")
ETCD_CERT = os.environ.get("ETCD_CERT_FILE", "")
ETCD_KEY = os.environ.get("ETCD_KEY_FILE", "")
ETCD_HOSTNAME_SSL = "etcd-authority-ssl"

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
        try:
            # No env variable set; try to auto detect.
            socket_type = socket.AF_INET6 if v6 else socket.AF_INET
            s = socket.socket(socket_type, socket.SOCK_DGRAM)
            remote_ip = "2001:4860:4860::8888" if v6 else "8.8.8.8"
            s.connect((remote_ip, 0))
            ip = s.getsockname()[0]
            s.close()
        except BaseException:
            # Failed to connect, just try to get the address from the interfaces
            version = 6 if v6 else 4
            ips = get_host_ips(version)
            if ips:
                ip = str(ips[0])

    return ip


def log_and_run(command):
    try:
        logger.info(command)
        results = check_output(command, shell=True, stderr=STDOUT).rstrip()
        lines = results.split("\n")
        for line in lines:
            logger.info("  # %s", line)
        return results
    except CalledProcessError as e:
        # Wrap the original exception with one that gives a better error
        # message (including command output).
        logger.info("  # Return code: %s", e.returncode)
        raise CommandExecError(e)


def retry_until_success(function, retries=10, ex_class=Exception):
    """
    Retries function until no exception is thrown. If exception continues,
    it is reraised.

    :param function: the function to be repeatedly called
    :param retries: the maximum number of times to retry the function.
    A value of 0 will run the function once with no retries.
    :param ex_class: The class of expected exceptions.
    :returns: the value returned by function
    """
    for retry in range(retries + 1):
        try:
            result = function()
        except ex_class:
            if retry < retries:
                sleep(1)
            else:
                raise
        else:
            # Successfully ran the function
            return result


def debug_failures(fn):
    """
    Decorator function to decorate assertion methods to pause the live system
    when an assertion fails, allowing the user to debug the problem.
    :param fn: The function to decorate.
    :return: The decorated function.
    """
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            if (os.getenv("DEBUG_FAILURES") != None and
                os.getenv("DEBUG_FAILURES").lower() == "true"):
                logger.error("TEST FAILED:\n%s\nEntering DEBUG mode."
                             % e.message)
                pdb.set_trace()
            else:
                raise e
    return wrapped


@debug_failures
def check_bird_status(host, expected):
    """
    Check the BIRD status on a particular host to see if it contains the
    expected BGP status.

    :param host: The host object to check.
    :param expected: A list of tuples containing:
        (peertype, ip address, state)
    where 'peertype' is one of "Global", "Mesh", "Node",  'ip address' is
    the IP address of the peer, and state is the expected BGP state (e.g.
    "Established" or "Idle").
    """
    output = host.calicoctl("status")
    lines = output.split("\n")
    for (peertype, ipaddr, state) in expected:
        for line in lines:
            # Status table format is of the form:
            # +--------------+-------------------+-------+----------+-------------+
            # | Peer address |     Peer type     | State |  Since   |     Info    |
            # +--------------+-------------------+-------+----------+-------------+
            # | 172.17.42.21 | node-to-node mesh |   up  | 16:17:25 | Established |
            # | 10.20.30.40  |       global      | start | 16:28:38 |   Connect   |
            # |  192.10.0.0  |   node specific   | start | 16:28:57 |   Connect   |
            # +--------------+-------------------+-------+----------+-------------+
            #
            # Splitting based on | separators results in an array of the
            # form:
            # ['', 'Peer address', 'Peer type', 'State', 'Since', 'Info', '']
            columns = re.split("\s*\|\s*", line.strip())
            if len(columns) != 7:
                continue

            # Find the entry matching this peer.
            if columns[1] == ipaddr and columns[2] == peertype:

                # Check that the connection state is as expected.  We check
                # that the state starts with the expected value since there
                # may be additional diagnostic information included in the
                # info field.
                if columns[5].startswith(state):
                    break
                else:
                    msg = "Error in BIRD status for peer %s:\n" \
                          "Expected: %s; Actual: %s\n" \
                          "Output:\n%s" % (ipaddr, state, columns[5],
                                           output)
                    raise AssertionError(msg)
        else:
            msg = "Error in BIRD status for peer %s:\n" \
                  "Type: %s\n" \
                  "Expected: %s\n" \
                  "Output: \n%s" % (ipaddr, peertype, state, output)
            raise AssertionError(msg)


@debug_failures
def assert_number_endpoints(host, expected):
    """
    Check that a host has the expected number of endpoints in Calico
    Parses the "calicoctl endpoint show" command for number of endpoints.
    Raises AssertionError if the number of endpoints does not match the
    expected value.

    :param host: DockerHost object
    :param expected: int, number of expected endpoints
    :return: None
    """
    hostname = host.get_hostname()
    output = host.calicoctl("endpoint show")
    lines = output.split("\n")
    actual = 0

    for line in lines:
        columns = re.split("\s*\|\s*", line.strip())
        if len(columns) > 1 and columns[1] == hostname:
                actual = columns[4]
                break

    if int(actual) != int(expected):
        msg = "Incorrect number of endpoints: \n" \
              "Expected: %s; Actual: %s" % (expected, actual)
        raise AssertionError(msg)

@debug_failures
def assert_profile(host, profile_name):
    """
    Check that profile is registered in Calico
    Parse "calicoctl profile show" for the given profilename

    :param host: DockerHost object
    :param profile_name: String of the name of the profile
    :return: Boolean: True if found, False if not found
    """
    output = host.calicoctl("profile show")
    lines = output.split("\n")
    found = False

    for line in lines:
        columns = re.split("\s*\|\s*", line.strip())
        if len(columns) > 1 and profile_name == columns[1]:
                found = True
                break

    if not found:
        raise AssertionError("Profile %s not found in Calico" % profile_name)

def get_profile_name(host, network):
    """
    Get the profile name from Docker
    A profile is created in Docker for each Network object.
    The profile name is a randomly generated string.

    :param host: DockerHost object
    :param network: Network object
    :return: String: profile name
    """
    info_raw = host.execute("docker network inspect %s" % network.name)
    info = json.loads(info_raw)

    # Network inspect returns a list of dicts for each network being inspected.
    # We are only inspecting 1, so use the first entry.
    return info[0]["Id"]

@debug_failures
def assert_network(host, network):
    """
    Checks that the given network is in Docker
    Raises an exception if the network is not found

    :param host: DockerHost object
    :param network: Network object
    :return: None
    """
    try:
        host.execute("docker network inspect %s" % network.name)
    except CommandExecError:
        raise AssertionError("Docker network %s not found" % network.name)
