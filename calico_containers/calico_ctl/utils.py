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
import socket
import os
import sys
import sh
import docker
import textwrap
import netaddr
import docker.errors
import re

from pycalico.ipam import IPAMClient
from netaddr.core import AddrFormatError


DOCKER_VERSION = "1.16"
ORCHESTRATOR_ID = "docker"
hostname = socket.gethostname()
client = IPAMClient()
docker_client = docker.Client(version=DOCKER_VERSION,
                              base_url=os.getenv("DOCKER_HOST",
                                                 "unix://var/run/docker.sock"))

try:
    sysctl = sh.Command._create("sysctl")
except sh.CommandNotFound as e:
    print "Missing command: %s" % e.message


def enforce_root():
    """
    Check if the current process is running as the root user.
    :return: Nothing. sys.exit if not running as root.
    """
    if os.geteuid() != 0:
        print >> sys.stderr, "This command must be run as root."
        sys.exit(2)


def print_paragraph(msg):
    """
    Print a fixed width (80 chars) paragraph of text.
    :param msg: The msg to print.
    :return: None.
    """
    print "\n".join(textwrap.wrap(msg, width=80))
    print


def get_container_ipv_from_arguments(arguments):
    """
    Determine the container IP version from the arguments.

    :param arguments: Docopt processed arguments.
    :return: The IP version.  4, 6 or None.
    """
    version = None
    if arguments.get("--ipv4"):
        version = 4
    elif arguments.get("--ipv6"):
        version = 6
    elif arguments.get("<IP>"):
        version = netaddr.IPAddress(arguments.get("<IP>")).version
    elif arguments.get("<PEER_IP>"):
        version = netaddr.IPAddress(arguments.get("<PEER_IP>")).version
    elif arguments.get("<CIDR>"):
        version = netaddr.IPNetwork(arguments.get("<CIDR>")).version
    elif arguments.get("<CIDRS>"):
        version = netaddr.IPNetwork(arguments.get("<CIDRS>")[0]).version
    elif arguments.get("<START_IP>"):
        version = netaddr.IPNetwork(arguments.get("<START_IP>")).version

    return version


def validate_cidr(cidr):
    """
    Validate cidr is in correct CIDR notation

    :param cidr: IP addr and associated routing prefix
    :return: Boolean: True if valid IP, False if invalid
    """
    try:
        netaddr.IPNetwork(cidr)
        return True
    except (AddrFormatError, ValueError):
    # Some versions of Netaddr have a bug causing them to return a
    # ValueError rather than an AddrFormatError, so catch both.
        return False


def validate_ip(ip_addr, version):
    """
    Validate that ip_addr is a valid IPv4 or IPv6 address

    :param ip_addr: IP address to be validated
    :param version: 4 or 6
    :return: Boolean: True if valid, False if invalid.
    """
    assert version in (4, 6)

    if version == 4:
        return netaddr.valid_ipv4(ip_addr)
    if version == 6:
        return netaddr.valid_ipv6(ip_addr)


def validate_characters(input_string):
    """
    Validate that input_string passed only contains letters a-z,
    numbers 0-9, and symbols _ . -

    :param input_string: string to be validated
    :return: Boolean: True is valid, False if invalid
    """
    # List of valid characters that Felix permits
    valid_chars = '[a-zA-Z0-9_\.\-]'

    # Check for invalid characters
    if not re.match("^%s+$" % valid_chars, input_string):
        return False
    else:
        return True

