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


def check_ip_version(ip, version, cls):
    """
    Parses and checks that the given IP matches the provided version.
    :param ip: The IP (string) to check.
    :param version: The version
    :param cls: The type of IP object (IPAddress or IPNetwork)
    :return: The parsed object of type "type"
    """
    assert version in ("v4", "v6")
    try:
        parsed = cls(ip)
    except AddrFormatError:
        print "%s is not a valid IP address." % ip
        sys.exit(1)
    if "v%d" % parsed.version != version:
        print "%s is an IPv%d prefix, this command is for IP%s." % \
              (parsed, parsed.version, version)
        sys.exit(1)
    return parsed


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
    :return: The IP version.  One of "v4", "v6" or None.
    """
    version = None
    if arguments.get("--ipv4"):
        version = "v4"
    elif arguments.get("--ipv6"):
        version = "v6"
    elif arguments.get("<IP>"):
        version = "v%s" % netaddr.IPAddress(arguments.get("<IP>")).version
    elif arguments.get("<PEER_IP>"):
        version = "v%s" % netaddr.IPAddress(arguments.get("<PEER_IP>")).version
    elif arguments.get("<CIDR>"):
        version = "v%s" % netaddr.IPNetwork(arguments.get("<CIDR>")).version
    return version

