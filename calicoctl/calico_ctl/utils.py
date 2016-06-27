# Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
from __future__ import print_function

import os
import re
import sys
import textwrap
import urllib

import netaddr
from netaddr.core import AddrFormatError
from pycalico.util import get_hostname

DOCKER_VERSION = "1.16"
DOCKER_LIBNETWORK_VERSION = "1.21"
# There is an issue with 2.0.9 and CAS (when using py-etcd) - https://github.com/projectcalico/calico-containers/issues/479
ETCD_VERSION = "2.0.10"
DOCKER_ORCHESTRATOR_ID = "docker"
NAMESPACE_ORCHESTRATOR_ID = "namespace"
REQUIRED_MODULES = ["xt_set", "ip6_tables"]
hostname = get_hostname()

# Extracts UUID, version and container status from rkt list output.
RKT_CONTAINER_RE = re.compile("([a-z0-9]+)\s+.*calico\/node:([a-z0-9\.\_\-]+)\s+([a-z]+)\s+")


def enforce_root():
    """
    Check if the current process is running as the root user.
    :return: Nothing. sys.exit if not running as root.
    """
    if os.geteuid() != 0:
        print("This command must be run as root.", file=sys.stderr)
        sys.exit(2)


def running_in_container():
    """
    Check whether the current code is running in a container.
    :return: True if in a container. False otherwise.
    """
    return os.getenv("CALICO_CTL_CONTAINER")

def print_paragraph(msg, file=sys.stdout):
    """
    Print a fixed width (80 chars) paragraph of text.
    :param msg: The msg to print.
    :param file: The text stream to write to (default sys.stdout)
    :return: None.
    """
    print("\n".join(textwrap.wrap(msg, width=80)), file=file)
    print("", file=file)


def escape_etcd(path):
    """
    Escape a string to make it safe for use as a path in etcd.
    See https://github.com/coreos/etcd/issues/669
    :param path: The path to escape
    :return: The escaped path.
    """
    return path.replace('/', '-')


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


def convert_asn_to_asplain(asn):
    """
    Convert AS number to plain, decimal representation.
    If AS number is not in dot notation return the argument unmodified.
    Call validate_asn before this function to ensure AS number is valid.

    :param asn: AS number in either dot or plain notation
    :return: AS number in plain notation
    """
    if "." in str(asn):
        left_asn, right_asn = str(asn).split(".")
        asn = 65536*int(left_asn)+int(right_asn)

    return asn


def ipv6_enabled():
    """
    Return if IPv6 is enabled on the system.
    :return:  True if IPv6 is enabled on the system.
    """
    # If the OS has not been built with IPv6 then the /proc config for IPv6
    # will not be present.
    return os.path.exists('/proc/sys/net/ipv6')


class URLGetter(urllib.FancyURLopener):
    """
    Retrieves binaries.  Overridden in order to handle errors when
    attempting to download a binary.
    """
    def http_error_default(self, url, fp, errcode, errmsg, headers):
        """
        Called when an error response is returned - override to handle 404
        errors.
        """
        # Check for errors.
        if errcode == 404:
            # The requested URL does not exist.
            raise IOError()

        # Call the super-class
        urllib.FancyURLopener.http_error_default(self, url, fp, errcode,
                                                 errmsg, headers)
