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

import errno
import logging
import os
import socket
import subprocess

import netaddr

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)


def ensure_dir_exists(path):
    """
    Ensure the supplied directory exists on the local server by creating it
    if it doesn't.

    :param path: The directory to create.
    """
    try:
        os.makedirs(path)
    except OSError as e:  # Python >2.5
        if e.errno == errno.EEXIST:
            pass
        else:
            raise


def get_local_ip(version=4):
    """
    Determine the local machine's IP address by attempting to connect to
    an arbitrary IP address.

    This isn't ideal since the machine may have multiple interfaces with
    routing rules set up for each interface.

    :return: The detected IP address, or None (if getting an IPv6 address
             and the local machine does not support IPv6)
    """
    assert version in [4, 6], "Unexpected IP version %s" % version

    af = socket.AF_INET if version == 4 else socket.AF_INET6
    dummy = "8.8.8.8" if version == 4 else "fe::"

    s = socket.socket(af, socket.SOCK_DGRAM)

    # The sock.connect() call can fail -- in the IPv6 case, this is a
    # sign that a machine does not have an IPv6 address.  For IPv4, it's
    # a bigger problem.
    try:
        s.connect((dummy, 53))
    except socket.error:
        if version == 4:
            raise
        else:
            _log.warning("Unable to detect an IPv6 address")
            return None

    ip = s.getsockname()[0]
    s.close()

    _log.debug("Determined local IP to be %s", ip)

    assert not ip.startswith("127.")

    if version == 4:
        assert netaddr.valid_ipv4(ip), "Invalid local IPv4 address: %s" % ip
    else:
        assert netaddr.valid_ipv6(ip), "Invalid local IPv6 address: %s" % ip

    return ip


def get_ip_6(host, port=80):
    """
    Determines ipv6 address for host (used below)
    :param host:
    :param port:
    :return:
    """

    alladdr = list(set([x[4] for x in socket.getaddrinfo(host, port)]))
    _log.debug("All addresses: \n%s", alladdr)
    ip6 = [x for x in alladdr if ":" in x[0]]
    _log.debug("IPv6 addrs:\n%s", ip6)
    return ip6[0][0]


def get_host_ip(host, version=4):
    """
    Determines the host ip address.
    :param host:
    :param version:
    :return:
    """

    if version == 4:
        ip = socket.gethostbyname(host)
        assert netaddr.valid_ipv4(ip), "Invalid IPv4 address for %s : %s" % (host, ip)
    else:
        ip = get_ip_6(host)
        assert netaddr.valid_ipv6(ip), "Invalid IPv6 address for %s : %s" % (host, ip)
    return ip


class MissingDependency(Exception):
    pass


def check_dependency(program):
    """
    Checks whether a dependency is installed using which.  Throws a
    MissingDependency exception if it can't be found.
    """
    try:
        subprocess.check_call(["which", program])
    except subprocess.CalledProcessError as e:
        _log.error("Failed to find dependency %s:", program)
        _log.error(e)
        raise MissingDependency("Failed to find dependency %s." % program)
