# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
"""
felix.devices
~~~~~~~~~~~~

Utility functions for managing devices in Felix.
"""
import logging
import os
import time

from calico import common
from calico.felix import futils

# Logger
log = logging.getLogger(__name__)

def tap_exists(tap):
    """
    Returns True if tap device exists.
    """
    return os.path.exists("/sys/class/net/" + tap)


def list_tap_ips(type, tap):
    """
    List IP addresses for which there are routes to a given tap interface.
    Returns a set with all addresses for which there is a route to the device.
    """
    ips = set()

    if type == futils.IPV4:
        data = futils.check_call(
            ["ip", "route", "list", "dev", tap]).stdout
    else:
        data = futils.check_call(
            ["ip", "-6", "route", "list", "dev", tap]).stdout

    lines = data.split("\n")

    log.debug("Existing routes to %s : %s" % (tap, ",".join(lines)))

    for line in lines:
        #*********************************************************************#
        #* Example of the lines we care about is (having specified the       *#
        #* device above) :                                                   *#
        #* 10.11.2.66 proto static scope link                                *#
        #*********************************************************************#
        words = line.split()

        if len(words) > 1:
            ip = words[0]
            if common.validate_ipv4_addr(ip) or common.validate_ipv6_addr(ip):
                # Looks like an IP address to me
                ips.add(words[0])
            else:
                # Not an IP address; seems odd.
                log.warning("No IP address found in line %s for %s", line, tap)

    log.debug("Found existing IP addresses : %s", ips)

    return ips


def configure_tap(tap):
    """
    Configure the various proc file system parameters for the tap interface.

    Specifically, allow packets from tap interfaces to be directed to
    localhost, and enable proxy ARP.
    """
    with open('/proc/sys/net/ipv4/conf/%s/route_localnet' % tap, 'wb') as f:
        f.write('1')

    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % tap, 'wb') as f:
        f.write('1')

    with open("/proc/sys/net/ipv4/neigh/%s/proxy_delay" % tap, 'wb') as f:
        f.write('0')


def add_route(type, ip, tap, mac):
    """
    Add a route to a given tap interface (including arp config).
    Errors lead to exceptions that are not handled here.

    Note that we use "ip route replace", since that overrides any imported
    routes to the same IP, which might exist in the middle of a migration.
    """
    if type == futils.IPV4:
        futils.check_call(['arp', '-s', ip, mac, '-i', tap])
        futils.check_call(["ip", "route", "replace", ip, "dev", tap])
    else:
        futils.check_call(["ip", "-6", "route", "replace", ip, "dev", tap])


def del_route(type, ip, tap):
    """
    Delete a route to a given tap interface (including arp config).
    Errors lead to exceptions that are not handled here.
    """
    if type == futils.IPV4:
        futils.check_call(['arp', '-d', ip, '-i', tap])
        futils.check_call(["ip", "route", "del", ip, "dev", tap])
    else:
        futils.check_call(["ip", "-6", "route", "del", ip, "dev", tap])


def interface_up(if_name):
    """
    Checks whether a given interface is up.
    """
    with open('/sys/class/net/%s/operstate' % if_name, 'r') as f:
        state = f.read()

    return 'up' in state
