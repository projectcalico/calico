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
import collections
from calico.felix.actor import Actor, actor_event
import gevent
from gevent import subprocess
import os
import socket
import struct

from calico import common
from calico.felix import futils

# Logger
import re

_log = logging.getLogger(__name__)


def interface_exists(interface):
    """
    Returns True if interface device exists.
    """
    return os.path.exists("/sys/class/net/" + interface)


def list_interface_ips(ip_type, interface):
    """
    List IP addresses for which there are routes to a given interface.
    Returns a set with all addresses for which there is a route to the device.
    """
    ips = set()

    if ip_type == futils.IPV4:
        data = futils.check_call(
            ["ip", "route", "list", "dev", interface]).stdout
    else:
        data = futils.check_call(
            ["ip", "-6", "route", "list", "dev", interface]).stdout

    lines = data.split("\n")

    _log.debug("Existing routes to %s : %s" % (interface, ",".join(lines)))

    for line in lines:
        #*********************************************************************#
        #* Example of the lines we care about is (having specified the       *#
        #* device above) :                                                   *#
        #* 10.11.2.66 proto static scope link                                *#
        #*********************************************************************#
        words = line.split()

        if len(words) > 1:
            ip = words[0]
            if common.validate_ip_addr(ip, futils.IP_TYPE_TO_VERSION[ip_type]):
                # Looks like an IP address. Note that we here are ignoring
                # routes to networks configured when the interface is created.
                ips.add(words[0])

    _log.debug("Found existing IP addresses : %s", ips)

    return ips


def configure_interface_ipv4(if_name):
    """
    Configure the various proc file system parameters for the interface for
    IPv4.

    Specifically, allow packets from controlled interfaces to be directed to
    localhost, and enable proxy ARP.

    :param if_name: The name of the interface to configure.
    :return: None
    """
    with open('/proc/sys/net/ipv4/conf/%s/route_localnet' % if_name, 'wb') as f:
        f.write('1')

    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % if_name, 'wb') as f:
        f.write('1')

    with open("/proc/sys/net/ipv4/neigh/%s/proxy_delay" % if_name, 'wb') as f:
        f.write('0')


def configure_interface_ipv6(if_name, proxy_target):
    """
    Configure an interface to support IPv6 traffic from an endpoint.
      - Enable proxy NDP on the interface.
      - Program the given proxy target (gateway the endpoint will use).

    :param if_name: The name of the interface to configure.
    :param proxy_target: IPv6 address which is proxied on this interface for
    NDP.
    :return: None
    :raises: FailedSystemCall
    """
    with open("/proc/sys/net/ipv6/conf/%s/proxy_ndp" % if_name, 'wb') as f:
        f.write('1')

    # Allows None if no IPv6 proxy target is required.
    if proxy_target:
        futils.check_call(["ip", "-6", "neigh", "add",
                           "proxy", str(proxy_target), "dev", if_name])


def add_route(ip_type, ip, interface, mac):
    """
    Add a route to a given interface (including arp config).
    Errors lead to exceptions that are not handled here.

    Note that we use "ip route replace", since that overrides any imported
    routes to the same IP, which might exist in the middle of a migration.

    :param ip_type: Type of IP (IPV4 or IPV6)
    :param str ip: IP address
    :param str interface: Interface name
    :param str mac: MAC address. May not be none unless ips is empty.
    :raises FailedSystemCall
    """
    if mac is None and ips:
        raise ValueError("mac must be supplied if ips is not empty")

    if ip_type == futils.IPV4:
        futils.check_call(['arp', '-s', ip, mac, '-i', interface])
        futils.check_call(["ip", "route", "replace", ip, "dev", interface])
    else:
        futils.check_call(["ip", "-6", "route", "replace", ip, "dev", interface])


def del_route(ip_type, ip, interface):
    """
    Delete a route to a given interface (including arp config).

    :param ip_type: Type of IP (IPV4 or IPV6)
    :param str ip: IP address
    :param str interface: Interface name
    :raises FailedSystemCall
    """
    if ip_type == futils.IPV4:
        futils.check_call(['arp', '-d', ip, '-i', interface])
        futils.check_call(["ip", "route", "del", ip, "dev", interface])
    else:
        futils.check_call(["ip", "-6", "route", "del", ip, "dev", interface])


def set_routes(ip_type, ips, interface, mac=None):
    """
    Set the routes on the interface to be the specified set.

    :param ip_type: Type of IP (IPV4 or IPV6)
    :param set ips: IPs to set up (any not in the set are removed)
    :param str interface: Interface name
    :param str mac|NoneType: MAC address. May not be none unless ips is empty.
    """
    if mac is None and ips:
        raise ValueError("mac must be supplied if ips is not empty")

    current_ips = list_interface_ips(ip_type, interface)
    for ip in (current_ips - ips):
        del_route(ip_type, ip, interface)
    for ip in (ips - current_ips):
        add_route(ip_type, ip, interface, mac)


def interface_up(if_name):
    """
    Checks whether a given interface is up.
    """
    with open('/sys/class/net/%s/operstate' % if_name, 'r') as f:
        state = f.read()
    _log.debug("Interface %s is in state %s", if_name, state)

    return 'up' in state


# These constants map to constants in the Linux kernel. This is a bit poor, but
# the kernel can never change them, so live with it for now.
RTMGRP_LINK = 1

NLMSG_NOOP = 1
NLMSG_ERROR = 2

RTM_NEWLINK = 16
RTM_DELLINK = 17

IFLA_IFNAME = 3

class RTNetlinkError(Exception):
    """
    How we report an error message.
    """
    pass

class InterfaceWatcher(Actor):
    def __init__(self, update_splitter):
        super(InterfaceWatcher, self).__init__()
        self.update_splitter = update_splitter
        self.interfaces = {}

    @actor_event
    def watch_interfaces(self):
        """
        Detects when interfaces appear, sending notifications to the update
        splitter.

        :returns: Never returns.
        """
        # Create the netlink socket and bind to RTMGRP_LINK,
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        s.bind((os.getpid(), RTMGRP_LINK))

        while True:
            # Get the next set of data.
            data = s.recv(65535)

            # First 16 bytes is the message header; unpack it.
            hdr = data[:16]
            data = data[16:]
            msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL", hdr)

            if msg_type == NLMSG_NOOP:
                # Noop - get some more data.
                continue
            elif msg_type == NLMSG_ERROR:
                # We have got an error. Raise an exception which brings the
                # process down.
                raise RTNetlinkError("Netlink error message, header : %s",
                                     futils.hex(hdr))

            # Now 16 bytes of netlink header.
            hdr = data[:16]
            data = data[16:]
            family, _, if_type, index, flags, change = struct.unpack("=BBHiII", hdr)

            # Bytes left is the message length minus the two headers of 16 bytes each.
            remaining = msg_len - 32

            while remaining:
                # The data content is an array of RTA objects, each of which
                # has a 4 byte header and some data.
                rta_len, rta_type = struct.unpack("=HH", data[:4])

                # This check comes from RTA_OK, and terminates a string of routing
                # attributes.
                if rta_len < 4:
                    break

                rta_data = data[4:rta_len]

                # Remove the RTA object from the data. The length to jump is
                # the rta_len rounded up to the nearest 4 byte boundary.
                increment = int((rta_len + 3) / 4) * 4
                data = data[increment:]
                remaining -= increment

                if rta_type == IFLA_IFNAME:
                    # We only really care about NEWLINK messages; if an
                    # interface goes away, we don't need to care (since it
                    # takes its routes with it, and the interface will
                    # presumably go away too). We do log though, just in case.
                    rta_data = rta_data[:-1]
                    if msg_type == RTM_NEWLINK:
                        _log.debug("Detected new network interface : %s", rta_data)
                        self.update_splitter.on_interface_update(rta_data)
                    else:
                        _log.debug("Network interface has gone away : %s", rta_data)
