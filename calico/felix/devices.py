# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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
from calico.felix.actor import Actor, actor_message
import os
import socket
import struct

from calico import common
from calico.felix import futils

# Logger
from calico.felix.futils import FailedSystemCall

_log = logging.getLogger(__name__)


def check_kernel_config():
    """
    Checks the kernel configuration for problems that would break our
    security guarantees, for example.

    :raises BadKernelConfig if a problem is detected.
    """

    # To prevent workloads from spoofing their IP addresses, we need to set the
    # per-interface rp_filter setting to 1, which enables strict RPF checking.
    # Verify that the kernel's global setting won't override our per-interface
    # setting with an insecure value.
    ps_name = "/proc/sys/net/ipv4/conf/all/rp_filter"
    rp_filter = int(_read_proc_sys(ps_name))
    if rp_filter > 1:
        _log.critical("Kernel's RPF check is set to 'loose'.  This would "
                      "allow endpoints to spoof their IP address.  Calico "
                      "requires net.ipv4.conf.all.rp_filter to be set to "
                      "0 or 1.")
        raise BadKernelConfig("net.ipv4.conf.all.rp_filter set to 'loose'")


def interface_exists(interface):
    """
    Checks if an interface exists.
    :param str interface: Interface name
    :returns: True if interface device exists
    :raises: FailedSystemCall if ip link list fails.

    We could check under /sys/class/net here, but there's a window where
    /sys/class/net/<iface> might still exist for a link that is in the process
    of being deleted, so we use ip link list instead.
    """
    try:
        futils.check_call(["ip", "link", "list", interface])
        return True
    except futils.FailedSystemCall as fsc:
        if fsc.stderr.count("does not exist") != 0:
            return False
        else:
            # An error other than does not exist; just pass on up
            raise


def list_interface_ips(ip_type, interface):
    """
    List IP addresses for which there are routes to a given interface.
    :param str ip_type: IP type, either futils.IPV4 or futils.IPV6
    :param str interface: Interface name
    :returns: a set of all addresses for which there is a route to the device.
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
        # Example of the lines we care about is (having specified the
        # device above):  "10.11.2.66 proto static scope link"
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

    Specifically,
      - Allow packets from controlled interfaces to be directed to localhost
      - Enable proxy ARP
      - Enable the kernel's RPF check.

    :param if_name: The name of the interface to configure.
    :returns: None
    """
    # Enable the kernel's RPF check, which ensures that a VM cannot spoof
    # its IP address.
    _write_proc_sys('/proc/sys/net/ipv4/conf/%s/rp_filter' % if_name, 1)
    _write_proc_sys('/proc/sys/net/ipv4/conf/%s/route_localnet' % if_name, 1)
    _write_proc_sys("/proc/sys/net/ipv4/conf/%s/proxy_arp" % if_name, 1)
    _write_proc_sys("/proc/sys/net/ipv4/neigh/%s/proxy_delay" % if_name, 0)


def configure_interface_ipv6(if_name, proxy_target):
    """
    Configure an interface to support IPv6 traffic from an endpoint.
      - Enable proxy NDP on the interface.
      - Program the given proxy target (gateway the endpoint will use).

    :param if_name: The name of the interface to configure.
    :param proxy_target: IPv6 address which is proxied on this interface for
    NDP.
    :returns: None
    :raises: FailedSystemCall
    """
    _write_proc_sys("/proc/sys/net/ipv6/conf/%s/proxy_ndp" % if_name, 1)

    # Allows None if no IPv6 proxy target is required.
    if proxy_target:
        futils.check_call(["ip", "-6", "neigh", "add",
                           "proxy", str(proxy_target), "dev", if_name])


def _read_proc_sys(name):
    with open(name, "rb") as f:
        return f.read().strip()


def _write_proc_sys(name, value):
    with open(name, "wb") as f:
        f.write(str(value))


def add_route(ip_type, ip, interface, mac):
    """
    Add a route to a given interface (including arp config).
    Errors lead to exceptions that are not handled here.

    Note that we use "ip route replace", since that overrides any imported
    routes to the same IP, which might exist in the middle of a migration.

    :param ip_type: Type of IP (IPV4 or IPV6)
    :param str ip: IP address
    :param str interface: Interface name
    :param str mac: MAC address. May not be None unless ip is None.
    :raises FailedSystemCall
    """
    if mac is None and ip:
        raise ValueError("mac must be supplied if ip is provided")

    if ip_type == futils.IPV4:
        futils.check_call(['arp', '-s', ip, mac, '-i', interface])
        futils.check_call(["ip", "route", "replace", ip, "dev", interface])
    else:
        futils.check_call(["ip", "-6", "route", "replace", ip, "dev",
                           interface])


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


def set_routes(ip_type, ips, interface, mac=None, reset_arp=False):
    """
    Set the routes on the interface to be the specified set.

    :param ip_type: Type of IP (IPV4 or IPV6)
    :param set ips: IPs to set up (any not in the set are removed)
    :param str interface: Interface name
    :param str mac|NoneType: MAC address. May not be none unless ips is empty.
    :param bool reset_arp: Reset arp. Only valid if IPv4.
    """
    if mac is None and ips:
        raise ValueError("mac must be supplied if ips is not empty")
    if reset_arp and ip_type != futils.IPV4:
        raise ValueError("reset_arp may only be supplied for IPv4")

    current_ips = list_interface_ips(ip_type, interface)

    removed_ips = (current_ips - ips)
    for ip in removed_ips:
        del_route(ip_type, ip, interface)
    remove_conntrack_flows(removed_ips, 4 if ip_type == futils.IPV4 else 6)
    for ip in (ips - current_ips):
        add_route(ip_type, ip, interface, mac)
    if reset_arp:
        for ip in (ips & current_ips):
            futils.check_call(['arp', '-s', ip, mac, '-i', interface])


def interface_up(if_name):
    """
    Checks whether a given interface is up.

    Check this by examining the interface flags and looking for whether the
    IFF_UP flag has been set. IFF_UP is the flag 0x01, so read in the flags
    (represented by a hexadecimal integer) and check if the 1 bit is set.

    :param str if_name: Interface name
    :returns: True if interface up, False if down or cannot detect
    """
    flags_file = '/sys/class/net/%s/flags' % if_name

    try:
        with open(flags_file, 'r') as f:
            flags = f.read().strip()
            _log.debug("Interface %s has flags %s", if_name, flags)
    except IOError as e:
        # If we fail to check that the interface is up, then it has probably
        # gone under our feet or is flapping.
        _log.warning("Cannot check flags for interface %s (%s) - assume "
                     "down: %r.", if_name, flags_file, e)
        return False

    return bool(int(flags, 16) & 1)


def remove_conntrack_flows(ip_addresses, ip_version):
    """
    Removes any conntrack entries that use any of the given IP
    addresses in their source/destination.
    """
    assert ip_version in (4, 6)
    for ip in ip_addresses:
        _log.debug("Removing conntrack rules for %s", ip)
        for direction in ["--orig-src", "--orig-dst",
                          "--reply-src", "--reply-dst"]:
            try:
                futils.check_call(["conntrack", "--family",
                                   "ipv%s" % ip_version, "--delete",
                                   direction, ip])
            except FailedSystemCall as e:
                if e.retcode == 1 and "0 flow entries" in e.stderr:
                    # Expected if there are no flows.
                    _log.debug("No conntrack entries found for %s/%s.",
                               ip, direction)
                else:
                    # Suppress the exception, conntrack entries will timeout
                    # and it's hard to think of an example where killing and
                    # restarting felix would help.
                    _log.exception("Failed to remove conntrack flows for %s. "
                                   "Ignoring.", ip)


# These constants map to constants in the Linux kernel. This is a bit poor, but
# the kernel can never change them, so live with it for now.
RTMGRP_LINK = 1

NLMSG_NOOP = 1
NLMSG_ERROR = 2

RTM_NEWLINK = 16
RTM_DELLINK = 17

IFLA_IFNAME = 3
IFLA_OPERSTATE = 16
IF_OPER_UP = 6


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

    @actor_message()
    def watch_interfaces(self):
        """
        Detects when interfaces appear, sending notifications to the update
        splitter.

        :returns: Never returns.
        """
        # Create the netlink socket and bind to RTMGRP_LINK,
        s = socket.socket(socket.AF_NETLINK,
                          socket.SOCK_RAW,
                          socket.NETLINK_ROUTE)
        s.bind((os.getpid(), RTMGRP_LINK))

        # A dict that remembers the detailed flags of an interface
        # when we last signalled it as being up.  We use this to avoid
        # sending duplicate interface_update signals.
        if_last_flags = {}

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
            _log.debug("Netlink message type %s len %s", msg_type, msg_len)

            if msg_type in [RTM_NEWLINK, RTM_DELLINK]:
                # A new or removed interface.  Read the struct
                # ifinfomsg, which is 16 bytes.
                hdr = data[:16]
                data = data[16:]
                _, _, _, index, flags, _ = struct.unpack("=BBHiII", hdr)
                _log.debug("Interface index %s flags %x", index, flags)

                # Bytes left is the message length minus the two headers of 16
                # bytes each.
                remaining = msg_len - 32

                # Loop through attributes, looking for the pieces of
                # information that we need.
                ifname = None
                operstate = None
                while remaining:
                    # The data content is an array of RTA objects, each of
                    # which has a 4 byte header and some data.
                    rta_len, rta_type = struct.unpack("=HH", data[:4])

                    # This check comes from RTA_OK, and terminates a string of
                    # routing attributes.
                    if rta_len < 4:
                        break

                    rta_data = data[4:rta_len]

                    # Remove the RTA object from the data. The length to jump
                    # is the rta_len rounded up to the nearest 4 byte boundary.
                    increment = int((rta_len + 3) / 4) * 4
                    data = data[increment:]
                    remaining -= increment

                    if rta_type == IFLA_IFNAME:
                        ifname = rta_data[:-1]
                        _log.debug("IFLA_IFNAME: %s", ifname)
                    elif rta_type == IFLA_OPERSTATE:
                        operstate, = struct.unpack("=B", rta_data[:1])
                        _log.debug("IFLA_OPERSTATE: %s", operstate)

                if (ifname and
                    ifname in if_last_flags and
                    (msg_type == RTM_DELLINK or operstate != IF_OPER_UP)):
                    # An interface that we've previously signalled is
                    # being deleted or oper down, so remove our record
                    # of it.
                    del if_last_flags[ifname]

                if (ifname and
                    msg_type == RTM_NEWLINK and
                    operstate == IF_OPER_UP and
                    (ifname not in if_last_flags or
                     if_last_flags[ifname] != flags)):
                    # We only care about notifying when a new
                    # interface is usable, which - according to
                    # https://www.kernel.org/doc/Documentation/networking/
                    # operstates.txt - is fully conveyed by the
                    # operstate.  (When an interface goes away, it
                    # automatically takes its routes with it.)
                    _log.debug("New network interface : %s %x", ifname, flags)
                    if_last_flags[ifname] = flags
                    self.update_splitter.on_interface_update(ifname,
                                                             async=True)


class BadKernelConfig(Exception):
    pass
