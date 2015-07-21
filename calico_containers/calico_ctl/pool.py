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
"""
Usage:
  calicoctl pool (add|remove) <CIDRS>... [--ipip] [--nat-outgoing]
  calicoctl pool range add <START_IP> <END_IP> [--ipip] [--nat-outgoing]
  calicoctl pool show [--ipv4 | --ipv6]

Description:
  Configure IP Pools

Options:
  --ipv4          Show IPv4 information only
  --ipv6          Show IPv6 information only
  --nat-outgoing  Apply NAT to outgoing traffic
  --ipip          Use IP-over-IP encapsulation across hosts
 """
import sys
import netaddr
from netaddr import IPNetwork, IPRange, IPAddress
from prettytable import PrettyTable
from pycalico.datastore_datatypes import IPPool
from utils import (validate_cidr, validate_ip, client,
                   get_container_ipv_from_arguments)


def validate_arguments(arguments):
    """
    Validate argument values:
        <CIDRS>

    :param arguments: Docopt processed arguments
    """
    # Validate CIDR
    cidrs = arguments.get("<CIDRS>")
    start_ip = arguments.get("<START_IP>")
    end_ip = arguments.get("<END_IP>")
    if cidrs:
        for cidr in cidrs:
            if not validate_cidr(cidr):
                print "Invalid CIDR specified %s" % cidr
                sys.exit(1)
    elif start_ip or end_ip:
        if not (validate_ip(start_ip, "v4") or validate_ip(start_ip, "v6")):
            print "Invalid START_IP specified."
            sys.exit(1)
        elif not (validate_ip(end_ip, "v4") or validate_ip(end_ip, "v6")):
            print "Invalid END_IP specified."
            sys.exit(1)
        elif IPAddress(start_ip).version != IPAddress(end_ip).version:
            print "START_IP and END_IP must be the same ip version"
            sys.exit(1)
        elif not IPAddress(start_ip) < IPAddress(end_ip):
            print "START_IP must be a smaller ip address than END_IP"
            sys.exit(1)


def pool(arguments):
    """
    Main dispatcher for pool commands. Calls the corresponding helper function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    validate_arguments(arguments)

    ip_version = get_container_ipv_from_arguments(arguments)
    if arguments.get("add"):
        if arguments.get("range"):
            ip_pool_range_add(arguments.get("<START_IP>"),
                              arguments.get("<END_IP>"),
                              ip_version,
                              arguments.get("--ipip"),
                              arguments.get("--nat-outgoing"))
        else:
            ip_pool_add(arguments.get("<CIDRS>"),
                        ip_version,
                        arguments.get("--ipip"),
                        arguments.get("--nat-outgoing"))
    elif arguments.get("remove"):
        ip_pool_remove(arguments.get("<CIDRS>"), ip_version)
    elif arguments.get("show"):
        if not ip_version:
            ip_pool_show("v4")
            ip_pool_show("v6")
        else:
            ip_pool_show(ip_version)


def ip_pool_add(cidrs, version, ipip, masquerade):
    """
    Add the given CIDRS to the IP address allocation pool.

    :param cidrs: The pools to set in CIDR format, e.g. 192.168.0.0/16
    :param version: v4 or v6
    :param ipip: Use IP in IP for this pool.
    :return: None
    """
    if version == "v6" and ipip:
        print "IP in IP not supported for IPv6 pools"
        sys.exit(1)

    # TODO Reject any cidrs that overlap with existing cidrs in the pool
    for cidr in cidrs:
        pool = IPPool(cidr, ipip=ipip, masquerade=masquerade)
        client.add_ip_pool(version, pool)


def ip_pool_range_add(start_ip, end_ip, version, ipip, masquerade):
    """
    Add the range of ip addresses as CIDRs to the IP address allocation pool.

    :param start_ip: The first ip address the ip range.
    :param end_ip: The last ip address in the ip range.
    :param version: v4 or v6
    :param ipip: Use IP in IP for this pool.
    :return: None
    """
    if version == "v6" and ipip:
        print "IP in IP not supported for IPv6 pools"
        sys.exit(1)

    ip_range = IPRange(start_ip, end_ip)
    pools = client.get_ip_pools(version)
    for pool in pools:
        pool_net = IPNetwork(pool.cidr)
        # Reject the new ip range if any of the following are true:
        # - The new ip range contains all ips of any existing pool
        # - An existing pool overlaps ips with the start of the new ip range
        # - An existing pool overlaps ips with the end of the new ip range
        if (pool_net in ip_range or
            start_ip in pool_net or
            end_ip in pool_net):
            print "Cannot add range - range conflicts with pool %s" % pool.cidr
            sys.exit(1)

    cidrs = netaddr.iprange_to_cidrs(start_ip, end_ip)
    for ip_net in cidrs:
        new_pool = IPPool(ip_net.cidr, ipip=ipip, masquerade=masquerade)
        client.add_ip_pool(version, new_pool)


def ip_pool_remove(cidrs, version):
    """
    Remove the given CIDRs from the IP address allocation pool.

    :param cidrs: The pools to remove in CIDR format, e.g. 192.168.0.0/16
    :param version: v4 or v6
    :return: None
    """
    for cidr in cidrs:
        try:
            client.remove_ip_pool(version, IPNetwork(cidr))
        except KeyError:
            print "%s is not a configured pool." % cidr


def ip_pool_show(version):
    """
    Print a list of IP allocation pools.
    :return: None
    """
    assert version in ("v4", "v6")
    headings = ["IP%s CIDR" % version, "Options"]
    pools = client.get_ip_pools(version)
    x = PrettyTable(headings)
    for pool in pools:
        enabled_options = []
        if version == "v4":
            if pool.ipip:
                enabled_options.append("ipip")
            if pool.masquerade:
                enabled_options.append("nat-outgoing")
        # convert option array to string
        row = [str(pool.cidr), ','.join(enabled_options)]
        x.add_row(row)
    print x.get_string(sortby=headings[0])
