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
"""
Usage:
  calicoctl pool add <CIDRS>... [--ipip] [--nat-outgoing]
  calicoctl pool remove <CIDRS>...
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
import time

import netaddr
from netaddr import IPNetwork, IPRange, IPAddress
from prettytable import PrettyTable
from pycalico.datastore_datatypes import IPPool
from pycalico.datastore_errors import InvalidBlockSizeError
from pycalico.block import BLOCK_PREFIXLEN
from pycalico.ipam import HostAffinityClaimedError
from pycalico.util import validate_ip, validate_cidr

from connectors import client
from utils import (get_container_ipv_from_arguments,
                   print_paragraph)


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
        if not (validate_ip(start_ip, 4) or validate_ip(start_ip, 6)):
            print "Invalid START_IP specified."
            sys.exit(1)
        elif not (validate_ip(end_ip, 4) or validate_ip(end_ip, 6)):
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
            ip_pool_show(4)
            ip_pool_show(6)
        else:
            ip_pool_show(ip_version)


def ip_pool_add(cidrs, version, ipip, masquerade):
    """
    Add the given CIDRS to the IP address allocation pool.

    :param cidrs: The pools to set in CIDR format, e.g. 192.168.0.0/16
    :param version: 4 or 6
    :param ipip: Use IP in IP for the pool(s).
    :param masquerade: Enable masquerade (outgoing NAT) for the pool(s).
    :return: None
    """
    if version == 6 and ipip:
        print "IP in IP not supported for IPv6 pools"
        sys.exit(1)

    current_pools = client.get_ip_pools(version)
    new_pools = []

    # Ensure new pools are valid and do not overlap with each other or existing
    # pools.
    for cidr in cidrs:

        try:
            pool = IPPool(cidr, ipip=ipip, masquerade=masquerade)

        except InvalidBlockSizeError:
            print "An IPv%s pool must have a prefix length of %s or lower." \
                  "\nGiven: %s.\nNo pools added." % \
                  (version, BLOCK_PREFIXLEN[version], cidr)
            sys.exit(1)

        # Check if new pool overlaps with any existing pool
        overlapping_pool = _get_overlapping_pool(pool, current_pools)
        if overlapping_pool:
            print "Cannot add IP pool %s - pool overlaps with an " \
                  "existing pool %s" % (cidr, overlapping_pool.cidr)
            sys.exit(1)

        # Check if this new pool overlaps with any other new pool
        overlapping_pool = _get_overlapping_pool(pool, new_pools)
        if overlapping_pool:
            print "Cannot add IP pool %s - pool overlaps with another " \
                  "new pool %s" % (cidr, overlapping_pool.cidr)
            sys.exit(1)

        # Append pool to pending list of new pools to add to Calico
        new_pools.append(pool)


    # Make client call to add each pool to Calico
    for new_pool in new_pools:
        client.add_ip_pool(version, new_pool)


def _get_overlapping_pool(pool, other_pools):
    """
    Check if the given pool overlaps with any pool in the list of other_pools.

    Ignore when a pool's CIDR is an exact match of another pool's CIDR in case
    a pool is being updated.

    :param pool: IPPool to check overlap for.
    :param other_pools: List of IPPools to check for overlap.
    :return: The first IPPool in other_pools that overlaps with pool, or None if
    no overlap.
    """
    for other_pool in other_pools:
        # Allow the cidr to be exactly the same in case pool is being updated,
        # for example to add/remove IP-IP support.
        if ((pool.cidr in other_pool.cidr or other_pool.cidr in pool.cidr) and
            (pool.cidr != other_pool.cidr)):
            return other_pool

    return None

def ip_pool_range_add(start_ip, end_ip, version, ipip, masquerade):
    """
    Add the range of ip addresses as CIDRs to the IP address allocation pool.

    :param start_ip: The first ip address the ip range.
    :param end_ip: The last ip address in the ip range.
    :param version: 4 or 6
    :param ipip: Use IP in IP for the pool(s).
    :param masquerade: Enable masquerade (outgoing NAT) for the pool(s).
    :return: None
    """
    if version == 6 and ipip:
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
    new_pools = []
    for ip_net in cidrs:
        try:
            new_pools.append(IPPool(ip_net.cidr, ipip=ipip, masquerade=masquerade))
        except InvalidBlockSizeError:
            pool_strings = [str(net) for net in cidrs]
            print "IPv%s ranges are split into pools, with the smallest pool " \
                  "size allowed having a prefix length of /%s. One or more " \
                  "of the generated pools is too small (prefix length is too " \
                  "high).\nRange given: %s - %s\nPools: %s\nNo pools added." % \
                  (version, BLOCK_PREFIXLEN[version], start_ip, end_ip,
                   pool_strings)
            sys.exit(1)
    for new_pool in new_pools:
        client.add_ip_pool(version, new_pool)


def ip_pool_remove(cidrs, version):
    """
    Remove the given CIDRs from the IP address allocation pool.

    :param cidrs: The pools to remove in CIDR format, e.g. 192.168.0.0/16
    :param version: 4 or 6
    :return: None
    """
    for cidr in cidrs:
        # Get the existing IP Pool so that we can disable it,
        try:
            pool = client.get_ip_pool_config(version, IPNetwork(cidr))
        except KeyError:
            print "%s is not a configured pool." % cidr
            sys.exit(1)

        try:
            # Disable the pool to prevent any further allocation blocks from
            # being assigned from the pool.  Existing allocation blocks will
            # still exist and may be allocated from until affinity is removed
            # from the blocks.
            print "Disabling IP Pool"
            pool.disabled = True
            client.set_ip_pool_config(version, pool)

            # Remove affinity from the allocation blocks for the pool.  This
            # will prevent these blocks from being used for auto-allocations.
            # We pause before removing the affinities and the pool to allow
            # any in-progress IP allocations to complete - there is a known
            # timing window here, which can be closed but at the expense of
            # additional etcd reads for each affine block allocation - since
            # deletion of a pool is not common, it is simplest to pause in
            # between disabling and deleting the pool.
            print "Removing IPAM configuration for pool"
            time.sleep(3)
            client.release_pool_affinities(pool)
            client.remove_ip_pool(version, pool.cidr)

            print "Deleted IP Pool"
        except (KeyError, HostAffinityClaimedError):
            print_paragraph("Conflicting modifications have been made to the "
                            "IPAM configuration for this pool.  Please retry "
                            "the command.")
            sys.exit(1)


def ip_pool_show(version):
    """
    Print a list of IP allocation pools.
    :return: None
    """
    assert version in (4, 6)
    headings = ["IPv%s CIDR" % version, "Options"]
    pools = client.get_ip_pools(version)
    x = PrettyTable(headings)
    for pool in pools:
        enabled_options = []
        if version == 4:
            if pool.ipip:
                enabled_options.append("ipip")
            if pool.masquerade:
                enabled_options.append("nat-outgoing")
        # convert option array to string
        row = [str(pool.cidr), ','.join(enabled_options)]
        x.add_row(row)
    print x.get_string(sortby=headings[0])
