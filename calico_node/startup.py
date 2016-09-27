# Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

import os
import sys
import socket
import time

import netaddr
from netaddr import AddrFormatError, IPAddress
from pycalico.datastore_datatypes import IPPool
from pycalico.datastore_errors import DataStoreError
from pycalico.ipam import IPAMClient
from pycalico.util import get_host_ips, validate_asn

DEFAULT_IPV4_POOL = IPPool("192.168.0.0/16")
DEFAULT_IPV6_POOL = IPPool("fd80:24e2:f998:72d6::/64")


def _find_pool(ip_addr, ipv4_pools):
    """
    Find the pool containing the given IP.

    :param ip_addr:  IP address to find.
    :param ipv4_pools:  iterable containing IPPools.
    :return: The pool, or None if not found
    """
    for pool in ipv4_pools:
        if ip_addr in pool.cidr:
            return pool
    else:
        return None


def _ensure_host_tunnel_addr(ipv4_pools, ipip_pools):
    """
    Ensure the host has a valid IP address for its IPIP tunnel device.

    This must be an IP address claimed from one of the IPIP pools.
    Handles re-allocating the address if it finds an existing address
    that is not from an IPIP pool.

    :param ipv4_pools: List of all IPv4 pools.
    :param ipip_pools: List of IPIP-enabled pools.
    """
    ip_addr = _get_host_tunnel_ip()
    if ip_addr:
        # Host already has a tunnel IP assigned, verify that it's still valid.
        pool = _find_pool(ip_addr, ipv4_pools)
        if pool and not pool.ipip:
            # No longer an IPIP pool. Release the IP, it's no good to us.
            client.release_ips({ip_addr})
            ip_addr = None
        elif not pool:
            # Not in any IPIP pool.  IP must be stale.  Since it's not in any
            # pool, we can't release it.
            ip_addr = None
    if not ip_addr:
        # Either there was no IP or the IP needs to be replaced.  Try to
        # get an IP from one of the IPIP-enabled pools.
        _assign_host_tunnel_addr(ipip_pools)


def _assign_host_tunnel_addr(ipip_pools):
    """
    Claims an IPIP-enabled IP address from the first pool with some
    space.

    Stores the result in the host's config as its tunnel address.

    Exits on failure.
    :param ipip_pools:  List of IPPools to search for an address.
    """
    for ipip_pool in ipip_pools:
        v4_addrs, _ = client.auto_assign_ips(
            num_v4=1, num_v6=0,
            handle_id=None,
            attributes={},
            pool=(ipip_pool, None),
            host=hostname
        )
        if v4_addrs:
            # Successfully allocated an address.  Unpack the list.
            [ip_addr] = v4_addrs
            break
    else:
        # Failed to allocate an address, the pools must be full.
        print "Failed to allocate an IP address from an IPIP-enabled pool " \
            "for the host's IPIP tunnel device.  Pools are likely " \
            "exhausted."

        sys.exit(1)
    # If we get here, we've allocated a new IPIP-enabled address,
    # Store it in etcd so that Felix will pick it up.
    client.set_per_host_config(hostname, "IpInIpTunnelAddr",
                               str(ip_addr))


def _remove_host_tunnel_addr():
    """
    Remove any existing IP address for this host's IPIP tunnel device.

    Idempotent; does nothing if there is no IP assigned.  Releases the
    IP from IPAM.
    """
    ip_addr = _get_host_tunnel_ip()
    if ip_addr:
        client.release_ips({ip_addr})
    client.remove_per_host_config(hostname, "IpInIpTunnelAddr")


def _get_host_tunnel_ip():
    """
    :return: The IPAddress of the host's IPIP tunnel or None if not
             present/invalid.
    """
    raw_addr = client.get_per_host_config(hostname, "IpInIpTunnelAddr")
    try:
        ip_addr = IPAddress(raw_addr)
    except (AddrFormatError, ValueError, TypeError):
        # Either there's no address or the data is bad.  Treat as missing.
        ip_addr = None
    return ip_addr


def error_if_bgp_ip_conflict(ip, ip6):
    """
    Prints an error message and exits if either of the IPv4 or IPv6 addresses
    is already in use by another calico BGP host.

    :param ip: User-provided IPv4 address to start this node with.
    :param ip6: User-provided IPv6 address to start this node with.
    :return: Nothing
    """
    ip_list = []
    if ip:
        ip_list.append(ip)
    if ip6:
        ip_list.append(ip6)
    try:
        # Get hostname of host that already uses the given IP, if it exists
        ip_conflicts = client.get_hostnames_from_ips(ip_list)
    except KeyError:
        # No hosts have been configured in etcd, so there cannot be a conflict
        return

    if ip_conflicts.keys():
        ip_error = "ERROR: IP address %s is already in use by host %s. " \
                   "Calico requires each compute host to have a unique IP. " \
                   "If this is your first time running the Calico node on " \
                   "this host, ensure that another host is not already using " \
                   "the same IP address."
        try:
            if ip_conflicts[ip] != hostname:
                ip_error = ip_error % (ip, str(ip_conflicts[ip]))
                print ip_error
                sys.exit(1)
        except KeyError:
            # IP address was not found in ip-host dictionary
            pass
        try:
            if ip6 and ip_conflicts[ip6] != hostname:
                ip_error = ip_error % (ip6, str(ip_conflicts[ip6]))
                print ip_error
                sys.exit(1)
        except KeyError:
            # IP address was not found in ip-host dictionary
            pass


def warn_if_unknown_ip(ip, ip6):
    """
    Prints a warning message if the IP addresses are not assigned to interfaces
    on the current host.

    :param ip: IPv4 address which should be present on the host.
    :param ip6: IPv6 address which should be present on the host.
    :return: None
    """
    if ip and IPAddress(ip) not in get_host_ips(version=4, exclude=["docker0"]):
        print "WARNING: Could not confirm that the provided IPv4 address is" \
              " assigned to this host."

    if ip6 and IPAddress(ip6) not in get_host_ips(version=6,
                                                  exclude=["docker0"]):
        print "WARNING: Could not confirm that the provided IPv6 address is" \
              " assigned to this host."


def warn_if_hostname_conflict(ip):
    """
    Prints a warning message if it seems like an existing host is already running
    calico using this hostname.

    :param ip: User-provided or detected IP address to start this node with.
    :return: Nothing
    """
    try:
        current_ipv4, _ = client.get_host_bgp_ips(hostname)
    except KeyError:
        # No other machine has registered configuration under this hostname.
        # This must be a new host with a unique hostname, which is the
        # expected behavior.
        pass
    else:
        if current_ipv4 != "" and current_ipv4 != ip:
            hostname_warning = "WARNING: Hostname '%s' is already in use " \
                               "with IP address %s. Calico requires each " \
                               "compute host to have a unique hostname. " \
                               "If this is your first time running " \
                               "the Calico node on this host, ensure " \
                               "that another host is not already using the " \
                               "same hostname." % (hostname, current_ipv4)
            print hostname_warning


def main():
    # Check to see if etcd is available.  If not, wait until it is before
    # continuing.  This is to avoid etcd / node startup race conditions.
    print "Waiting for etcd connection..."
    while os.getenv("WAIT_FOR_DATASTORE", "false") == "true":
        try:
            # Just try accessing etcd to see if we can reach it or not.
            client.get_host_as(hostname)
        except DataStoreError:
            # Not connected to etcd yet, wait a bit.
            time.sleep(1)
            continue
        else:
            # Connected to etcd - break out of loop.
            print "Connected to etcd"
            break

    # Start node.
    ip = os.getenv("IP")
    ip = ip or None
    if ip and not netaddr.valid_ipv4(ip):
        print "IP environment (%s) is not a valid IPv4 address." % ip
        sys.exit(1)

    ip6 = os.getenv("IP6")
    ip6 = ip6 or None
    if ip6 and not netaddr.valid_ipv6(ip6):
        print "IP6 environment (%s) is not a valid IPv6 address." % ip6
        sys.exit(1)

    as_num = os.getenv("AS")
    as_num = as_num or None
    if as_num and not validate_asn(as_num):
        print "AS environment (%s) is not a AS number." % as_num
        sys.exit(1)

    # Get IP address of host, if none was specified
    if not ip:
        ips = get_host_ips(exclude=["^docker.*", "^cbr.*",
                                    "virbr.*", "lxcbr.*", "veth.*",
                                    "cali.*", "tunl.*", "flannel.*"])
        try:
            ip = str(ips.pop())
        except IndexError:
            print "Couldn't autodetect a management IP address. Please " \
                  "provide an IP address by rerunning the container with the" \
                  " IP environment variable set."
            sys.exit(1)
        else:
            print "No IP provided. Using detected IP: %s" % ip

    # Write a startup environment file containing the IP address that may have
    # just been detected.
    # This is required because the confd templates expect to be able to fill in
    # some templates by fetching them from the environment.
    with open('startup.env', 'w') as f:
        f.write("IP=%s\n" % ip)
        f.write("HOSTNAME=%s\n" % hostname)

    warn_if_hostname_conflict(ip)

    # Verify that IPs are not already in use by another host.
    error_if_bgp_ip_conflict(ip, ip6)

    # Verify that the chosen IP exists on the current host
    warn_if_unknown_ip(ip, ip6)

    if os.getenv("NO_DEFAULT_POOLS", "").lower() != "true":
        # Set up etcd
        ipv4_pools = client.get_ip_pools(4)
        ipv6_pools = client.get_ip_pools(6)

        # Create default pools if required
        if not ipv4_pools:
            client.add_ip_pool(4, DEFAULT_IPV4_POOL)

        # If the OS has not been built with IPv6 then the /proc config for IPv6
        # will not be present.
        if not ipv6_pools and os.path.exists('/proc/sys/net/ipv6'):
            client.add_ip_pool(6, DEFAULT_IPV6_POOL)

    client.ensure_global_config()
    client.create_host(hostname, ip, ip6, as_num)

    # If IPIP is enabled, the host requires an IP address for its tunnel
    # device, which is in an IPIP pool.  Without this, a host can't originate
    # traffic to a pool address because the response traffic would not be
    # routed via the tunnel (likely being dropped by RPF checks in the fabric).
    ipv4_pools = client.get_ip_pools(4)
    ipip_pools = [p for p in ipv4_pools if p.ipip]

    if ipip_pools:
        # IPIP is enabled, make sure the host has an address for its tunnel.
        _ensure_host_tunnel_addr(ipv4_pools, ipip_pools)
    else:
        # No IPIP pools, clean up any old address.
        _remove_host_tunnel_addr()


# Try the HOSTNAME environment variable, but default to
# the socket.gethostname() value if unset.
hostname = os.getenv("HOSTNAME")
if not hostname:
    hostname = socket.gethostname()

client = IPAMClient()

if __name__ == "__main__":
    main()
