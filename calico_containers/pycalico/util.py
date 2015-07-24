import sys
import re
from netaddr import IPNetwork, AddrFormatError
from subprocess import check_output, CalledProcessError

"""
Compile Regexes
"""
# Splits into groups that start w/ no whitespace and contain all lines below that start w/ whitespace
INTERFACE_SPLIT_RE = re.compile(r'(\d+:.*(?:\n\s+.*)+)')
# Grabs interface name
IFACE_RE = re.compile(r'^\d+: (\S+):')
# Grabs v4 addresses
IPV4_RE = re.compile(r'inet ((?:\d+\.){3}\d+)\/\d+')
# Grabs v6 addresses
IPV6_RE = re.compile(r'inet6 ([a-fA-F\d:]+)\/\d{1,3}')

def generate_cali_interface_name(prefix, ep_id):
    """Helper method to generate a name for a calico veth, given the endpoint ID

    This takes a prefix, and then truncates the EP ID.

    :param prefix: T
    :param ep_id:
    :return:
    """
    if len(prefix) > 4:
        raise ValueError('Prefix must be 4 characters or less.')
    return prefix + ep_id[:11]


def get_host_ips(version=4, exclude=None):
    """
    Gets all IP addresses assigned to this host.

    Ignores Loopback Addresses

    This function is fail-safe and will return an empty array instead of
    raising any exceptions.

    :param version: Desired version of IP addresses. Can be 4 or 6. defaults to 4
    :param exclude: list of interfaces (strings) to ignore (ex. ["lo","docker0"])
    :return: List of string representations of IP Addresses.
    """
    exclude = exclude or []
    ip_addrs = []

    # Select Regex for IPv6 or IPv4.
    IP_RE = IPV4_RE if version is 4 else IPV6_RE

    # Call `ip addr`.
    try:
        ip_addr_output = check_output(["ip", "-%d" % (version), "addr"])
    except CalledProcessError, OSError:
        print "Call to 'ip addr' Failed"
        sys.exit(1)

    # Separate interface blocks from ip addr output and iterate.
    for iface_block in INTERFACE_SPLIT_RE.findall(ip_addr_output):
        # Exclude certain interfaces.
        match = IFACE_RE.match(iface_block)
        if match and match.group(1) not in exclude:
            # Iterate through Addresses on interface.
            for address in IP_RE.findall(iface_block):
                # Append non-loopback addresses.
                if not IPNetwork(address).ip.is_loopback():
                    ip_addrs.append(address)

    return ip_addrs

