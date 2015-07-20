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
  calicoctl bgp peer add <PEER_IP> as <AS_NUM>
  calicoctl bgp peer remove <PEER_IP>
  calicoctl bgp peer show [--ipv4 | --ipv6]
  calicoctl bgp node-mesh [on|off]
  calicoctl bgp default-node-as [<AS_NUM>]


Description:
  Configure default global BGP settings for all nodes. Note: per-node settings
  will override these globals for that node.

Options:
 --ipv4    Show IPv4 information only.
 --ipv6    Show IPv6 information only.
"""
import sys
from utils import client
from pycalico.datastore_datatypes import BGPPeer
from netaddr import IPAddress
from prettytable import PrettyTable
from utils import get_container_ipv_from_arguments
from utils import validate_ip


def validate_arguments(arguments):
    """
    Validate argument values:
        <PEER_IP>
        <AS_NUM>

    Arguments not validated:

    :param arguments: Docopt processed arguments
    """
    # Validate IPs
    peer_ip_ok = arguments.get("<PEER_IP>") is None or \
                    validate_ip(arguments["<PEER_IP>"], 4) or \
                    validate_ip(arguments["<PEER_IP>"], 6)
    asnum_ok = True
    if arguments.get("<AS_NUM>"):
        try:
            asnum = int(arguments["<AS_NUM>"])
            asnum_ok = 0 <= asnum <= 4294967295
        except ValueError:
            asnum_ok = False

    # Print error messages
    if not peer_ip_ok:
        print "Invalid IP address specified."
    if not asnum_ok:
        print "Invalid AS Number specified."

    # Exit if not valid arguments
    if not (peer_ip_ok and asnum_ok):
        sys.exit(1)


def bgp(arguments):
    """
    Main dispatcher for bgp commands. Calls the corresponding helper function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    validate_arguments(arguments)

    ip_version = get_container_ipv_from_arguments(arguments)
    if arguments.get("peer"):
        if arguments.get("add"):
            bgp_peer_add(arguments.get("<PEER_IP>"), ip_version,
                         arguments.get("<AS_NUM>"))
        elif arguments.get("remove"):
            bgp_peer_remove(arguments.get("<PEER_IP>"), ip_version)
        elif arguments.get("show"):
            if not ip_version:
                bgp_peer_show(4)
                bgp_peer_show(6)
            else:
                bgp_peer_show(ip_version)

    elif arguments.get("node-mesh"):
        if arguments.get("on") or arguments.get("off"):
            set_bgp_node_mesh(arguments.get("on"))
        else:
            show_bgp_node_mesh()
    elif arguments.get("default-node-as"):
        if arguments.get("<AS_NUM>"):
            set_default_node_as(arguments.get("<AS_NUM>"))
        else:
            show_default_node_as()


def bgp_peer_add(ip, version, as_num):
    """
    Add a new global BGP peer with the supplied IP address and AS Number.  All
    nodes will peer with this.

    :param ip: The address to add
    :param version: 4 or 6
    :param as_num: The peer AS Number.
    :return: None
    """
    address = IPAddress(ip)
    peer = BGPPeer(address, as_num)
    client.add_bgp_peer(version, peer)


def bgp_peer_remove(ip, version):
    """
    Remove a global BGP peer.

    :param ip: The address to use.
    :param version: 4 or 6
    :return: None
    """
    address = IPAddress(ip)
    try:
        client.remove_bgp_peer(version, address)
    except KeyError:
        print "%s is not a globally configured peer." % address
        sys.exit(1)
    else:
        print "BGP peer removed from global configuration"


def bgp_peer_show(version):
    """
    Print a list of the global BGP Peers.
    """
    assert version in (4, 6)
    peers = client.get_bgp_peers(version)
    if peers:
        heading = "Global IPv%s BGP Peer" % version
        x = PrettyTable([heading, "AS Num"], sortby=heading)
        for peer in peers:
            x.add_row([peer.ip, peer.as_num])
        x.align = "l"
        print x.get_string(sortby=heading)
    else:
        print "No global IPv%s BGP Peers defined.\n" % version


def set_default_node_as(as_num):
    """
    Set the default node BGP AS Number.

    :param as_num:  The default AS number
    :return: None.
    """
    client.set_default_node_as(as_num)


def show_default_node_as():
    """
    Display the default node BGP AS Number.

    :return: None.
    """
    value = client.get_default_node_as()
    print value


def show_bgp_node_mesh():
    """
    Display the BGP node mesh setting.

    :return: None.
    """
    value = client.get_bgp_node_mesh()
    print "on" if value else "off"


def set_bgp_node_mesh(enable):
    """
    Set the BGP node mesh setting.

    :param enable:  (Boolean) Whether to enable or disable the node-to-node
    mesh.
    :return: None.
    """
    client.set_bgp_node_mesh(enable)
