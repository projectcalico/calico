# Copyright (c) 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from subprocess import call, check_output, check_call, CalledProcessError
import socket
import logging
import logging.handlers
import sys
import uuid
import os.path

from netaddr import IPNetwork, IPAddress

from datastore import Endpoint, IF_PREFIX
from nsenter import Namespace


_log = logging.getLogger(__name__)

HOSTNAME = socket.gethostname()

VETH_NAME = "eth1"
"""The name to give to the veth in the target container's namespace. Default
to eth1 because eth0 could be in use"""

ROOT_NETNS = "1"
"""The pid of the root namespace.  On almost all systems, the init system is
pid 1
"""

PREFIX_LEN = {4: 32, 6: 128}
"""The IP address prefix length to assign, by IP version."""

PROC_ALIAS = "/proc_host"
"""The alias for /proc.  This is useful when the filesystem is containerized.
"""


def setup_logging(logfile):
    _log.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    _log.addHandler(handler)
    handler = logging.handlers.TimedRotatingFileHandler(logfile,
                                                        when='D',
                                                        backupCount=10)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    _log.addHandler(handler)


def remove_endpoint(ep_id):
    """
    Remove an endpoint.

    :param ep_id: The endpoint ID to remove
    :return: Nothing
    """
    iface = IF_PREFIX + ep_id[:11]
    call("ip link delete %s" % iface, shell=True)


def add_ip_to_interface(container_pid, ip, interface_name,
                    proc_alias=PROC_ALIAS):
    """
    Add an IP to an interface in a container.

    :param container_pid: The PID and name of the namespace to operate in.
    :param ip: The IPAddress to add.
    :param interface_name: The interface to add the address to.
    :param proc_alias: The head of the /proc filesystem on the host.
    :return: None. raises CalledProcessError on error.
    """
    with Namespace(container_pid, 'net', proc=proc_alias):
        check_call("ip -%(version)s addr add "
                   "%(addr)s/%(len)s dev %(device)s" %
                   {"version": ip.version,
                    "len": PREFIX_LEN[ip.version],
                    "addr": ip,
                    "device": interface_name},
                   shell=True)

def remove_ip_from_interface(container_pid, ip, interface_name,
                    proc_alias=PROC_ALIAS):
    """
    Remove an IP from an interface in a container.

    :param container_pid: The PID and name of the namespace to operate in.
    :param ip: The IPAddress to remove.
    :param interface_name: The interface to remove the address from.
    :param proc_alias: The head of the /proc filesystem on the host.
    :return: None. raises CalledProcessError on error.
    """
    with Namespace(container_pid, 'net', proc=proc_alias):
        check_call("ip -%(version)s addr del "
                   "%(addr)s/%(len)s dev %(device)s" %
                   {"version": ip.version,
                    "len": PREFIX_LEN[ip.version],
                    "addr": ip,
                    "device": interface_name},
                   shell=True)


def set_up_endpoint(ip, cpid, next_hop_ips,
                    veth_name=VETH_NAME,
                    proc_alias=PROC_ALIAS):
    """
    Set up an endpoint (veth) in the network namespace idenfitied by the PID.

    :param ip: The IP address to assign to the endpoint (veth) as Netaddr
    IPAddress.
    :param cpid: The PID of a process currently running in the namespace.
    :param next_hop_ips: Dict of {version: IPAddress} for the next hops of the
    default routes.
    namespace, as opposed to the root namespace.  If so, this method also moves
    the other end of the veth into the root namespace.
    :param veth_name: The name of the interface inside the container namespace,
    e.g. eth1
    :param proc_alias: The head of the /proc filesystem on the host.
    :return: An Endpoint describing the veth just created.
    """
    assert isinstance(ip, IPAddress)

    # Generate a new endpoint ID.
    ep_id = uuid.uuid1().hex

    iface = IF_PREFIX + ep_id[:11]
    iface_tmp = "tmp" + ep_id[:11]

    # Provision the networking.  We create a temporary link from the proc
    # alias to the /var/run/netns to provide a named namespace.  If we don't
    # do this, when run from the calico-node container the PID of the
    # container process is not recognised by `ip link set <if> netns <pid>`
    # command because that uses /proc rather than the proc alias to
    # dereference the PID.
    #
    # TODO: Something similar to Namespace() to arbitrarily specify the proc
    # ...   alias for the ip link set command.
    try:
        check_call("mkdir -p /var/run/netns", shell=True)
        check_call("ln -s %s/%s/ns/net /var/run/netns/pid-%s" %
                     (proc_alias, cpid, cpid),
                   shell=True)
        _log.debug(check_output("ls -l /var/run/netns", shell=True))

        # Create the veth pair and move one end into container:
        check_call("ip link add %s type veth peer name %s" %
                     (iface, iface_tmp),
                   shell=True)
        check_call("ip link set %s up" % iface, shell=True)
        check_call("ip link set %s netns pid-%s" % (iface_tmp, cpid),
                   shell=True)
        _log.debug(check_output("ip link", shell=True))
    finally:
        check_call("rm /var/run/netns/pid-%s" % cpid, shell=True)

    # Rename within the container to something sensible.
    with Namespace(cpid, 'net', proc=proc_alias):
        check_call("ip link set dev %s name %s" % (iface_tmp,veth_name),
                   shell=True)
        check_call("ip link set %s up" % (veth_name), shell=True)

    # Add an IP address.
    add_ip_to_interface(cpid, ip, veth_name, proc_alias=proc_alias)

    # Connected route to next hop & default route.
    next_hop = next_hop_ips[ip.version]
    with Namespace(cpid, 'net', proc=proc_alias):
        check_call("ip -%(version)s route replace"
                   " %(next_hop)s dev %(device)s" %
                   {"version": ip.version,
                    "device": veth_name,
                    "next_hop": next_hop},
                   shell=True)
        check_call("ip -%(version)s route replace"
                   " default via %(next_hop)s dev %(device)s" %
                   {"version": ip.version,
                    "device": veth_name,
                    "next_hop": next_hop},
                   shell=True)

        # Get the MAC address.
        mac = check_output(
            "ip link show %s | grep ether | awk '{print $2}'" %
            (veth_name), shell=True).strip()

    # Return an Endpoint
    network = IPNetwork(IPAddress(ip))
    ep = Endpoint(ep_id=ep_id, state="active", mac=mac)
    if network.version == 4:
        ep.ipv4_nets.add(network)
        ep.ipv4_gateway = next_hop
    else:
        ep.ipv6_nets.add(network)
        ep.ipv6_gateway = next_hop
    return ep
