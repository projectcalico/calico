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

from subprocess import call, check_output, check_call
import socket
import logging
import logging.handlers
import os
import sys
import uuid

from netaddr import IPNetwork, IPAddress
from datastore import Endpoint, IF_PREFIX

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
    with NamedNamespace(container_pid, proc=proc_alias) as ns:
        ns.check_call("ip -%(version)s addr add %(addr)s/%(len)s "
                      "dev %(device)s" %
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
    with NamedNamespace(container_pid, proc=proc_alias) as ns:
        ns.check_call("ip -%(version)s addr del %(addr)s/%(len)s "
                      "dev %(device)s" %
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
    with NamedNamespace(cpid, proc=proc_alias) as ns:
        # Create the veth pair and move one end into container:
        check_call("ip link add %s type veth peer name %s" %
                     (iface, iface_tmp),
                   shell=True)
        check_call("ip link set %s up" % iface, shell=True)
        check_call("ip link set %s netns %s" % (iface_tmp, ns.name),
                   shell=True)
        _log.debug(check_output("ip link", shell=True))

        # Rename within the container to something sensible.
        ns.check_call("ip link set dev %s name %s" % (iface_tmp,veth_name),
                      shell=True)
        ns.check_call("ip link set %s up" % (veth_name), shell=True)

    # Add an IP address.
    add_ip_to_interface(cpid, ip, veth_name, proc_alias=proc_alias)

    with NamedNamespace(cpid, proc=proc_alias) as ns:
        # Connected route to next hop & default route.
        next_hop = next_hop_ips[ip.version]
        ns.check_call("ip -%(version)s route replace"
                      " %(next_hop)s dev %(device)s" %
                      {"version": ip.version,
                       "device": veth_name,
                       "next_hop": next_hop},
                      shell=True)
        ns.check_call("ip -%(version)s route replace"
                      " default via %(next_hop)s dev %(device)s" %
                      {"version": ip.version,
                       "device": veth_name,
                       "next_hop": next_hop},
                      shell=True)

        # Get the MAC address.
        mac = ns.check_output(
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


class NamedNamespace(object):
    """
    Create a named namespace to allow commands to be run within the namespace
    in both the calico-node and within the root namespace.
    """
    def __init__(self, cpid, proc=PROC_ALIAS):
        self.name = uuid.uuid1().hex
        self.pid_dir = "%s/%s/ns/net" % (proc, cpid)
        self.nsn_dir = "/var/run/netns/%s" % self.name

    def __enter__(self):
        """
        Add the appropriate configuration to name the namespace.  This links
        the PID to the namespace name.
        """
        _log.debug("Creating link between ns name and PID")
        try:
            os.makedirs("/var/run/netns")
        except os.error:
            _log.info("Unable to create /var/run/netns dir")
        os.symlink(self.pid_dir, self.nsn_dir)
        return self

    def __exit__(self, _type, _value, _traceback):
        try:
            os.unlink(self.nsn_dir)
        except BaseException:
            _log.exception("Failed to remove link: %s", self.nsn_dir)
        return False

    def check_call(self, command, shell=False):
        """
        Run a command within the named namespace.
        :param command: The command to run.
        :param shell: Whether this is a shell command.
        """
        _log.debug("Run command: %s", command)
        check_call("ip netns exec %s %s" % (self.name, command), shell=shell)

    def check_output(self, command, shell=False):
        """
        Run a command within the named namespace.
        :param command: The command to run.
        :param shell: Whether this is a shell command.
        """
        _log.debug("Run command: %s", command)
        return check_output("ip netns exec %s %s" % (self.name, command),
                            shell=shell)
