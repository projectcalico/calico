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
from calico_etcd import Endpoint
import uuid
from netaddr import IPNetwork, IPAddress

_log = logging.getLogger(__name__)

HOSTNAME = socket.gethostname()

VETH_NAME = "eth0"
"""The name to give to the veth in the target container's namespace"""

ROOT_NETNS = "1"
"""The pid of the root namespace.  On almost all systems, the init system is pid 1"""

PROC_ALIAS = "proc_host"
"""The alias for /proc.  This is useful when the filesystem is containerized."""


def setup_logging(logfile):
    _log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')
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
    iface = "cali" + ep_id[:11]
    call("ip link delete %s" % iface, shell=True)

def set_up_endpoint(ip, cpid, in_container=False, veth_name=VETH_NAME, proc_alias=PROC_ALIAS):
    """
    Set up an endpoint (veth) in the network namespace idenfitied by the PID.

    :param ip: The IP address to assign to the endpoint (veth)
    :param cpid: The PID of a process currently running in the namespace.
    :param in_container: When True, we assume this program is itself running in a container
    namespace, as opposed to the root namespace.  If so, this method also moves the other end of
    the veth into the root namespace.
    :param veth_name: The name of the interface inside the container namespace, e.g. eth0
    :return: An Endpoint describing the veth just created.
    """

    # Generate a new endpoint ID.
    ep_id = uuid.uuid1().hex

    # TODO - need to handle containers exiting straight away...
    iface = "cali" + ep_id[:11]
    iface_tmp = "tmp" + ep_id[:11]

    # Provision the networking
    check_call("mkdir -p /var/run/netns", shell=True)
    check_call("ln -s /%s/%s/ns/net /var/run/netns/%s" % (proc_alias, cpid, cpid), shell=True)

    # If running in a container, set up a link to the root netns.
    if in_container:
        try:
            check_call("ln -s /%s/%s/ns/net /var/run/netns/%s" % (proc_alias,
                                                                  ROOT_NETNS,
                                                                  ROOT_NETNS),
                       shell=True)
        except CalledProcessError:
            pass  # Only need to do this once.
    _log.debug(check_output("ls -l /var/run/netns", shell=True))

    # Create the veth pair and move one end into container:
    check_call("ip link add %s type veth peer name %s" % (iface, iface_tmp), shell=True)
    check_call("ip link set %s up" % iface, shell=True)
    check_call("ip link set %s netns %s" % (iface_tmp, cpid), shell=True)
    _log.debug(check_output("ip netns exec %s ip link" % cpid, shell=True))

    # Rename within the container to something sensible.
    check_call("ip netns exec %s ip link set dev %s name %s" % (cpid,
                                                                iface_tmp,
                                                                veth_name),
               shell=True)
    check_call("ip netns exec %s ip link set %s up" % (cpid, veth_name), shell=True)

    # If in container, the iface end of the veth pair will be in the container namespace.  We need
    # to move it to the root namespace so it will participate in routing.
    if in_container:
        # Move the other end of the veth pair into the root namespace
        check_call("ip link set %s netns %s" % (iface, ROOT_NETNS), shell=True)
        check_call("ip netns exec %s ip link set %s up" % (ROOT_NETNS, iface), shell=True)

    # Set the IP address
    check_call("ip netns exec %s ip addr add %s/32 dev %s" % (cpid, ip, veth_name), shell=True)

    # Set the default route.
    # Is there already a default route?  This occurs if there is already networking set up on
    # the container.  We want Calico to be the default route.
    routes = check_output(['ip', 'netns', 'exec', str(cpid), 'ip', 'route'])
    _log.debug('Netns %d "ip route" output:\n%s', cpid, routes)
    if 'default' in routes:
        # Delete the default.
        _log.info('Found default route in output, deleting.')
        _log.debug('"ip route" output:\n%s', routes)
        check_call("ip netns exec %s ip route del default" % cpid, shell=True)

    check_call("ip netns exec %s ip route add default dev %s" % (cpid, veth_name), shell=True)

    # Get the MAC address.
    mac = check_output("ip netns exec %s ip link show %s | grep ether | awk '{print $2}'" %
                       (cpid, veth_name), shell=True).strip()

    # Return an Endpoint
    network = IPNetwork(IPAddress(ip))
    ep = Endpoint(ep_id=ep_id, state="enabled", mac=mac, felix_host=HOSTNAME)
    if network.version == 4:
        ep.ipv4_nets.add(network)
    else:
        ep.ipv6_nets.add(network)
    return ep

