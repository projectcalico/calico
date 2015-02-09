# Copyright 2015 Metaswitch Networks

from subprocess import call, check_output, check_call, CalledProcessError
import socket
import logging
import logging.handlers
import sys
from calico_etcd import Endpoint
import uuid

_log = logging.getLogger(__name__)

HOSTNAME = socket.gethostname()

VETH_NAME = "eth0"
"""The name to give to the veth in the target container's namespace"""

ROOT_NETNS = "1"
"""The pid of the root namespace.  On almost all systems, the init system is pid 1"""


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


def set_up_endpoint(ip, cpid, in_container=False):
    """
    Set up an endpoint (veth) in the network namespace idenfitied by the PID.

    :param ip: The IP address to assign to the endpoint (veth)
    :param cpid: The PID of a process currently running in the namespace.
    :param in_container: When True, we assume this program is itself running in a container
    namespace, as opposed to the root namespace.  If so, this method also moves the other end of
    the veth into the root namespace.
    :return: An Endpoint describing the veth just created.
    """

    # Generate a new endpoint ID.
    ep_id = uuid.uuid1().hex

    # TODO - need to handle containers exiting straight away...
    iface = "tap" + ep_id[:11]
    iface_tmp = "tmp" + ep_id[:11]

    # Provision the networking
    check_call("mkdir -p /var/run/netns", shell=True)
    check_call("ln -s /proc_host/%s/ns/net /var/run/netns/%s" % (cpid, cpid), shell=True)

    # If running in a container, set up a link to the root netns.
    if in_container:
        try:
            check_call("ln -s /proc_host/%s/ns/net /var/run/netns/%s" % (ROOT_NETNS,
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
                                                                VETH_NAME),
               shell=True)
    check_call("ip netns exec %s ip link set %s up" % (cpid, VETH_NAME), shell=True)

    # If in container, the iface end of the veth pair will be in the container namespace.  We need
    # to move it to the root namespace so it will participate in routing.
    if in_container:
        # Move the other end of the veth pair into the root namespace
        check_call("ip link set %s netns %s" % (iface, ROOT_NETNS), shell=True)
        check_call("ip netns exec %s ip link set %s up" % (ROOT_NETNS, iface), shell=True)

    # Add an IP address to that thing :
    check_call("ip netns exec %s ip addr add %s/32 dev %s" % (cpid, ip, VETH_NAME), shell=True)
    check_call("ip netns exec %s ip route add default dev %s" % (cpid, VETH_NAME), shell=True)

    # Get the MAC address.
    mac = check_output("ip netns exec %s ip link show %s | grep ether | awk '{print $2}'" %
                       (cpid, VETH_NAME), shell=True).strip()

    # Return an Endpoint
    return Endpoint(id=ep_id, addrs=[{"addr":ip}], state="enabled", mac=mac)

