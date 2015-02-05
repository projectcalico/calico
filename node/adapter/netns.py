# Copyright 2015 Metaswitch Networks

from subprocess import call, check_output, check_call, CalledProcessError
import socket
import logging

_log = logging.getLogger(__name__)
_log.addHandler(logging.StreamHandler())
_log.setLevel(logging.INFO)

HOSTNAME = socket.gethostname()

VETH_NAME = "eth1"
"""The name to give to the veth in the target container's namespace"""

ROOT_NETNS = "1"
"""The pid of the root namespace.  On almost all systems, the init system is pid 1"""

def set_up_endpoint(ip, group, cid, cpid, in_container=False):

    # TODO - need to handle containers exiting straight away...
    iface = "tap" + cid[:11]
    iface_tmp = "tmp" + cid[:11]

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
    mac = check_output("ip netns exec %s ip link show %s | grep ether | awk '{print $2}'" % (cpid, VETH_NAME), shell=True).strip()
    name = ip.replace('.', '_')
    base_config = """
[endpoint %s]
id=%s
ip=%s
mac=%s
host=%s
group=%s
""" % (name, cid, ip, mac, HOSTNAME, group)

    # Write the config file to the data directory
    ep_config = open("/config/data/%s.txt" % name, mode="w")
    ep_config.write(base_config)
    ep_config.close()
