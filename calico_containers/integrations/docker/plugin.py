#!/usr/bin/env python
"""plugin

Usage:
  plugin CreateNetwork <nid> [options ...]
  plugin DeleteNetwork <nid>
  plugin CreateEndpoint <nid> <eid> [options ...]
  plugin DeleteEndpoint <nid> <eid>
  plugin EndpointInfo <nid> <eid>
  plugin Join <nid> <eid> <sboxKey> [options ...]
  plugin Leave <nid> <eid> [options ...]
"""
from docopt import docopt
from collections import namedtuple
from calico_containers.adapter.ipam import IPAMClient

JoinInfo = namedtuple("JoinInfo", "HostsPath")

# SandboxInfo represents all possible information that
# the driver wants to place in the sandbox which includes
# interfaces, routes and gateway
# SandboxInfo = namedtuple("SandboxInfo", "Interfaces Gateway GatewayIPv6")


# type EndpointInfo interface {
# Interfaces returns a list of interfaces bound to the endpoint.
# If the list is not empty the driver is only expected to consume the interfaces.
# It is an error to try to add interfaces to a non-empty list.
# If the list is empty the driver is expected to populate with 0 or more interfaces.
# Interfaces() []InterfaceInfo

#
# // InterfaceInfo provides a go interface for drivers to retrive
# // network information to interface resources.
# type InterfaceInfo interface {
# 	// Address returns the IPv4 address.
# 	Address() net.IPNet
#
# 	// AddressIPv6 returns the IPv6 address.
# 	AddressIPv6() net.IPNet
#
# 	// ID returns the numerical id of the interface and has significance only within
# 	// the endpoint.
# 	ID() int
# }


# TODO - config

client = IPAMClient()

def CreateNetwork(nid, options):
    """
    CreateNetwork invokes the driver method to create a network passing
    the network id and network specific config. The config mechanism will
    eventually be replaced with labels which are yet to be introduced.

    :param nid: The network ID (a UUID)
    :param option: Map of String to arbitrary objects
    :return: just errors
    """

    # Create a profile to represent the "network"
    client.create_profile(nid)

    # TODO - what other config might we want to be passed in?

def DeleteNetwork(nid):
    """
    DeleteNetwork invokes the driver method to delete network passing
    the network id.

    :param nid:
    :return: just errors
    """
    # Delete the profile.
    client.remove_profile(nid)


def CreateEndpoint(nid, eid, options, epInfo):
    """
    CreateEndpoint invokes the driver method to create an endpoint
    passing the network id, endpoint id and driver
    specific config. The config mechanism will eventually be replaced
    with labels which are yet to be introduced.

    :param nid:
    :param eid:
    :param options:
    :param epInfo: a list of InterfaceInfo objects

    :return: the epInfo is updated in place.
    """
    # This endpoint can only exist on one host
    # We _could_ create it in etcd now, but it's not clear yet whether
    # there's any point.
    # We do need to allocate an IP though
    # TODO allocate IP
    # ...and create and return a SandboxInfo object

    # THe epInfo object might be empty, if it is then we assign IP addresses.
    # If it's not, then we should (try to) use the values it contains.

    if epInfo:
        # Using passed in IPv4 and IPv6 addresses.
        # TODO - What can e actually do with them? We can create an endpoint
        #  object. We know the profile and the addresses, (and our
        # hostname) but nothing else. What we're missing from the path
        #   - workload_id
        # What we're missing from the json blob
        #   - name (of the linux interface on the host)
        #   - mac
        #   - the gateway address (well, it's ourselves...)
        # So - we could assign the interface name now, with a mac and we
        # know the gateway. So we're only missing the workload ID....

        # In this scenario we're being passed the IP - what does that mean?
    """
    We could just assign it, and ignore the fact that it might already be
    assigned... seems reasonable.

    And how do we handle being passed multiple IPs?
        We _could_ just create a single endpoint with all the IPs on it...
        Or we could create multiple endpoint objects.
    """


    else:
        # Assigning IP
        # TODO - as above, jsut assign the IP first.

"""

    We also need to create the veths - we just don't push them into the
    sandbox ourselves.

"""
    pass



def DeleteEndpoint(nid, eid):
    """
    DeleteEndpoint invokes the driver method to delete an endpoint
    passing the network id and endpoint id.

    :param nid:
    :param eid:
    :return: just errors
    """
    # Delete the endpoint from etcd.
    # client.remove_endpoint() # TODO doesn't exist yet...

    # Do we need to handle deleting the veths too?
    pass

def EndpointInfo(nid, eid):
    """
    EndpointInfo retrieves from the driver the operational data related to the specified endpoint

    :param nid:
    :param eid:
    :return: Map of String to arbitrary objects
    """
    # I don't know what this does yet...
    pass

def Join(nid, eid, sboxKey, options):
    """
    Join method is invoked when a Sandbox is attached to an endpoint.

    :param nid:
    :param eid:
    :param sboxKey:
    :param options:
    :return: a JoinInfo object
    """
    # sboxkey identifies the actual workload. So move the endpoint to the
    # right place.

    # JoinInfo allows us to add
    # a list of src/dst interface names
    # a default gateway
    pass

def Leave(nid, eid, options):
    """
    Leave method is invoked when a Sandbox detaches from an endpoint.

    :param nid:
    :param eid:
    :param options:
    :return: just errors
    """
    pass


def EndpointOperInfo(nid, eid):
    """
    EndpointInfo retrieves from the driver the operational data related to the specified endpoint

    :param nid:
    :param eid:
    :return: (map[string]interface{}, error)
    """
    pass


if __name__ == '__main__':
    arguments = docopt(__doc__)

    if arguments["node"]:
        pass

