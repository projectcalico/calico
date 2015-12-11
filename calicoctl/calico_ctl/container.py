"""
Usage:
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container <CONTAINER> endpoint show
  calicoctl container <CONTAINER> profile (append|remove|set) [<PROFILES>...]
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER>

Description:
  Add or remove containers to Calico networking, manage their IP addresses and profiles.
  All these commands must be run on the host that contains the container.

Options:
  <IP>                     The IP address desired. If "ipv4", "ipv6", or a CIDR
                           is given, then Calico will attempt to automatically
                           assign an available IPv4 address, IPv6 address, or
                           IP from any Pool matching the provided CIDR,
                           respectively. NOTE: When a CIDR is passed, it must
                           exactly match an existing Calico pool.
  --interface=<INTERFACE>  The name to give to the interface in the container
                           [default: eth1]
"""

import os
import sys
import uuid

import docker.errors
from requests.exceptions import ConnectionError
from urllib3.exceptions import MaxRetryError
from subprocess import CalledProcessError
from netaddr import IPAddress, IPNetwork
from calico_ctl import endpoint
from pycalico import netns
from pycalico.datastore_datatypes import IPPool, Endpoint
from pycalico.ipam import AlreadyAssignedError

from connectors import client
from connectors import docker_client
from utils import hostname, DOCKER_ORCHESTRATOR_ID, NAMESPACE_ORCHESTRATOR_ID, \
    escape_etcd
from utils import enforce_root
from utils import print_paragraph
from utils import validate_cidr
from utils import validate_ip


def assign_any(v4_count, v6_count, pool=(None, None)):
    """
    Reserve <count> IP(s) from the datastore to be applied to a container

    :param arguments: v4_count = Count of IPv4 addresses
                      v6_count = Count of IPv6 addresses
                      pool = tuple(<IPv4 cidr>, <IPv6 cidr>)
    :return: tuple(list(IPv4 IPAddresses), list(IPv6 IPAddresses))
    """
    v4_list, v6_list = client.auto_assign_ips(v4_count, v6_count, None, {},
                                              pool=pool)
    if not any((v4_list, v6_list)):
        sys.exit("Failed to allocate any IPs (requested {0} IPv4s and {1} IPv6s). "
                 "Pools are likely exhausted.".format(v4_count, v6_count))

    return (v4_list, v6_list)

def validate_arguments(arguments):
    """
    Validate argument values:
        <IP>

    Arguments not validated:
        <CONTAINER>
        <INTERFACE>

    :param arguments: Docopt processed arguments
    """
    # Validate IP
    requested_ip = arguments.get("<IP>")
    if not (requested_ip is None or
            validate_ip(requested_ip, 4) or
            validate_ip(requested_ip, 6) or
            validate_cidr(requested_ip) or
            requested_ip.lower() in ('ipv4', 'ipv6')):
        print_paragraph("Invalid IP address specified.  Argument must be a "
                        "valid IP or CIDR.")
        sys.exit(1)

    # Validate POOL
    if requested_ip is not None and '/' in requested_ip:
        requested_pool = IPNetwork(requested_ip)

        try:
            client.get_ip_pool_config(requested_pool.version, requested_pool)
        except KeyError:
            print_paragraph("Invalid CIDR specified for desired pool. "
                            "No pool found for {0}.".format(requested_pool))
            sys.exit(1)


    # Validate PROFILE
    endpoint.validate_arguments(arguments)

def container(arguments):
    """
    Main dispatcher for container commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    validate_arguments(arguments)

    try:
        if arguments.get("ip"):
            if arguments.get("add"):
                container_ip_add(arguments.get("<CONTAINER>"),
                                 arguments.get("<IP>"),
                                 arguments.get("--interface"))
            elif arguments.get("remove"):
                container_ip_remove(arguments.get("<CONTAINER>"),
                                    arguments.get("<IP>"),
                                    arguments.get("--interface"))
            else:
                if arguments.get("add"):
                    container_add(arguments.get("<CONTAINER>"),
                                  arguments.get("<IP>"),
                                  arguments.get("--interface"))
                if arguments.get("remove"):
                    container_remove(arguments.get("<CONTAINER>"))
        elif arguments.get("endpoint"):
            orchestrator_id, workload_id = \
                                  lookup_workload(arguments.get("<CONTAINER>"))
            endpoint.endpoint_show(hostname,
                                   orchestrator_id,
                                   workload_id,
                                   None,
                                   True)
        elif arguments.get("profile"):
            orchestrator_id, workload_id = \
                                  lookup_workload(arguments.get("<CONTAINER>"))
            if arguments.get("append"):
                endpoint.endpoint_profile_append(hostname,
                                                 orchestrator_id,
                                                 workload_id,
                                                 None,
                                                 arguments['<PROFILES>'])
            elif arguments.get("remove"):
                endpoint.endpoint_profile_remove(hostname,
                                                 orchestrator_id,
                                                 workload_id,
                                                 None,
                                                 arguments['<PROFILES>'])
            elif arguments.get("set"):
                endpoint.endpoint_profile_set(hostname,
                                              orchestrator_id,
                                              workload_id,
                                              None,
                                              arguments['<PROFILES>'])
        else:
            if arguments.get("add"):
                container_add(arguments.get("<CONTAINER>"),
                              arguments.get("<IP>"),
                              arguments.get("--interface"))
            if arguments.get("remove"):
                container_remove(arguments.get("<CONTAINER>"))
    except ConnectionError as e:
        # We hit a "Permission denied error (13) if the docker daemon
        # does not have sudo permissions
        if permission_denied_error(e):
            print_paragraph("Unable to run command.  Re-run the "
                            "command as root, or configure the docker "
                            "group to run with sudo privileges (see docker "
                            "installation guide for details).")
        else:
            print_paragraph("Unable to run docker commands. Is the docker "
                            "daemon running?")
        sys.exit(1)


def lookup_workload(container_id):
    """
    Lookup the workload_id and choose the correct orchestrator ID.

    :param container_id: The container ID
    :return: and tuple of orchestrator and workload_id
    """
    if container_id.startswith("/") and os.path.exists(container_id):
        # The ID is a path. Don't do any docker lookups
        workload_id = escape_etcd(container_id)
        orchestrator_id = NAMESPACE_ORCHESTRATOR_ID
    else:
        info = get_container_info_or_exit(container_id)
        workload_id = info["Id"]
        orchestrator_id = DOCKER_ORCHESTRATOR_ID
    return orchestrator_id, workload_id


def container_add(container_id, ip, interface):
    """
    Add a container (on this host) to Calico networking with the given IP.

    :param container_id: The namespace path or the docker name/ID of the container.
    :param ip: An IPAddress object with the desired IP to assign.
    :param interface: The name of the interface in the container.
    """
    # The netns manipulations must be done as root.
    enforce_root()

    # TODO: This section is redundant in container_add_ip and elsewhere
    if container_id.startswith("/") and os.path.exists(container_id):
        # The ID is a path. Don't do any docker lookups
        workload_id = escape_etcd(container_id)
        orchestrator_id = NAMESPACE_ORCHESTRATOR_ID
        namespace = netns.Namespace(container_id)
    else:
        info = get_container_info_or_exit(container_id)
        workload_id = info["Id"]
        orchestrator_id = DOCKER_ORCHESTRATOR_ID
        namespace = netns.PidNamespace(info["State"]["Pid"])

        # Check the container is actually running.
        if not info["State"]["Running"]:
            print "%s is not currently running." % container_id
            sys.exit(1)

        # We can't set up Calico if the container shares the host namespace.
        if info["HostConfig"]["NetworkMode"] == "host":
            print "Can't add %s to Calico because it is " \
                  "running NetworkMode = host." % container_id
            sys.exit(1)

    # Check if the container already exists
    try:
        _ = client.get_endpoint(hostname=hostname,
                                orchestrator_id=orchestrator_id,
                                workload_id=workload_id)
    except KeyError:
        # Calico doesn't know about this container.  Continue.
        pass
    else:
        # Calico already set up networking for this container.  Since we got
        # called with an IP address, we shouldn't just silently exit, since
        # that would confuse the user: the container would not be reachable on
        # that IP address.
        print "%s has already been configured with Calico Networking." % \
              container_id
        sys.exit(1)

    ip, pool = get_ip_and_pool(ip)

    # The next hop IPs for this host are stored in etcd.
    next_hops = client.get_default_next_hops(hostname)
    try:
        next_hops[ip.version]
    except KeyError:
        print "This node is not configured for IPv%d." % ip.version
        unallocated_ips = client.release_ips({ip})
        if unallocated_ips:
            print ("Error during cleanup. {0} was already unallocated."
                  ).format(unallocated_ips)
        sys.exit(1)

    # Get the next hop for the IP address.
    next_hop = next_hops[ip.version]

    network = IPNetwork(IPAddress(ip))
    ep = Endpoint(hostname=hostname,
                  orchestrator_id=DOCKER_ORCHESTRATOR_ID,
                  workload_id=workload_id,
                  endpoint_id=uuid.uuid1().hex,
                  state="active",
                  mac=None)
    if network.version == 4:
        ep.ipv4_nets.add(network)
        ep.ipv4_gateway = next_hop
    else:
        ep.ipv6_nets.add(network)
        ep.ipv6_gateway = next_hop

    # Create the veth, move into the container namespace, add the IP and
    # set up the default routes.
    netns.increment_metrics(namespace)
    netns.create_veth(ep.name, ep.temp_interface_name)
    netns.move_veth_into_ns(namespace, ep.temp_interface_name, interface)
    netns.add_ip_to_ns_veth(namespace, ip, interface)
    netns.add_ns_default_route(namespace, next_hop, interface)

    # Grab the MAC assigned to the veth in the namespace.
    ep.mac = netns.get_ns_veth_mac(namespace, interface)

    # Register the endpoint with Felix.
    client.set_endpoint(ep)

    # Let the caller know what endpoint was created.
    print "IP %s added to %s" % (str(ip), container_id)
    return ep


def container_remove(container_id):
    """
    Remove a container (on this host) from Calico networking.

    The container may be left in a state without any working networking.
    If there is a network adaptor in the host namespace used by the container
    then it is removed.

    :param container_id: The namespace path or the ID of the container.
    """
    # The netns manipulations must be done as root.
    enforce_root()

    # Resolve the name to ID.
    if container_id.startswith("/") and os.path.exists(container_id):
        # The ID is a path. Don't do any docker lookups
        orchestrator_id = NAMESPACE_ORCHESTRATOR_ID
        endpoints = client.get_endpoints(hostname=hostname,
                                         orchestrator_id=orchestrator_id,
                                         workload_id=escape_etcd(container_id))
    else:
        # We know we're using "docker" as the orchestrator. If we have a direct
        # hit on the container id then we can proceed. Otherwise, ask docker to
        # try converting the name/id fragment into a full ID.
        orchestrator_id = DOCKER_ORCHESTRATOR_ID
        endpoints = client.get_endpoints(hostname=hostname,
                                         orchestrator_id=orchestrator_id,
                                         workload_id=container_id)

        if not endpoints:
            container_id = get_workload_id(container_id)
            endpoints = client.get_endpoints(hostname=hostname,
                                             orchestrator_id=orchestrator_id,
                                             workload_id=container_id)

    for endpoint in endpoints:
        # Remove any IP address assignments that this endpoint has
        client.release_ips(set(map(IPAddress,
                                   endpoint.ipv4_nets | endpoint.ipv6_nets)))

        try:
            # Remove the interface if it exists
            netns.remove_veth(endpoint.name)
        except CalledProcessError:
            print "Could not remove Calico interface %s" % endpoint.name

    # Always try to remove the workload, even if we didn't find any
    # endpoints.
    try:
        client.remove_workload(hostname, orchestrator_id, container_id)
        print "Removed Calico from %s" % container_id
    except KeyError:
        print "Failed find Calico data for %s" % container_id


# TODO: If container created with IPv4 and then add IPv6 address, do we set up the
# default route for IPv6 correctly (code read suggests not).
def container_ip_add(container_id, ip, interface):
    """
    Add an IP address to an existing Calico networked container.

    :param container_id: The namespace path or container_id of the container.
    :param ip: The IP to add
    :param interface: The name of the interface in the container.

    :return: None
    """

    # The netns manipulations must be done as root.
    enforce_root()

    if container_id.startswith("/") and os.path.exists(container_id):
        # The ID is a path. Don't do any docker lookups
        workload_id = escape_etcd(container_id)
        namespace = netns.Namespace(container_id)
        orchestrator_id = NAMESPACE_ORCHESTRATOR_ID
    else:
        info = get_container_info_or_exit(container_id)
        workload_id = info["Id"]
        namespace = netns.PidNamespace(info["State"]["Pid"])
        orchestrator_id = DOCKER_ORCHESTRATOR_ID

        # Check the container is actually running.
        if not info["State"]["Running"]:
            print "%s is not currently running." % container_id
            sys.exit(1)

    # Check that the container is already networked
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=orchestrator_id,
                                       workload_id=workload_id)
    except KeyError:
        print "Failed to add IP address to container.\n"
        print_container_not_in_calico_msg(container_id)
        sys.exit(1)

    # From here, this method starts having side effects. If something
    # fails then at least try to leave the system in a clean state.
    address, pool = get_ip_and_pool(ip)

    try:
        if address.version == 4:
            endpoint.ipv4_nets.add(IPNetwork(address))
        else:
            endpoint.ipv6_nets.add(IPNetwork(address))
        client.update_endpoint(endpoint)
    except (KeyError, ValueError):
        client.release_ips({address})
        print "Error updating datastore. Aborting."
        sys.exit(1)

    if not netns.ns_veth_exists(namespace, interface):
        print "Interface provided does not exist in container. Aborting."
        sys.exit(1)

    try:
        netns.add_ip_to_ns_veth(namespace, address, interface)
    except CalledProcessError:
        print "Error updating networking in container. Aborting."
        if address.version == 4:
            endpoint.ipv4_nets.remove(IPNetwork(address))
        else:
            endpoint.ipv6_nets.remove(IPNetwork(address))
        client.update_endpoint(endpoint)
        client.release_ips({address})
        sys.exit(1)

    print "IP %s added to %s" % (str(address), container_id)


def container_ip_remove(container_id, ip, interface):
    """
    Add an IP address to an existing Calico networked container.

    :param container_id: The namespace path or container_id of the container.
    :param ip: The IP to add
    :param interface: The name of the interface in the container.

    :return: None
    """
    address = IPAddress(ip)

    # The netns manipulations must be done as root.
    enforce_root()

    pool = get_pool_or_exit(address)
    if container_id.startswith("/") and os.path.exists(container_id):
        # The ID is a path. Don't do any docker lookups
        workload_id = escape_etcd(container_id)
        namespace = netns.Namespace(container_id)
        orchestrator_id = NAMESPACE_ORCHESTRATOR_ID
    else:
        info = get_container_info_or_exit(container_id)
        workload_id = info["Id"]
        namespace = netns.PidNamespace(info["State"]["Pid"])
        orchestrator_id = DOCKER_ORCHESTRATOR_ID

        # Check the container is actually running.
        if not info["State"]["Running"]:
            print "%s is not currently running." % container_id
            sys.exit(1)

    # Check that the container is already networked
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=orchestrator_id,
                                       workload_id=workload_id)
        if address.version == 4:
            nets = endpoint.ipv4_nets
        else:
            nets = endpoint.ipv6_nets

        if not IPNetwork(address) in nets:
            print "IP address is not assigned to container. Aborting."
            sys.exit(1)

    except KeyError:
        print "Container is unknown to Calico."
        sys.exit(1)

    try:
        nets.remove(IPNetwork(address))
        client.update_endpoint(endpoint)
    except (KeyError, ValueError):
        print "Error updating datastore. Aborting."
        sys.exit(1)

    try:
        netns.remove_ip_from_ns_veth(namespace, address, interface)

    except CalledProcessError:
        print "Error updating networking in container. Aborting."
        sys.exit(1)

    client.release_ips({address})

    print "IP %s removed from %s" % (ip, container_id)


def get_ip_and_pool(ip):
    if ip.lower() in ("ipv4", "ipv6"):
        if '4' in ip:
            result = assign_any(1, 0)
            ip = result[0][0]
        else:
            result = assign_any(0, 1)
            ip = result[1][0]
        pool = get_pool_or_exit(ip)
    elif ip is not None and '/' in ip:
        pool = IPPool(ip)
        if IPNetwork(ip).version == 4:
            result = assign_any(1, 0, pool=(pool, None))
            ip = result[0][0]
        else:
            result = assign_any(0, 1, pool=(None, pool))
            ip = result[1][0]
    else:
        # Check the IP is in the allocation pool.  If it isn't, BIRD won't
        # export it.
        ip = IPAddress(ip)
        pool = get_pool_or_exit(ip)

        # Assign the IP
        try:
            client.assign_ip(ip, None, {})
        except AlreadyAssignedError:
            print_paragraph("IP address is already assigned in pool "
                            "%s." % pool)
            sys.exit(1)

    return (ip, pool)


def get_pool_or_exit(ip):
    """
    Get the first allocation pool that an IP is in.

    :param ip: The IPAddress to find the pool for.
    :return: The pool or sys.exit
    """
    pools = client.get_ip_pools(ip.version)
    pool = None
    for candidate_pool in pools:
        if ip in candidate_pool:
            pool = candidate_pool
            break
    if pool is None:
        print "%s is not in any configured pools" % ip
        sys.exit(1)

    return pool


def print_container_not_in_calico_msg(container_name):
    """
    Display message indicating that the supplied container is not known to
    Calico.
    :param container_name: The container name.
    :return: None.
    """
    print_paragraph("Container %s is unknown to Calico." % container_name)
    print_paragraph("Use `calicoctl container add` to add the container "
                    "to the Calico network.")


def get_workload_id(container_id):
    """
    Get the a workload ID from either a namespace path or a partial Docker
    ID or Docker name.

    :param container_id: The namespace or Docker ID/Name.
    :return: The workload ID as a string.
    """
    if container_id.startswith("/") and os.path.exists(container_id):
        # The ID is a path. Don't do any docker lookups
        workload_id = escape_etcd(container_id)
    else:
        info = get_container_info_or_exit(container_id)
        workload_id = info["Id"]
    return workload_id


def get_container_info_or_exit(container_name):
    """
    Get the full container info array from a partial ID or name.

    :param container_name: The partial ID or name of the container.
    :return: The container info array, or sys.exit if not found.
    """
    try:
        info = docker_client.inspect_container(container_name)
    except docker.errors.APIError as e:
        if e.response.status_code == 404:
            print "Container %s was not found." % container_name
        else:
            print e.message
        sys.exit(1)
    return info


def permission_denied_error(conn_error):
    """
    Determine whether the supplied connection error is from a permission denied
    error.
    :param conn_error: A requests.exceptions.ConnectionError instance
    :return: True if error is from permission denied.
    """
    # Grab the MaxRetryError from the ConnectionError arguments.
    mre = None
    for arg in conn_error.args:
        if isinstance(arg, MaxRetryError):
            mre = arg
            break
    if not mre:
        return None

    # See if permission denied is in the MaxRetryError arguments.
    se = None
    for arg in mre.args:
        if "Permission denied" in str(arg):
            se = arg
            break
    if not se:
        return None

    return True
