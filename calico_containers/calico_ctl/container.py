"""
Usage:
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container <CONTAINER> endpoint-id show
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER>

Description:
  Add or remove containers to calico networking and manage their assigned IP addresses.

Options:
  --interface=<INTERFACE>  The name to give to the interface in the container
                           [default: eth1]
"""
import sys
import uuid

import docker.errors
from requests.exceptions import ConnectionError
from urllib3.exceptions import MaxRetryError
from subprocess import CalledProcessError
from netaddr import IPAddress, IPNetwork

from pycalico import netns
from pycalico.datastore_datatypes import Endpoint
from utils import hostname, ORCHESTRATOR_ID
from utils import client
from utils import enforce_root
from utils import get_container_ipv_from_arguments
from utils import docker_client
from utils import print_paragraph
from utils import validate_ip


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
    container_ip_ok = arguments.get("<IP>") is None or \
                        validate_ip(arguments["<IP>"], 4) or \
                        validate_ip(arguments["<IP>"], 6)

    # Print error message and exit if not valid argument
    if not container_ip_ok:
        print "Invalid IP address specified."
        sys.exit(1)


def container(arguments):
    """
    Main dispatcher for container commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    validate_arguments(arguments)

    ip_version = get_container_ipv_from_arguments(arguments)
    try:
        if arguments.get("endpoint-id"):
            container_endpoint_id_show(arguments.get("<CONTAINER>"))
        elif arguments.get("ip"):
            if arguments.get("add"):
                container_ip_add(arguments.get("<CONTAINER>"),
                                 arguments.get("<IP>"),
                                 ip_version,
                                 arguments.get("--interface"))
            elif arguments.get("remove"):
                container_ip_remove(arguments.get("<CONTAINER>"),
                                    arguments.get("<IP>"),
                                    ip_version,
                                    arguments.get("--interface"))
            else:
                if arguments.get("add"):
                    container_add(arguments.get("<CONTAINER>"),
                                  arguments.get("<IP>"),
                                  arguments.get("--interface"))
                if arguments.get("remove"):
                    container_remove(arguments.get("<CONTAINER>"))
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


def container_add(container_name, ip, interface):
    """
    Add a container (on this host) to Calico networking with the given IP.

    :param container_name: The name or ID of the container.
    :param ip: An IPAddress object with the desired IP to assign.
    :param interface: The name of the interface in the container.
    """
    # The netns manipulations must be done as root.
    enforce_root()
    info = get_container_info_or_exit(container_name)
    container_id = info["Id"]

    # Check if the container already exists
    try:
        _ = client.get_endpoint(hostname=hostname,
                                orchestrator_id=ORCHESTRATOR_ID,
                                workload_id=container_id)
    except KeyError:
        # Calico doesn't know about this container.  Continue.
        pass
    else:
        # Calico already set up networking for this container.  Since we got
        # called with an IP address, we shouldn't just silently exit, since
        # that would confuse the user: the container would not be reachable on
        # that IP address.
        print "%s has already been configured with Calico Networking." % \
              container_name
        sys.exit(1)

    # Check the container is actually running.
    if not info["State"]["Running"]:
        print "%s is not currently running." % container_name
        sys.exit(1)

    # We can't set up Calico if the container shares the host namespace.
    if info["HostConfig"]["NetworkMode"] == "host":
        print "Can't add %s to Calico because it is " \
              "running NetworkMode = host." % container_name
        sys.exit(1)

    # Check the IP is in the allocation pool.  If it isn't, BIRD won't export
    # it.
    ip = IPAddress(ip)
    pool = get_pool_or_exit(ip)

    # The next hop IPs for this host are stored in etcd.
    next_hops = client.get_default_next_hops(hostname)
    try:
        next_hops[ip.version]
    except KeyError:
        print "This node is not configured for IPv%d." % ip.version
        sys.exit(1)

    # Assign the IP
    if not client.assign_address(pool, ip):
        print "IP address is already assigned in pool %s " % pool
        sys.exit(1)

    # Get the next hop for the IP address.
    next_hop = next_hops[ip.version]

    network = IPNetwork(IPAddress(ip))
    ep = Endpoint(hostname=hostname,
                  orchestrator_id=ORCHESTRATOR_ID,
                  workload_id=container_id,
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
    pid = info["State"]["Pid"]
    netns.create_veth(ep.name, ep.temp_interface_name)
    netns.move_veth_into_ns(pid, ep.temp_interface_name, interface)
    netns.add_ip_to_ns_veth(pid, ip, interface)
    netns.add_ns_default_route(pid, next_hop, interface)

    # Grab the MAC assigned to the veth in the namespace.
    ep.mac = netns.get_ns_veth_mac(pid, interface)

    # Register the endpoint with Felix.
    client.set_endpoint(ep)

    # Let the caller know what endpoint was created.
    return ep


def container_remove(container_name):
    """
    Remove a container (on this host) from Calico networking.

    The container may be left in a state without any working networking.
    If there is a network adaptor in the host namespace used by the container
    then it is removed.

    :param container_name: The name or ID of the container.
    """
    # The netns manipulations must be done as root.
    enforce_root()

    # Resolve the name to ID.
    workload_id = get_container_id(container_name)

    # Find the endpoint ID. We need this to find any ACL rules
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=ORCHESTRATOR_ID,
                                       workload_id=workload_id)
    except KeyError:
        print "Container %s doesn't contain any endpoints" % container_name
        sys.exit(1)

    # Remove any IP address assignments that this endpoint has
    for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
        assert(net.size == 1)
        ip = net.ip
        pools = client.get_ip_pools(ip.version)
        for pool in pools:
            if ip in pool:
                # Ignore failure to unassign address, since we're not
                # enforcing assignments strictly in datastore.py.
                client.unassign_address(pool, ip)

    # Remove the endpoint
    netns.remove_veth(endpoint.name)

    # Remove the container from the datastore.
    client.remove_workload(hostname, ORCHESTRATOR_ID, workload_id)

    print "Removed Calico interface from %s" % container_name


# TODO: If container created with IPv4 and then add IPv6 address, do we set up the
# default route for IPv6 correctly (code read suggests not).
def container_ip_add(container_name, ip, interface):
    """
    Add an IP address to an existing Calico networked container.

    :param container_name: The name of the container.
    :param ip: The IP to add
    :param interface: The name of the interface in the container.

    :return: None
    """
    address = IPAddress(ip)

    # The netns manipulations must be done as root.
    enforce_root()

    pool = get_pool_or_exit(address)

    info = get_container_info_or_exit(container_name)
    container_id = info["Id"]

    # Check the container is actually running.
    if not info["State"]["Running"]:
        print "%s is not currently running." % container_name
        sys.exit(1)

    # Check that the container is already networked
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=ORCHESTRATOR_ID,
                                       workload_id=container_id)
    except KeyError:
        print "Failed to add IP address to container.\n"
        print_container_not_in_calico_msg(container_name)
        sys.exit(1)

    # From here, this method starts having side effects. If something
    # fails then at least try to leave the system in a clean state.
    if not client.assign_address(pool, ip):
        print "IP address is already assigned in pool %s " % pool
        sys.exit(1)

    try:
        if address.version == 4:
            endpoint.ipv4_nets.add(IPNetwork(address))
        else:
            endpoint.ipv6_nets.add(IPNetwork(address))
        client.update_endpoint(endpoint)
    except (KeyError, ValueError):
        client.unassign_address(pool, ip)
        print "Error updating datastore. Aborting."
        sys.exit(1)

    try:
        container_pid = info["State"]["Pid"]
        netns.add_ip_to_ns_veth(container_pid, address, interface)
    except CalledProcessError:
        print "Error updating networking in container. Aborting."
        if address.version == 4:
            endpoint.ipv4_nets.remove(IPNetwork(address))
        else:
            endpoint.ipv6_nets.remove(IPNetwork(address))
        client.update_endpoint(endpoint)
        client.unassign_address(pool, ip)
        sys.exit(1)

    print "IP %s added to %s" % (ip, container_id)


def container_ip_remove(container_name, ip, interface):
    """
    Add an IP address to an existing Calico networked container.

    :param container_name: The name of the container.
    :param ip: The IP to add
    :param interface: The name of the interface in the container.

    :return: None
    """
    address = IPAddress(ip)

    # The netns manipulations must be done as root.
    enforce_root()

    pool = get_pool_or_exit(address)

    info = get_container_info_or_exit(container_name)
    container_id = info["Id"]

    # Check the container is actually running.
    if not info["State"]["Running"]:
        print "%s is not currently running." % container_name
        sys.exit(1)

    # Check that the container is already networked
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=ORCHESTRATOR_ID,
                                       workload_id=container_id)
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
        container_pid = info["State"]["Pid"]
        netns.remove_ip_from_ns_veth(container_pid, address, interface)

    except CalledProcessError:
        print "Error updating networking in container. Aborting."
        sys.exit(1)

    client.unassign_address(pool, ip)

    print "IP %s removed from %s" % (ip, container_name)


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


def container_endpoint_id_show(container_name):
    """
    Prints the endpoint-id of the endpoint attached to the specified
    container, or an appropriate Not-found error message.

    :param container_name: Name of the container the target endpoint
    is attached to.
    :return: None
    """
    workload_id = get_container_id(container_name)
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=ORCHESTRATOR_ID,
                                       workload_id=workload_id)
        print endpoint.endpoint_id
    except KeyError:
        print "No endpoint was found for %s" % container_name


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


def get_container_id(container_name):
    """
    Get the full container ID from a partial ID or name.

    :param container_name: The partial ID or name of the container.
    :return: The container ID as a string.
    """
    info = get_container_info_or_exit(container_name)
    return info["Id"]


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
