from flask import Flask, jsonify, abort, request
import os
import socket
from subprocess import check_call
import logging

from netaddr import IPAddress, IPNetwork
import sys

from pycalico.datastore import IF_PREFIX, Endpoint
from pycalico.ipam import SequentialAssignment, IPAMClient

FIXED_MAC = "EE:EE:EE:EE:EE:EE"

CONTAINER_NAME = "undefined"

app = Flask(__name__)
hostname = socket.gethostname()
client = IPAMClient()


app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)

app.logger.info("Application started")


@app.route('/Plugin.Activate', methods=['POST'])
def activate():
    return jsonify({"Implements": ["NetworkDriver"]})


@app.route('/NetworkDriver.CreateNetwork', methods=['POST'])
def create_network():
    # force is required since the request doesn't have the correct mimetype
    # If the JSON is malformed, then a BadRequest exception is raised,
    # which returns a HTTP 400 response.
    json_data = request.get_json(force=True)

    # Create the "network" as a profile. The network ID is somewhat unwieldy
    # so in future we might want to obtain a human readable name for it.
    network_id = json_data["NetworkID"]
    app.logger.info("Creating profile %s", network_id)
    client.create_profile(network_id)

    return jsonify({})


@app.route('/NetworkDriver.DeleteNetwork', methods=['POST'])
def delete_network():
    json_data = request.get_json(force=True)

    # Remove the network. We don't raise an error if the profile is still
    # being used by endpoints. We assume libnetwork will enforce this.
    # From https://github.com/docker/libnetwork/blob/master/docs/design.md
    #   LibNetwork will not allow the delete to proceed if there are any
    #   existing endpoints attached to the Network.
    network_id = json_data["NetworkID"]
    app.logger.info("Removing profile %s", network_id)
    client.remove_profile(network_id)

    return jsonify({})


@app.route('/NetworkDriver.CreateEndpoint', methods=['POST'])
def create_endpoint():
    # TODO - what happens when an operation fails? rollback and error codes.
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    net_id = json_data["NetworkID"]

    if len(json_data["Interfaces"]) == 0:
        # No interfaces were passed, we need to allocated one. By default we
        #  only assign an IPv4 address.
        ip = assign_ip("v4")
        ip6 = assign_ip("v6")
        app.logger.info("Assigned IP %s and %s", ip, ip6)
        if not ip:
            app.logger.error("Failed to allocate IP for endpoint %s",
                             ep_id)
            abort(500)

        ip = IPNetwork(ip)
        next_hop = client.get_default_next_hops(hostname)[ip.version]

        # TODO - do we really have to set the if_name here. And should sort
        # out the naming of the outside interface name.
        ep = Endpoint(ep_id=ep_id, state="active", mac=FIXED_MAC, if_name='cali0')
        ep.ipv4_nets.add(ip)
        ep.ipv4_gateway = next_hop

        iface_json = {
            "ID": 0,
            "Address": str(ip),
            "MacAddress": ep.mac
        }

        if ip6:
            ip6 = IPNetwork(ip6)
            ep.ipv6_nets.add(ip6)
            iface_json["AddressIPv6"] = str(ip6)

            try:
                next_hop6 = client.get_default_next_hops(hostname)[ip6.version]
            except KeyError:
                app.logger.info("Couldn't find IPv6 gateway for endpoint %s",
                                ep_id)
            else:
                ep.ipv6_gateway = next_hop6
        else:
            app.logger.info("Failed to allocate IPv6 address for endpoint %s",
                            ep_id)

        ep.profile_id = net_id

        # This iface name must match the code in the Endpoint object.
        iface = IF_PREFIX + ep_id[:11]

        # Create the veth
        check_call(['ip', 'link',
                    'add', ep.name,
                    'type', 'veth',
                    'peer', 'name', ep.temp_interface_name()])

        # Set the host end of the veth to 'up' so felix notices it.
        check_call(['ip', 'link', 'set', iface, 'up'])

        # Set the mac as libnetwork doesn't do this for us.
        check_call(['ip', 'link', 'set',
                    'dev', ep.temp_interface_name(),
                    'address', FIXED_MAC])

        client.set_endpoint(hostname, CONTAINER_NAME, ep)

        return jsonify({
            "Interfaces": [iface_json]
        })
    else:
        app.logger.error("Currently don't support being passed interfaces")
        abort(500)
        # TODO - untested
        # TODO - We don't know how to support multiple interfaces. How can
        # an endpoint have multiple interfaces?
        # TODO - Check that the provided IP is valid, and in a pool and
        # currently unassigned.


@app.route('/NetworkDriver.DeleteEndpoint', methods=['POST'])
def delete_endpoint():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    app.logger.info("Removing endpoint %s", ep_id)

    ep = client.get_endpoint(hostname, CONTAINER_NAME, ep_id)
    for ip in ep.ipv4_nets.union(ep.ipv6_nets):
        unassign_ip(ip)

    client.remove_endpoint(hostname, CONTAINER_NAME, ep_id)

    # TODO - understand if we need to delete the veth or if libnetwork does it.

    return jsonify({"Value": {}})


@app.route('/NetworkDriver.EndpointOperInfo', methods=['POST'])
def endpoint_oper_info():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    net_id = json_data["NetworkID"]
    app.logger.info("Endpoint operation info requested for %s", ep_id)

    # TODO - check what other drivers return.

    # Nothing is supported yet, just pass blank data.
    return jsonify({"Value": {}})


@app.route('/NetworkDriver.Join', methods=['POST'])
def join():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    app.logger.info("Joining endpoint %s", ep_id)

    ep = client.get_endpoint(hostname, CONTAINER_NAME, ep_id)
    ret_json = {
        "InterfaceNames": [{
            "SrcName": ep.temp_interface_name(),
            "DstName": IF_PREFIX
        }],
        "Gateway": str(ep.ipv4_gateway),
        "StaticRoutes": [{
            "Destination": "%s/32" % ep.ipv4_gateway,
            "RouteType": 1,  # 1 = CONNECTED
            "NextHop": "",
            "InterfaceID": 0  # 1st interface created in EndpointCreate
            }]
    }
    if ep.ipv6_gateway:
        ret_json["GatewayIPv6"] = str(ep.ipv6_gateway)
        ret_json["StaticRoutes"].append({
            "Destination": "%s/128" % ep.ipv6_gateway,
            "RouteType": 1,  # 1 = CONNECTED
            "NextHop": "",
            "InterfaceID": 0  # 1st interface created in EndpointCreate
            })

    return jsonify(ret_json)


@app.route('/NetworkDriver.Leave', methods=['POST'])
def leave():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    app.logger.info("Leaving endpoint %s", ep_id)

    # Noop. There's nothing to do.

    return jsonify({"Value": {}})


def assign_ip(version):
    """
    Assign a IP address from the configured pools.
    :param version: "v4" for IPv4, "v6" for IPv6.
    :return: An IPAddress, or None if an IP couldn't be
             assigned
    """
    ip = None

    assert version in ["v4", "v6"]
    # For each configured pool, attempt to assign an IP before giving up.
    for pool in client.get_ip_pools(version):
        assigner = SequentialAssignment()
        ip = assigner.allocate(pool)
        if ip is not None:
            ip = IPAddress(ip)
            break
    return ip


def unassign_ip(ip):
    """
    Unassign a IP address from the configured pools.
    :param ip: IPAddress to unassign.
    :return: True if the unassignment succeeded. False otherwise.
    """
    # For each configured pool, attempt to unassign the IP before giving up.
    version = "v%d" % ip.version
    for pool in client.get_ip_pools(version):
        # TODO check pool membership locally.
        if client.unassign_address(pool, ip):
            return True
    return False


if __name__ == '__main__':
    # Used when being invoked by the flask development server
    PLUGIN_DIR = "/usr/share/docker/plugins/"
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR)
    with open(os.path.join(PLUGIN_DIR, 'calico.spec'), 'w') as f:
        f.write("tcp://localhost:5000")

    # Turns on better error messages and reloading support.
    app.debug = True
    app.run()

