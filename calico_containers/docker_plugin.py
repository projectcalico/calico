from flask import Flask, jsonify, abort, request
import os
import socket
from subprocess import check_call

from netaddr import IPAddress, IPNetwork

from pycalico.datastore import IF_PREFIX, Endpoint
from pycalico.ipam import SequentialAssignment, IPAMClient

CONTAINER_NAME = "undefined"

app = Flask(__name__)
hostname = socket.gethostname()
client = IPAMClient()


@app.route('/Plugin.Activate', methods=['POST'])
def activate():
    return jsonify({"Implements": ["NetworkDriver"]})


@app.route('/NetworkDriver.CreateNetwork', methods=['POST'])
def create_network():
    json_data = request.get_json(force=True) # TODO - what if JSON can't be parsed

    # Create the "network" as a profile
    client.create_profile(json_data["NetworkID"])

    return jsonify({})


@app.route('/NetworkDriver.DeleteNetwork', methods=['POST'])
def delete_network():
    json_data = request.get_json(force=True)

    # Remove the network
    client.remove_profile(json_data["NetworkID"])

    #TODO - What if the profile has endpoints?
    return jsonify({})


@app.route('/NetworkDriver.CreateEndpoint', methods=['POST'])
def create_endpoint():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    net_id = json_data["NetworkID"]

    if len(json_data["Interfaces"]) == 0:
        # No interfaces were passed, we need to allocated them.
        ip = assign_ipv4()
        app.logger.info("Assigned IP %s", ip)
        if not ip:
            app.logger.error("Failed to allocate IP for endpoint %s",
                             ep_id)
            abort(500)
        ip = IPNetwork(ip)
        # TODO - Mac. Create one, use a fixed one or what? What does
        # libnetwork do with it?

        next_hop = client.get_default_next_hops(hostname)[ip.version]
        container_id = CONTAINER_NAME
        mac = "EE:EE:EE:EE:EE:EE"
        iface = IF_PREFIX + ep_id[:11]
        iface_tmp = "tmp" + ep_id[:11]

        # Create the veth
        check_call(['ip', 'link',
                    'add', iface,
                    'type', 'veth',
                    'peer', 'name', iface_tmp])

        # Set the host end of the veth to 'up' so felix notices it.
        check_call(['ip', 'link', 'set', iface, 'up'])

        # Set the mac as libnetwork doesn't do this for us.
        check_call(['ip', 'link', 'set', 'dev', iface_tmp, 'address', mac])

        ep = Endpoint(ep_id=ep_id, state="active", mac=mac, if_name='cali0')
        ep.ipv4_nets.add(ip)
        ep.ipv4_gateway = next_hop
        ep.profile_id = net_id

        client.set_endpoint(hostname, container_id, ep)

        return jsonify({
            "Interfaces": [{
                "ID": 0,
                "Address": str(ip),
                # "AddressIPv6": "",
                "MacAddress": ep.mac
            }]})
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

    client.remove_endpoint(hostname, CONTAINER_NAME, ep_id)

    return jsonify({"Value": {}})


@app.route('/NetworkDriver.EndpointOperInfo', methods=['POST'])
def endpoint_oper_info():
    # Nothing is supported yet, just pass blank data.
    return jsonify({"Value": {}})


@app.route('/NetworkDriver.Join', methods=['POST'])
def join():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]

    ep = client.get_endpoint(hostname, CONTAINER_NAME, ep_id)

    interface_source = "tmp" + ep_id[:11]
    interface_destination_prefix = IF_PREFIX

    return jsonify({
        "InterfaceNames": [{
            "SrcName": interface_source,
            "DstName": interface_destination_prefix
        }],
        "Gateway": str(ep.ipv4_gateway),
        "StaticRoutes": [{
            "Destination": "%s/32" % ep.ipv4_gateway,
            "RouteType": 1,  # 1 = CONNECTED
            "NextHop": "",
            "InterfaceID": 0
        }]
    })

@app.route('/NetworkDriver.Leave', methods=['POST'])
def leave():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]

    # TODO - Should this do anything?

    return jsonify({"Value": {}})

def create_spec():
    PLUGIN_DIR = "/usr/share/docker/plugins/"
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR)
    with open(os.path.join(PLUGIN_DIR, 'calico.spec'), 'w') as f:
        f.write("tcp://localhost:5000")  #TODO change the port at some point.


def assign_ipv4():
    """
    Assign a IPv4 address from the configured pools.
    :return: An IPAddress, or None if an IP couldn't be
             assigned
    """
    ip = None

    # For each configured pool, attempt to assign an IP before giving up.
    for pool in client.get_ip_pools("v4"):
        assigner = SequentialAssignment()
        ip = assigner.allocate(pool)
        if ip is not None:
            ip = IPAddress(ip)
            break
    return ip


# Uncomment get logging of all requests.
# @app.before_request
# def log_request():
#     from flask import current_app
#     current_app.logger.debug(request.data)

if __name__ == '__main__':
    create_spec()
    app.debug = True  # TODO Only required during development.
    app.run()

