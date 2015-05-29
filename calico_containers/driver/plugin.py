from flask import Flask, jsonify, abort, request
import os
import socket
from subprocess import check_call

from netaddr import IPAddress, IPNetwork

from datastore import IF_PREFIX, Endpoint
from ipam import SequentialAssignment, IPAMClient

app = Flask(__name__)
hostname = socket.gethostname()
client = IPAMClient()
#TODO - stop responding to GETs


@app.route('/Plugin.Activate', methods=['GET', 'POST'])
def activate():
    return jsonify({"Implements": ["NetworkDriver"]})


@app.route('/NetworkDriver.CreateNetwork', methods=['GET', 'POST'])
def create_network():
    json_data = request.get_json(force=True) # TODO - what if JSON can't be parsed

    # Create the "network" as a profile
    client.create_profile(json_data["NetworkID"])

    return jsonify({})


@app.route('/NetworkDriver.DeleteNetwork', methods=['GET', 'POST'])
def delete_network():
    # TODO - untested
    json_data = request.get_json(force=True)

    # Remove the network
    client.remove_profile(json_data["NetworkID"])

    #TODO - What if the profile has endpoints?

    return jsonify({})


@app.route('/NetworkDriver.CreateEndpoint', methods=['GET', 'POST'])
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
        container_id = "undefined"  # Always used a fixed value.
        mac = "11:22:33:44:55:66"
        iface = IF_PREFIX + ep_id[:10]
        iface_tmp = "tmp" + ep_id[:10]

        # Create the veth and set the host name to be up.
        check_call("ip link add %s type veth peer name %s" % (iface, iface_tmp),
                   shell=True)
        check_call("ip link set %s up" % iface, shell=True)

        ep = Endpoint(ep_id=ep_id, state="active", mac=mac, if_name=iface)
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

@app.route('/NetworkDriver.EndpointOperInfo', methods=['GET', 'POST'])
def endpoint_oper_info():
    # Nothing is supported yet, just pass blank data.
    return jsonify({"Value": {}})


@app.route('/NetworkDriver.Join', methods=['GET', 'POST'])
def join():
    app.logger.info("Join was passed %s", request.data)
    json_data = request.get_json(force=True)
    app.logger.info("Parsed data = %s", json_data)
    app.logger.info("NetworkID: %s", json_data["NetworkID"])
    app.logger.info("EndpointID: %s", json_data["EndpointID"])
    app.logger.info("SandboxKey: %s", json_data["SandboxKey"])

    # TODO - Just get the data out of etcd and return it? Actually, there's
    # nothing that we need in etcd... yet...
    iface = IF_PREFIX + json_data["EndpointID"][:10]
    iface_tmp = "tmp" + json_data["EndpointID"][:10]

    # Add in the gateway and routes once I've got the remote api updated.
    return jsonify({
        "InterfaceNames": [{
            "SrcName": iface_tmp,
            "DstName": iface
        }],
        # Don't include optional bits for now.
        # "Gateway": string,
        # "GatewayIPv6": string,
        # "HostsPath": string,
        # "ResolvConfPath": string
        }
    )

def create_spec():
    PLUGIN_DIR = "/usr/share/docker/plugins/"
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR)
    with open(os.path.join(PLUGIN_DIR, 'calico.spec'), 'w') as f:
        f.write("tcp://localhost:5000")

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


# @app.before_request
# def log_request():
#     from flask import current_app
#     current_app.logger.debug(request.data)

if __name__ == '__main__':
    # create_spec()
    app.debug = True
    app.run()

