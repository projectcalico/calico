from flask import Flask, jsonify, abort, request
import os
from subprocess import check_call

from netaddr import IPAddress

from calico_containers.adapter.datastore import IF_PREFIX
from calico_containers.adapter.ipam import SequentialAssignment, IPAMClient

app = Flask(__name__)
client = IPAMClient()

@app.route('/Plugin.Activate', methods=['GET', 'POST'])
def activate():
    return jsonify({"Implements": ["NetworkDriver"]})

@app.route('/NetworkDriver.CreateNetwork', methods=['GET', 'POST'])
def create_network():
    app.logger.info("CreateNetwork was passed %s", request.data)
    json_data = request.get_json(force=True)
    app.logger.info("Parsed data = %s", json_data)
    app.logger.info(json_data["NetworkID"])

    # Create the "network" as a profile
    client.create_profile(json_data["NetworkID"])

    return jsonify({})


@app.route('/NetworkDriver.CreateEndpoint', methods=['GET', 'POST'])
def create_endpoint():
    app.logger.info("CreateEndpoint was passed %s", request.data)
    json_data = request.get_json(force=True)
    app.logger.info("Parsed data = %s", json_data)
    app.logger.info("NetworkID: %s", json_data["NetworkID"])
    app.logger.info("EndpointID: %s", json_data["EndpointID"])
    for interface in json_data["Interfaces"]:
        app.logger.info(interface["ID"])
        app.logger.info(interface["Address"])
        app.logger.info(interface["AddressIPv6"])
        app.logger.info(interface["MacAddress"])

    if len(json_data["Interfaces"]) != 0:
        app.logger.error("Currently don't support being passed interfaces")

    ip = assign_ipv4()
    app.logger.info("Assigned IP %s", ip)
    if not ip:
        abort(500)

    # TODO record this endpoint in etcd
    return jsonify({
        "Interfaces": [{
            "ID": 0,
            "Address": "%s/32" % ip,
            # "AddressIPv6": "",
            "MacAddress": "11:22:33:44:55:66"
        }]})


@app.route('/NetworkDriver.EndpointOperInfo', methods=['GET', 'POST'])
def endpoint_oper_info():
    app.logger.info("EndpointOperInfo was passed %s", request.data)
    json_data = request.get_json(force=True)
    app.logger.info("Parsed data = %s", json_data)

    # Nothing is supported yet.
    return jsonify({"Value":{}})


@app.route('/NetworkDriver.Join', methods=['GET', 'POST'])
def join():
    app.logger.info("Join was passed %s", request.data)
    json_data = request.get_json(force=True)
    app.logger.info("Parsed data = %s", json_data)
    app.logger.info("NetworkID: %s", json_data["NetworkID"])
    app.logger.info("EndpointID: %s", json_data["EndpointID"])
    app.logger.info("SandboxKey: %s", json_data["SandboxKey"])

    iface = IF_PREFIX + json_data["EndpointID"][:10]
    iface_tmp = "tmp" + json_data["EndpointID"][:10]

    check_call("ip link add %s type veth peer name %s" % (iface, iface_tmp),
               shell=True)

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


if __name__ == '__main__':
    # create_spec()
    app.debug = True
    app.run()

