# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from flask import Flask, jsonify, abort, request
import os
import socket
import logging
import sys

from subprocess32 import check_call, CalledProcessError, call
from werkzeug.exceptions import HTTPException, default_exceptions
from netaddr import IPNetwork

from libnetwork_plugin.datastore_libnetwork import LibnetworkDatastoreClient
from pycalico.datastore import IF_PREFIX
from pycalico.datastore_errors import DataStoreError
from pycalico.datastore_datatypes import Endpoint
from pycalico.ipam import SequentialAssignment


FIXED_MAC = "EE:EE:EE:EE:EE:EE"
CONTAINER_NAME = "libnetwork"
ORCHESTRATOR_ID = "docker"

# How long to wait (seconds) for IP commands to complete.
IP_CMD_TIMEOUT = 5

hostname = socket.gethostname()
client = LibnetworkDatastoreClient()

# Return all errors as JSON. From http://flask.pocoo.org/snippets/83/
def make_json_app(import_name, **kwargs):
    """
    Creates a JSON-oriented Flask app.

    All error responses that you don't specifically
    manage yourself will have application/json content
    type, and will contain JSON like this (just an example):

    { "Err": "405: Method Not Allowed" }
    """
    def make_json_error(ex):
        response = jsonify({"Err":str(ex)})
        response.status_code = (ex.code
                                if isinstance(ex, HTTPException)
                                else 500)
        return response

    app = Flask(import_name, **kwargs)

    for code in default_exceptions.iterkeys():
        app.error_handler_spec[None][code] = make_json_error

    return app

app = make_json_app(__name__)
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
    app.logger.debug("CreateNetwork JSON=%s", json_data)

    # Create the "network" as a profile. The network ID is somewhat unwieldy
    # so in future we might want to obtain a human readable name for it.
    network_id = json_data["NetworkID"]

    #@TODO Maybe, for atomicity write with prevExist=False
    if client.profile_exists(network_id):
        app.logger.info("Not creating existing profile %s", network_id)
    else:
        app.logger.info("Creating profile %s", network_id)
        client.create_profile(network_id)

    return jsonify({})


@app.route('/NetworkDriver.DeleteNetwork', methods=['POST'])
def delete_network():
    json_data = request.get_json(force=True)
    app.logger.debug("DeleteNetwork JSON=%s", json_data)

    # Remove the network. We don't raise an error if the profile is still
    # being used by endpoints. We assume libnetwork will enforce this.
    # From https://github.com/docker/libnetwork/blob/master/docs/design.md
    #   LibNetwork will not allow the delete to proceed if there are any
    #   existing endpoints attached to the Network.
    network_id = json_data["NetworkID"]
    try:
        client.remove_profile(network_id)
        app.logger.info("Removed profile %s", network_id)
    except KeyError:
        app.logger.info("Not removing missing profile %s", network_id)

    return jsonify({})


@app.route('/NetworkDriver.CreateEndpoint', methods=['POST'])
def create_endpoint():
    json_data = request.get_json(force=True)
    app.logger.debug("CreateEndpoint JSON=%s", json_data)
    ep_id = json_data["EndpointID"]

    #@TODO We assume libnetwork runs this first on the local host first and
    # then on other hosts.  We should verify this is the case.
    if client.cnm_endpoint_exists(ep_id):
        app.logger.info("Ignoring existing endpoint %s", ep_id)
        return jsonify({})
    app.logger.info("Creating endpoint %s", ep_id)

    # If the host has a v4 address and a v4 pool defined then assign a v4
    # address. Likewise for v6. If neither are assigned then abort.
    next_hops = client.get_default_next_hops(hostname)
    ip = None
    ip6 = None
    if next_hops.get(4):
        ip = assign_ip("v4")
        if ip:
            app.logger.info("Assigned IPv4 %s for ep %s" % (ip, ep_id))
        else:
            app.logger.error("Failed to allocate IPv4 for endpoint %s", ep_id)

    if next_hops.get(6):
        ip6 = assign_ip("v6")
        if ip6:
            app.logger.info("Assigned IPv6 %s for ep %s" % (ip6, ep_id))
        else:
            app.logger.error("Failed to allocate IPv6 for endpoint %s", ep_id)
    if not ip and not ip6:
        app.logger.error("Failed to allocate and address for endpoint %s",
                        ep_id)
        abort(500)

    # Create the JSON to return to libnetwork
    response = {"Interfaces":
                    [{"ID": 0,
                 "MacAddress": FIXED_MAC}]}
    if ip:
        response["Interfaces"][0]["Address"] = str(ip)
    if ip6:
        response["Interfaces"][0]["AddressIPv6"] = str(ip6)

    # Save this response along with the ep_id into the datastore.
    client.write_cnm_endpoint(ep_id, response)

    return jsonify(response)


@app.route('/NetworkDriver.DeleteEndpoint', methods=['POST'])
def delete_endpoint():
    json_data = request.get_json(force=True)
    app.logger.debug("DeleteEndpoint JSON=%s", json_data)
    ep_id = json_data["EndpointID"]

    # TODO - Should we backout IP assignment first in case of failure mid way through? If IP backout fails then there is no way to correlate endpoint with IPs again.

    # Backout IP assignment then remove CNM EP
    cnm_ep = client.read_cnm_endpoint(ep_id)

    if cnm_ep and client.delete_cnm_endpoint(ep_id):
        app.logger.info("Removing endpoint %s", ep_id)
        backout_ip_assignments(cnm_ep)
    else:
        app.logger.info("Not removing missing endpoint %s", ep_id)

    return jsonify({})


@app.route('/NetworkDriver.EndpointOperInfo', methods=['POST'])
def endpoint_oper_info():
    json_data = request.get_json(force=True)
    app.logger.debug("EndpointOperInfo JSON=%s", json_data)
    ep_id = json_data["EndpointID"]
    app.logger.info("Endpoint operation info requested for %s", ep_id)

    # Nothing is supported yet, just pass blank data.
    return jsonify({"Value": {}})


@app.route('/NetworkDriver.Join', methods=['POST'])
def join():
    json_data = request.get_json(force=True)
    app.logger.debug("Join JSON=%s", json_data)
    ep_id = json_data["EndpointID"]
    net_id = json_data["NetworkID"]
    app.logger.info("Joining endpoint %s", ep_id)

    # Get CNM endpoint ID from datastore so we can find the IP addresses
    # assigned to it.
    cnm_ep = client.read_cnm_endpoint(ep_id)

    # Read the next hops from etcd
    next_hops = client.get_default_next_hops(hostname)

    # Create a Calico endpoint object.
    #TODO - set the CONTAINER_NAME to something better (the sandbox key?)
    ep = Endpoint(hostname, "docker", CONTAINER_NAME, ep_id, "active",
                  FIXED_MAC)
    ep.profile_ids.append(net_id)

    #TODO - this assumes there are still IPv6 gateways configured (could
    # have been deleted in the interim)
    address_ip4 = cnm_ep['Interfaces'][0].get('Address')
    if address_ip4:
        ep.ipv4_nets.add(IPNetwork(address_ip4))
        ep.ipv4_gateway = next_hops[4]

    address_ip6 = cnm_ep['Interfaces'][0].get('AddressIPv6')
    if address_ip6:
        ep.ipv6_nets.add(IPNetwork(address_ip6))
        ep.ipv6_gateway = next_hops[6]

    try:
        # Next, create the veth.
        create_veth(ep)

        # Finally, write the endpoint to the datastore.
        client.set_endpoint(ep)
    except (CalledProcessError, DataStoreError) as e:
        # Failed to create or configure the veth, or failed to write the
        # endpoint to the datastore. In both cases, ensure veth is removed.
        app.logger.exception(e)
        remove_veth(ep)
        abort(500)

    ret_json = {
        "InterfaceNames": [{
            "SrcName": ep.temp_interface_name(),
            "DstPrefix": IF_PREFIX
        }],
        "Gateway": str(ep.ipv4_gateway),
        "StaticRoutes": [{
            "Destination": "%s/32" % ep.ipv4_gateway,
            "RouteType": 1,  # 1 = CONNECTED
            "NextHop": "",
            "InterfaceID": 0
            }]
    }
    if ep.ipv6_gateway:
        ret_json["GatewayIPv6"] = str(ep.ipv6_gateway)
        ret_json["StaticRoutes"].append({
            "Destination": "%s/128" % ep.ipv6_gateway,
            "RouteType": 1,  # 1 = CONNECTED
            "NextHop": "",
            "InterfaceID": 0
            })

    return jsonify(ret_json)


@app.route('/NetworkDriver.Leave', methods=['POST'])
def leave():
    json_data = request.get_json(force=True)
    app.logger.debug("Leave JSON=%s", json_data)
    ep_id = json_data["EndpointID"]
    app.logger.info("Leaving endpoint %s", ep_id)

    # Remove the endpoint object and the veth
    ep = None
    try:
        ep = client.get_endpoint(hostname=hostname,
                                 orchestrator_id=ORCHESTRATOR_ID,
                                 workload_id=CONTAINER_NAME,
                                 endpoint_id=ep_id)
        client.remove_endpoint(ep)
    except (DataStoreError, KeyError) as e:
        app.logger.exception(e)
        app.logger.warning("Failed to remove endpoint %s from datastore",
                           ep_id)
    # TODO - Remove veth before removing endpoint from etcd in case of errors?
    # TODO - If we fail to remove endpoint, still return success?
    if ep:
        remove_veth(ep)
    else:
        app.logger.warning("Failed to remove veth for endpoint %s", ep_id)
        abort(500)

    return jsonify({})


#TODO move assign_ip/unassign_ip
#TODO This current returns an IPNetwork not an IPAddress
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
            ip = IPNetwork(ip)
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
        if ip in pool and client.unassign_address(pool, ip):
            return True
    return False


def backout_ip_assignments(cnm_ep):
    # TODO - more testing
    for address in (cnm_ep['Interfaces'][0].get('Address'),
                    cnm_ep['Interfaces'][0].get('AddressIPv6')):
        # If either of the addresses aren't present, then .get will just
        # return None.
        if address is not None and not unassign_ip(IPNetwork(address).ip):
            # The unassignment is best effort. Just log if it fails.
            app.logger.warn("Failed to unassign IP address %s", address)


# TODO move to netns
def create_veth(ep):  #pragma: no cover
    # Create the veth
    check_call(['ip', 'link',
                'add', ep.name,
                'type', 'veth',
                'peer', 'name', ep.temp_interface_name()],
               timeout=IP_CMD_TIMEOUT)

    # Set the host end of the veth to 'up' so felix notices it.
    check_call(['ip', 'link', 'set', ep.name, 'up'],
               timeout=IP_CMD_TIMEOUT)

    # Set the mac as libnetwork doesn't do this for us.
    check_call(['ip', 'link', 'set',
                'dev', ep.temp_interface_name(),
                'address', FIXED_MAC],
               timeout=IP_CMD_TIMEOUT)

#TODO move to netns
def remove_veth(ep):  #pragma: no cover
    # The veth removal is best effort. If it fails then just log.
    rc = call(['ip', 'link', 'del', ep.name], timeout=IP_CMD_TIMEOUT)
    if rc != 0:
        app.logger.warn("Failed to delete veth %s", ep.name)


if __name__ == '__main__':   #pragma: no cover
    # Used when being invoked by the flask development server
    PLUGIN_DIR = "/usr/share/docker/plugins/"
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR)
    with open(os.path.join(PLUGIN_DIR, 'calico.spec'), 'w') as f:
        f.write("tcp://localhost:5000")

    # Turns on better error messages and reloading support.
    app.debug = True
    app.run()
