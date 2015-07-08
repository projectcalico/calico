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
from netaddr import IPAddress, IPNetwork

from pycalico.datastore import IF_PREFIX
from pycalico.datastore_errors import DataStoreError
from pycalico.datastore_datatypes import Endpoint
from pycalico.ipam import SequentialAssignment, IPAMClient

FIXED_MAC = "EE:EE:EE:EE:EE:EE"

CONTAINER_NAME = "libnetwork"

ORCHESTRATOR_ID = "docker"
# How long to wait (seconds) for IP commands to complete.
IP_CMD_TIMEOUT = 5

hostname = socket.gethostname()
client = IPAMClient()

# Return all errors as JSON. From http://flask.pocoo.org/snippets/83/
def make_json_app(import_name, **kwargs):
    """
    Creates a JSON-oriented Flask app.

    All error responses that you don't specifically
    manage yourself will have application/json content
    type, and will contain JSON like this (just an example):

    { "message": "405: Method Not Allowed" }
    """
    def make_json_error(ex):
        response = jsonify(message=str(ex))
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
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    net_id = json_data["NetworkID"]

    # Create a calico endpoint object which we can populate and return to
    # libnetwork at the end of this method.
    ep = Endpoint(hostname, "docker", CONTAINER_NAME, ep_id, "active",
                  FIXED_MAC)
    ep.profile_ids.append(net_id)

    # This method is split into three phases that have side effects.
    # 1) Assigning IP addresses
    # 2) Creating VETHs
    # 3) Writing the endpoint to the datastore.
    #
    # A failure in a later phase attempts to roll back the effects of
    # the earlier phases.

    # First up is IP assignment. By default we assign both IPv4 and IPv6
    # addresses.
    # IPv4 failures may abort the request if the address couldn't be assigned.
    ipv4_and_gateway(ep)
    # IPv6 is currently best effort and won't abort the request.
    ipv6_and_gateway(ep)

    # Next, create the veth.
    try:
        create_veth(ep)
    except CalledProcessError as e:
        # Failed to create or configure the veth.
        # Back out the IP assignments and the veth creation.
        app.logger.exception(e)
        backout_ip_assignments(ep)
        remove_veth(ep)
        abort(500)

    # Finally, write the endpoint to the datastore.
    try:
        client.set_endpoint(ep)
    except DataStoreError as e:
        # We've failed to write the endpoint to the datastore.
        # Back out the IP assignments and the veth creation.
        app.logger.exception(e)
        backout_ip_assignments(ep)
        remove_veth(ep)
        abort(500)

    # Everything worked, create the JSON and return it to libnetwork.
    assert len(ep.ipv4_nets) == 1
    assert len(ep.ipv6_nets) <= 1
    iface_json = {"ID": 0,
                  "Address": str(list(ep.ipv4_nets)[0]),
                  "MacAddress": ep.mac}

    if ep.ipv6_nets:
        iface_json["AddressIPv6"] = str(list(ep.ipv6_nets)[0])

    return jsonify({"Interfaces": [iface_json]})


@app.route('/NetworkDriver.DeleteEndpoint', methods=['POST'])
def delete_endpoint():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    app.logger.info("Removing endpoint %s", ep_id)

    # Remove the endpoint from the datastore, the IPs that were assigned to
    # it and the veth. Even if one fails, try to do the others.
    ep = None
    try:
        ep = client.get_endpoint(hostname=hostname,
                                 orchestrator_id="docker",
                                 workload_id=CONTAINER_NAME,
                                 endpoint_id=ep_id)
        backout_ip_assignments(ep)
    except (KeyError, DataStoreError) as e:
        app.logger.exception(e)
        app.logger.warning("Failed to unassign IPs for endpoint %s", ep_id)

    if ep:
        try:
            client.remove_endpoint(ep)
        except DataStoreError as e:
            app.logger.exception(e)
            app.logger.warning("Failed to remove endpoint %s from datastore",
                               ep_id)

    # libnetwork expects us to delete the veth pair.  (Note that we only need
    # to delete one end).
    if ep:
        remove_veth(ep)

    return jsonify({})


@app.route('/NetworkDriver.EndpointOperInfo', methods=['POST'])
def endpoint_oper_info():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    app.logger.info("Endpoint operation info requested for %s", ep_id)

    # Nothing is supported yet, just pass blank data.
    return jsonify({"Value": {}})


@app.route('/NetworkDriver.Join', methods=['POST'])
def join():
    json_data = request.get_json(force=True)
    ep_id = json_data["EndpointID"]
    app.logger.info("Joining endpoint %s", ep_id)

    ep = client.get_endpoint(hostname=hostname,
                             orchestrator_id="docker",
                             workload_id=CONTAINER_NAME,
                             endpoint_id=ep_id)
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

    return jsonify({})


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
        if ip in pool:
            if client.unassign_address(pool, ip):
                return True
    return False


def ipv4_and_gateway(ep):
    # Get the gateway before trying to assign an address. This will avoid
    # needing to backout the assignment if fetching the gateway fails.
    try:
        next_hop = client.get_default_next_hops(hostname)[4]
    except KeyError as e:
        app.logger.exception(e)
        abort(500)

    ip = assign_ip("v4")
    app.logger.info("Assigned IPv4 %s", ip)

    if not ip:
        app.logger.error("Failed to allocate IPv4 for endpoint %s",
                         ep.endpoint_id)
        abort(500)

    ip = IPNetwork(ip)
    ep.ipv4_nets.add(ip)
    ep.ipv4_gateway = next_hop


def ipv6_and_gateway(ep):
    try:
        next_hop6 = client.get_default_next_hops(hostname)[6]
    except KeyError:
        app.logger.info("Couldn't find IPv6 gateway for endpoint %s. "
                        "Skipping IPv6 assignment.",
                        ep.endpoint_id)
    else:
        ip6 = assign_ip("v6")
        if ip6:
            ip6 = IPNetwork(ip6)
            ep.ipv6_gateway = next_hop6
            ep.ipv6_nets.add(ip6)
        else:
            app.logger.info("Failed to allocate IPv6 address for endpoint %s",
                            ep.endpoint_id)


def backout_ip_assignments(ep):
    for net in ep.ipv4_nets.union(ep.ipv6_nets):
        # The unassignment is best effort. Just log if it fails.
        if not unassign_ip(net.ip):
            app.logger.warn("Failed to unassign IP %s", net.ip)


def create_veth(ep):
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


def remove_veth(ep):
    # The veth removal is best effort. If it fails then just log.
    rc = call(['ip', 'link', 'del', ep.name], timeout=IP_CMD_TIMEOUT)
    if rc != 0:
        app.logger.warn("Failed to delete veth %s", ep.name)


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
