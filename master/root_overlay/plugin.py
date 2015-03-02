"""plugin.py

Usage:
  plugin.py [options] endpoint
  plugin.py [options] network

Options:
    --log-dir=DIR      Log directory [default: /var/log/calico]

"""
import json
import logging
import logging.handlers
import sys
import time
import zmq
from docopt import docopt
import os

import etcd
ENV_ETCD = "ETCD_AUTHORITY"
etcd_authority = os.getenv(ENV_ETCD, None)
if not etcd_authority:
    client = etcd.Client()
else:
    # TODO: Error handling
    (host, port) = etcd_authority.split(":", 1)
    client = etcd.Client(host=host, port=int(port))

zmq_context = zmq.Context()
log = logging.getLogger(__name__)
log_api = logging.getLogger("api")


def setup_logging(logfile):
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.ERROR)
    handler.setFormatter(formatter)
    log.addHandler(handler)
    handler = logging.handlers.TimedRotatingFileHandler(logfile,
                                                        when='D',
                                                        backupCount=10)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    log.addHandler(handler)


    log_api.setLevel(logging.DEBUG)
    handler_api = logging.handlers.TimedRotatingFileHandler(logfile + "api",
                                                        when='D',
                                                        backupCount=10)
    handler_api.setLevel(logging.DEBUG)
    handler_api.setFormatter(formatter)
    log_api.addHandler(handler_api)


# Global variables for system state. These will be set up in load_data.
eps_by_host = {}
all_groups = {}
ips_by_endpointid = {}
last_resync = {}

def parse_json(value):
    """
    Try to parse JSON out into a python data structure, so that when we serialize it back for
    zeroMQ we're not doing JSON in JSON.
    """
    ret_val = value
    try:
        ret_val = json.loads(value)
        log.debug("Parsed JSON %s", value)
    except ValueError:
        log.debug("Failed to parse JSON %s", value)

    return ret_val

def process_endpoint_data(res, keyparts):
    host = keyparts[3]
    endpoint_id = keyparts[8]
    key = keyparts[-1]

    # Make sure the parent dicts are created since Python has no autovivification.
    if not host in eps_by_host:
        eps_by_host[host] = {}
    if not endpoint_id in eps_by_host[host]:
        eps_by_host[host][endpoint_id] = {}

    eps_by_host[host][endpoint_id][key] = parse_json(res.value)

    if key == "addrs":
        ips_by_endpointid[endpoint_id] = parse_json(res.value)

def process_network_data(res, keyparts):
    key = keyparts[-1]
    group = keyparts[4]
    type = keyparts[5]

    if not group in all_groups:
        all_groups[group] = {}
        all_groups[group]["member"] = {}
        all_groups[group]["rule"] = {}
        all_groups[group]["rule"]["inbound"] = []
        all_groups[group]["rule"]["outbound"] = []

    if type == "member":
        all_groups[group]["member"][key] = []
    elif type == "rule":
        rule_type = keyparts[6]
        if rule_type in ("inbound", "outbound"):
            all_groups[group]["rule"][rule_type].append(parse_json(res.value))
        else:
            all_groups[group]["rule"][key] = res.value
    elif key == "name":
        all_groups[group][key] = parse_json(res.value)


def load_data():
    """
    Load data from datastore - ccurently just etcd
    """
    # Clear all of the data structures
    log.info("Clearing data structures for full resync")
    eps_by_host.clear()
    all_groups.clear()
    ips_by_endpointid.clear()

    result = client.read('/calico', recursive=True)

    # Iterate over all the leaves that we get back. For each leave we get the full path,
    # so we parse that to determine whether to process the key as network or endpoint API data.
    # The goal of this iteration is to get the data into a simple Python data structure,
    # as opposed to the slightly complicated etcd datastructure.
    for res in result.leaves:
        log.debug("Processing key %s", res.key)
        keyparts = res.key.split("/")

        try:
            if keyparts[2] == "network":
                log.debug("Network")
                process_network_data(res, keyparts)
            elif keyparts[4] == "workload":
                log.debug("Endpoint")
                process_endpoint_data(res, keyparts)
            else:
                log.debug("Ignoring key %s", res.key)
                continue
        except IndexError:
            log.debug("Ignoring key %s", res.key)
            continue
    log.info("Finished reading data. Database contains %s hosts and %s groups",
             len(eps_by_host), len(all_groups))

def do_ep_api():
    # Create the EP REP socket
    resync_socket = zmq_context.socket(zmq.REP)
    resync_socket.bind("tcp://*:9901")
    resync_socket.SNDTIMEO = 10000
    resync_socket.RCVTIMEO = 10000
    log_api.info("Created REP socket on port 9901")

    # We create an EP REQ socket each time we get a connection from another
    # host.
    create_sockets = {}

    # Wait for a resync request, and send the response. Note that Felix is
    # expected to just send us a resync every now and then; it will do this 
    # because it keeps timing out our connections.                          
    while True:
        try:
            data = resync_socket.recv()
            log_api.info("Received REP socket data:\n%s", data)
            fields = json.loads(data)
        except zmq.error.Again:
            # No data received after timeout.
            fields = {'type': ""}

        # Reload config files.
        load_data()

        if fields['type'] == "RESYNCSTATE":
            resync_id = fields['resync_id']
            host = fields['hostname']
            rsp = {"rc": "SUCCESS",
                   "message": "Hooray",
                   "type": fields['type'],
                   "endpoint_count": str(len(eps_by_host.get(host, set())))}
            rsp_json = json.dumps(rsp)
            log_api.info("Sending RESYNCSTATE response to %s\n%s", host, rsp_json)
            resync_socket.send(rsp_json)

            last_resync[host] = int(time.time())

            send_all_eps(create_sockets, host, resync_id)

        elif fields['type'] == "HEARTBEAT":
            # Keepalive. We are still here.
            rsp = {"rc": "SUCCESS", "message": "Hooray", "type": fields['type']}
            rsp_json = json.dumps(rsp)
            log_api.info("Sending resync HEARTBEAT\n%s" % rsp_json)
            resync_socket.send(rsp_json)


        # Send a keepalive on each EP REQ socket.
        for host in create_sockets.keys():
            last_time = last_resync.get(host, 0)
            log.debug("Last resync from %s was at %d", host, last_time)
            if time.time() - last_time > 15:
                log.error("Host %s has not sent a resync - "
                          "send lots of ENDPOINTCREATEDs to make sure", host)
                send_all_eps(create_sockets, host, None)
                last_resync[host] = int(time.time())
            else:
                create_socket = create_sockets[host]
                msg = {"type": "HEARTBEAT",
                       "issued": int(time.time() * 1000)}
                msg_json = json.dumps(msg)
                log_api.info("Sending HEARTBEAT to %s:\n%s" % (host, msg_json))
                create_socket.send(msg_json)
                data = create_socket.recv()
                log_api.info("Received HEARTBEAT response from %s:\n%s", host, data)


def get_ip_for_host(host):
    return client.read('/calico/host/%s/bird_ip' % host).value


def send_all_eps(create_sockets, host, resync_id):
    create_socket = create_sockets.get(host)
    log.info("Sending ENDPOINTCREATED messages for host %s", host)

    if create_socket is None:
        create_socket = zmq_context.socket(zmq.REQ)
        create_socket.SNDTIMEO = 10000
        create_socket.RCVTIMEO = 10000
        ip = get_ip_for_host(host)
        create_socket.connect("tcp://%s:9902" % ip)
        create_sockets[host] = create_socket
        log_api.info("Created REQ socket on port 9902")

    # Send all of the ENDPOINTCREATED messages.
    for ep in eps_by_host.get(host, {}):
        log.info("Sending ENDPOINTCREATED message for endpoint %s", ep)
        msg = {"type": "ENDPOINTCREATED",
               "mac": eps_by_host[host][ep]["mac"],
               "endpoint_id": ep,
               "resync_id": resync_id,
               "issued": int(time.time() * 1000),
               "state": "enabled", # TODO - Map through enabled properly
               "addrs": eps_by_host[host][ep]["addrs"]}
        msg_json = json.dumps(msg)
        log_api.info("Sending ENDPOINTCREATED to %s:\n%s" % (host, msg_json))
        create_socket.send(msg_json)
        data = create_socket.recv()
        log_api.info("Received ENPOINTCREATED response:\n%s", data)


def do_network_api():
    # Create the sockets
    rep_socket = zmq_context.socket(zmq.REP)
    rep_socket.bind("tcp://*:9903")
    rep_socket.RCVTIMEO = 15000
    log_api.info("Created REP socket on port 9903")

    pub_socket = zmq_context.socket(zmq.PUB)
    pub_socket.bind("tcp://*:9904")
    log_api.info("Created PUB socket on port 9904")


    while True:
        # We just hang around waiting until we get a request for all
        # groups. If we do not get one within 15 seconds, we just send the  
        # data anyway. If we never receive anything (even a keepalive)      
        # we'll never send anything but that doesn't matter; if the ACL     
        # manager is there it will be sending either GETGROUPS or           
        # HEARTBEATs.                                                       
        try:
            data = rep_socket.recv()
            log_api.info("Received REP message: %s", data)
            fields = json.loads(data)
            if fields['type'] == "GETGROUPS":
                rsp = {"rc": "SUCCESS",
                       "message": "Hooray",
                       "type": fields['type']}
                rsp_json = json.dumps(rsp)
                log_api.info("Sent     REP message: \n%s", rsp_json)
                rep_socket.send(rsp_json)
            else:
                # Heartbeat. Whatever.
                rsp = {"rc": "SUCCESS", "message": "Hooray", "type": fields['type']}
                rsp_json = json.dumps(rsp)
                log_api.info("Sent     REP message: \n%s", rsp_json)
                rep_socket.send(rsp_json)

        except zmq.error.Again:
            # Timeout - press on.
            log.warning("No data received - send all groups anyway")

        send_all_groups(pub_socket)

def send_all_groups(pub_socket):
    # Reload config file just in case, before we send all the data.
    load_data()

    # Now send all the data we have on the PUB socket.
    log.info("Build groups data to publish")

    if not all_groups:
        # No groups to send; send a keepalive instead so ACL Manager
        # doesn't think we have gone away.
        log.info("No groups defined, sending networkheartbeat")
        msg = {"type": "HEARTBEAT",
               "issued": int(time.time() * 1000)}
        rsp_json = json.dumps(msg).encode('utf-8')
        log_api.info("Sent  HB PUB message: \n%s", rsp_json)
        pub_socket.send_multipart(['networkheartbeat'.encode('utf-8'),
                                   rsp_json])

    for group in all_groups:
        rules = all_groups[group]["rule"]
        members = all_groups[group]["member"]

        # Add IP addresses for endpoints.
        members_with_ips = {}
        for member in members:
            ep_ip_configs = ips_by_endpointid[member]
            # Eac ep_ip_config is a dictionary containing addr, gateway, etc.  We only care about
            # the address, so flatten to just a list.  This is what the GROUPUPDATE API expects.
            ep_ips = [ip_config["addr"] for ip_config in ep_ip_configs]
            members_with_ips[member] = ep_ips

        data = {"type": "GROUPUPDATE",
                "group": group,
                "rules": rules,  # all outbound, inbound from group
                "members": members_with_ips,  # all endpoints
                "issued": int(time.time() * 1000)}

        # Send the data to the ACL manager.
        rsp_json = json.dumps(data).encode('utf-8')
        log_api.info("Sent GROUPUPDATE for group %s:\n%s", group, rsp_json)
        pub_socket.send_multipart(['groups'.encode('utf-8'),
                                   rsp_json])

if __name__ == '__main__':
    arguments = docopt(__doc__)

    if arguments["endpoint"]:
        setup_logging("%s/plugin_ep.log" % arguments["--log-dir"])
        do_ep_api()
    if arguments["network"]:
        setup_logging("%s/plugin_net.log" % arguments["--log-dir"])
        do_network_api()
