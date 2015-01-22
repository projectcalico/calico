# This is a dummy plugin. It takes a file, loads it all up, then throws it over
# the interfaces.
import ConfigParser
import json
import logging
import logging.handlers
import os
import sys
import time
import zmq

args = sys.argv

if len(sys.argv) != 2:
    print "Not enough command line args - need one arg, endpoint or network"
    exit(1)

if sys.argv[1].startswith("e") or sys.argv[0].startswith("E"):
    endpoint = True
    name = "endpoint"
    print "Doing endpoint API only"
elif sys.argv[1].startswith("n") or sys.argv[0].startswith("N"):
    endpoint = False
    name = "network"
    print "Doing network API only"
else:
    print "Need one arg, endpoint or network"
    exit(1)

zmq_context = zmq.Context()

# Logging
log = logging.getLogger(__name__)

log.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)
log.addHandler(handler)

log.error("Starting up Docker demo %s plugin", name)
config_path = "/config/data"


class Endpoint:
    """
    Endpoint as seen by the plugin. Enough to know what to put in an endpoint created message.
    """
    def __init__(self, id, mac, ip, group):
        self.id = id
        self.mac = mac
        self.ip = ip
        self.group = group


#*****************************************************************************#
#* Global variables for system state. These will be set up in load_files.    *#
#*****************************************************************************#
eps_by_host = dict()
felix_ip    = dict()
all_groups  = dict()

def strip(data):
    # Remove all from the first dot onwards
    index = data.find(".")
    if index > 0:
        data = data[0:index]
    return data

def load_files(config_path):
    """
    Load a set of config files with the data in it. Each section is an endpoint
    or host.
    """
    files = [os.path.join(config_path, f) for f in os.listdir(config_path)]
    parser = ConfigParser.ConfigParser()
    parser.read(files)

    log.debug("Read config from %s (%s)", config_path, files)

    # Clear all of the data structures
    eps_by_host.clear()
    felix_ip.clear()
    all_groups.clear()

    # Build up the list of sections.
    for section in parser.sections():
        items = dict(parser.items(section))
        if section.lower().startswith("endpoint"):
            #*****************************************************************#
            #* Endpoint. Note that we just fall over if there are missing    *#
            #* lines.                                                        *#
            #*****************************************************************#
            id = items['id']
            mac = items['mac']
            ip = items['ip']
            group = items.get('group', 'default')

            # Put this endpoint in a group.
            if group not in all_groups:
                all_groups[group] = dict()

            all_groups[group][id] = [ip]

            # Remove anything after the dot in host.
            host = strip(items['host'])

            if not host in eps_by_host:
                eps_by_host[host] = set()
            eps_by_host[host].add(Endpoint(id, mac, ip, group))
            log.debug("  Found configured endpoint %s (host=%s, mac=%s, ip=%s, group=%s)" %
                      (id, host, mac, ip, group))
        elif section.lower().startswith("felix"):
            ip = items['ip']
            host = strip(items['host'])
            felix_ip[host] = ip
            log.debug("  Found configured Felix %s at %s" % (host, ip))

    return

def do_ep_api():
    # Create the EP REP socket
    resync_socket = zmq_context.socket(zmq.REP)
    resync_socket.bind("tcp://*:9901")
    resync_socket.SNDTIMEO = 10000
    resync_socket.RCVTIMEO = 10000
    log.debug("Created EP socket for resync")

    # We create an EP REQ socket each time we get a connection from another
    # host.
    create_sockets = {}

    #*************************************************************************#
    #* Wait for a resync request, and send the response. Note that Felix is  *#
    #* expected to just send us a resync every now and then; it will do this *#
    #* because it keeps timing out our connections.                          *#
    #*************************************************************************#
    while True:
        try:
            data   = resync_socket.recv()
            fields = json.loads(data)
            log.debug("Got %s EP msg : %s" % (fields['type'], fields))
        except zmq.error.Again:
            # No data received after timeout.
            fields = {'type': ""}

        # Reload config files.
        load_files(config_path)

        if fields['type'] == "RESYNCSTATE":
            resync_id = fields['resync_id']
            host = strip(fields['hostname'])
            rsp = {"rc": "SUCCESS",
                   "message": "Hooray",
                   "type": fields['type'],
                   "endpoint_count": str(len(get_eps_for_host(host)))}
            resync_socket.send(json.dumps(rsp))
            log.debug("Sending %s EP msg : %s" % (fields['type'], rsp))

            #*****************************************************************#
            #* Sleep for a second while that response gets through.  This is *#
            #* not required with the latest Felix, but avoids a bug (now     *#
            #* fixed) where the RESYNC response must arrive before the       *#
            #* ENDPOINTCREATED.                                              *#
            #*****************************************************************#
            time.sleep(1)

            send_all_eps(create_sockets, host, resync_id)

        elif fields['type'] == "HEARTBEAT":
            # Keepalive. We are still here.
            rsp = {"rc": "SUCCESS", "message": "Hooray", "type": fields['type']}
            resync_socket.send(json.dumps(rsp))
        else:
            # Nothing happened.
            log.debug("Nothing happened - send lots of ENDPOINTCREATED messages to make sure")
            for host in eps_by_host.keys():
                send_all_eps(create_sockets, host, None)

        # Send a keepalive on each EP REQ socket.
        for host in create_sockets.keys():
            create_socket = create_sockets[host]
            msg = {"type": "HEARTBEAT",
                   "issued": int(time.time()* 1000)}
            log.debug("Sending KEEPALIVE to %s : %s" % (host, msg))
            create_socket.send(json.dumps(msg))
            create_socket.recv()
            log.debug("Got response from host %s" % host)


def send_all_eps(create_sockets, host, resync_id):
    create_socket = create_sockets.get(host)

    if host not in felix_ip:
        raise Exception("Host name %s not recognised", host)

    if create_socket is None:
        create_socket = zmq_context.socket(zmq.REQ)
        create_socket.SNDTIMEO = 10000
        create_socket.RCVTIMEO = 10000
        create_socket.connect("tcp://%s:9902" % felix_ip[host])
        create_sockets[host] = create_socket

    # Send all of the ENDPOINTCREATED messages.
    for ep in get_eps_for_host(host):
        msg = {"type": "ENDPOINTCREATED",
               "mac": ep.mac,
               "endpoint_id": ep.id,
               "resync_id": resync_id,
               "issued": int(time.time()* 1000),
               "state": "enabled",
               "addrs": [{"addr": ep.ip}]}
        log.debug("Sending ENDPOINTCREATED to %s : %s" % (host, msg))
        create_socket.send(json.dumps(msg))
        create_socket.recv()
        log.debug("Got endpoint created response")


def get_eps_for_host(host):
    if host in eps_by_host:
        eps = eps_by_host[host]
    else:
        eps = set()

    return eps


def do_network_api():
    # Create the sockets
    rep_socket = zmq_context.socket(zmq.REP)
    rep_socket.bind("tcp://*:9903")
    rep_socket.RCVTIMEO = 15000

    pub_socket = zmq_context.socket(zmq.PUB)
    pub_socket.bind("tcp://*:9904")

    while True:
        #*********************************************************************#
        #* We just hang around waiting until we get a request for all        *#
        #* groups. If we do not get one within 15 seconds, we just send the  *#
        #* data anyway. If we never receive anything (even a keepalive)      *#
        #* we'll never send anything but that doesn't matter; if the ACL     *#
        #* manager is there it will be sending either GETGROUPS or           *#
        #* HEARTBEATs.                                                       *#
        #*********************************************************************#
        try:
            data   = rep_socket.recv()
            fields = json.loads(data)
            log.debug("Got %s network msg : %s" % (fields['type'], fields))
            if fields['type'] == "GETGROUPS":
                rsp = {"rc": "SUCCESS",
                       "message": "Hooray",
                       "type": fields['type']}
                rep_socket.send(json.dumps(rsp))
                got_groups = True
            else:
                # Heartbeat. Whatever.
                rsp = {"rc": "SUCCESS", "message": "Hooray", "type": fields['type']}
                rep_socket.send(json.dumps(rsp))

        except zmq.error.Again:
            # Timeout - press on.
            log.debug("No data received")

        # Reload config file just in case, before we send all the data.
        load_files(config_path)

        # Now send all the data we have on the PUB socket.
        log.debug("Build data to publish")

        if not all_groups:
            # No groups to send; send a keepalive instead so ACL Manager
            # doesn't think we have gone away.
            msg = {"type": "HEARTBEAT",
                   "issued": int(time.time()* 1000)}
            log.debug("Sending network heartbeat %s", msg)
            pub_socket.send_multipart(['networkheartbeat'.encode('utf-8'),
                                       json.dumps(msg).encode('utf-8')])


        for group in all_groups:
            members = all_groups[group]

            rules = dict()

            rule1 = {"group": group,
                     "cidr": None,
                     "protocol": None,
                     "port": None}

            rule2 = {"group": None,
                     "cidr": "0.0.0.0/0",
                     "protocol": None,
                     "port": None}

            rules["inbound"] = [rule1]
            rules["outbound"] = [rule1, rule2]
            rules["inbound_default"] = "deny"
            rules["outbound_default"] = "deny"

            data = {"type": "GROUPUPDATE",
                    "group": group,
                    "rules": rules, # all outbound, inbound from group
                    "members": members, # all endpoints
                    "issued": int(time.time() * 1000)}

            # Send the data to the ACL manager.
            log.debug("Sending data about group %s : %s" % (group, data))
            pub_socket.send_multipart(['groups'.encode('utf-8'),
                                       json.dumps(data).encode('utf-8')])


def main():
    # Load files.
    load_files(config_path)

    if endpoint:
        # Do what we need to over the endpoint API.
        do_ep_api()
    else:
        # Do what we need to over the network API.
        do_network_api()

try:
    main()
except:
    log.exception("Terminating on exception")
    os._exit(1)
