# -*- coding: utf-8 -*-
#
# Copyright (c) 2014, 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# ZeroMQ-based transport for the Calico/OpenStack Plugin.

# Standard Python library imports.
import eventlet
from eventlet.green import zmq
import json
import time
from zmq.error import Again

# OpenStack imports.
from oslo.config import cfg

# Calico imports.
from calico.openstack.transport import CalicoTransport

LOG = None

# TCP port numbers used by the 0MQ sockets that connect the Calico plugin,
# Felix and ACL Manager components, as shown by the following diagram.
#
#
#                ROUTER #1 +------------+ #3 ROUTER
#          ,-------------->|            |<-------------------.
#          |               |   Plugin   |                    |
#          |   ,-----------|            |<---------------.   |
#          |   |     REQ   +------------+ #4 PUB         |   |
#          |   |                                         |   |
#          |   |                                         |   |
#          |   |                                         |   |
#          |   |                                         |   |
#          |   |                                         |   |
#          |   |                                         |   |
#          |   |                                         |   |
#      REQ |   | REP                                 SUB |   | REQ
#          |   V #2                                      |   |
#     +------------+ SUB                  PUB #6 +-----------------+
#     |            |---------------------------->|                 |
#     |   Felix    |                             |   ACL Manager   |
#     |            |---------------------------->|                 |
#     +------------+ REQ               ROUTER #5 +-----------------+
#
#
#  #1: tcp://controller:PLUGIN_ENDPOINT_PORT
#
#  #2: tcp://felix_host:FELIX_ENDPOINT_PORT
#
#  #3: tcp://controller:PLUGIN_ACLGET_PORT
#
#  #4: tcp://controller:PLUGIN_ACLPUB_PORT
#
#  #5: tcp://acl_host:MANAGER_ACLGET_PORT
#
#  #6: tcp://acl_host:MANAGER_ACLPUB_PORT

PLUGIN_ENDPOINT_PORT = 9901
FELIX_ENDPOINT_PORT = 9902
PLUGIN_ACLGET_PORT = 9903
PLUGIN_ACLPUB_PORT = 9904

# Time (ms) to allow for Felix to send us an ENDPOINT* response.
ENDPOINT_RESPONSE_TIMEOUT = 10000

# Time (ms) to allow for Felix to send us a HEARTBEAT response.
HEARTBEAT_RESPONSE_TIMEOUT = 10000

# TIME between heartbeats, in seconds.
HEARTBEAT_SEND_INTERVAL_SECS = 30


class FelixUnavailable(Exception):
    """
    Exception raised when a Felix instance cannot be contacted.
    """
    def __init__(self, op, port, hostname):
        action = {'CREATED': "create",
                  'UPDATED': "update",
                  'DESTROYED': "destroy"}

        super(FelixUnavailable, self).__init__(
            "Failed to %s port %s because unable to contact Felix at %s" %
            (action[op], port, hostname))


class CalicoTransport0MQ(CalicoTransport):
    """Legacy Calico transport implementation based on 0MQ sockets."""

    def __init__(self, driver, logger):
        super(CalicoTransport0MQ, self).__init__(driver)

        # Initialize dictionary mapping Felix hostnames to corresponding REQ
        # sockets.
        self.felix_peer_sockets = {}

        # Initialize logger.
        global LOG
        LOG = logger

    def initialize(self):
        self.zmq_context = zmq.Context()
        LOG.warn("pyzmq version is %s" % zmq.pyzmq_version())

        bind_address = cfg.CONF.bind_host or '*'

        # Create ROUTER socket for Felix instances to connect to.
        self.felix_router_socket = self.zmq_context.socket(zmq.ROUTER)
        self.felix_router_socket.bind("tcp://%s:%s" % (bind_address,
                                                       PLUGIN_ENDPOINT_PORT))

        # Create ROUTER socket for ACL Manager(s) to connect to.
        self.acl_get_socket = self.zmq_context.socket(zmq.ROUTER)
        self.acl_get_socket.bind("tcp://%s:%s" % (bind_address,
                                                  PLUGIN_ACLGET_PORT))

        # Create PUB socket for sending ACL updates to ACL Manager(s).
        self.acl_pub_socket = self.zmq_context.socket(zmq.PUB)
        self.acl_pub_socket.bind("tcp://%s:%s" % (bind_address,
                                                  PLUGIN_ACLPUB_PORT))
        eventlet.spawn(self.acl_heartbeat_thread)

        # Spawn green thread for handling RESYNCSTATE requests on the
        # Felix-ROUTER socket.
        eventlet.spawn(self.felix_router_thread)

        # Spawn green thread for handling GETGROUPS requests on the ACL-GET
        # socket.
        eventlet.spawn(self.acl_get_thread)

        LOG.info("Started threads")

    def acl_heartbeat_thread(self):

        while True:

            # Sleep until time for next heartbeat.
            LOG.info("Network-HEARTBEAT: sleep till time for next heartbeat")
            eventlet.sleep(HEARTBEAT_SEND_INTERVAL_SECS)

            # Send a heartbeat.
            try:
                pub = {'type': 'HEARTBEAT',
                       'issued': time.time() * 1000}
                self.acl_pub_socket.send_multipart(
                    ['networkheartbeat'.encode('utf-8'),
                     json.dumps(pub).encode('utf-8')])
                LOG.info("HEARTBEAT published to ACL managers")
            except:
                LOG.exception("Exception publishing HEARTBEAT to ACL managers")
                return

    def felix_router_thread(self):

        while True:

            LOG.info("Felix-ROUTER: wait to receive next message")
            try:
                # Receive the next message on the ROUTER socket for Felix
                # instances.  This may block, but that's OK because all other
                # green threads in the Neutron server process can run in the
                # meantime.
                message = self.felix_router_socket.recv_multipart()

                # Every message on this socket should be multipart with 3
                # parts, of which the second part is always empty.  (Why?)
                assert (len(message) == 3)
                assert not message[1]

                # The first part is the connection identity, and the third is
                # the message content.
                peer = message[0]
                rq = json.loads(message[2].decode('utf-8'))
                LOG.info("Felix-ROUTER RX [%s] %s" % (peer, rq))

                if rq['type'] == 'RESYNCSTATE':
                    # It's a RESYNCSTATE request.
                    LOG.info("RESYNCSTATE request")

                    # Get a list of all ports on the Felix host.  Unfortunately
                    # it isn't possible to use 'binding:host_id' as a query
                    # filter, so we filter the results ourselves instead.
                    LOG.info("Query Neutron DB...")
                    ports = [port for port in self.driver.get_endpoints()
                             if port['binding:host_id'] == rq['hostname']]

                    resync_rsp = {'type': 'RESYNCSTATE',
                                  'endpoint_count': len(ports),
                                  'interface_prefix': 'tap',
                                  'rc': 'SUCCESS',
                                  'message': 'Здра́вствуйте!'}

                    # Send the prepared response.
                    LOG.info("Sending response: %s" % resync_rsp)
                    self.felix_router_socket.send_multipart(
                        [peer,
                         '',
                         json.dumps(resync_rsp).encode('utf-8')])

                    # If we don't already have a REQ socket to this Felix,
                    # create that now.
                    self._ensure_socket_to_felix_peer(rq['hostname'])

                    # Now also send an ENDPOINTCREATED request to the Felix
                    # instance, for each port.
                    for port in ports:
                        self.send_endpoint(rq['resync_id'], port, 'CREATED')

                elif rq['type'] == 'HEARTBEAT':
                    # It's a heartbeat.  Send the same back.
                    LOG.info("HEARTBEAT")
                    self.felix_router_socket.send_multipart(
                        [peer,
                         '',
                         json.dumps(rq).encode('utf-8')])

                else:
                    # It's something unexpected.  Log a warning, but send it
                    # back anyway.
                    LOG.warn("Unexpected request type")
                    self.felix_router_socket.send_multipart(
                        [peer,
                         '',
                         json.dumps(rq).encode('utf-8')])
            except:
                LOG.exception("Exception in Felix-facing ROUTER socket thread")

    def _ensure_socket_to_felix_peer(self, hostname):
        if hostname not in self.felix_peer_sockets:
            LOG.info("Create new socket for %s" % hostname)
            try:
                sock = self.zmq_context.socket(zmq.REQ)
                sock.setsockopt(zmq.LINGER, 0)
                sock.connect("tcp://%s:%s" % (hostname, FELIX_ENDPOINT_PORT))
                self.felix_peer_sockets[hostname] = sock

                # Tell OpenStack that Felix on this host is up.
                self.driver.felix_status(hostname, True)

                eventlet.spawn(self.felix_heartbeat_thread, hostname, sock)
            except:
                LOG.exception("Peer is not actually available")

    def _get_socket_for_felix_peer(self, hostname):
        if hostname in self.felix_peer_sockets:
            return self.felix_peer_sockets[hostname]
        else:
            return None

    def _clear_socket_to_felix_peer(self, hostname):
        if hostname in self.felix_peer_sockets:
            self.felix_peer_sockets[hostname].close()
            del self.felix_peer_sockets[hostname]

    def endpoint_created(self, port):
        self.send_endpoint(None, port, 'CREATED')

    def endpoint_updated(self, port):
        self.send_endpoint(None, port, 'UPDATED')

    def endpoint_deleted(self, port):
        self.send_endpoint(None, port, 'DESTROYED')

    def send_endpoint(self, resync_id, port, op):
        LOG.info("Send ENDPOINT%s for %s" % (op, port))
        hostname = port['binding:host_id']

        # Get the socket that we should send on to the Felix on this hostname.
        # If there is no such socket, bail out.
        sock = self._get_socket_for_felix_peer(hostname)
        if not sock:
            LOG.error("No connection to host %s, bail out" % hostname)
            raise FelixUnavailable(op, port['id'], hostname)

        # Prepare the fields that are common to all ENDPOINT* requests.
        rq = {'type': 'ENDPOINT%s' % op,
              'endpoint_id': port['id'],
              'issued': time.time() * 1000}

        # Add the fields that are common to ENDPOINTCREATED and
        # ENDPOINTUPDATED.
        if op == 'CREATED' or op == 'UPDATED':
            rq.update(
                {'addrs': [{'addr': ip['ip_address'],
                            'gateway': ip['gateway'],
                            'properties': {'gr': False}}
                           for ip in port['fixed_ips']],
                 'mac': port['mac_address'],
                 'state': 'enabled' if port['admin_state_up'] else 'disabled'}
            )

        # For ENDPOINTCREATED, add in the resync_id and interface name.  For
        # ENDPOINTUPDATED verify that our caller didn't specify any resync_id,
        # as it isn't allowed in that case.
        if op == 'CREATED':
            rq.update(
                {'resync_id': resync_id,
                 'interface_name': 'tap' + port['id'][:11]}
            )

        else:
            assert not resync_id

        # Log the prepared request.
        LOG.info("Prepared request: %s" % rq)

        # Send the request.  Don't allow this to block - if it does, an
        # exception will be thrown.
        try:
            sock.send_json(rq, zmq.NOBLOCK)
            LOG.info("Request sent")
        except:
            LOG.exception("Exception sending ENDPOINT* request to Felix")
            self._clear_socket_to_felix_peer(hostname)
            return

        # Receive and log Felix's response.  Use poll and NOBLOCK to require
        # that this comes within ENDPOINT_RESPONSE_TIMEOUT milliseconds.  An
        # exception will be thrown if there's no response in the allowed time.
        try:
            sock.poll(ENDPOINT_RESPONSE_TIMEOUT)
            rsp = sock.recv_json(zmq.NOBLOCK)
            if rsp['rc'] == 'SUCCESS':
                LOG.info("Response: %s" % rsp)
            else:
                LOG.error("Response: %s" % rsp)
        except Again:
            LOG.error("No response from Felix within allowed time (%sms)" %
                      ENDPOINT_RESPONSE_TIMEOUT)
            self._clear_socket_to_felix_peer(hostname)
            raise FelixUnavailable(op, port['id'], hostname)
        except:
            LOG.exception("Exception receiving ENDPOINT* response from Felix")
            self._clear_socket_to_felix_peer(hostname)
            raise FelixUnavailable(op, port['id'], hostname)

    def felix_heartbeat_thread(self, hostname, sock):

        while True:

            # Sleep until time for next heartbeat.
            LOG.info("Felix-HEARTBEAT [%s]: sleep till time for next heartbeat"
                     % hostname)
            eventlet.sleep(HEARTBEAT_SEND_INTERVAL_SECS)

            # Check that the socket for which this thread was started is still
            # valid.
            if sock is not self._get_socket_for_felix_peer(hostname):
                LOG.info("Socket no longer valid, bail out")
                return

            # Send a heartbeat.
            try:
                sock.send_json({'type': 'HEARTBEAT'}, zmq.NOBLOCK)
                LOG.info("HEARTBEAT sent to Felix on %s" % hostname)
            except:
                LOG.exception("Exception sending HEARTBEAT to Felix on %s"
                              % hostname)
                self._clear_socket_to_felix_peer(hostname)
                return

            # Receive and log Felix's response.  Use poll and NOBLOCK to
            # require that this comes within HEARTBEAT_RESPONSE_TIMEOUT
            # milliseconds.  The recv_json call will throw an exception if
            # there's no response in the allowed time, and in that case this
            # heartbeat thread will exit.
            try:
                sock.poll(HEARTBEAT_RESPONSE_TIMEOUT)
                rsp = sock.recv_json(zmq.NOBLOCK)
                if rsp['type'] == 'HEARTBEAT':
                    LOG.info("HEARTBEAT response from Felix on %s: %s"
                             % (hostname, rsp))
                else:
                    LOG.error("Unexpected response from Felix on %s: %s"
                              % (hostname, rsp))
            except Again:
                LOG.error("No response from Felix within allowed time (%sms)" %
                          HEARTBEAT_RESPONSE_TIMEOUT)
                self._clear_socket_to_felix_peer(hostname)
                return
            except:
                LOG.exception("Exception receiving HEARTBEAT from Felix on %s"
                              % hostname)
                self._clear_socket_to_felix_peer(hostname)
                return

            # Felix is still there, tell OpenStack.
            self.driver.felix_status(hostname, True)

    def acl_get_thread(self):

        while True:

            LOG.info("ACL-GET: wait to receive next message")
            try:
                # Receive the next message on the ROUTER socket for ACL
                # Managers.  This may block, but that's OK because all other
                # green threads in the Neutron server process can run in the
                # meantime.
                message = self.acl_get_socket.recv_multipart()

                # Every message on this socket should be multipart with 3
                # parts, of which the second part is always empty.  (Why?)
                assert (len(message) == 3)
                assert not message[1]

                # The first part is the connection identity, and the third is
                # the message content.
                peer = message[0]
                rq = json.loads(message[2].decode('utf-8'))
                LOG.info("ACL-GET RX [%s] %s" % (peer, rq))

                if rq['type'] == 'GETGROUPS':
                    # It's a GETGROUPS request.
                    LOG.info("GETGROUPS request")

                    # Send a GETGROUPS response, with no detail, on the ROUTER
                    # socket.
                    rsp = {'type': 'GETGROUPS'}
                    LOG.info("Sending GETGROUPS response: %s" % rsp)
                    self.acl_get_socket.send_multipart(
                        [peer,
                         '',
                         json.dumps(rsp).encode('utf-8')])

                    # Send a GROUPUPDATE message for each group.
                    for sg in self.driver.get_security_groups():
                        self.send_group(sg)

                elif rq['type'] == 'HEARTBEAT':
                    # It's a heartbeat.  Send the same back.
                    LOG.info("HEARTBEAT")
                    self.acl_get_socket.send_multipart(
                        [peer,
                         '',
                         json.dumps(rq).encode('utf-8')])

                else:
                    # It's something unexpected.  Log a warning, but send it
                    # back anyway.
                    LOG.warn("Unexpected request type")
                    self.acl_get_socket.send_multipart(
                        [peer,
                         '',
                         json.dumps(rq).encode('utf-8')])
            except:
                LOG.exception("Exception in ACL Manager-facing ROUTER thread")

    def send_group(self, sg):
        LOG.info("Publish definition of security group %s" % sg)

        # Send a GROUPUPDATE message, with the definition of this security
        # group, on the PUB socket.
        [inbound, outbound] = self.translate_rules(sg)
        pub = {'type': 'GROUPUPDATE',
               'group': sg['id'],
               'rules': {'inbound': inbound,
                         'outbound': outbound,
                         'inbound_default': 'deny',
                         'outbound_default': 'deny'},
               'members': sg['members'],
               'issued': time.time() * 1000}
        LOG.info("Sending GROUPUPDATE: %s" % pub)

        self.acl_pub_socket.send_multipart(['groups'.encode('utf-8'),
                                            json.dumps(pub).encode('utf-8')])
        LOG.info("Message sent")

    def translate_rules(self, sg):
        inbound = []
        outbound = []
        for rule in sg['security_group_rules']:
            LOG.info("Neutron rule %s" % rule)

            # Map the straightforward fields from Neutron to Calico format.
            api_rule = {'group': rule['remote_group_id'],
                        'cidr': rule['remote_ip_prefix'],
                        'protocol': rule['protocol']}

            # OpenStack (sometimes) represents 'any IP address' by setting both
            # 'remote_group_id' and 'remote_ip_prefix' to None.  For the Calico
            # Network API we must represent that as an explicit 0.0.0.0/0 (for
            # IPv4) or ::/0 (for IPv6).
            if not (api_rule['group'] or api_rule['cidr']):
                api_rule['cidr'] = {'IPv4': '0.0.0.0/0',
                                    'IPv6': '::/0'}[rule['ethertype']]

            # The 'port' field can be '*', or a single number, or a range.
            if rule['port_range_min'] == -1:
                api_rule['port'] = '*'
            elif rule['port_range_min'] == rule['port_range_max']:
                api_rule['port'] = rule['port_range_min']
            else:
                api_rule['port'] = [rule['port_range_min'],
                                    rule['port_range_max']]

            # Add to either the inbound or outbound list, according to
            # Neutron's 'direction' field.
            if rule['direction'] == 'ingress':
                LOG.info("=> Inbound Calico rule %s" % api_rule)
                inbound.append(api_rule)
            else:
                LOG.info("=> Outbound Calico rule %s" % api_rule)
                outbound.append(api_rule)

        return [inbound, outbound]

    def security_group_updated(self, sg):
        self.send_group(sg)
