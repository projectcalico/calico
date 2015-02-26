# -*- coding: utf-8 -*-
#
# Copyright (c) 2014 Metaswitch Networks
# Copyright (c) 2013 OpenStack Foundation
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

# Calico/OpenStack Plugin
#
# This module is the OpenStack-specific implementation of the Plugin component
# of the new Calico architecture (described by the "Felix, the Calico Plugin
# and the Calico ACL Manager" wiki page at
# https://github.com/Metaswitch/calico-docs/wiki).
#
# It is implemented as a Neutron/ML2 mechanism driver.

from oslo.config import cfg
from neutron.common import constants
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
import eventlet
from eventlet.green import zmq
import json
import time
from neutron import context as ctx
from neutron import manager
from zmq.error import Again

LOG = log.getLogger(__name__)

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

# An OpenStack agent type name for Felix, the Calico agent component in the new
# architecture.
AGENT_TYPE_FELIX = 'Felix (Calico agent)'


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


class CalicoMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Neutron/ML2 mechanism driver for Project Calico.

    CalicoMechanismDriver communicates information about endpoints and security
    configuration, over the Endpoint and Network APIs respectively, to the
    other components of the Calico architecture; namely to the Felix instances
    running on each compute host, and to one or more ACL Managers.
    """

    def __init__(self):
        super(CalicoMechanismDriver, self).__init__(
            constants.AGENT_TYPE_DHCP,
            'tap',
            {'port_filter': True})

        # Initialize dictionary mapping Felix hostnames to corresponding REQ
        # sockets.
        self.felix_peer_sockets = {}

        # Initialize fields for the database object and context.  We will
        # initialize these properly when we first need them.
        self.db = None

    def _get_db(self):
        if not self.db:
            self.db = manager.NeutronManager.get_plugin()
            LOG.info("db = %s" % self.db)

            # Installer a notifier proxy in order to catch security group
            # changes, if we haven't already.
            if self.db.notifier.__class__ != CalicoNotifierProxy:
                self.db.notifier = CalicoNotifierProxy(self.db.notifier, self)
            else:
                # In case the notifier proxy already exists but the current
                # CalicoMechanismDriver instance has changed, ensure that the
                # notifier proxy will delegate to the current
                # CalicoMechanismDriver instance.
                self.db.notifier.calico_driver = self

    def check_segment_for_agent(self, segment, agent):
        LOG.debug("Checking segment %s with agent %s" % (segment, agent))
        if segment[api.NETWORK_TYPE] in ['local', 'flat']:
            return True
        else:
            return False

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

    def felix_router_thread(self):

        # Get a Neutron DB context for this thread.
        db_context = ctx.get_admin_context()

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

                    # Set up access to the Neutron database, if we haven't
                    # already.
                    self._get_db()

                    # Get a list of all ports on the Felix host.  Unfortunately
                    # it isn't possible to use 'binding:host_id' as a query
                    # filter, so we filter the results ourselves instead.
                    LOG.info("Query Neutron DB...")
                    ports = [port for port in self.db.get_ports(db_context)
                             if (port['binding:host_id'] == rq['hostname'] and
                                 self._port_is_endpoint_port(port))]

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
                    self._ensure_socket_to_felix_peer(rq['hostname'],
                                                      db_context)

                    # Now also send an ENDPOINTCREATED request to the Felix
                    # instance, for each port.
                    for port in ports:
                        self.send_endpoint(rq['hostname'],
                                           rq['resync_id'],
                                           port,
                                           'CREATED',
                                           db_context)

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

    def _ensure_socket_to_felix_peer(self, hostname, db_context):
        if hostname not in self.felix_peer_sockets:
            LOG.info("Create new socket for %s" % hostname)
            try:
                sock = self.zmq_context.socket(zmq.REQ)
                sock.setsockopt(zmq.LINGER, 0)
                sock.connect("tcp://%s:%s" % (hostname, FELIX_ENDPOINT_PORT))
                self.felix_peer_sockets[hostname] = sock
                self.db.create_or_update_agent(db_context,
                                               {'agent_type': AGENT_TYPE_FELIX,
                                                'binary': '',
                                                'host': hostname,
                                                'topic':
                                                    constants.L2_AGENT_TOPIC,
                                                'start_flag': True})
                eventlet.spawn(self.felix_heartbeat_thread, hostname)
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

    def _port_is_endpoint_port(self, port):

        # Return True if port is a VM port.
        if port['device_owner'].startswith('compute:'):
            return True

        # Otherwise log and return False.
        LOG.debug("Not a VM port: %s" % port)
        return False

    def send_endpoint(self, hostname, resync_id, port, op, db_context):
        LOG.info("Send ENDPOINT%s to %s for %s" % (op, hostname, port))

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
                            'gateway': self._get_subnet_gw(ip['subnet_id'],
                                                           db_context),
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

    def _get_subnet_gw(self, subnet_id, db_context):
        assert self.db
        subnet = self.db.get_subnet(db_context, subnet_id)
        return subnet['gateway_ip']

    def create_network_postcommit(self, context):
        LOG.info("CREATE_NETWORK_POSTCOMMIT: %s" % context)

    def update_network_postcommit(self, context):
        LOG.info("UPDATE_NETWORK_POSTCOMMIT: %s" % context)

    def delete_network_postcommit(self, context):
        LOG.info("DELETE_NETWORK_POSTCOMMIT: %s" % context)

    def create_subnet_postcommit(self, context):
        LOG.info("CREATE_SUBNET_POSTCOMMIT: %s" % context)

    def update_subnet_postcommit(self, context):
        LOG.info("UPDATE_SUBNET_POSTCOMMIT: %s" % context)

    def delete_subnet_postcommit(self, context):
        LOG.info("DELETE_SUBNET_POSTCOMMIT: %s" % context)

    def create_port_postcommit(self, context):
        LOG.info("CREATE_PORT_POSTCOMMIT: %s" % context)
        port = context._port
        if self._port_is_endpoint_port(port):
            LOG.info("Created port: %s" % port)
            self.send_endpoint(port['binding:host_id'],
                               None,
                               port,
                               'CREATED',
                               context._plugin_context)
            self._get_db()
            self.db.update_port_status(context._plugin_context,
                                       port['id'],
                                       constants.PORT_STATUS_ACTIVE)

    def update_port_postcommit(self, context):
        LOG.info("UPDATE_PORT_POSTCOMMIT: %s" % context)
        port = context._port
        original = context.original
        if self._port_is_endpoint_port(port):
            LOG.info("Updated port: %s" % port)
            LOG.info("Original: %s" % original)
            if port['binding:vif_type'] == 'unbound':
                # This indicates part 1 of a port being migrated: the port
                # being unbound from its old location.  The old compute host is
                # available from context.original.  We should send an
                # ENDPOINTDESTROYED to the old compute host.
                #
                # Ref: http://lists.openstack.org/pipermail/openstack-dev/
                # 2014-February/027571.html
                LOG.info("Migration part 1")
                self.send_endpoint(original['binding:host_id'],
                                   None,
                                   original,
                                   'DESTROYED',
                                   context._plugin_context)
            elif original['binding:vif_type'] == 'unbound':
                # This indicates part 2 of a port being migrated: the port
                # being bound to its new location.  We should send an
                # ENDPOINTCREATED to the new compute host.
                #
                # Ref: http://lists.openstack.org/pipermail/openstack-dev/
                # 2014-February/027571.html
                LOG.info("Migration part 2")
                self.send_endpoint(port['binding:host_id'],
                                   None,
                                   port,
                                   'CREATED',
                                   context._plugin_context)
            elif original['binding:host_id'] != port['binding:host_id']:
                # Migration as implemented in Icehouse.
                LOG.info("Migration as implemented in Icehouse")
                self.send_endpoint(original['binding:host_id'],
                                   None,
                                   original,
                                   'DESTROYED',
                                   context._plugin_context)
                self.send_endpoint(port['binding:host_id'],
                                   None,
                                   port,
                                   'CREATED',
                                   context._plugin_context)
            else:
                # This is a non-migration-related update.
                self.send_endpoint(port['binding:host_id'],
                                   None,
                                   port,
                                   'UPDATED',
                                   context._plugin_context)

    def delete_port_postcommit(self, context):
        LOG.info("DELETE_PORT_POSTCOMMIT: %s" % context)
        port = context._port
        if self._port_is_endpoint_port(port):
            LOG.info("Deleted port: %s" % port)
            self.send_endpoint(port['binding:host_id'],
                               None,
                               port,
                               'DESTROYED',
                               context._plugin_context)

    def felix_heartbeat_thread(self, hostname):

        # Get a Neutron DB context for this thread.
        db_context = ctx.get_admin_context()

        while True:

            # Sleep until time for next heartbeat.
            LOG.info("Felix-HEARTBEAT [%s]: sleep till time for next heartbeat"
                     % hostname)
            eventlet.sleep(HEARTBEAT_SEND_INTERVAL_SECS)

            # Check that there is still a socket to this Felix.
            sock = self._get_socket_for_felix_peer(hostname)
            if not sock:
                LOG.info("No connection to this host, bail out")
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
            self.db.create_or_update_agent(db_context,
                                           {'agent_type': AGENT_TYPE_FELIX,
                                            'binary': '',
                                            'host': hostname,
                                            'topic': constants.L2_AGENT_TOPIC})

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

    def acl_get_thread(self):

        # Get a Neutron DB context for this thread.
        db_context = ctx.get_admin_context()

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

                    # Set up access to the Neutron database, if we haven't
                    # already.
                    self._get_db()

                    # Get a list of all security groups.
                    LOG.info("Query Neutron DB...")
                    sgs = self.db.get_security_groups(db_context)

                    # Send a GROUPUPDATE message for each group.
                    for sg in sgs:
                        self.send_group(sg, db_context)

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

    def send_group(self, sg, db_context):
        LOG.info("Publish definition of security group %s" % sg)

        # Send a GROUPUPDATE message, with the definition of this security
        # group, on the PUB socket.
        [inbound, outbound] = self._get_rules(sg)
        pub = {'type': 'GROUPUPDATE',
               'group': sg['id'],
               'rules': {'inbound': inbound,
                         'outbound': outbound,
                         'inbound_default': 'deny',
                         'outbound_default': 'deny'},
               'members': self._get_members(sg, db_context),
               'issued': time.time() * 1000}
        LOG.info("Sending GROUPUPDATE: %s" % pub)

        self.acl_pub_socket.send_multipart(['groups'.encode('utf-8'),
                                            json.dumps(pub).encode('utf-8')])
        LOG.info("Message sent")

    def _get_rules(self, sg):
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

    def _get_members(self, sg, db_context):
        filters = {'security_group_id': [sg['id']]}
        bindings = self.db._get_port_security_group_bindings(db_context,
                                                             filters)
        endpoints = {}
        for binding in bindings:
            port_id = binding['port_id']
            port = self.db.get_port(db_context, port_id)
            endpoints[port_id] = [ip['ip_address'] for ip in port['fixed_ips']]

        LOG.info("Endpoints for SG %s are %s" % (sg['id'], endpoints))
        return endpoints

    def send_sg_updates(self, sgids, db_context):
        for sgid in sgids:
            self.send_group(self.db.get_security_group(db_context, sgid),
                            db_context)


class CalicoNotifierProxy(object):
    """Proxy pattern class used to intercept security-related notifications
    from the ML2 plugin.
    """

    def __init__(self, ml2_notifier, calico_driver):
        self.ml2_notifier = ml2_notifier
        self.calico_driver = calico_driver

    def __getattr__(self, name):
        return getattr(self.ml2_notifier, name)

    def security_groups_rule_updated(self, context, sgids):
        LOG.info("security_groups_rule_updated: %s %s" % (context, sgids))
        self.calico_driver.send_sg_updates(sgids, context)
        self.ml2_notifier.security_groups_rule_updated(context, sgids)

    def security_groups_member_updated(self, context, sgids):
        LOG.info("security_groups_member_updated: %s %s" % (context, sgids))
        self.calico_driver.send_sg_updates(sgids, context)
        self.ml2_notifier.security_groups_member_updated(context, sgids)
