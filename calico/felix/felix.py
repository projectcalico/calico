# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
"""
felix.felix
~~~~~~~~~~~

The main logic for Felix, including the Felix Agent.
"""
import collections
import logging
import logging.handlers
import os
import socket
import subprocess
import sys
import time
import uuid
import zmq

from calico.felix.config import Config
from calico.felix.endpoint import Address, Endpoint
from calico.felix.fsocket import Socket, Message
from calico.felix import futils
from calico import common


# Logger
log = logging.getLogger(__name__)

# Return codes to send.
RC_SUCCESS  = "SUCCESS"
RC_INVALID  = "INVALID"
RC_NOTEXIST = "NOTEXIST"

class FelixAgent(object):
    """
    A single Felix agent for a Calico network.

    The Felix agent is responsible for communicating with the other components
    in a Calico network, using information passed to it to program the
    networking state on an individual compute host. Felix is primarily
    responsible programming network state for virtual machines running on a
    Linux host.
    """
    def __init__(self):
        #: The ZeroMQ context for this Felix.
        self.zmq_context = zmq.Context()

        #: The hostname of the machine on which this Felix is running.
        self.hostname = socket.gethostname()

        #: All the felix sockets owned by this Felix, keyed off their socket
        #: type.
        self.sockets = {}

        #: All the endpoints managed by this Felix, keyed off their UUID.
        self.endpoints = {}

        # Set of UUIDs of endpoints that need to be retried (the tap interface
        # did not exist when the ENDPOINTCREATED was received).
        self.ep_retry = set()

        # Properties for handling resynchronization.
        self.resync_id = None
        self.resync_recd = None
        self.resync_expected = None
        self.resync_time = None

        # Build a dispatch table for handling various messages.
        self.handlers = {
            Message.TYPE_HEARTBEAT: self.handle_heartbeat,
            Message.TYPE_EP_CR: self.handle_endpointcreated,
            Message.TYPE_EP_UP: self.handle_endpointupdated,
            Message.TYPE_EP_RM: self.handle_endpointdestroyed,
            Message.TYPE_RESYNC: self.handle_resyncstate,
            Message.TYPE_GET_ACL: self.handle_getaclstate,
            Message.TYPE_ACL_UPD: self.handle_aclupdate,
        }

        # Message queues for our request sockets. These exist because we can
        # only ever have one request outstanding.
        self.endpoint_queue = collections.deque()
        self.acl_queue = collections.deque()

        # Initiate our connections.
        self.connect_to_plugin()
        self.connect_to_acl_manager()

        # Begin full endpoint resync. We do not resync ACLs, since we resync
        # the ACLs for each endpoint when we are get an ENDPOINTCREATED in the
        # endpoint resync (and doing it now when we don't know of any endpoints
        # would just be a noop anyway).
        self.resync_endpoints()

    def connect_to_plugin(self):
        """
        This method creates the sockets needed for connecting to the plugin.
        """
        for type in Socket.EP_TYPES:
            sock = Socket(type)
            sock.communicate(self.hostname, self.zmq_context)
            self.sockets[type] = sock

    def connect_to_acl_manager(self):
        """
        This method creates the sockets needed for connecting to the ACL
        manager.
        """
        for type in Socket.ACL_TYPES:
            sock = Socket(type)
            sock.communicate(self.hostname, self.zmq_context)
            self.sockets[type] = sock

    def send_request(self, message, socket_type):
        """
        Sends a request on a given socket type.

        This is used to handle the fact that we cannot have multiple
        outstanding requests on a given socket. It attempts to send the message
        immediately, and if it cannot it queues it.
        """
        assert socket_type in Socket.REQUEST_TYPES

        socket = self.sockets[socket_type]
        if socket.request_outstanding:
            if socket_type == Socket.TYPE_EP_REQ:
                self.endpoint_queue.appendleft(message)
            else:
                self.acl_queue.appendleft(message)
        else:
            socket.send(message)

        return

    def resync_endpoints(self):
        """
        This function is called to resync all endpoint state, both periodically
        and during initialisation.
        """
        self.resync_id       = str(uuid.uuid4())
        self.resync_recd     = 0
        self.resync_expected = 0
        log.info("Do total resync - ID : %s" % self.resync_id)
        # Mark all the endpoints as expecting to be resynchronized.
        for ep in self.endpoints.values():
            ep.pending_resync = True

        # If we had anything queued up to send, clear the queue - it is
        # superseded. Since we are about to ask for ACLs for all endpoints too,
        # we want to clear that queue as well.
        self.endpoint_queue.clear()
        self.acl_queue.clear()

        # Send the RESYNCSTATE message.
        fields = {
            'resync_id': self.resync_id,
            'issued': time.time() * 1000,
            'hostname': self.hostname,
        }
        self.send_request(
            Message(Message.TYPE_RESYNC, fields),
            Socket.TYPE_EP_REQ
        )

    def resync_acls(self):
        """
        Initiates a full ACL resynchronisation procedure.
        """
        # ACL resynchronization involves requesting ACLs for all endpoints
        # for which we have an ID.
        self.acl_queue.clear()

        for endpoint_id, endpoint in self.endpoints.iteritems():
            endpoint.need_acls = True

            fields = {
                'endpoint_id': endpoint_id,
                'issued': time.time() * 1000,
            }
            self.send_request(
                Message(Message.TYPE_GET_ACL, fields),
                Socket.TYPE_ACL_REQ
            )

    def complete_endpoint_resync(self, successful):
        """
        Resync has finished
        """
        log.debug("Finishing resynchronisation, success = %s", successful)
        self.resync_id       = None
        self.resync_recd     = None
        self.resync_expected = None
        self.resync_time     = time.time() * 1000

        if successful:
            for ep in self.endpoints.values():
                if ep.pending_resync:
                    log.info("Remove endpoint %s that is no longer being managed" % ep.uuid)
                    ep.remove()

        # Now remove rules for any endpoints that should no longer exist. This
        # method returns a set of endpoint suffices.
        known_ids = { ep.suffix for ep in self.endpoints.values() }

        for type in [ futils.IPV4, futils.IPV6 ]:
            rule_ids  = futils.list_eps_with_rules(type)

            for id in [ id for id in rule_ids if id not in known_ids ]:
                # Found rules which we own for an endpoint which does not
                # exist.  Remove those rules.
                log.warning("Removing %s rules for removed object %s" % (type, id))
                futils.del_rules(id, type)

    def handle_endpointcreated(self, message):
        """
        Handles an ENDPOINTCREATED message.

        ENDPOINTCREATED can be received in two cases: either as part of a
        state resynchronization, or to notify Felix of a new endpoint to
        manage.
        """
        # TODO: Throughout these message handling, we can fail if mandatory
        # fields are missing. Better to catch and return an error response.
        log.debug("Received endpoint create: %s", message.fields)

        endpoint_id = message.fields['endpoint_id']
        resync_id   = message.fields['resync_id']
        issued      = message.fields['issued']
        mac         = message.fields['mac']

        # First, check whether we know about this endpoint already. If we do,
        # we should raise a warning log unless we're in the middle of a resync.
        endpoint = self.endpoints.get(endpoint_id)
        if endpoint is not None and resync_id is None:
            log.warning(
                "Received endpoint creation for existing endpoint %s",
                endpoint_id
            )
        elif endpoint is not None and resync_id is not None:
            endpoint.pending_resync = False
        elif endpoint is None:
            endpoint = self._create_endpoint(endpoint_id, mac)

        try:
            # Update the endpoint state; this can fail.
            self._update_endpoint(endpoint, message.fields)

            fields = {
                "rc": RC_SUCCESS,
                "message": "",
            }

        except InvalidRequest as error:
            # Invalid request fields. Return an error.
            fields = {
                "rc": RC_INVALID,
                "message": error.value,
            }
            
        # Now we send the response.
        sock = self.sockets[Socket.TYPE_EP_REP]
        sock.send(Message(Message.TYPE_EP_CR, fields))

        # Finally, if this was part of our current resync then increment the
        # count of received resyncs. If we know how many are coming and this is
        # the last one, complete the resync.
        resync_in_progress = (resync_id and resync_id == self.resync_id)

        if resync_in_progress:
            self.resync_recd += 1

        last_resync = (self.resync_expected and
                       self.resync_recd == self.resync_expected)

        if resync_in_progress and last_resync:
            self.complete_endpoint_resync(True)

        return

    def handle_endpointupdated(self, message):
        """
        Handles an ENDPOINTUPDATED message.

        This has very similar logic to ENDPOINTCREATED, but does not actually
        create new endpoints.
        """
        log.debug("Received endpoint update: %s", message.fields)

        # Get the endpoint data from the message.
        endpoint_id = message.fields['endpoint_id']
        issued      = message.fields['issued']

        try:
            # Update the endpoint
            endpoint = self.endpoints[endpoint_id]

            # Update the endpoint state; this can fail.
            self._update_endpoint(endpoint, message.fields)

            fields = {
                "rc": RC_SUCCESS,
                "message": "",
            }

        except KeyError:
            log.error("Received update for absent endpoint %s", endpoint_id)

            fields = {
                "rc": RC_NOTEXIST,
                "message": "Endpoint %s does not exist" % endpoint_id,
            }

        except InvalidRequest as error:
            # Invalid request fields. Return an error.
            fields = {
                "rc": RC_INVALID,
                "message": error.value,
            }
            
        # Now we send the response.
        sock = self.sockets[Socket.TYPE_EP_REP]
        sock.send(Message(Message.TYPE_EP_UP, fields))

        return

    def handle_endpointdestroyed(self, message):
        """
        Handles an ENDPOINTDESTROYED message.

        ENDPOINTDESTROYED is an active notification that an endpoint is going
        away.
        """
        log.debug("Received endpoint destroy: %s", message.fields)

        delete_id = message.fields['endpoint_id']
        issued    = message.fields['issued']

        try:
            endpoint = self.endpoints.pop(delete_id)
        except KeyError:
            log.error("Received destroy for absent endpoint %s", delete_id)
            return

        # Unsubscribe endpoint.
        sock = self.sockets[Socket.TYPE_ACL_SUB]
        sock._zmq.setsockopt(zmq.UNSUBSCRIBE, delete_id.encode('utf-8'))

        endpoint.remove()

        # Send a message indicating our success.
        sock = self.sockets[Socket.TYPE_EP_REP]
        fields = {
            "rc": RC_SUCCESS,
            "message": "",
        }
        sock.send(Message(Message.TYPE_EP_RM, fields))

        return

    def handle_heartbeat(self, message):
        """
        Handles a HEARTBEAT request.

        We respond to HEARTBEATs immediately.
        """
        log.debug("Received heartbeat message on EP REP socket.")
        sock = self.sockets[Socket.TYPE_EP_REP]
        sock.send(Message(Message.TYPE_HEARTBEAT, {}))
        return

    def handle_resyncstate(self, message):
        """
        Handles a RESYNCSTATE response.

        If the response is an error, abandon the resync. Otherwise, if we
        expect no endpoints we're done. Otherwise, set the expected number of
        endpoints.
        """
        log.debug("Received resync response: %s", message.fields)

        endpoint_count = message.fields['endpoint_count']
        return_code = message.fields['rc']
        return_str = message.fields['message']

        if return_code != RC_SUCCESS:
            log.error('Resync request refused with rc : %s, %s', return_code, return_str)
            self.complete_endpoint_resync(False)
            return

        # If there are no endpoints to expect, or we got this after all the
        # resyncs, then we're done.
        if not endpoint_count or endpoint_count == self.resync_recd:
            self.complete_endpoint_resync(True)
            return

        self.resync_expected = endpoint_count
        return

    def handle_getaclstate(self, message):
        """
        Handles a GETACLSTATE response.

        Currently this is basically a no-op. We log on errors, but can't do
        anything about them.
        """
        log.debug("Received GETACLSTATE response: %s", message.fields)

        return_code = message.fields['rc']
        return_str = message.fields['message']

        if return_code != RC_SUCCESS:
            log.error("ACL state request refused with rc : %s, %s", return_code, return_str)

        return

    def handle_aclupdate(self, message):
        """
        Handles ACLUPDATE publications.

        This provides the ACL state to the endpoint in question.
        """
        log.debug("Received ACL update message for %s: %s" %
                  (message.endpoint_id,message.fields))

        endpoint_id = message.endpoint_id
        endpoint = self.endpoints[endpoint_id]

        endpoint.need_acls = False
        endpoint.acl_data  = message.fields['acls']

        if endpoint.uuid in self.ep_retry:
            log.debug("Holding ACLs for endpoint %s that is pending retry" % endpoint.suffix)
        else:
            endpoint.update_acls()

        return

    def _create_endpoint(self, endpoint_id, mac):
        """
        Creates an endpoint after having been informed about it over the API.
        Does the state programming required to get future updates for this
        endpoint, and issues a request for its ACL state.
        """

        log.debug("Create endpoint %s" % endpoint_id)

        # First message about an endpoint about which we know nothing.
        endpoint = Endpoint(endpoint_id, mac)

        self.endpoints[endpoint_id] = endpoint

        # Start listening to the subscription for this endpoint.
        sock = self.sockets[Socket.TYPE_ACL_SUB]
        sock._zmq.setsockopt(zmq.SUBSCRIBE, endpoint_id.encode('utf-8'))

        # Having subscribed, we can now request ACL state for this endpoint.
        fields = {
            'endpoint_id': endpoint_id,
            'issued': time.time() * 1000,
        }
        self.send_request(
            Message(Message.TYPE_GET_ACL, fields),
            Socket.TYPE_ACL_REQ
        )

        return endpoint

    def _update_endpoint(self, endpoint, fields):
        """
        Updates an endpoint's data.
        """
        mac   = fields['mac'].encode('ascii')
        state = fields['state'].encode('ascii')

        addresses = set()
        for addr in fields.get('addrs',None):
            addresses.add(Address(addr))
        endpoint.addresses = addresses

        endpoint.mac   = mac
        if state in Endpoint.STATES:
            endpoint.state = state
        else:
            # Invalid state. For now, we assume that the endpoint is disabled,
            # even it it was not before.
            log.error("Invalid state for endpoint %s : %s" % (endpoint.uuid, state))
            endpoint.state = ENDPOINT.DISABLED
            raise InvalidRequest("Invalid state for endpoint %s" % state)

        # Program the endpoint - i.e. set things up for it.
        log.debug("Program %s" % endpoint.suffix)
        if endpoint.program_endpoint():
            # Failed to program this endpoint - put on the retry list.
            self.ep_retry.add(endpoint.uuid)

        return

    def read_programmed_state(self):
        """This function reads the programmed state, figuring out which endpoints and rules
        exist (as opposed to which endpoints and rules Felix has been told to make exist.
        """
        futils.set_global_rules()

    def initialise(self):
        """
        Initialise agent structures
        """
        # Read the programmed state, i.e. what rules are there.
        self.read_programmed_state()

    def run(self):
        """
        Executes the main agent loop.
        """
        self.initialise()

        while True:
            # Issue a poll request on all active sockets
            endpoint_resync_needed = False
            acl_resync_needed = False

            lPoller = zmq.Poller()
            for sock in self.sockets.values():
                # Easiest just to poll on all sockets, even if we expect no activity
                lPoller.register(sock._zmq, zmq.POLLIN)

            polled_sockets = dict(lPoller.poll(Config.EP_RETRY_INT_MS))

            # Get all the sockets with activity.
            active_sockets = (
                s for s in self.sockets.values()
                if s._zmq in polled_sockets
                and polled_sockets[s._zmq] == zmq.POLLIN
            )

            # For each active socket, pull the message off and handle it.
            for sock in active_sockets:
                message = sock.receive()

                if message is not None:
                    self.handlers[message.type](message)

            for sock in self.sockets.values():
                # See if anything else is required on this socket. First, check
                # whether any have timed out.
                # A timed out socket needs to be reconnected. Also, whatever
                # API it belongs to needs to be resynchronised.
                if sock.timed_out:
                    log.warning("Socket %s timed out", sock.type)
                    sock.close()
                    sock.communicate(self.hostname, self.zmq_context)

                    if sock.type in Socket.EP_TYPES:
                        endpoint_resync_needed = True
                    else:
                        acl_resync_needed = True

                    # Flush the message queue.
                    if sock.type == Socket.TYPE_EP_REQ:
                        self.endpoint_queue.clear()
                    elif sock.type == Socket.TYPE_ACL_REQ:
                        self.acl_queue.clear()

            # If we have any queued messages to send, we should do so.
            endpoint_socket = self.sockets[Socket.TYPE_EP_REQ]
            acl_socket = self.sockets[Socket.TYPE_ACL_REQ]

            if (len(self.endpoint_queue) and
                not endpoint_socket.request_outstanding):

                message = self.endpoint_queue.pop()
                endpoint_socket.send(message)

            if len(self.acl_queue) and not acl_socket.request_outstanding:
                message = self.acl_queue.pop()
                acl_socket.send(message)

            # Now, check if we need to resynchronize and do it.
            if self.resync_id == None and (time.time() - self.resync_time > Config.RESYNC_INT_SEC):
                # Time for a total resync of all endpoints
                endpoint_resync_needed = True

            if endpoint_resync_needed:
                self.resync_endpoints()
            elif acl_resync_needed:
                # Note that an endpoint resync implicitly involves an ACL
                # resync, so there is no point in triggering one when an
                # endpoint resync has just started (as opposed to when we are
                # in the middle of an endpoint resync and just lost our
                # connection).
                self.resync_acls()

            # Finally, retry any endpoints which need retrying.
            retry_list = list(self.ep_retry)
            self.ep_retry.clear()
            for uuid in retry_list:
                if uuid in self.endpoints:
                    endpoint = self.endpoints[uuid]
                    log.debug("Retry program of %s" % endpoint.suffix)
                    if endpoint.program_endpoint():
                        # Failed again - put back on list
                        self.ep_retry.add(uuid)
                    else:
                        # Programmed OK, so we should apply any ACLs we might have.
                        endpoint.update_acls()
                else:
                    log.debug("No retry programming %s - no longer exists" % uuid)

def initialise_logging():
    """
    Sets up the full logging configuration. This applies to the felix log and
    hence to all children.
    """
    # Here we want to set fields in the logger of the parent, so remove the
    # last dot and all after it from __name__.
    name = __name__
    log  = logging.getLogger(name[:name.rfind(".")])

    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')

    common.mkdir_p(os.path.dirname(Config.LOGFILE))
    handler = logging.handlers.TimedRotatingFileHandler(Config.LOGFILE, when='D', backupCount=10)
    handler.setLevel(Config.LOGLEVFILE)
    handler.setFormatter(formatter)
    log.addHandler(handler)

    handler = logging.handlers.SysLogHandler()
    handler.setLevel(Config.LOGLEVSYS)
    log.addHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(Config.LOGLEVSCR)
    handler.setFormatter(formatter)
    log.addHandler(handler)

def set_global_state():
    """This function sets up global state, such as IP forwarding or global IP tables.
    CB2: not terribly well defined yet, but might be worth you doing some of this.
    """

def main():
    try:
        # Initialise the logging.
        initialise_logging()

        # We have restarted - tell the world.
        log.error("Felix started")

        # Read and set up global state
        set_global_state()

        # Create an instance of the Felix agent and start it running.
        agent = FelixAgent()
        agent.run()
    except:
        e = sys.exc_info()[0]
        log.exception(e)


if __name__ == "__main__":
    main()

class InvalidRequest(Exception):
    """
    Exception that allows us to report an invalid request.
    """
    pass

