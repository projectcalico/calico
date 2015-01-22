# -*- coding: utf-8 -*-
# Copyright (c) 2014 Metaswitch Networks
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

"""
felix.felix
~~~~~~~~~~~

The main logic for Felix.
"""
import argparse
import collections
import logging
import os
import socket
import time
import uuid
import zmq

from calico.felix.config import Config
from calico.felix.endpoint import Address, Endpoint
from calico.felix.fsocket import Socket, Message
from calico.felix import frules
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
    networking state for a set of endpoints; for example for a set of virtual
    machines or containers on an individual compute host.
    """
    def __init__(self, config_path, context):
        # Get some configuration.
        self.config = Config(config_path)

        # Complete logging initialisation, now we have config.
        common.complete_logging(
            self.config.LOGFILE,
            self.config.LOGLEVFILE,
            self.config.LOGLEVSYS,
            self.config.LOGLEVSCR
        )

        # We have restarted and set up logs - tell the world.
        log.error("Felix starting")

        # The ZeroMQ context for this Felix.
        self.zmq_context = context

        # The hostname of the machine on which this Felix is running.
        self.hostname = self.config.HOSTNAME

        # The sockets owned by this Felix, keyed off their socket type.
        self.sockets = {}

        # The endpoints managed by this Felix, keyed off their UUID.
        self.endpoints = {}

        # Set of UUIDs of endpoints that need to be retried (the tap interface
        # did not exist when the ENDPOINTCREATED was received).
        self.ep_retry = set()

        # Properties for handling resynchronization.
        #
        # resync_id is a UUID for the resync, passed on the API. It ensures
        # that we can correlate ENDPOINTCREATED requests with resyncs. If this
        # field is None, then no resync is in progress, and neither resync_recd
        # nor resync_expected is meaningful.
        self.resync_id = None

        # resync_recd counts all of the ENDPOINTCREATED requests received for
        # this resync, so we know when they have all arrived.
        self.resync_recd = None

        # resync_expected is the number of ENDPOINTCREATED requests that are
        # going to be sent for this resync, as reported in the resync
        # response. This is None if that response has not yet been received.
        self.resync_expected = None

        # resync_time is always defined once the first resync has been sent. It
        # is the time, in integer milliseconds since the epoch, of the sending
        # of the last resync. This is used to detect when it is time for
        # another resync.  Note that integers in python automatically convert
        # from 32 to 64 bits when they are too large, and so we do not have to
        # worry about overflowing for many thousands of years yet.
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

        # Set up the global rules.
        frules.set_global_rules(self.config)

    def connect_to_plugin(self):
        """
        This method creates the sockets needed for connecting to the plugin.
        """
        for type in Socket.EP_TYPES:
            sock = Socket(type, self.config)
            sock.communicate(self.hostname, self.zmq_context)
            self.sockets[type] = sock

    def connect_to_acl_manager(self):
        """
        This method creates the sockets needed for connecting to the ACL
        manager.
        """
        for type in Socket.ACL_TYPES:
            sock = Socket(type, self.config)
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
        self.resync_expected = None

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
            'issued': futils.time_ms(),
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
            fields = {
                'endpoint_id': endpoint_id,
                'issued': futils.time_ms()
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
        self.resync_time     = futils.time_ms()

        if successful:
            for uuid in self.endpoints.keys():
                ep = self.endpoints[uuid]
                if ep.pending_resync:
                    log.info(
                        "Remove endpoint %s that is no longer being managed" %
                        ep.uuid)
                    ep.remove()
                    del self.endpoints[ep]

        #*********************************************************************#
        #* Now remove rules for any endpoints that should no longer          *#
        #* exist. This method returns a set of endpoint suffices.            *#
        #*********************************************************************#
        known_suffices = {ep.suffix for ep in self.endpoints.values()}

        for type in [futils.IPV4, futils.IPV6]:
            found_suffices  = frules.list_eps_with_rules(type)

            for found_suffix in found_suffices:
                if found_suffix not in known_suffices:
                    # Found rules which we own for an endpoint which does not
                    # exist.  Remove those rules.
                    log.warning("Removing %s rules for removed object %s" %
                                (type, found_suffix))
                    frules.del_rules(found_suffix, type)

    def handle_endpointcreated(self, message, sock):
        """
        Handles an ENDPOINTCREATED message.

        ENDPOINTCREATED can be received in two cases: either as part of a
        state resynchronization, or to notify Felix of a new endpoint to
        manage.
        """
        log.debug("Received endpoint create: %s", message.fields)

        # TODO: Ought to firewall missing mandatory fields here.
        endpoint_id = message.fields['endpoint_id']
        mac         = message.fields['mac']
        resync_id   = message.fields.get('resync_id')

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

        if resync_id:
            # This endpoint created was part of a resync.
            if resync_id == self.resync_id:
                #*************************************************************#
                #* It was part of the most recent resync.  Increment how     *#
                #* many ENDPOINTCREATED requests we have received, and if    *#
                #* this is the last one expected, complete the resync.       *#
                #*************************************************************#
                self.resync_recd += 1
                if self.resync_expected is None:
                    # resync_expected not set - resync response pending
                    log.debug("Received ENDPOINTCREATED number %d for resync "
                              "before resync response" ,
                              self.resync_recd)
                else:
                    log.debug("Received ENDPOINTCREATED for resync, %d out of %d",
                              self.resync_recd, self.resync_expected)

                if self.resync_recd == self.resync_expected:
                    self.complete_endpoint_resync(True)
            else:
                #*************************************************************#
                #* We just got an ENDPOINTCREATED for the wrong resync. This *#
                #* can happen (perhaps we restarted during a resync and are  *#
                #* seeing messages from that old resync).  Log it though,    *#
                #* since this is very unusual and strange.                   *#
                #*************************************************************#
                log.warning(
                    "Received ENDPOINTCREATED for %s with invalid "
                    "resync %s (expected %s)" ,
                    endpoint_id, resync_id, self.resync_id)

        return

    def handle_endpointupdated(self, message, sock):
        """
        Handles an ENDPOINTUPDATED message.

        This has very similar logic to ENDPOINTCREATED, but does not actually
        create new endpoints.
        """
        log.debug("Received endpoint update: %s", message.fields)

        # Get the endpoint data from the message.
        endpoint_id = message.fields['endpoint_id']

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

    def handle_endpointdestroyed(self, message, sock):
        """
        Handles an ENDPOINTDESTROYED message.

        ENDPOINTDESTROYED is an active notification that an endpoint is going
        away.
        """
        log.debug("Received endpoint destroy: %s", message.fields)

        delete_id = message.fields['endpoint_id']

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

    def handle_heartbeat(self, message, sock):
        """
        Handles a HEARTBEAT request or response.
        """
        if sock.type == Socket.TYPE_EP_REQ or sock.type == Socket.TYPE_ACL_REQ:
            log.debug("Received heartbeat response on %s socket", sock.type)
        else:
            assert(sock.type == Socket.TYPE_EP_REP)
            log.debug("Received heartbeat message on EP REP socket")
            sock.send(Message(Message.TYPE_HEARTBEAT, {}))
        return

    def handle_resyncstate(self, message, sock):
        """
        Handles a RESYNCSTATE response.

        If the response is an error, abandon the resync. Otherwise, if we
        expect no endpoints we're done. Otherwise, set the expected number of
        endpoints.
        """
        log.debug("Received resync response: %s", message.fields)

        endpoint_count = int(message.fields['endpoint_count'])
        return_code = message.fields['rc']
        return_str = message.fields['message']

        if return_code != RC_SUCCESS:
            log.error('Resync request refused with rc : %s, %s',
                      return_code,
                      return_str)
            self.complete_endpoint_resync(False)
            return

        # If there are no endpoints to expect, or we got this after all the
        # resyncs, then we're done.
        if endpoint_count == 0 or endpoint_count == self.resync_recd:
            self.complete_endpoint_resync(True)
            return

        self.resync_expected = endpoint_count
        return

    def handle_getaclstate(self, message, sock):
        """
        Handles a GETACLSTATE response.

        Currently this is basically a no-op. We log on errors, but can't do
        anything about them.
        """
        log.debug("Received GETACLSTATE response: %s", message.fields)

        return_code = message.fields['rc']
        return_str = message.fields['message']

        if return_code != RC_SUCCESS:
            #*****************************************************************#
            #* It's hard to see what errors we might get other than a timing *#
            #* window one of "never heard of that endpoint". We just log it  *#
            #* and continue onwards.                                         *#
            #*****************************************************************#
            log.error("ACL state request refused with rc : %s, %s",
                      return_code,
                      return_str)

        return

    def handle_aclupdate(self, message, sock):
        """
        Handles ACLUPDATE publications.

        This provides the ACL state to the endpoint in question.
        """
        log.debug("Received ACL update message for %s: %s" %
                  (message.endpoint_id, message.fields))

        endpoint_id = message.endpoint_id
        try:
            endpoint = self.endpoints[endpoint_id]
        except KeyError:
            # Endpoint deleted under our feet. Log and ignore.
            log.info("ACLUPDATE for endpoint %s which does not exist" %
                      endpoint_id)
            return

        endpoint.acl_data  = message.fields['acls']

        if endpoint.uuid in self.ep_retry:
            log.debug("Holding ACLs for endpoint %s that is pending retry" %
                      endpoint.suffix)
        else:
            endpoint.update_acls()

        return

    def _create_endpoint(self, endpoint_id, mac):
        """
        Creates an endpoint after having been informed about it over the API.
        Does the state programming required to get future updates for this
        endpoint, and issues a request for its ACL state.

        This routine must only be called if the endpoint is not already known
        to Felix.
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
            'issued': futils.time_ms()
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
        mac   = fields.get('mac')
        state = fields.get('state')
        addresses = set()
        try:
            for addr in fields['addrs']:
                addresses.add(Address(addr))
        except KeyError:
            log.error("Missing addrs or IP in addrs for endpoint %s, data %s",
                      self.uuid, fields)
            raise InvalidRequest("No valid address for endpoint %s")

        if mac is None:
            log.error("No mac address for endpoint %s")
            raise InvalidRequest("No mac address for endpoint %s")

        if state is None:
            log.error("No state for endpoint %s")
            raise InvalidRequest("No state for endpoint %s")

        if state not in Endpoint.STATES:
            log.error("Invalid state %s for endpoint %s : %s" %
                      (state, endpoint.uuid, state))
            raise InvalidRequest("Invalid state %s for endpoint %s" %
                                 (state, endpoint.uuid))

        endpoint.addresses = addresses

        endpoint.mac   = mac.encode('ascii')
        endpoint.state = state.encode('ascii')

        # Program the endpoint - i.e. set things up for it.
        log.debug("Program %s" % endpoint.suffix)
        if endpoint.program_endpoint():
            # Failed to program this endpoint - put on the retry list.
            self.ep_retry.add(endpoint.uuid)

        return

    def run(self):
        """
        Executes one iteration of the main agent loop.
        """
        # Issue a poll request on all active sockets.
        endpoint_resync_needed = False
        acl_resync_needed = False

        lPoller = zmq.Poller()
        for sock in self.sockets.values():
            # Easier just to poll all sockets, even if we expect nothing.
            lPoller.register(sock._zmq, zmq.POLLIN)

        polled_sockets = dict(lPoller.poll(self.config.EP_RETRY_INT_MS))

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
                self.handlers[message.type](message, sock)

        for sock in self.sockets.values():
            #*****************************************************************#
            #* See if anything else is required on this socket. First, check *#
            #* whether any have timed out.  A timed out socket needs to be   *#
            #* reconnected. Also, whatever API it belongs to needs to be     *#
            #* resynchronised.                                               *#
            #*****************************************************************#
            if sock.timed_out():
                log.warning("Socket %s timed out", sock.type)
                sock.close()

                #*************************************************************#
                #* If we lost the connection on which we would receive       *#
                #* ENDPOINTCREATED messages, we need to trigger a total      *#
                #* endpoint resync, and similarly for ACLs if we have lost   *#
                #* the connection on which we would receive ACLUPDATE        *#
                #* messages.                                                 *#
                #*************************************************************#
                if sock.type == Socket.TYPE_EP_REP:
                    endpoint_resync_needed = True
                elif sock.type == Socket.TYPE_ACL_SUB:
                    acl_resync_needed = True

                # Flush the message queue.
                if sock.type == Socket.TYPE_EP_REQ:
                    self.endpoint_queue.clear()
                elif sock.type == Socket.TYPE_ACL_REQ:
                    self.acl_queue.clear()

                # Recreate the socket.
                sock.communicate(self.hostname, self.zmq_context)

                # If this is the ACL SUB socket, then subscribe for all
                # endpoints.
                if sock.type == Socket.TYPE_ACL_SUB:
                    for endpoint_id in self.endpoints:
                        sock._zmq.setsockopt(zmq.SUBSCRIBE,
                                             endpoint_id.encode('utf-8'))

        # If we have any queued messages to send, we should do so.
        endpoint_socket = self.sockets[Socket.TYPE_EP_REQ]
        acl_socket = self.sockets[Socket.TYPE_ACL_REQ]

        if (len(self.endpoint_queue) and
                not endpoint_socket.request_outstanding):
            message = self.endpoint_queue.pop()
            endpoint_socket.send(message)
        elif (endpoint_socket.keepalive_due() and
              not endpoint_socket.request_outstanding):
            endpoint_socket.send(Message(Message.TYPE_HEARTBEAT, {}))

        if len(self.acl_queue) and not acl_socket.request_outstanding:
            message = self.acl_queue.pop()
            acl_socket.send(message)
        elif (acl_socket.keepalive_due() and
              not acl_socket.request_outstanding):
            acl_socket.send(Message(Message.TYPE_HEARTBEAT, {}))

        # Now, check if we need to resynchronize and do it.
        if (self.resync_id is None and
                (futils.time_ms() - self.resync_time >
                 self.config.RESYNC_INT_SEC * 1000)):
            # Time for a total resync of all endpoints
            endpoint_resync_needed = True

        if endpoint_resync_needed:
            self.resync_endpoints()
        elif acl_resync_needed:
            #*****************************************************************#
            #* Note that an endpoint resync implicitly involves an ACL       *#
            #* resync, so there is no point in triggering one when an        *#
            #* endpoint resync has just started (as opposed to when we are   *#
            #* in the middle of an endpoint resync and just lost our         *#
            #* connection).                                                  *#
            #*****************************************************************#
            self.resync_acls()

        #*********************************************************************#
        #* Finally, retry any endpoints which need retrying. We remove them  *#
        #* from ep_retry if they no longer exist or if the retry succeeds;   *#
        #* the simplest way to do this is to copy the list, clear ep_retry   *#
        #* then add them back if necessary.                                  *#
        #*********************************************************************#
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
                    # Programmed OK, so apply any ACLs we might have.
                    endpoint.update_acls()
            else:
                log.debug("No retry programming %s - no longer exists" %
                          uuid)


def main():
    try:
        # Initialise the logging with default parameters.
        common.default_logging()

        #*********************************************************************#
        #* This is the default configuration path - we expect in most cases  *#
        #* that the configuration file path is passed in on the command      *#
        #* line.                                                             *#
        #*********************************************************************#
        CONFIG_FILE_PATH = 'felix.cfg'
        parser = argparse.ArgumentParser(description='Felix (Calico agent)')
        parser.add_argument('-c', '--config-file', dest='config_file')
        args = parser.parse_args()

        config_path = args.config_file or CONFIG_FILE_PATH

        # Create an instance of the Felix agent and start it running.
        agent = FelixAgent(config_path, zmq.Context())
        while True:
            agent.run()

    except:
        #*********************************************************************#
        #* Log the exception then terminate. We cannot call sys.exit here    *#
        #* because sometimes we hang on exit processing deep inside zmq      *#
        #* (when the exception that causes termination was caused by a       *#
        #* socket error).                                                    *#
        #*********************************************************************#
        log.exception("Felix exiting after uncaught exception")
        os._exit(1)

if __name__ == "__main__":
    main()


class InvalidRequest(Exception):
    """
    Exception that allows us to report an invalid request.
    """
    pass
