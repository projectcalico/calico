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
import logging
import os
import pkg_resources
import socket
import time
import uuid
import zmq

from calico.felix.config import Config
from calico.felix.endpoint import Address, Endpoint, InvalidAddress
from calico.felix.fsocket import Socket, Message
from calico.felix import fiptables
from calico.felix import frules
from calico.felix import fsocket
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
        log.error("Felix starting (version: %s)",
                  pkg_resources.get_distribution('calico'))

        # The ZeroMQ context for this Felix.
        self.zmq_context = context

        # The hostname of the machine on which this Felix is running.
        self.hostname = self.config.HOSTNAME

        # The sockets owned by this Felix, keyed off their socket type.
        self.sockets = {}

        # The endpoints managed by this Felix, keyed off their UUID.
        self.endpoints = {}

        # Set of UUIDs of endpoints that need to be retried (the interface did
        # not exist when the ENDPOINTCREATED was received).
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

        # Interface prefix. Only present after first resync response received.
        self.iface_prefix = None

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

        # Initiate our connections.
        self.connect_to_plugin()
        self.connect_to_acl_manager()

        # Grab a new iptables state.
        self.iptables_state = fiptables.TableState()

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
        """
        assert socket_type in Socket.REQUEST_TYPES
        self.sockets[socket_type].send(message)

        return

    def resync_endpoints(self):
        """
        This function is called to resync all endpoint state, both periodically
        and during initialisation.
        """
        self.resync_id       = str(uuid.uuid4())
        self.resync_recd     = 0
        self.resync_expected = None

        #*********************************************************************#
        #* Log the version here, ensuring that we log it periodically (in    *#
        #* case we try to debug with logs that do not cover Felix starting). *#
        #*********************************************************************#
        log.info("Do total resync - ID : %s (version: %s)",
                 self.resync_id,
                 pkg_resources.get_distribution('calico'))

        # Mark all the endpoints as expecting to be resynchronized.
        for ep in self.endpoints.values():
            ep.pending_resync = True

        # Since we are about to ask for ACLs for all endpoints too, we want to
        # clear that queue.
        self.sockets[Socket.TYPE_ACL_REQ].clear_queue()

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
        # for which we have an ID. That means any queued requests are really
        # no longer relevant as they are duplicates.
        self.sockets[Socket.TYPE_ACL_REQ].clear_queue()

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
                    ep.remove(self.iptables_state)
                    del self.endpoints[uuid]

        #*********************************************************************#
        #* Now remove rules for any endpoints that should no longer          *#
        #* exist. This method returns a set of endpoint suffices.            *#
        #*********************************************************************#
        known_suffices = set(ep.suffix for ep in self.endpoints.values())

        for type in [futils.IPV4, futils.IPV6]:
            found_suffices  = frules.list_eps_with_rules(self.iptables_state,
                                                         type)

            for found_suffix in found_suffices:
                if found_suffix not in known_suffices:
                    # Found rules which we own for an endpoint which does not
                    # exist.  Remove those rules.
                    log.warning("Removing %s rules for removed object %s",
                                type, found_suffix)
                    frules.del_rules(self.iptables_state, found_suffix, type)

    def handle_endpointcreated(self, message, sock):
        """
        Handles an ENDPOINTCREATED message.

        ENDPOINTCREATED can be received in two cases: either as part of a
        state resynchronization, or to notify Felix of a new endpoint to
        manage.
        """
        log.debug("Received endpoint create: %s", message.fields)

        # Default to success
        fields = { "rc": RC_SUCCESS, "message": "" }

        try:
            try:
                endpoint_id = message.fields['endpoint_id']
            except KeyError:
                raise InvalidRequest("Missing \"endpoint_id\" field",
                                     message.fields)
            try:
                mac = message.fields['mac']
            except KeyError:
                raise InvalidRequest("Missing \"mac\" field",
                                     message.fields)

            try:
                resync_id = message.fields['resync_id']
            except KeyError:
                raise InvalidRequest("Missing \"resync_id\" field",
                                     message.fields)

            try:
                interface = message.fields['interface_name']
            except KeyError:
                raise InvalidRequest("Missing \"interface_name\" field",
                                     message.fields)

            if not interface.startswith(self.iface_prefix):
                raise InvalidRequest("Interface \"%s\" does not start with \"%s\""
                                     % (interface, self.iface_prefix),
                                     message.fields)

            endpoint = self.endpoints.get(endpoint_id)
            if endpoint is not None and resync_id is None:
                # We know about this endpoint, but not a resync; accept, but log.
                log.warning(
                    "Received endpoint creation for existing endpoint %s",
                    endpoint_id
                )
            elif endpoint is not None and resync_id is not None:
                # We know about this endpoint, and this is a resync.
                endpoint.pending_resync = False
            elif endpoint is None:
                # New endpoint.
                endpoint = self._create_endpoint(endpoint_id,
                                                 mac,
                                                 interface)

            # Update the endpoint state; this can fail with Invalid Request.
            self._update_endpoint(endpoint, message.fields)

            if resync_id:
                # This endpoint created was part of a resync.
                if resync_id == self.resync_id:
                    #*********************************************************#
                    #* It was part of the most recent resync.  Increment how *#
                    #* many ENDPOINTCREATED requests we have received, and   *#
                    #* if this is the last one expected, complete the        *#
                    #* resync.                                               *#
                    #*********************************************************#
                    self.resync_recd += 1
                    if self.resync_expected is None:
                        # resync_expected not set - resync response pending
                        log.debug(
                            "Received ENDPOINTCREATED number %d for resync "
                            "before resync response", self.resync_recd)
                    else:
                        log.debug(
                            "Received ENDPOINTCREATED for resync, %d out of %d",
                            self.resync_recd, self.resync_expected)

                    if self.resync_recd == self.resync_expected:
                        self.complete_endpoint_resync(True)
                else:
                    #*********************************************************#
                    #* We just got an ENDPOINTCREATED for the wrong          *#
                    #* resync. This can happen (perhaps we restarted during  *#
                    #* a resync and are seeing messages from that old        *#
                    #* resync).  Log it though, since this is very unusual   *#
                    #* and strange.                                          *#
                    #*********************************************************#
                    log.warning(
                        "Received ENDPOINTCREATED for %s with invalid "
                        "resync %s (expected %s)" ,
                        endpoint_id, resync_id, self.resync_id)

        except InvalidRequest as error:
            fields = {
                "rc": RC_INVALID,
                "message": error.message,
            }
            log.error("Got invalid ENDPOINTCREATED message : %s, "
                      "request fields %s", error.message, error.fields)

        # Send the response.
        sock.send(Message(Message.TYPE_EP_CR, fields))

    def handle_endpointupdated(self, message, sock):
        """
        Handles an ENDPOINTUPDATED message.

        This has very similar logic to ENDPOINTCREATED, but does not actually
        create new endpoints.
        """
        log.debug("Received endpoint update: %s", message.fields)

        # Initially assume success.
        fields = {"rc": RC_SUCCESS, "message": ""}

        try:
            # Get the endpoint ID from the message.
            try:
                endpoint_id = message.fields['endpoint_id']
            except KeyError:
                raise InvalidRequest("Missing \"endpoint_id\" field",
                                     message.fields)

            try:
                # Update the endpoint
                endpoint = self.endpoints[endpoint_id]

            except KeyError:
                log.error("Received update for absent endpoint %s", endpoint_id)

                fields = {
                    "rc": RC_NOTEXIST,
                    "message": "Endpoint %s does not exist" % endpoint_id,
                }

            else:
                # Update the endpoint state; this can fail with InvalidRequest.
                self._update_endpoint(endpoint, message.fields)

        except InvalidRequest as error:
            fields = {
                "rc": RC_INVALID,
                "message": error.message,
            }
            log.error("Got invalid ENDPOINTUPDATED message : %s, "
                      "request fields %s", error.message, error.fields)

        # Send the response.
        sock.send(Message(Message.TYPE_EP_UP, fields))

    def handle_endpointdestroyed(self, message, sock):
        """
        Handles an ENDPOINTDESTROYED message.

        ENDPOINTDESTROYED is an active notification that an endpoint is going
        away.
        """
        log.debug("Received endpoint destroy: %s", message.fields)

        # Initially assume success.
        fields = {"rc": RC_SUCCESS, "message": ""}

        try:
            # Get the endpoint ID from the message.
            try:
                delete_id = message.fields['endpoint_id']
            except KeyError:
                raise InvalidRequest("Missing \"endpoint_id\" field",
                                     message.fields)
            try:
                # Remove this endpoint from Felix's list of managed
                # endpoints.
                endpoint = self.endpoints.pop(delete_id)
            except KeyError:
                log.error("Received destroy for absent endpoint %s", delete_id)
                fields = {
                    "rc": RC_NOTEXIST,
                    "message": "Endpoint %s does not exist" % delete_id,
                }
            else:
                # Unsubscribe from ACL information for this endpoint.
                self.sockets[Socket.TYPE_ACL_SUB].unsubscribe(
                    delete_id.encode('utf-8')
                )

                # Remove programming for this endpoint.
                endpoint.remove(self.iptables_state)

        except InvalidRequest as error:
            fields = {
                "rc": RC_INVALID,
                "message": error.message,
            }
            log.error("Got invalid ENDPOINTDESTROYED message : %s, "
                      "request fields %s", error.message, error.fields)

        # Send the response.
        sock.send(Message(Message.TYPE_EP_RM, fields))

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
        try:
            try:
                endpoint_count = int(message.fields['endpoint_count'])
            except KeyError:
                raise InvalidRequest("Missing \"endpoint_count\" field",
                                     message.fields)
            try:
                return_code = message.fields['rc']
            except KeyError:
                raise InvalidRequest("Missing \"rc\" field",
                                     message.fields)
            try:
                return_str = message.fields['message']
            except KeyError:
                raise InvalidRequest("Missing \"message\" field",
                                     message.fields)
            try:
                self.iface_prefix = message.fields['interface_prefix']
            except KeyError:
                raise InvalidRequest("Missing \"interface_prefix\" field",
                                     message.fields)
        except InvalidRequest as error:
            log.error("Got invalid RESYNCSTATE response : %s, "
                      "request fields %s", error.message, error.fields)
            self.complete_endpoint_resync(False)
            return

        if return_code != RC_SUCCESS:
            log.error('Resync request refused with rc : %s, %s',
                      return_code,
                      return_str)
            self.complete_endpoint_resync(False)
            return

        # Reset / create the global rules.
        frules.set_global_rules(self.config,
                                self.iface_prefix,
                                self.iptables_state)

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

        try:
            try:
                return_code = message.fields['rc']
            except KeyError:
                raise InvalidRequest("Missing \"rc\" field",
                                     message.fields)

            try:
                return_str = message.fields['message']
            except KeyError:
                raise InvalidRequest("Missing \"message\" field",
                                     message.fields)

            if return_code != RC_SUCCESS:
                #*************************************************************#
                #* It's hard to see what errors we might get other than a    *#
                #* timing window one of "never heard of that endpoint". We   *#
                #* just log it and continue onwards.                         *#
                #*************************************************************#
                log.error("ACL state request refused with rc : %s, %s",
                          return_code,
                          return_str)

        except InvalidRequest as error:
            log.error("Got invalid GETACLSTATE response : %s, "
                        "request fields %s", error.message, error.fields)

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

    def _create_endpoint(self, endpoint_id, mac, interface):
        """
        Creates an endpoint after having been informed about it over the API.
        Does the state programming required to get future updates for this
        endpoint, and issues a request for its ACL state.

        This routine must only be called if the endpoint is not already known
        to Felix.
        """
        log.debug("Create endpoint %s", endpoint_id)

        endpoint = Endpoint(endpoint_id,
                            mac,
                            interface,
                            self.iface_prefix)

        self.endpoints[endpoint_id] = endpoint

        # Start listening to the subscription for this endpoint.
        self.sockets[Socket.TYPE_ACL_SUB].subscribe(
            endpoint_id.encode('utf-8')
        )

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
        try:
            mac = fields['mac']
        except KeyError:
            raise InvalidRequest("Missing \"mac\" field", fields)

        try:
            state = fields['state']
        except KeyError:
            raise InvalidRequest("Missing \"state\" field", fields)

        try:
            addrs = fields['addrs']
        except KeyError:
            raise InvalidRequest("Missing \"addrs\" field", fields)

        addresses = set()
        try:
            for addr in addrs:
                addresses.add(Address(addr))
        except InvalidAddress:
            log.error("Invalid address for endpoint %s : %s",
                      endpoint.uuid, fields)
            raise InvalidRequest("Invalid address for endpoint",
                                 fields)

        if state not in Endpoint.STATES:
            log.error("Invalid state %s for endpoint %s : %s",
                      state, endpoint.uuid, fields)
            raise InvalidRequest("Invalid state \"%s\"" % state, fields)

        endpoint.addresses = addresses

        endpoint.mac = mac.encode('ascii')
        endpoint.state = state.encode('ascii')

        # Program the endpoint - i.e. set things up for it.
        log.debug("Program %s", endpoint.suffix)
        if endpoint.program_endpoint(self.iptables_state):
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

        if self.iface_prefix:
            poll_list = self.sockets.values()
        else:
            # Not got an first resync response (as no interface prefix), so
            # ignore all sockets except the EP_REQ socket until we do.
            poll_list = [self.sockets[Socket.TYPE_EP_REQ]]

        active_sockets = fsocket.poll(poll_list,
                                      self.config.EP_RETRY_INT_MS)

        # For each active socket, pull the message off and handle it.
        for sock in active_sockets:
            message = sock.receive()

            if message is not None:
                try:
                    self.handlers[message.type](message, sock)
                except KeyError:
                    # We are going down, but raise a better exception.
                    raise InvalidRequest("Unrecognised message type",
                                         message.fields)

        for sock in self.sockets.values():
            #*****************************************************************#
            #* See if anything else is required on this socket. First, check *#
            #* whether any have timed out.  A timed out socket needs to be   *#
            #* reconnected. Also, whatever API it belongs to needs to be     *#
            #* resynchronised.                                               *#
            #*****************************************************************#
            if sock.timed_out():
                log.error("Timed out remote entity : %s", sock.descr)

                #*************************************************************#
                #* If we lost the connection on which we would receive       *#
                #* ENDPOINTCREATED messages, we need to trigger a total      *#
                #* endpoint resync, and similarly for ACLs if we have lost   *#
                #* the connection on which we would receive ACLUPDATE        *#
                #* messages.                                                 *#
                #*************************************************************#
                if sock.type == Socket.TYPE_EP_REP:
                    #*********************************************************#
                    #* We lost the connection on which we would receive      *#
                    #* ENDPOINTCREATED messages. We may be out of step, so   *#
                    #* need a total endpoint update.                         *#
                    #*********************************************************#
                    endpoint_resync_needed = True
                elif (sock.type == Socket.TYPE_ACL_SUB or
                      sock.type == Socket.TYPE_ACL_REQ):
                    #*********************************************************#
                    #* We lost the connection on which we would receive      *#
                    #* ACLUPDATE messages, or might have lost some queued    *#
                    #* GETACLSTATE messages. We may be out of step, so we    *#
                    #* need a total ACL resync.                              *#
                    #*********************************************************#
                    acl_resync_needed = True

                if (self.resync_id is not None and
                    sock.type in (Socket.TYPE_EP_REQ, Socket.TYPE_EP_REP)):
                    #*********************************************************#
                    #* A resync was in progress, but we may have lost the    *#
                    #* RESYNCSTATE request or response or (potentially) an   *#
                    #* ENDPOINTCREATED message due to a lost                 *#
                    #* connection. That means we have to give up on this     *#
                    #* resync, tidy up and retry.                            *#
                    #*********************************************************#
                    self.complete_endpoint_resync(False)
                    endpoint_resync_needed = True

                # Recreate the socket.
                sock.restart(self.hostname, self.zmq_context)

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

        # We are not about to send any more messages; send any required
        # keepalives.
        for sock in self.sockets.values():
            sock.keepalive()

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
                if endpoint.program_endpoint(self.iptables_state):
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
    def __init__(self, message, fields):
        super(InvalidRequest, self).__init__(message)
        self.fields = fields

    def __str__(self):
        return "%s (request : %s)" % (self.message, self.fields)
