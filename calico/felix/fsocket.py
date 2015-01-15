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
felix.fsocket
~~~~~~~~~~~~

Function for managing ZeroMQ sockets.
"""
import json
import logging
import time
import zmq

from calico.felix import futils

log = logging.getLogger(__name__)


class Socket(object):
    """
    Socket is an encapsulation of a 0MQ socket wrapping the messaging logic.
    It handles connecting and signalling errors, and maintains state about the
    message flows.
    """
    # Socket types
    TYPE_EP_REQ  = "EP REQ"
    TYPE_EP_REP  = "EP REP"
    TYPE_ACL_REQ = "ACL REQ"
    TYPE_ACL_SUB = "ACL SUB"

    ALL_TYPES = set((TYPE_EP_REQ, TYPE_EP_REP, TYPE_ACL_REQ, TYPE_ACL_SUB))
    REQUEST_TYPES = set((TYPE_EP_REQ, TYPE_ACL_REQ))
    ACL_TYPES = set((TYPE_ACL_REQ, TYPE_ACL_SUB))
    EP_TYPES = set((TYPE_EP_REQ, TYPE_EP_REP))

    PORT = {TYPE_EP_REQ:  9901,
            TYPE_EP_REP:  9902,
            TYPE_ACL_REQ: 9905,
            TYPE_ACL_SUB: 9906}

    ZTYPE = {TYPE_EP_REQ:  zmq.REQ,
             TYPE_EP_REP:  zmq.REP,
             TYPE_ACL_REQ: zmq.REQ,
             TYPE_ACL_SUB: zmq.SUB}

    def __init__(self, type, config):
        self.config = config
        self.type = type
        self.remote_addr = None
        self.port = Socket.PORT[type]
        self._zmq = None
        self.last_activity = None
        self.request_outstanding = False

        if type in Socket.EP_TYPES:
            self.remote_addr = self.config.PLUGIN_ADDR
        else:
            self.remote_addr = self.config.ACL_ADDR

    def close(self):
        """
        Close this connection cleanly.
        """
        if self._zmq is not None:
            self._zmq.close()
            self._zmq = None

    def communicate(self, hostname, context):
        """
        Create and connect / bind a socket
        """
        log.info(
            "Creating socket to entity %s:%d", self.remote_addr, self.port
        )

        self._zmq = context.socket(Socket.ZTYPE[self.type])

        if self.type == Socket.TYPE_EP_REP:
            self._zmq.bind("tcp://%s:%s" % (self.config.LOCAL_ADDR, self.port))
        else:
            self._zmq.connect("tcp://%s:%s" % (self.remote_addr, self.port))

        if self.type == Socket.TYPE_ACL_SUB:
            self._zmq.setsockopt(zmq.IDENTITY, hostname)
            self._zmq.setsockopt(zmq.SUBSCRIBE, 'aclheartbeat')

        # The socket connection event is always the time of last activity.
        self.last_activity = futils.time_ms()

    def send(self, msg):
        """
        Send a specified message on a socket.
        """
        log.info("Sent %s on socket %s" % (msg.descr, self.type))
        self.last_activity = futils.time_ms()

        #*********************************************************************#
        #* We never expect any type of socket that we use to block since we  *#
        #* use only REQ or REP sockets - so if we get blocking then we       *#
        #* consider that something is wrong, and let the exception take down *#
        #* Felix.                                                            *#
        #*********************************************************************#
        try:
            self._zmq.send(msg.zmq_msg, zmq.NOBLOCK)

            if self.type in Socket.REQUEST_TYPES:
                self.request_outstanding = True
        except:
            log.exception("Socket %s blocked on send", self.type)
            raise

    def receive(self):
        """
        Receive a message on this socket. For subscriptions, this will return
        a list of bytes.
        """
        log.debug("Received something on %s", self.type)

        #*********************************************************************#
        #* We never expect any type of socket that we use to block since we  *#
        #* just polled to check - so if we get blocking then we consider     *#
        #* that something is wrong, and let the exception take down Felix.   *#
        #*********************************************************************#
        try:
            if self.type != Socket.TYPE_ACL_SUB:
                data = self._zmq.recv(zmq.NOBLOCK)
                uuid = None
            else:
                uuid, data = self._zmq.recv_multipart(zmq.NOBLOCK)
        except:
            log.exception("Socket %s blocked on receive", self.type)
            raise

        message = Message.parse_message(data, uuid)

        # Log that we received the message.
        log.info("Received %s on socket %s" % (message.descr, self.type))

        # If this is a response, we're no longer waiting for one.
        if self.type in Socket.REQUEST_TYPES:
            self.request_outstanding = False

        self.last_activity = futils.time_ms()

        # A special case: heartbeat messages on the subscription interface are
        # swallowed; the application code has no use for them.
        if (self.type == Socket.TYPE_ACL_SUB and
                message.type == Message.TYPE_HEARTBEAT):
            return None

        return message

    def timed_out(self):
        """
        Returns True if the socket has been inactive for at least the timeout;
        all sockets must have heartbeats on them.
        """
        return ((futils.time_ms() - self.last_activity) >
                self.config.CONN_TIMEOUT_MS)

    def keepalive_due(self):
        """
        Returns True if we are due to send a keepalive on the socket.

        The caller is responsible for deciding which sockets need keepalives.
        """
        return ((futils.time_ms() - self.last_activity) >
                self.config.CONN_KEEPALIVE_MS)


class Message(object):
    """This represents a message either sent or received by Felix."""
    TYPE_RESYNC    = "RESYNCSTATE"
    TYPE_EP_CR     = "ENDPOINTCREATED"
    TYPE_EP_UP     = "ENDPOINTUPDATED"
    TYPE_EP_RM     = "ENDPOINTDESTROYED"
    TYPE_GET_ACL   = "GETACLSTATE"
    TYPE_ACL_UPD   = "ACLUPDATE"
    TYPE_HEARTBEAT = "HEARTBEAT"

    def __init__(self, type, fields, endpoint_id=None):
        #: The type of the message.
        self.type = type

        #: The description of the message, used for logging only.
        if type == Message.TYPE_RESYNC and 'resync_id' in fields:
            self.descr = "%s(%s)" % (type, fields['resync_id'])
        elif endpoint_id is not None:
            self.descr = "%s(%s)" % (type, endpoint_id)
        elif 'endpoint_id' in fields:
            self.descr = "%s(%s)" % (type, fields['endpoint_id'])
        elif type in (Message.TYPE_EP_CR,
                      Message.TYPE_EP_UP,
                      Message.TYPE_EP_RM):
            self.descr = "%s response" % (type)
        else:
            self.descr = type

        #: A dictionary containing the other dynamic fields on the message.
        self.fields = fields

        # The endpoint ID for which this message is valid. Only used when
        # type is TYPE_ACL_UPD.
        self.endpoint_id = endpoint_id

    @property
    def zmq_msg(self):
        """
        The serialized form of the message, suitable for sending on the wire.
        """
        data = self.fields.copy()
        data['type'] = self.type
        return json.dumps(data)

    @classmethod
    def parse_message(cls, text, endpoint_id=None):
        """Parse a received message."""
        data = json.loads(text)
        type = data.pop('type')
        msg = cls(type, data, endpoint_id)
        return msg
