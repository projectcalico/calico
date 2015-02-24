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
felix.test.stub_zmq
~~~~~~~~~~~~

Stub version of the 0MQ interface.
"""
import json
import logging
import calico.felix.test.stub_utils as stub_utils

# Globals defined by 0MQ
POLLIN = "POLLIN"

# Socket types
REP = "REP"
REQ = "REQ"
SUB = "SUB"

# Socket option types
IDENTITY = "IDENTITY"
SUBSCRIBE = "SUBSCRIBE"
UNSUBSCRIBE = "UNSUBSCRIBE"
NOBLOCK = "NOBLOCK"

# Socket types - matching the values in fsocket, but arbitrary.
TYPE_EP_REQ  = "EP REQ"
TYPE_EP_REP  = "EP REP"
TYPE_ACL_REQ = "ACL REQ"
TYPE_ACL_SUB = "ACL SUB"
TYPE_UNKNOWN = "Unknown"

# Logger
log = logging.getLogger(__name__)

#*****************************************************************************#
#* The next few methods are not exposed to production code, but are called   *#
#* by test code.                                                             *#
#*****************************************************************************#
class PollResult(object):
    """
    A PollResult object is simply something that can happen on a poll -
    essentially a dictionary that maps socket types to messages, plus a time to
    set.
    """
    def __init__(self, time, socket_type=None, msg=None):
        self.time = time
        self.events = {}
        self.uuid = {}
        if socket_type is not None:
            self.add(socket_type, msg)

    def add(self, socket_type, msg, uuid=None):
        self.events[socket_type] = json.dumps(msg)
        self.uuid[socket_type] = uuid

class ZmqStubException(Exception):
    pass

#*****************************************************************************#
#* Methods from here down are actually on the interface exposed to           *#
#* production code.                                                          *#
#*****************************************************************************#
class StubSocket(object):
    """
    This is called a stub socket because there are two other things called a
    socket, and this particular class is not exposed on the interface.
    """
    def __init__(self, context, zmq_type):
        self.zmq_type = zmq_type
        self.type = TYPE_UNKNOWN
        self.msg = None
        self.uuid = None # uuid corresponding to msg above for recv_multipart
        self.context = context

    def bind(self, addr):
        if self.zmq_type != REP:
            raise ZmqStubException("Cannot bind to non-REP socket (%s)" %
                                   self.zmq_type)
        if addr.endswith(":9902"):
            self.type = TYPE_EP_REP
        else:
            raise ZmqStubException("Unexpected port in bind : %s" % addr)

    def connect(self, addr):
        if self.zmq_type == REP:
            raise ZmqStubException("Cannot connect to REP socket")
        if addr.endswith(":9901"):
            self.type = TYPE_EP_REQ
        elif addr.endswith(":9905"):
            self.type = TYPE_ACL_REQ
        elif addr.endswith(":9906"):
            self.type = TYPE_ACL_SUB
        else:
            raise ZmqStubException("Unexpected port in connect : %s" % addr)

    def setsockopt(self, option_type, option_value):
        pass

    def send(self, msg, options=None):
        log.debug("Sending message %s to %s", msg, self.type)
        self.context.sent_data[self.type].append(json.loads(msg))

    def recv(self, options=None):
        if self.msg is None:
            raise ZmqStubException("No message available")
        return self.msg

    def recv_multipart(self, options=None):
        if self.msg is None:
            raise ZmqStubException("No message available")
        elif self.uuid is None:
            raise ZmqStubException("No uuid available")
        return (self.uuid, self.msg)

    def close(self):
        del self.context.sent_data[self.type][:]

class Poller(object):
    def __init__(self):
        self.sockets = set()
        self.context = None

    def register(self, socket, poll_type):
        self.sockets.add(socket)
        self.context = socket.context

    def poll(self, timeout):
        if not self.context.poll_results:
            # No poll results left - end test
            raise stub_utils.TestOverException

        poll_result = self.context.poll_results.pop(0)
        log.debug("Got poll request (%d left), returning new time %d, events : %s" %
                  (len(self.context.poll_results),
                   poll_result.time,
                   poll_result.events))

        stub_utils.set_time(poll_result.time)

        retval = {}

        for socket in self.sockets:
            if socket.type in poll_result.events:
                socket.msg = poll_result.events[socket.type]
                socket.uuid = poll_result.uuid[socket.type]
                retval[socket] = POLLIN
                del poll_result.events[socket.type]

        if poll_result.events:
            # Make sure that all the events have been assigned to a socket.
            # We just log if not; sometimes Felix does not poll all sockets.
            log.debug("Got event for socket not polled on : %s",
                      poll_result.events)

        return retval


class Context(object):
    """
    In production code, a ZMQ context is passed around all over the place.
    In test code, we replace that ZMQ context with this structure, allowing us
    to track which sockets exist and what state they are in.
    """
    def __init__(self):
        # Array of PollResults, created and passed in by the tests.
        self.poll_results = []

        # Data sent by Felix - a dictionary, of which each element is a list.
        self.sent_data = {}
        self.sent_data[TYPE_EP_REQ] = []
        self.sent_data[TYPE_EP_REP] = []
        self.sent_data[TYPE_ACL_REQ] = []
        self.sent_data[TYPE_ACL_SUB] = []

    def socket(self, type):
        sock = StubSocket(self, type)
        return sock

    def add_poll_result(self, time, socket_type=None, msg=None):
        poll_result = PollResult(time, socket_type, msg)
        self.poll_results.append(poll_result)
        return poll_result

    def sent_data_present(self):
        """
        Return a True result if any sent_data is present. Used to validate that
        only expected data is there.
        """
        for socket_type in self.sent_data:
            if self.sent_data[socket_type]:
                log.debug("Got data to send for socket type : %s" %
                          socket_type)
                return True
        return False
