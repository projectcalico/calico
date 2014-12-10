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
NOBLOCK = "NOBLOCK"

poll_results = []

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
        self.events = dict()
        if socket_type is not None:
            self.events[socket_type] = msg
        poll_results.append(self)

    def add(socket_type, msg):
        self.events[socket_type] = msg

def clear_poll_results():
    global poll_results
    poll_results = []

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

    # xxx Ouch. This has the type of the ZMQ socket, not of the blasted Felix socket

    def __init__(self, type):
        self._type = type
        self._msg = None

    def bind(self, addr):
        if self._type != REP:
            raise ZmqStubException("Cannot bind to non-REP socket")
        pass

    def connect(self, addr):
        if self._type == REP:
            raise ZmqStubException("Cannot bind to REP socket")
        pass

    def setsockopt(self, option_type, option_value):
        pass

    def send(self, msg, option=None):
        pass

class Poller(object):
    def __init__(self):
        self.sockets = set()

    def register(self, socket, poll_type):
        self.sockets.add(socket)

    def poll(self, timeout):
        if not poll_results:
            # No poll results left - end test
            raise stub_utils.TestOverException

        poll_result = poll_results.pop(0)
        stub_utils.set_time(poll_result.time)

        retval = dict();

        for socket in self.sockets:
            if socket._type in poll_result.events:
                socket._msg = poll_result.events[socket._type]
                retval[socket] = "POLLIN"

        return retval


class Context(object):
    def __init__(self):
        pass

    def socket(self, type):
        sock = StubSocket(type)
        return sock

