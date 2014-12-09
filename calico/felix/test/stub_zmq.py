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

class ZmqStubException(Exception):
    pass

class Socket(object):
    def __init__(self, type):
        self.type = type

    def bind(self, addr):
        if self.type != REP:
            raise ZmqStubException("Cannot bind to non-REP socket")
        pass

    def connect(self, addr):
        if self.type == REP:
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
        pass


class Context(object):
    def __init__(self):
        pass

    def socket(self, type):
        sock = Socket(type)
        return sock

