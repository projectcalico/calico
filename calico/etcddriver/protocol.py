# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
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
calico.etcddriver.protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~

Protocol constants for Felix <-> Driver protocol.
"""
import logging
import msgpack
import select

_log = logging.getLogger(__name__)

MSG_KEY_TYPE = "type"

# Init message Felix -> Driver.
MSG_TYPE_INIT = "init"
MSG_KEY_ETCD_URL = "etcd_url"
MSG_KEY_HOSTNAME = "hostname"

# Config loaded message Driver -> Felix.
MSG_TYPE_CONFIG_LOADED = "config_loaded"
MSG_KEY_GLOBAL_CONFIG = "global"
MSG_KEY_HOST_CONFIG = "host"

# Config message Felix -> Driver.
MSG_TYPE_CONFIG = "conf"
MSG_KEY_LOG_FILE = "log_file"
MSG_KEY_SEV_FILE = "sev_file"
MSG_KEY_SEV_SCREEN = "sev_screen"
MSG_KEY_SEV_SYSLOG = "sev_syslog"

# Status message Driver -> Felix.
MSG_TYPE_STATUS = "stat"
MSG_KEY_STATUS = "status"
STATUS_WAIT_FOR_READY = "wait-for-ready"
STATUS_RESYNC = "resync"
STATUS_IN_SYNC = "in-sync"

# Force resync message Felix->Driver.
MSG_TYPE_RESYNC = "resync"

# Update message Driver -> Felix.
MSG_TYPE_UPDATE = "u"
MSG_KEY_KEY = "k"
MSG_KEY_VALUE = "v"


class SocketClosed(Exception):
    pass


class MessageWriter(object):
    def __init__(self, sck):
        self._sck = sck

    def send_message(self, msg_type, fields=None):
        msg = {MSG_KEY_TYPE: msg_type}
        if fields:
            msg.update(fields)
        self._sck.sendall(msgpack.dumps(msg))


class MessageReader(object):
    def __init__(self, sck):
        self._sck = sck
        self._unpacker = msgpack.Unpacker()

    def new_messages(self, timeout=None):
        """
        Generator: generates 0 or more tuples containing message type and
        message body (as a dict).

        :param timeout: Maximum time to block waiting on the socket before
               giving up.  No exception is raised upon timeout but 0 events
               are generated.
        :raises SocketClosed if the socket is closed.
        """
        if timeout is not None:
            read_ready, _, _ = select.select([self._sck], [], [], 1)
            if not read_ready:
                return
        data = self._sck.recv(16384)
        if not data:
            # No data indicates an orderly shutdown of the socket,
            # which shouldn't happen.
            _log.error("Socket closed by other end.")
            raise SocketClosed()
        # Feed the data into the Unpacker, if it has enough data it will then
        # generate some messages.
        self._unpacker.feed(data)
        for msg in self._unpacker:
            yield msg[MSG_KEY_TYPE], msg
