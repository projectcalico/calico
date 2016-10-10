# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
import errno
import os
import struct
from io import BytesIO
import select

from calico.felix import felixbackend_pb2

_log = logging.getLogger(__name__)

MSG_KEY_TYPE = "type"

# Init message Felix -> Driver.
MSG_TYPE_INIT = "init"
MSG_KEY_ETCD_URLS = "etcd_urls"
MSG_KEY_HOSTNAME = "hostname"
MSG_KEY_KEY_FILE = "etcd_key_file"
MSG_KEY_CERT_FILE = "etcd_cert_file"
MSG_KEY_CA_FILE = "etcd_ca_cert_file"
MSG_KEY_PROM_PORT = "prom_port"

# Config loaded message Driver -> Felix.
MSG_TYPE_CONFIG_UPDATE = "config_update"
MSG_KEY_GLOBAL_CONFIG = "global"
MSG_KEY_HOST_CONFIG = "per_host"

# Config message Felix -> Driver.
MSG_TYPE_CONFIG_RESOLVED = "config_resolved"
MSG_KEY_LOG_FILE = "log_file"
MSG_KEY_SEV_FILE = "sev_file"
MSG_KEY_SEV_SCREEN = "sev_screen"
MSG_KEY_SEV_SYSLOG = "sev_syslog"
MSG_KEY_EP_REPORT_DELAY_SECS = "endpoint_status_reporting_delay"
MSG_KEY_EP_REPORT_RESYNC_SECS = "endpoint_status_resync_interval"

# Status message Driver -> Felix.
MSG_TYPE_IN_SYNC = "in_sync"

MSG_TYPE_PROFILE_UPDATE = "active_profile_update"
MSG_TYPE_PROFILE_REMOVED = "active_profile_remove"
MSG_TYPE_POLICY_UPDATE = "active_policy_update"
MSG_TYPE_POLICY_REMOVED = "active_policy_remove"
MSG_KEY_TIER_NAME = "tier"
MSG_KEY_NAME = "name"
MSG_KEY_POLICY = "policy"
MSG_KEY_PROFILE = "profile"

MSG_TYPE_WL_EP_UPDATE = "workload_endpoint_update"
MSG_TYPE_WL_EP_REMOVE = "workload_endpoint_remove"
MSG_TYPE_HOST_EP_UPDATE = "host_endpoint_update"
MSG_TYPE_HOST_EP_REMOVE = "host_endpoint_remove"
MSG_KEY_ORCH = "orchestrator"
MSG_KEY_WORKLOAD_ID = "workload_id"
MSG_KEY_ENDPOINT_ID = "endpoint_id"
MSG_KEY_ENDPOINT = "endpoint"

# Selector/IP added/removed message Driver -> Felix.
MSG_TYPE_IPSET_UPDATE = "ipset_update"
MSG_TYPE_IPSET_REMOVED = "ipset_remove"
MSG_TYPE_IPSET_DELTA = "ipset_delta_update"

MSG_KEY_MEMBERS = "members"
MSG_KEY_ADDED_IPS = "added_members"
MSG_KEY_REMOVED_IPS = "removed_members"
MSG_KEY_IPSET_ID = "id"

MSG_TYPE_HOST_METADATA_UPDATE = "host_metadata_update"
MSG_TYPE_HOST_METADATA_REMOVE = "host_metadata_remove"

MSG_TYPE_IPAM_POOL_UPDATE = "ipam_pool_update"
MSG_TYPE_IPAM_POOL_REMOVE = "ipam_pool_remove"

# Status reports
MSG_TYPE_FELIX_STATUS = "felix_status_update"
MSG_KEY_TIME = "iso_timestamp"
MSG_KEY_UPTIME = "uptime"

MSG_TYPE_WL_ENDPOINT_STATUS = "workload_endpoint_status_update"
MSG_TYPE_WL_ENDPOINT_STATUS_REMOVE = "workload_endpoint_status_remove"
MSG_TYPE_HOST_ENDPOINT_STATUS = "host_endpoint_status_update"
MSG_TYPE_HOST_ENDPOINT_STATUS_REMOVE = "host_endpoint_status_remove"

__all__ = [
    'MSG_KEY_ADDED_IPS',
    'MSG_KEY_CA_FILE',
    'MSG_KEY_CERT_FILE',
    'MSG_KEY_ENDPOINT',
    'MSG_KEY_ENDPOINT_ID',
    'MSG_KEY_EP_REPORT_DELAY_SECS',
    'MSG_KEY_EP_REPORT_RESYNC_SECS',
    'MSG_KEY_ETCD_URLS',
    'MSG_KEY_GLOBAL_CONFIG',
    'MSG_KEY_HOSTNAME',
    'MSG_KEY_HOST_CONFIG',
    'MSG_KEY_IPSET_ID',
    'MSG_KEY_KEY_FILE',
    'MSG_KEY_LOG_FILE',
    'MSG_KEY_MEMBERS',
    'MSG_KEY_NAME',
    'MSG_KEY_ORCH',
    'MSG_KEY_POLICY',
    'MSG_KEY_PROFILE',
    'MSG_KEY_PROM_PORT',
    'MSG_KEY_REMOVED_IPS',
    'MSG_KEY_SEV_FILE',
    'MSG_KEY_SEV_SCREEN',
    'MSG_KEY_SEV_SYSLOG',
    'MSG_KEY_TIER_NAME',
    'MSG_KEY_TIME',
    'MSG_KEY_TYPE',
    'MSG_KEY_UPTIME',
    'MSG_KEY_WORKLOAD_ID',
    'MSG_TYPE_CONFIG_RESOLVED',
    'MSG_TYPE_CONFIG_UPDATE',
    'MSG_TYPE_FELIX_STATUS',
    'MSG_TYPE_HOST_ENDPOINT_STATUS',
    'MSG_TYPE_HOST_ENDPOINT_STATUS_REMOVE',
    'MSG_TYPE_HOST_EP_REMOVE',
    'MSG_TYPE_HOST_EP_UPDATE',
    'MSG_TYPE_INIT',
    'MSG_TYPE_IPSET_DELTA',
    'MSG_TYPE_IPSET_REMOVED',
    'MSG_TYPE_IPSET_UPDATE',
    'MSG_TYPE_IPAM_POOL_REMOVE',
    'MSG_TYPE_IPAM_POOL_UPDATE',
    'MSG_TYPE_HOST_METADATA_UPDATE',
    'MSG_TYPE_HOST_METADATA_REMOVE',
    'MSG_TYPE_POLICY_REMOVED',
    'MSG_TYPE_POLICY_UPDATE',
    'MSG_TYPE_PROFILE_REMOVED',
    'MSG_TYPE_PROFILE_UPDATE',
    'MSG_TYPE_IN_SYNC',
    'MSG_TYPE_WL_ENDPOINT_STATUS',
    'MSG_TYPE_WL_ENDPOINT_STATUS_REMOVE',
    'MSG_TYPE_WL_EP_REMOVE',
    'MSG_TYPE_WL_EP_UPDATE',
    'MessageReader',
    'MessageWriter',
    'SocketClosed',
    'WriteFailed',
]

FLUSH_THRESHOLD = 200


class SocketClosed(Exception):
    """The socket was unexpectedly closed by the other end."""
    pass


class WriteFailed(Exception):
    """Write to the socket failed."""
    pass


class MessageWriter(object):
    """
    Wrapper around a socket used to write protocol messages.

    Supports buffering a number of messages for subsequent flush().
    """
    def __init__(self, sck):
        self._pipe = sck
        self._buf = BytesIO()
        self._updates_pending = 0

    def send_message(self, msg, flush=True):
        """
        Send a message of the given type with the given fields.
        Optionally, flush the data to the socket.

        This method will flush the buffer if it grows too large in any
        case.

        :param msg_type: one of the MSG_TYPE_* constants.
        :param dict fields: dict mapping MSG_KEY_* constants to values.
        :param flush: True to force the data to be written immediately.
        """
        _log.debug("Sending message: %s", msg)
        data = msg.SerializeToString()
        length = len(data)
        serialized_length = struct.pack("<Q", length)

        self._buf.write(serialized_length)
        self._buf.write(data)
        if flush:
            self.flush()
        else:
            self._maybe_flush()

    def _maybe_flush(self):
        self._updates_pending += 1
        if self._updates_pending > FLUSH_THRESHOLD:
            self.flush()

    def flush(self):
        """
        Flushes the write buffer to the socket immediately.
        """
        _log.debug("Flushing the buffer to the socket")
        buf_contents = self._buf.getvalue()
        if buf_contents:
            try:
                self._pipe.write(buf_contents)
                self._pipe.flush()
            except OSError as e:
                _log.exception("Failed to write to pipe")
                raise WriteFailed(e)
            self._buf = BytesIO()
        self._updates_pending = 0


class MessageReader(object):
    def __init__(self, pipe):
        self._pipe = pipe
        self._current_msg_type = None
        self._buf = ""

    def new_messages(self):
        """
        Generator: generates 0 or more tuples containing message type and
        message body (as a dict).

        May generate 0 events in certain conditions even if there are
        events available.  (If the read returns EAGAIN, for example.)

        :raises SocketClosed if the socket is closed.
        :raises socket.error if an unexpected socket error occurs.
        """
        while len(self._buf) < 8:
            _log.debug("Reading length header...")
            self._read(8 - len(self._buf))

        (length,) = struct.unpack("<Q", self._buf)
        _log.debug("Read message length: %s", length)

        self._buf = ""
        while len(self._buf) < length:
            _log.debug("Reading data. Have: %s, need: %s", len(self._buf),
                       length)
            self._read(length - len(self._buf))

        envelope = felixbackend_pb2.ToDataplane()
        envelope.ParseFromString(self._buf)
        self._buf = ""
        _log.debug("Received message: envelope = %s", envelope)
        message_type = envelope.WhichOneof("payload")
        payload = getattr(envelope, message_type)
        _log.debug("Payload: %s", payload)
        yield message_type, payload, envelope.sequence_number

    def _read(self, num_bytes):
        try:
            data = self._pipe.read(num_bytes)
            _log.debug("Read %s bytes", len(data))
        except OSError as e:
            if e.errno in (errno.EAGAIN,
                           errno.EWOULDBLOCK,
                           errno.EINTR):
                _log.debug("Retryable error on read.")
                return
            else:
                _log.error("Failed to read from pipe: %r", e)
                raise
        if not data:
            # No data indicates an orderly shutdown of the pipe,
            # which shouldn't happen.
            _log.error("Socket closed by other end.")
            raise SocketClosed()
        self._buf += data
