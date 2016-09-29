# Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

import random

import etcd
import functools
import json
import logging
import re
from socket import timeout as SocketTimeout
import time
from types import StringTypes

from urllib3.exceptions import ReadTimeoutError
from urllib3 import Timeout

from networking_calico.datamodel_v1 import READY_KEY
from networking_calico.logutils import logging_exceptions

_log = logging.getLogger(__name__)

# Since this module does long-polling, we expect read timeouts from etcd but
# urllib3 logs timeouts at warning level.  Disable that to avoid log spam.
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

# Map etcd event actions to the effects we care about.
ACTION_MAPPING = {
    "set": "set",
    "compareAndSwap": "set",
    "create": "set",
    "update": "set",

    "delete": "delete",
    "compareAndDelete": "delete",
    "expire": "delete",
}


class PathDispatcher(object):
    def __init__(self):
        self.handler_root = {}

    def register(self, path, on_set=None, on_del=None):
        _log.info("Registering path %s set=%s del=%s", path, on_set, on_del)
        parts = path.strip("/").split("/")
        node = self.handler_root
        for part in parts:
            m = re.match(r'<(.*)>', part)
            if m:
                capture_name = m.group(1)
                name, node = node.setdefault("capture", (capture_name, {}))
                assert name == capture_name, (
                    "Conflicting capture name %s vs %s" % (name, capture_name)
                )
            else:
                node = node.setdefault(part, {})
        if on_set:
            node["set"] = on_set
        if on_del:
            node["delete"] = on_del

    def handle_event(self, response):
        """handle_event

        :param EtcdResponse: A python-etcd response object for a watch.
        """
        _log.debug("etcd event %s for key %s", response.action, response.key)
        key_parts = response.key.strip("/").split("/")
        self._handle(key_parts, response, self.handler_root, {})

    def _handle(self, key_parts, response, handler_node, captures):
        while key_parts:
            next_part = key_parts.pop(0)
            if "capture" in handler_node:
                capture_name, handler_node = handler_node["capture"]
                captures[capture_name] = next_part
            elif next_part in handler_node:
                handler_node = handler_node[next_part]
            else:
                _log.debug("No matching sub-handler for %s", response.key)
                return
        # We've reached the end of the key.
        action = ACTION_MAPPING.get(response.action)
        if action in handler_node:
            _log.debug("Found handler for event %s for %s, captures: %s",
                       action, response.key, captures)
            handler_node[action](response, **captures)
        else:
            _log.debug("No handler for event %s on %s. Handler node %s.",
                       action, response.key, handler_node)


class EtcdClientOwner(object):
    """Base class for objects that own an etcd Client.

    Supports reconnecting, optionally copying the cluster ID.
    """
    def __init__(self,
                 etcd_addrs,
                 etcd_scheme="http",
                 etcd_key=None,
                 etcd_cert=None,
                 etcd_ca=None):
        """Constructor.

        :param str|list[str] etcd_addrs: Either an authority string, such as
               'localhost:1234' to connect to a single server (or proxy) or a
               list of authority strings to connect to a cluster.
        :param str etcd_scheme: "http" or "https"
        :param etcd_key: Required if using HTTPS, path to the key file.
        :param etcd_cert: Required if using HTTPS, path to the client cert
               file.
        :param etcd_ca: Required if using HTTPS, path to the CA cert.
        """
        super(EtcdClientOwner, self).__init__()
        if isinstance(etcd_addrs, basestring):
            # For back-compatibility, allow a single authority string to be
            # supplied instead of a list.
            _log.debug("Single etcd address: %s, wrapping in list.",
                       etcd_addrs)
            etcd_addrs = [etcd_addrs]
        self.etcd_hosts = []
        for addr in etcd_addrs:
            host = None
            port = None
            if ":" in addr:
                host, port = addr.split(":")
                port = int(port)
            else:
                host = addr
                port = 4001
            self.etcd_hosts.append((host, port))
        self.etcd_scheme = etcd_scheme
        self.etcd_key = etcd_key
        self.etcd_cert = etcd_cert
        self.etcd_ca = etcd_ca
        self.client = None
        self.reconnect()

    def reconnect(self, copy_cluster_id=True):
        """Reconnects the etcd client."""
        if self.client and copy_cluster_id:
            old_cluster_id = self.client.expected_cluster_id
            _log.info("(Re)connecting to etcd. Old etcd cluster ID was %s.",
                      old_cluster_id)
        else:
            _log.info("(Re)connecting to etcd. No previous cluster ID.")
            old_cluster_id = None

        key_pair = None
        if self.etcd_cert and self.etcd_key:
            key_pair = (self.etcd_cert, self.etcd_key)

        # Shuffle the list of hosts so that each client will fail over to
        # a different etcd host on failure, spreading the load.
        random.shuffle(self.etcd_hosts)

        # python-etcd requires a single etcd endpoint to be specified using the
        # host=, port= parameters, but requires a different syntax for
        # multiple (>1): host=((host, port), ...).  Allow_reconnect only makes
        # sense when multiple endpoints are available.
        if len(self.etcd_hosts) == 1:
            self.client = etcd.Client(
                host=self.etcd_hosts[0][0],
                port=self.etcd_hosts[0][1],
                protocol=self.etcd_scheme,
                cert=key_pair,
                ca_cert=self.etcd_ca,
                expected_cluster_id=old_cluster_id
            )
        else:
            self.client = etcd.Client(
                host=tuple(self.etcd_hosts),
                protocol=self.etcd_scheme,
                cert=key_pair,
                ca_cert=self.etcd_ca,
                expected_cluster_id=old_cluster_id,
                allow_reconnect=True
            )


class EtcdWatcher(EtcdClientOwner):
    """Helper class for managing an etcd watch session.

    Maintains the etcd polling index and handles expected exceptions.
    """

    def __init__(self,
                 etcd_addrs,
                 key_to_poll,
                 etcd_scheme="http",
                 etcd_key=None,
                 etcd_cert=None,
                 etcd_ca=None,
                 poll_timeout=10,
                 connect_timeout=5):
        super(EtcdWatcher, self).__init__(etcd_addrs,
                                          etcd_scheme=etcd_scheme,
                                          etcd_key=etcd_key,
                                          etcd_cert=etcd_cert,
                                          etcd_ca=etcd_ca)
        self.etcd_timeout = Timeout(connect=connect_timeout,
                                    read=poll_timeout)
        self.key_to_poll = key_to_poll
        self.next_etcd_index = None

        # Forces a resync after the current poll if set.  Safe to set from
        # another thread.  Automatically reset to False after the resync is
        # triggered.
        self.resync_after_current_poll = False

        # Tells the watcher to stop after this poll.  One-way flag.
        self._stopped = False

        self.dispatcher = PathDispatcher()

    @logging_exceptions(_log)
    def loop(self):
        _log.info("Started %s loop", self)
        while not self._stopped:
            try:
                _log.info("Reconnecting and loading snapshot from etcd...")
                self.reconnect(copy_cluster_id=False)
                self._on_pre_resync()
                try:
                    # Load initial dump from etcd.  First just get all the
                    # endpoints and profiles by id.  The response contains a
                    # generation ID allowing us to then start polling for
                    # updates without missing any.
                    initial_dump = self.load_initial_dump()
                    _log.info("Loaded snapshot from etcd cluster %s, "
                              "processing it...",
                              self.client.expected_cluster_id)
                    self._on_snapshot_loaded(initial_dump)
                    while not self._stopped:
                        # Wait for something to change.
                        response = self.wait_for_etcd_event()
                        if not self._stopped:
                            self.dispatcher.handle_event(response)
                except ResyncRequired:
                    _log.info("Polling aborted, doing resync.")
            except etcd.EtcdException as e:
                # Most likely a timeout or other error in the pre-resync;
                # start over.  These exceptions have good semantic error text
                # so the stack trace would just add log spam.
                _log.error("Unexpected IO or etcd error, triggering "
                           "resync with etcd: %r.", e)
                time.sleep(1)  # Prevent tight loop due to unexpected error.
        _log.info("%s.loop() stopped due to self.stop == True", self)

    def register_path(self, *args, **kwargs):
        self.dispatcher.register(*args, **kwargs)

    def wait_for_ready(self, retry_delay):
        _log.info("Waiting for etcd to be ready...")
        ready = False
        while not ready:
            try:
                db_ready = self.client.read(READY_KEY, timeout=10).value
            except etcd.EtcdKeyNotFound:
                _log.warn("Ready flag not present in etcd; felix will pause "
                          "updates until the orchestrator sets the flag.")
                db_ready = "false"
            except etcd.EtcdException as e:
                # Note: we don't log the
                _log.error("Failed to retrieve ready flag from etcd (%r). "
                           "Felix will not receive updates until the "
                           "connection to etcd is restored.", e)
                db_ready = "false"

            if db_ready == "true":
                _log.info("etcd is ready.")
                ready = True
            else:
                _log.info("etcd not ready.  Will retry.")
                time.sleep(retry_delay)
                continue

    def load_initial_dump(self):
        """Does a recursive get on the key and returns the result.

        As a side effect, initialises the next_etcd_index field for
        use by wait_for_etcd_event()

        :return: The etcd response object.
        """
        initial_dump = None
        while not initial_dump:
            try:
                initial_dump = self.client.read(self.key_to_poll,
                                                recursive=True)
            except etcd.EtcdKeyNotFound:
                # Avoid tight-loop if the whole directory doesn't exist yet.
                if self._stopped:
                    _log.info("Stopped: aborting load of initial dump.")
                    raise
                _log.info("Waiting for etcd directory '%s' to exist...",
                          self.key_to_poll)
                time.sleep(1)

        # The etcd_index is the high-water-mark for the snapshot, record that
        # we want to poll starting at the next index.
        self.next_etcd_index = initial_dump.etcd_index + 1
        return initial_dump

    def wait_for_etcd_event(self):
        """Polls etcd until something changes.

        Retries on read timeouts and other non-fatal errors.

        :returns: The etcd response object for the change.
        :raises ResyncRequired: If we get out of sync with etcd or hit
            a fatal error.
        """
        assert self.next_etcd_index is not None, \
            "load_initial_dump() should be called first."
        response = None
        while not response:
            if self.resync_after_current_poll:
                _log.debug("Told to resync, aborting poll.")
                self.resync_after_current_poll = False
                raise ResyncRequired()

            try:
                _log.debug("About to wait for etcd update %s",
                           self.next_etcd_index)
                response = self.client.read(self.key_to_poll,
                                            wait=True,
                                            waitIndex=self.next_etcd_index,
                                            recursive=True,
                                            timeout=self.etcd_timeout)
                _log.debug("etcd response: %r", response)
            except etcd.EtcdConnectionFailed as e:
                if isinstance(e.cause, (ReadTimeoutError, SocketTimeout)):
                    # This is expected when we're doing a poll and nothing
                    # happened. socket timeout doesn't seem to be caught by
                    # urllib3 1.7.1.  Simply reconnect.
                    _log.debug("Read from etcd timed out (%r), retrying.", e)
                    # Force a reconnect to ensure urllib3 doesn't recycle the
                    # connection.  (We were seeing this with urllib3 1.7.1.)
                    self.reconnect()
                else:
                    # We don't log out the stack trace here because it can
                    # spam the logs heavily if the requests keep failing.
                    # The errors are very descriptive anyway.
                    _log.warning("Connection to etcd failed: %r.", e)
                    # Limit our retry rate in case etcd is down.
                    time.sleep(1)
                    self.reconnect()
            except (etcd.EtcdClusterIdChanged,
                    etcd.EtcdEventIndexCleared) as e:
                _log.warning("Out of sync with etcd (%r).  Reconnecting "
                             "for full sync.", e)
                raise ResyncRequired()
            except etcd.EtcdException as e:
                # Assume any other errors are fatal to our poll and
                # do a full resync.
                _log.exception("Unknown etcd error %r; doing resync.",
                               e.message)
                # Limit our retry rate in case etcd is down.
                time.sleep(1)
                self.reconnect()
                raise ResyncRequired()
            except Exception:
                _log.exception("Unexpected exception during etcd poll")
                raise

        # Since we're polling on a subtree, we can't just increment
        # the index, we have to look at the modifiedIndex to spot
        # if we've skipped a lot of updates.
        self.next_etcd_index = max(self.next_etcd_index,
                                   response.modifiedIndex) + 1
        return response

    def stop(self):
        self._stopped = True

    def _on_pre_resync(self):
        """Abstract:

        Called before the initial dump is loaded and passed to
        _on_snapshot_loaded().
        """
        pass

    def _on_snapshot_loaded(self, etcd_snapshot_response):
        """Abstract:

        Called once a snapshot has been loaded, replaces all previous
        state.

        Responsible for applying the snapshot.
        :param etcd_snapshot_response: Etcd response holding a complete dump.
        """
        pass


class ResyncRequired(Exception):
    pass


def intern_dict(d, fields_to_intern=None):
    """intern_dict

    Return a copy of the input dict where all its string/unicode keys
    are interned, optionally interning some of its values too.

    Caveat: assumes that it is safe to convert the keys and interned values
    to str by calling .encode("utf8") on each string.

    :param dict[StringTypes,...] d: Input dict.
    :param set[StringTypes] fields_to_intern: set of field names whose values
        should also be interned.
    :return: new dict with interned keys/values.
    """
    fields_to_intern = fields_to_intern or set()
    out = {}
    for k, v in d.iteritems():
        # We can't intern unicode strings, as returned by etcd but all our
        # keys should be ASCII anyway.  Use the utf8 encoding just in case.
        k = intern(k.encode("utf8"))
        if k in fields_to_intern:
            if isinstance(v, StringTypes):
                v = intern(v.encode("utf8"))
            elif isinstance(v, list):
                v = intern_list(v)
        out[k] = v
    return out


def intern_list(l):
    """intern_list

    Returns a new list with interned versions of the input list's contents.

    Non-strings are copied to the new list verbatim.  Returned strings are
    encoded using .encode("utf8").
    """
    out = []
    for item in l:
        if isinstance(item, StringTypes):
            item = intern(item.encode("utf8"))
        out.append(item)
    return out


# Intern JSON keys as we load them to reduce occupancy.
FIELDS_TO_INTERN = set([
    # Endpoint dicts.  It doesn't seem worth interning items like the MAC
    # address or TAP name, which are rarely (if ever) shared.
    "profile_id",
    "profile_ids",
    "state",
    "ipv4_gateway",
    "ipv6_gateway",

    # Rules dicts.
    "protocol",
    "!protocol",
    "src_tag",
    "!src_tag",
    "dst_tag",
    "!dst_tag",
    "action",
])
json_decoder = json.JSONDecoder(
    object_hook=functools.partial(intern_dict,
                                  fields_to_intern=FIELDS_TO_INTERN)
)


def safe_decode_json(raw_json, log_tag=None):
    try:
        return json_decoder.decode(raw_json)
    except (TypeError, ValueError):
        _log.warning("Failed to decode JSON for %s: %r.  Returning None.",
                     log_tag, raw_json)
        return None
