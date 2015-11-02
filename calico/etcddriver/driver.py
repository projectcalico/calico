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
calico.etcddriver.driver
~~~~~~~~~~~~~~~~~~~~~~~~

Contains the logic for the etcd driver process, which monitors etcd for
changes and sends them to Felix over a unix socket.

The driver is responsible for

* loading the configuration from etcd at start-of-day (Felix needs this before
  it can receive further updates)
* handling the initial load of data from etcd
* watching etcd for changes
* doing the above in parallel and merging the result into a consistent
  sequence of events
* resolving directory deletions so that if a directory is deleted, it tells
  Felix about all the individual keys that are deleted.
"""

from httplib import HTTPException
import logging
from Queue import Queue, Empty
import socket
try:
    # simplejson is a faster drop-in replacement.
    import simplejson as json
except ImportError:
    import json
from threading import Thread, Event
import time
from urlparse import urlparse

from ijson.backends import yajl2 as ijson
import urllib3
from urllib3 import HTTPConnectionPool
from urllib3.exceptions import ReadTimeoutError

from calico.etcddriver.protocol import (
    MessageReader, MSG_TYPE_INIT, MSG_TYPE_CONFIG, MSG_TYPE_RESYNC,
    MSG_KEY_ETCD_URL, MSG_KEY_HOSTNAME, MSG_KEY_LOG_FILE, MSG_KEY_SEV_FILE,
    MSG_KEY_SEV_SYSLOG, MSG_KEY_SEV_SCREEN, STATUS_WAIT_FOR_READY,
    STATUS_RESYNC, STATUS_IN_SYNC, MSG_TYPE_CONFIG_LOADED,
    MSG_KEY_GLOBAL_CONFIG, MSG_KEY_HOST_CONFIG, MSG_TYPE_UPDATE, MSG_KEY_KEY,
    MSG_KEY_VALUE, MessageWriter, MSG_TYPE_STATUS, MSG_KEY_STATUS,
    WriteFailed)
from calico.etcdutils import ACTION_MAPPING
from calico.common import complete_logging
from calico.monotonic import monotonic_time
from calico.datamodel_v1 import (
    READY_KEY, CONFIG_DIR, dir_for_per_host_config, VERSION_DIR
)
from calico.etcddriver.hwm import HighWaterTracker

_log = logging.getLogger(__name__)


class EtcdDriver(object):
    def __init__(self, felix_sck):
        # Wrap the socket with our protocol reader/writer objects.
        self._msg_reader = MessageReader(felix_sck)
        self._msg_writer = MessageWriter(felix_sck)

        # Global stop event used to signal to all threads to stop.
        self._stop_event = Event()

        # Threads to own the connection from/to Felix.  The resync thread
        # is responsible for doing resyncs and merging updates from the
        # watcher thread (which it manages).
        self._reader_thread = Thread(target=self._read_from_socket,
                                     name="reader-thread")
        self._resync_thread = Thread(target=self._resync_and_merge,
                                     name="resync-thread")
        self._watcher_thread = None  # Created on demand
        self._watcher_stop_event = None

        # High-water mark cache.  Owned by resync thread.
        self._hwms = HighWaterTracker()
        self._first_resync = True
        self._resync_http_pool = None
        self._cluster_id = None

        # Set by the reader thread once the init message has been received
        # from Felix.
        self._init_received = Event()
        # Initial config, received in the init message.
        self._etcd_base_url = None
        self._hostname = None
        # Set by the reader thread once the logging config has been received
        # from Felix.  Triggers the first resync.
        self._config_received = Event()

        # Flag to request a resync.  Set by the reader thread, polled by the
        # resync and merge thread.
        self._resync_requested = False

    def start(self):
        """Starts the driver's reader and resync threads."""
        self._reader_thread.start()
        self._resync_thread.start()

    def join(self, timeout=None):
        """
        Blocks until the driver stops or until timeout expires.

        :returns True if the driver stopped, False on timeout.
        """
        return self._stop_event.wait(timeout=timeout)

    def stop(self):
        _log.info("Stopping driver")
        self._stop_event.set()

    def _read_from_socket(self):
        """
        Thread: reader thread.  Reads messages from Felix.

        So far, this means reading the init message and then dealing
        with the exception if Felix dies.
        """
        try:
            while not self._stop_event.is_set():
                for msg_type, msg in self._msg_reader.new_messages():
                    if msg_type == MSG_TYPE_INIT:
                        self._handle_init(msg)
                    elif msg_type == MSG_TYPE_CONFIG:
                        self._handle_config(msg)
                    elif msg_type == MSG_TYPE_RESYNC:
                        self._handle_resync(msg)
                    else:
                        _log.warning("Unexpected message from Felix")
        finally:
            _log.error("Reader thread shutting down, triggering stop event")
            self.stop()

    def _handle_init(self, msg):
        """
        Handle init message from Felix.

        Called from the reader thread.
        """
        # OK to dump the msg, it's a one-off.
        _log.info("Got init message from Felix %s", msg)
        self._etcd_base_url = msg[MSG_KEY_ETCD_URL].rstrip("/")
        self._etcd_url_parts = urlparse(self._etcd_base_url)
        self._hostname = msg[MSG_KEY_HOSTNAME]
        self._init_received.set()

    def _handle_config(self, msg):
        """
        Handle config message from Felix.

        Called from the reader thread.
        """
        complete_logging(msg[MSG_KEY_LOG_FILE],
                         file_level=msg[MSG_KEY_SEV_FILE],
                         syslog_level=msg[MSG_KEY_SEV_SYSLOG],
                         stream_level=msg[MSG_KEY_SEV_SCREEN],
                         gevent_in_use=False)
        self._config_received.set()
        _log.info("Received config from Felix: %s", msg)

    def _handle_resync(self, msg):
        _log.info("Got resync message from felix: %s", msg)
        self._resync_requested = True

    def _resync_and_merge(self):
        """
        Thread: Resync-and-merge thread.  Loads the etcd snapshot, merges
        it with the events going on concurrently and sends the event stream
        to Felix.
        """
        _log.info("Resync thread started, waiting for config to be loaded...")
        self._init_received.wait()
        _log.info("Config loaded; continuing.")

        while not self._stop_event.is_set():
            loop_start = monotonic_time()
            # Only has an effect if it's running.  Note: stopping the watcher
            # is async (and may take a long time for its connection to time
            # out).
            self._stop_watcher()
            try:
                # Start with a fresh HTTP pool just in case it got into a bad
                # state.
                self._resync_http_pool = self.get_etcd_connection()
                # Before we get to the snapshot, Felix needs the configuration.
                self._send_status(STATUS_WAIT_FOR_READY)
                self._wait_for_ready()
                self._preload_config()
                # Now (on the first run through) wait for Felix to process the
                # config.
                self._config_received.wait()
                # Kick off the snapshot request as far as the headers.
                self._send_status(STATUS_RESYNC)
                resp, snapshot_index = self._start_snapshot_request()
                # Before reading from the snapshot, start the watcher thread.
                self._start_watcher(snapshot_index)
                # Incrementally process the snapshot, merging in events from
                # the queue.
                self._process_snapshot_and_events(resp, snapshot_index)
                # We're now in-sync.  Tell Felix.
                self._send_status(STATUS_IN_SYNC)
                self._process_events_only()
            except WriteFailed:
                _log.exception("Write to Felix failed; shutting down.")
                self.stop()
            except WatcherDied:
                _log.warning("Watcher died; resyncing.")
            except (urllib3.exceptions.HTTPError,
                    HTTPException,
                    socket.error) as e:
                _log.error("Request to etcd failed: %r; resyncing.", e)
                if monotonic_time() - loop_start < 1:
                    _log.debug("May be tight looping, sleeping...")
                    time.sleep(1)
            except:
                _log.exception("Unexpected exception; shutting down.")
                self.stop()
                raise
            finally:
                self._first_resync = False
                self._resync_requested = False

    def _wait_for_ready(self):
        """
        Waits for the global Ready flag to be set.  We don't load the first
        snapshot until that flag is set.
        """
        ready = False
        while not ready:
            # Read failure here will be handled by outer loop.
            resp = self._resync_http_pool.request(
                "GET",
                self._etcd_base_url + "/v2/keys" + READY_KEY,
                timeout=5,
                preload_content=True
            )
            self._check_cluster_id(resp)
            try:
                etcd_resp = json.loads(resp.data)
                ready = etcd_resp["node"]["value"] == "true"
            except (TypeError, ValueError, KeyError) as e:
                _log.warning("Failed to load Ready flag from etcd: %r", e)
                time.sleep(1)

    def _preload_config(self):
        """
        Loads the config for Felix from etcd and sends it to Felix as a
        dedicated message.
        """
        _log.info("Pre-loading config.")
        global_config = self._load_config(CONFIG_DIR)
        host_config_dir = dir_for_per_host_config(self._hostname)
        host_config = self._load_config(host_config_dir)
        self._msg_writer.send_message(
            MSG_TYPE_CONFIG_LOADED,
            {
                MSG_KEY_GLOBAL_CONFIG: global_config,
                MSG_KEY_HOST_CONFIG: host_config,
            }
        )
        _log.info("Sent config message to Felix.")

    def _load_config(self, config_dir):
        """
        Loads all the config keys from the given etcd directory.
        """
        # Read failure here will be handled by outer loop.
        resp = self._resync_http_pool.request(
            "GET",
            self._etcd_base_url + "/v2/keys" + config_dir,
            fields={
                "recursive": "true",
            },
            timeout=5,
            preload_content=True
        )
        self._check_cluster_id(resp)
        try:
            etcd_resp = json.loads(resp.data)
            if etcd_resp.get("errorCode") == 100:  # Not found
                _log.info("No config found at %s", config_dir)
                return {}
            config_nodes = etcd_resp["node"]["nodes"]
            config = {}
            for node in config_nodes:
                if "key" in node and "value" in node:
                    config[node["key"].split("/")[-1]] = node["value"]
        except (TypeError, ValueError, KeyError) as e:
            _log.warning("Failed to load config from etcd: %r,"
                         "data %r", e, resp.data)
            raise ResyncRequired(e)
        return config

    def _start_snapshot_request(self):
        """
        Issues the HTTP request to etcd to load the snapshot but only
        loads it as far as the headers.
        :return: tuple of response and snapshot's etcd index.
        :raises HTTPException
        :raises HTTPError
        :raises socket.error
        :raises DriverShutdown if the etcd cluster ID changes.
        """
        _log.info("Loading snapshot headers...")
        resp = self._resync_http_pool.request(
            "GET",
            self._etcd_base_url + "/v2/keys/calico/v1",
            fields={"recursive": "true"},
            timeout=120,
            preload_content=False
        )
        snapshot_index = int(resp.getheader("x-etcd-index", 1))
        self._check_cluster_id(resp)
        if not self._cluster_id:
            _log.error("Snapshot response did not contain cluster ID, "
                       "resyncing to avoid inconsistency")
            raise ResyncRequired()
        _log.info("Got snapshot headers, snapshot index is %s; starting "
                  "watcher...", snapshot_index)
        return resp, snapshot_index

    def _check_cluster_id(self, resp):
        """
        Checks the x-etcd-cluster-id header for changes since the last call.

        On change, stops the driver and raises DriverShutdown.
        :param resp: urllib3 Response object.
        """
        cluster_id = resp.getheader("x-etcd-cluster-id")
        if cluster_id:
            if self._cluster_id:
                if self._cluster_id != cluster_id:
                    _log.error("etcd cluster ID changed from %s to %s.  "
                               "This invalidates our local state so Felix "
                               "must restart.", self._cluster_id, cluster_id)
                    self.stop()
                    raise DriverShutdown()
            else:
                _log.info("First successful read from etcd.  Cluster ID: %s",
                          cluster_id)
                self._cluster_id = cluster_id
        else:
            # Missing on certain error responses.
            _log.warning("etcd response was missing cluster ID header, unable "
                         "to check cluster ID")

    def _process_snapshot_and_events(self, etcd_response, snapshot_index):
        """
        Processes the etcd snapshot response incrementally while, concurrently,
        merging in updates from the watcher thread.
        :param etcd_response: file-like object representing the etcd response.
        :param snapshot_index: the etcd index of the response.
        """
        self._hwms.start_tracking_deletions()
        for snap_mod, snap_key, snap_value in parse_snapshot(etcd_response):
            old_hwm = self._hwms.update_hwm(snap_key, snapshot_index)
            if snap_mod > old_hwm:
                # This specific key's HWM is newer than the previous
                # version we've seen, send an update.
                self._on_key_updated(snap_key, snap_value)

            # After we process an update from the snapshot, process
            # several updates from the watcher queue (if there are
            # any).  We limit the number to ensure that we always
            # finish the snapshot eventually.
            for _ in xrange(100):
                if not self._watcher_queue or self._watcher_queue.empty():
                    # Don't block on the watcher if there's nothing to do.
                    break
                try:
                    self._handle_next_watcher_event()
                except WatcherDied:
                    # Continue processing to ensure that we make
                    # progress.
                    _log.warning("Watcher thread died, continuing "
                                 "with snapshot")
                    break
            if self._stop_event.is_set():
                _log.error("Stop event set, exiting")
                raise DriverShutdown()
        # Save occupancy by throwing away the deletion tracking metadata.
        self._hwms.stop_tracking_deletions()
        # Scan for deletions that happened before the snapshot.  We effectively
        # mark all the values seen in the current snapshot above and then this
        # sweeps the ones we didn't touch.
        self._scan_for_deletions(snapshot_index)

    def _process_events_only(self):
        """
        Loops processing the event stream from the watcher thread and feeding
        it to etcd.
        :raises WatcherDied:
        :raises FelixWriteFailed:
        :raises DriverShutdown:
        """
        _log.info("In sync, now processing events only...")
        while not self._stop_event.is_set():
            self._handle_next_watcher_event()
            self._msg_writer.flush()

    def _scan_for_deletions(self, snapshot_index):
        """
        Scans the high-water mark cache for keys that haven't been seen since
        before the snapshot_index and deletes them.
        """
        if self._first_resync:
            _log.info("First resync: skipping deletion scan")
            return
        # Find any keys that were deleted while we were unable to
        # keep up with etcd.
        _log.info("Scanning for deletions")
        deleted_keys = self._hwms.remove_old_keys(snapshot_index)
        for ev_key in deleted_keys:
            # We didn't see the value during the snapshot or via
            # the event queue.  It must have been deleted.
            self._on_key_updated(ev_key, None)
        _log.info("Found %d deleted keys", len(deleted_keys))

    def _handle_next_watcher_event(self):
        """
        Waits for an event on the watcher queue and sends it to Felix.
        :raises DriverShutdown:
        :raises WatcherDied:
        :raises FelixWriteFailed:
        :raises ResyncRequested:
        """
        if self._watcher_queue is None:
            raise WatcherDied()
        while not self._stop_event.is_set():
            if self._resync_requested and self._watcher_stop_event:
                _log.info("Resync requested, triggering one.")
                self._watcher_stop_event.set()
                raise WatcherDied()
            try:
                event = self._watcher_queue.get(timeout=1)
            except Empty:
                pass
            else:
                break
        else:
            raise DriverShutdown()
        if event is None:
            self._watcher_queue = None
            raise WatcherDied()
        ev_mod, ev_key, ev_val = event
        if ev_val is not None:
            # Normal update.
            self._hwms.update_hwm(ev_key, ev_mod)
            self._on_key_updated(ev_key, ev_val)
        else:
            # Deletion.
            deleted_keys = self._hwms.store_deletion(ev_key,
                                                     ev_mod)
            for child_key in deleted_keys:
                self._on_key_updated(child_key, None)

    def _start_watcher(self, snapshot_index):
        """
        Starts the watcher thread, creating its queue and event in the process.
        """
        self._watcher_queue = Queue()
        self._watcher_stop_event = Event()
        # Note: we pass the queue and event in as arguments so that the thread
        # will always access the current queue and event.  If it used self.xyz
        # to access them then an old thread that is shutting down could access
        # a new queue.
        self._watcher_thread = Thread(target=self.watch_etcd,
                                      args=(snapshot_index + 1,
                                            self._watcher_queue,
                                            self._watcher_stop_event),
                                      name="watcher-thread")
        self._watcher_thread.daemon = True
        self._watcher_thread.start()

    def _stop_watcher(self):
        """
        If it's running, signals the watcher thread to stop.
        """
        if self._watcher_stop_event is not None:
            _log.info("Watcher was running before, stopping it")
            self._watcher_stop_event.set()
            self._watcher_stop_event = None

    def get_etcd_connection(self):
        return HTTPConnectionPool(self._etcd_url_parts.hostname,
                                  self._etcd_url_parts.port or 2379,
                                  maxsize=1)

    def _on_key_updated(self, key, value):
        """
        Called when we've worked out that a key  ahs been updated/deleted.

        Deos any local processing and sends the update to Felix.
        :param str key: The etcd key that has changed.
        :param str|NoneType value: the new value of the key (None indicates
               deletion).
        """
        if key == READY_KEY and value != "true":
            _log.warning("Ready key no longer set to true, triggering resync.")
            raise ResyncRequired()
        self._msg_writer.send_message(
            MSG_TYPE_UPDATE,
            {
                MSG_KEY_KEY: key,
                MSG_KEY_VALUE: value,
            },
            flush=False
        )

    def _send_status(self, status):
        """
        Queues the given status to felix as a status message.
        """
        _log.info("Sending status to Felix: %s", status)
        self._msg_writer.send_message(
            MSG_TYPE_STATUS,
            {
                MSG_KEY_STATUS: status,
            }
        )

    def watch_etcd(self, next_index, event_queue, stop_event):
        """
        Thread: etcd watcher thread.  Watches etcd for changes and
        sends them over the queue to the resync thread, which owns
        the socket to Felix.

        Dies if it receives an error from etcd.

        Note: it is important that we pass the index, queue and event
        as parameters to ensure that each watcher thread only touches
        the versions of those values that were created for it as
        opposed to a later-created watcher thread.

        :param next_index: The etcd index to start watching from.
        :param event_queue: Queue of updates back to the resync thread.
        :param stop_event: Event used to stop this thread when it is no
               longer needed.
        """
        _log.info("Watcher thread started")
        http = None
        try:
            while not stop_event.is_set():
                if not http:
                    _log.info("No HTTP pool, creating one...")
                    http = HTTPConnectionPool("localhost", 4001, maxsize=1)
                try:
                    _log.debug("Waiting on etcd index %s", next_index)
                    resp = http.request(
                        "GET",
                        "http://localhost:4001/v2/keys/calico/v1",
                        fields={"recursive": "true",
                                "wait": "true",
                                "waitIndex": next_index},
                        timeout=90,
                        # Don't pre-load so we can check the cluster ID before
                        # we wait for the body.
                        preload_content=False,
                    )
                    if resp.status != 200:
                        _log.warning("etcd watch returned bad HTTP status: %s",
                                     resp.status)
                    self._check_cluster_id(resp)
                    resp_body = resp.data  # Force read inside try block.
                except ReadTimeoutError:
                    _log.debug("Watch read timed out, restarting watch at "
                               "index %s", next_index)
                    # Workaround urllib3 bug #718.  After a ReadTimeout, the
                    # connection is incorrectly recycled.
                    http = None
                    continue
                try:
                    etcd_resp = json.loads(resp_body)
                    if "errorCode" in etcd_resp:
                        _log.error("Error from etcd: %s; triggering a resync.",
                                   etcd_resp)
                        break
                    node = etcd_resp["node"]
                    key = node["key"]
                    action = ACTION_MAPPING[etcd_resp["action"]]
                    is_dir = node.get("dir", False)
                    value = node.get("value")
                    if is_dir:
                        if action != "delete":
                            # Just ignore sets to directories, we only track
                            # leaves.
                            _log.debug("Skipping non-delete to dir %s", key)
                            continue
                        else:
                            if key == VERSION_DIR:
                                # Special case: if the whole keyspace is
                                # deleted, that implies the ready flag is gone
                                # too; resync rather than generating deletes
                                # for every key.
                                _log.warning("Whole %s deleted, resyncing",
                                             VERSION_DIR)
                                break
                    modified_index = node["modifiedIndex"]
                except (KeyError, TypeError, ValueError):
                    _log.exception("Unexpected format for etcd response: %r;"
                                   "triggering a resync.",
                                   resp_body)
                    break
                else:
                    event_queue.put((modified_index, key, value))
                    next_index = modified_index + 1
        except:
            _log.exception("Exception finishing watcher thread.")
            raise
        finally:
            # Signal to the resync thread that we've exited.
            _log.info("Watcher thread finished. Signalling to resync thread.")
            event_queue.put(None)


def parse_snapshot(resp):
    """
    Generator: iteratively parses the response to the etcd snapshot.

    Generates tuples of the form (modifiedIndex, key, value) for each
    leaf encountered in the snapshot.

    :raises ResyncRequired if the snapshot contains an error response.
    """
    if resp.status != 200:
        raise ResyncRequired("Read from etcd failed.  HTTP status code %s",
                             resp.status)
    parser = ijson.parse(resp)  # urllib3 response is file-like.
    stack = []
    frame = Node()
    for prefix, event, value in parser:
        if event == "start_map":
            stack.append(frame)
            frame = Node()
        elif event == "map_key":
            frame.current_key = value
        elif event in ("string", "number"):
            if frame.done:
                continue
            if frame.current_key == "modifiedIndex":
                frame.modifiedIndex = value
            elif frame.current_key == "key":
                frame.key = value
            elif frame.current_key == "value":
                frame.value = value
            elif frame.current_key == "errorCode":
                raise ResyncRequired("Error from etcd, etcd error code %s",
                                     value)
            if (frame.key is not None and
                    frame.value is not None and
                    frame.modifiedIndex is not None):
                frame.done = True
                yield frame.modifiedIndex, frame.key, frame.value
            frame.current_key = None
        elif event == "end_map":
            frame = stack.pop(-1)


class Node(object):
    __slots__ = ("key", "value", "action", "current_key", "modifiedIndex",
                 "done")

    def __init__(self):
        self.modifiedIndex = None
        self.key = None
        self.value = None
        self.action = None
        self.current_key = None
        self.done = False


class WatcherDied(Exception):
    pass


class DriverShutdown(Exception):
    pass


class ResyncRequired(Exception):
    pass
