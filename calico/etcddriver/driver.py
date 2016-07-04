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
import logging
import random
import socket
from Queue import Queue, Empty
from functools import partial

from ijson import JSONError

from calico.stats import AggregateStat, RateStat

try:
    # simplejson is a faster drop-in replacement.
    import simplejson as json
except ImportError:
    import json
from threading import Thread, Event, Lock
import time
from urlparse import urlparse

try:
    from ijson.backends import yajl2 as ijson
except (ImportError, AttributeError): # pragma: no cover
    # Fall back on Python-native implementation.
    # Added for RH6.5 compatibility where yajl is not available.
    from ijson.backends import python as ijson  # pragma: no cover
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool
import urllib3.exceptions
import httplib
from prometheus_client import Counter, Histogram, Gauge, start_http_server

from calico.etcddriver.protocol import (
    MessageReader, MSG_TYPE_INIT, MSG_TYPE_CONFIG, MSG_TYPE_RESYNC,
    MSG_KEY_ETCD_URLS, MSG_KEY_HOSTNAME, MSG_KEY_LOG_FILE, MSG_KEY_SEV_FILE,
    MSG_KEY_SEV_SYSLOG, MSG_KEY_SEV_SCREEN, STATUS_WAIT_FOR_READY,
    STATUS_RESYNC, STATUS_IN_SYNC, MSG_TYPE_CONFIG_LOADED,
    MSG_KEY_GLOBAL_CONFIG, MSG_KEY_HOST_CONFIG, MSG_TYPE_UPDATE, MSG_KEY_KEY,
    MSG_KEY_VALUE, MessageWriter, MSG_TYPE_STATUS, MSG_KEY_STATUS,
    MSG_KEY_KEY_FILE, MSG_KEY_CERT_FILE, MSG_KEY_CA_FILE, WriteFailed,
    SocketClosed, MSG_KEY_PROM_PORT)
from calico.etcdutils import ACTION_MAPPING
from calico.common import complete_logging
from calico.monotonic import monotonic_time
from calico.datamodel_v1 import (
    READY_KEY, CONFIG_DIR, dir_for_per_host_config, VERSION_DIR,
    ROOT_DIR)
from calico.etcddriver.hwm import HighWaterTracker

_log = logging.getLogger(__name__)


# Bound on the size of the queue between watcher and resync thread.  In
# general, Felix and the resync thread process much more quickly than the
# watcher can read from etcd so this is defensive.
WATCHER_QUEUE_SIZE = 20000

# Threshold in seconds for detecting watcher tight looping on exception.
REQ_TIGHT_LOOP_THRESH = 0.2
# How often to log stats.
STATS_LOG_INTERVAL = 30

RESYNCS_STARTED = Counter("felix_resyncs_started",
                          "Number of resync attempts.")
RESYNCS_COMPLETED = Counter("felix_resyncs_completed",
                            "Number of resyncs completed.")
RESYNC_TIME = Histogram("felix_time_in_resync",
                        "duration of successful resyncs.")
ETCD_INDEX_CLEARED = Counter("felix_etcd_index_cleared",
                             "Number of etcd index cleared errors, "
                             "triggering resyncs.")
ETCD_OTHER_ERROR = Counter("felix_etcd_other_error",
                           "Number of unexpected etcd errors, triggering "
                           "resync.")
RESYNC_STATE = Gauge("felix_resync_state",
                     "1=wait-for-ready; 2=in-resync; 3=in-sync; "
                     "4=in-resync-watcher-dead")
STATUS_TO_GUAGE_VALUE = {
    STATUS_WAIT_FOR_READY: 1,
    STATUS_RESYNC: 2,
    STATUS_IN_SYNC: 3
}
RESYNC_STATE_WATCHER_DIED_DURING_RESYNC = 4


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
        self._reader_thread.daemon = True
        self._resync_thread = Thread(target=self._resync_and_merge,
                                     name="resync-thread")
        self._resync_thread.daemon = True
        self._watcher_thread = None  # Created on demand
        self._watcher_stop_event = None
        self._watcher_start_index = None

        # High-water mark cache.  Owned by resync thread.
        self._hwms = HighWaterTracker()
        self._first_resync = True
        self._resync_http_pool = None
        self._cluster_id = None

        # Resync thread stats.
        self._snap_keys_processed = RateStat("snapshot keys processed")
        self._event_keys_processed = RateStat("event keys processed")
        self._felix_updates_sent = RateStat("felix updates sent")
        self._resync_stats = [
            self._snap_keys_processed,
            self._event_keys_processed,
            self._felix_updates_sent,
        ]
        self._last_resync_stat_log_time = monotonic_time()

        # Set by the reader thread once the init message has been received
        # from Felix.
        self._init_received = Event()
        # Initial config, received in the init message.
        self._etcd_base_url = None
        self._etcd_other_urls = []
        # Lock for the etcd url fields: this is the only lock, and no thread
        # ever recursively acquires it, so it cannot deadlock.  Must be locked
        # to access the _etcd_base_url and _etcd_other_urls fields (after they
        # are initialized).
        self._etcd_url_lock = Lock()
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
        self._stop_event.wait(timeout=timeout)
        stopped = self._stop_event.is_set()
        if stopped:
            self._resync_thread.join(timeout=timeout)
            resync_alive = self._resync_thread.is_alive()
            stopped &= not resync_alive
            _log.debug("Resync thread alive: %s", resync_alive)

            self._reader_thread.join(timeout=timeout)
            reader_alive = self._reader_thread.is_alive()
            stopped &= not reader_alive
            _log.debug("Reader thread alive: %s", reader_alive)

            try:
                self._watcher_thread.join(timeout=timeout)
                watcher_alive = self._watcher_thread.is_alive()
                stopped &= not watcher_alive
                _log.debug("Watcher thread alive: %s", watcher_alive)
            except AttributeError:
                pass
        return stopped

    def stop(self):
        _log.info("Stopping driver")
        self._stop_event.set()

    def _read_from_socket(self):
        """
        Thread: reader thread.  Reads messages from Felix and fans them out.
        """
        try:
            while not self._stop_event.is_set():
                for msg_type, msg in self._msg_reader.new_messages(timeout=1):
                    if msg_type == MSG_TYPE_INIT:
                        # Init message, received at start of day.
                        self._handle_init(msg)
                    elif msg_type == MSG_TYPE_CONFIG:
                        # Config message, expected after we send the raw
                        # config to Felix.
                        self._handle_config(msg)
                    elif msg_type == MSG_TYPE_RESYNC:
                        # Request to do a resync.
                        self._handle_resync(msg)
                    else:
                        _log.error("Unexpected message from Felix: %s", msg)
                        raise RuntimeError("Unexpected message from Felix")
        except SocketClosed:
            _log.warning("Felix closed its socket.  The driver must exit.")
        except DriverShutdown:
            _log.warning("Reader thread stopping due to driver shutdown.")
        finally:
            _log.info("Reader thread shutting down, triggering stop event")
            self.stop()

    def _handle_init(self, msg):
        """
        Handle init message from Felix.

        Called from the reader thread.
        """
        # OK to dump the msg, it's a one-off.
        _log.info("Got init message from Felix %s", msg)
        etcd_urls = msg[MSG_KEY_ETCD_URLS]
        # Shuffle the etcd URLs so that each client connects to different
        # cluster nodes.
        random.shuffle(etcd_urls)
        self._etcd_base_url = etcd_urls[0].rstrip("/")
        self._etcd_url_parts = urlparse(self._etcd_base_url)
        self._etcd_other_urls = etcd_urls[1:]
        self._etcd_key_file = msg[MSG_KEY_KEY_FILE]
        self._etcd_cert_file = msg[MSG_KEY_CERT_FILE]
        self._etcd_ca_file = msg[MSG_KEY_CA_FILE]
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
        if msg[MSG_KEY_PROM_PORT]:
            _log.info("Prometheus metrics enabled, starting driver metrics"
                      "server on port %s", msg[MSG_KEY_PROM_PORT])
            start_http_server(msg[MSG_KEY_PROM_PORT])

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
            _log.info("Stop event not set, starting new resync...")
            self._reset_resync_thread_stats()
            loop_start = monotonic_time()
            try:
                # Start with a fresh HTTP pool just in case it got into a bad
                # state.
                RESYNCS_STARTED.inc()
                self._resync_http_pool = self.get_etcd_connection()
                # Before we get to the snapshot, Felix needs the configuration.
                self._send_status(STATUS_WAIT_FOR_READY)
                self._wait_for_ready()
                self._preload_config()
                # Wait for config if we have not already received it.
                self._wait_for_config()
                # Kick off the snapshot request as far as the headers.
                self._send_status(STATUS_RESYNC)
                resp, snapshot_index = self._start_snapshot_request()
                # Before reading from the snapshot, start the watcher thread.
                self._ensure_watcher_running(snapshot_index)
                # Incrementally process the snapshot, merging in events from
                # the queue.
                self._process_snapshot_and_events(resp, snapshot_index)
                # We're now in-sync.  Tell Felix.
                self._send_status(STATUS_IN_SYNC)
                # Then switch to processing events only.
                RESYNCS_COMPLETED.inc()
                time_to_resync = monotonic_time() - loop_start
                RESYNC_TIME.observe(time_to_resync)
                self._process_events_only()
            except WriteFailed:
                _log.exception("Write to Felix failed; shutting down.")
                self.stop()
            except WatcherDied:
                _log.warning("Watcher died; resyncing.")
                self._stop_watcher()  # Clean up the event
            except (urllib3.exceptions.HTTPError,
                    httplib.HTTPException,
                    socket.error) as e:
                _log.error("Request to etcd failed: %r; resyncing.", e)
                self._stop_watcher()
                self._rotate_etcd_url()  # Try a different etcd URL if possible
                if monotonic_time() - loop_start < 1:
                    _log.warning("May be tight looping, sleeping...")
                    time.sleep(1)
            except ResyncRequested:
                _log.info("Resync requested, looping to start a new resync. "
                          "Leaving watcher running if possible.")
            except ResyncRequired:
                _log.warn("Detected inconsistency requiring a full resync, "
                          "stopping watcher")
                self._stop_watcher()
            except DriverShutdown:
                _log.info("Driver shut down.")
                return
            except:
                _log.exception("Unexpected exception; shutting down.")
                self.stop()
                raise
            finally:
                self._first_resync = False
                self._resync_requested = False
        _log.info("Stop event set, exiting resync loop.")

    def _rotate_etcd_url(self):
        """
        Rotate the in use etcd URL if more than one is configured,
        """
        if len(self._etcd_other_urls) > 0:
            with self._etcd_url_lock:
                self._etcd_other_urls.append(self._etcd_base_url)
                self._etcd_base_url = self._etcd_other_urls.pop(0).rstrip("/")
                self._etcd_url_parts = urlparse(self._etcd_base_url)
                _log.info("Rotated etcd URL to: %s", self._etcd_base_url)

    def _wait_for_config(self):
        while not self._config_received.is_set():
            _log.info("Waiting for Felix to process the config...")
            self._check_stop_event()
            self._config_received.wait(1)
            _log.info("Felix sent us the config, continuing.")

    def _wait_for_ready(self):
        """
        Waits for the global Ready flag to be set.  We don't load the first
        snapshot until that flag is set.
        """
        ready = False
        while not ready and not self._stop_event.is_set():
            # Read failure here will be handled by outer loop.
            resp = self._etcd_request(self._resync_http_pool, READY_KEY)
            try:
                etcd_resp = json.loads(resp.data)
                ready = etcd_resp["node"]["value"] == "true"
                mod_idx = etcd_resp["node"]["modifiedIndex"]
            except (TypeError, ValueError, KeyError) as e:
                _log.warning("Failed to load Ready flag from etcd: %r", e)
                time.sleep(1)
            else:
                _log.info("Ready flag set to %s", etcd_resp["node"]["value"])
                self._hwms.update_hwm(READY_KEY, mod_idx)
        self._check_stop_event()

    def _check_stop_event(self):
        if self._stop_event.is_set():
            _log.info("Told to stop, raising DriverShutdown.")
            raise DriverShutdown()

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
        resp = self._etcd_request(self._resync_http_pool,
                                  config_dir, recursive=True)
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
        resp = self._etcd_request(self._resync_http_pool,
                                  VERSION_DIR,
                                  recursive=True,
                                  timeout=120,
                                  preload_content=False)
        snapshot_index = int(resp.getheader("x-etcd-index", 1))
        if not self._cluster_id:
            _log.error("Snapshot response did not contain cluster ID, "
                       "resyncing to avoid inconsistency")
            raise ResyncRequired()
        _log.info("Got snapshot headers, snapshot index is %s; starting "
                  "watcher...", snapshot_index)
        return resp, snapshot_index

    def _etcd_request(self, http_pool, key, timeout=5, wait_index=None,
                      recursive=False, preload_content=None):
        """
        Make a request to etcd on the given HTTP pool for the given key
        and check the cluster ID.

        :param timeout: Read timeout for the request.
        :param int wait_index: If set, issues a watch request.
        :param recursive: True to request a recursive GET or watch.

        :return: The urllib3 Response object.
        """
        resp = self._issue_etcd_request(
            http_pool, key, timeout, wait_index,
            recursive, preload_content
        )
        self._check_cluster_id(resp)
        return resp

    def _issue_etcd_request(self, http_pool, key, timeout=5, wait_index=None,
                            recursive=False, preload_content=None):
        fields = {}
        if recursive:
            _log.debug("Adding recursive=true to request")
            fields["recursive"] = "true"
        if wait_index is not None:
            _log.debug("Request is a watch, adding wait* headers and forcing "
                       "preload_content to False")
            fields["wait"] = "true"
            fields["waitIndex"] = wait_index
            preload_content = False
        if preload_content is None:
            preload_content = True
        resp = http_pool.request(
            "GET",
            self._calculate_url(key),
            fields=fields or None,
            timeout=timeout,
            preload_content=preload_content
        )
        return resp

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
        parse_snapshot(etcd_response,
                       callback=partial(self._handle_etcd_node,
                                        snapshot_index=snapshot_index))

        # Save occupancy by throwing away the deletion tracking metadata.
        self._hwms.stop_tracking_deletions()
        # Scan for deletions that happened before the snapshot.  We effectively
        # mark all the values seen in the current snapshot above and then this
        # sweeps the ones we didn't touch.
        self._scan_for_deletions(snapshot_index)

    def _handle_etcd_node(self, snap_mod, snap_key, snap_value,
                          snapshot_index=None):
        """
        Callback for use with parse_snapshot.  Called once for each key/value
        pair that is found.

        Handles the key/value itself and then checks for work from the
        watcher.

        :param snap_mod: Modified index of the key.
        :param snap_key: The key itself.
        :param snap_value: The value attached to the key.
        :param snapshot_index: Index of the snapshot as a whole.
        """
        assert snapshot_index is not None
        self._snap_keys_processed.store_occurence()
        old_hwm = self._hwms.update_hwm(snap_key, snapshot_index)
        if snap_mod > old_hwm:
            # This specific key's HWM is newer than the previous
            # version we've seen, send an update.
            self._on_key_updated(snap_key, snap_value)
        # After we process an update from the snapshot, process several
        # updates from the watcher queue (if there are any).  We limit the
        # number to ensure that we always finish the snapshot eventually.
        # The limit isn't too sensitive but values much lower than 100 seemed
        # to starve the watcher in testing.
        for _ in xrange(100):
            if not self._watcher_queue or self._watcher_queue.empty():
                # Don't block on the watcher if there's nothing to do.
                break
            try:
                self._handle_next_watcher_event(resync_in_progress=True)
            except WatcherDied:
                # Continue processing to ensure that we make
                # progress.
                _log.warning("Watcher thread died, continuing "
                             "with snapshot")
                RESYNC_STATE.set(RESYNC_STATE_WATCHER_DIED_DURING_RESYNC)
                break
        self._check_stop_event()
        self._maybe_log_resync_thread_stats()

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
            self._handle_next_watcher_event(resync_in_progress=False)
            self._msg_writer.flush()
        self._check_stop_event()

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

    def _handle_next_watcher_event(self, resync_in_progress):
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
            # To make sure we always make progress, only trigger a new resync
            # if we're not in the middle of one.
            if not resync_in_progress and self._resync_requested:
                _log.info("Resync requested, triggering one.")
                raise ResyncRequested()
            self._maybe_log_resync_thread_stats()
            try:
                event = self._next_watcher_event()
            except Empty:
                pass
            else:
                break
        else:
            raise DriverShutdown()
        if event is None:
            self._watcher_queue = None
            raise WatcherDied()
        self._event_keys_processed.store_occurence()
        ev_mod, ev_key, ev_val = event
        if ev_val is not None:
            # Normal update.
            self._hwms.update_hwm(ev_key, ev_mod)
            self._on_key_updated(ev_key, ev_val)
        else:
            # Deletion.  In case this is a directory deletion, we search the
            # trie for anything that is under the deleted key and send
            # individual deletions to Felix for each one.
            deleted_keys = self._hwms.store_deletion(ev_key,
                                                     ev_mod)
            for child_key in deleted_keys:
                self._on_key_updated(child_key, None)

    def _next_watcher_event(self):
        """Get the next event from the watcher queue

        This is mostly here to allow it to be hooked in the UTs.

        :raises Empty if there is no event within the timeout."""
        return self._watcher_queue.get(timeout=1)

    def _ensure_watcher_running(self, snapshot_index):
        """
        Starts a new watcher from the given snapshot index, if needed.
        """
        if (self._watcher_thread is not None and
                self._watcher_thread.is_alive() and
                self._watcher_stop_event is not None and
                not self._watcher_stop_event.is_set() and
                self._watcher_queue is not None and
                self._watcher_start_index <= snapshot_index):
            _log.info("Watcher is still alive and started from a valid index, "
                      "leaving it running")
            return

        self._watcher_start_index = snapshot_index
        self._watcher_queue = Queue(maxsize=WATCHER_QUEUE_SIZE)
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
        with self._etcd_url_lock:
            port = self._etcd_url_parts.port or 2379
            if self._etcd_url_parts.scheme == "https":
                _log.debug("Getting new HTTPS connection to %s:%s",
                           self._etcd_url_parts.hostname, port)
                pool = HTTPSConnectionPool(self._etcd_url_parts.hostname,
                                           port,
                                           key_file=self._etcd_key_file,
                                           cert_file=self._etcd_cert_file,
                                           ca_certs=self._etcd_ca_file,
                                           maxsize=1)
            else:
                _log.debug("Getting new HTTP connection to %s:%s",
                           self._etcd_url_parts.hostname, port)
                pool = HTTPConnectionPool(self._etcd_url_parts.hostname,
                                          port,
                                          maxsize=1)
            return pool

    def _on_key_updated(self, key, value):
        """
        Called when we've worked out that a key has been updated/deleted.

        Does any local processing and sends the update to Felix.
        :param str key: The etcd key that has changed.
        :param str|NoneType value: the new value of the key (None indicates
               deletion).
        """
        if key == READY_KEY and value != "true":
            # Special case: the global Ready flag has been unset, trigger a
            # resync, which will poll the Ready flag until it is set to true
            # again.
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
        self._felix_updates_sent.store_occurence()

    def _send_status(self, status):
        """
        Queues the given status to felix as a status message.
        """
        _log.info("Sending status to Felix: %s", status)
        RESYNC_STATE.set(STATUS_TO_GUAGE_VALUE.get(status, 0))
        self._msg_writer.send_message(
            MSG_TYPE_STATUS,
            {
                MSG_KEY_STATUS: status,
            }
        )

    def _calculate_url(self, etcd_key):
        with self._etcd_url_lock:
            url = self._etcd_base_url + "/v2/keys/" + etcd_key.strip("/")
        return url

    def _reset_resync_thread_stats(self):
        for stat in self._resync_stats:
            stat.reset()
        self._last_resync_stat_log_time = monotonic_time()

    def _maybe_log_resync_thread_stats(self):
        now = monotonic_time()
        if now - self._last_resync_stat_log_time > STATS_LOG_INTERVAL:
            for stat in self._resync_stats:
                _log.info("STAT: Resync thread %s", stat)
                stat.reset()
            self._last_resync_stat_log_time = now

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

        :param int next_index: The etcd index to start watching from.
        :param Queue event_queue: Queue of updates back to the resync thread.
        :param Event stop_event: Event used to stop this thread when it is no
               longer needed.
        """
        _log.info("Watcher thread started with next index %s", next_index)
        last_log_time = monotonic_time()
        req_end_time = None
        non_req_time_stat = AggregateStat("processing time", "ms")
        etcd_response_time = None
        etcd_response_time_stat = AggregateStat("etcd response time", "ms")
        stats = [etcd_response_time_stat,
                 non_req_time_stat]
        http = None
        try:
            while not self._stop_event.is_set() and not stop_event.is_set():
                if not http:
                    _log.info("No HTTP pool, creating one...")
                    http = self.get_etcd_connection()
                req_start_time = monotonic_time()
                if req_end_time is not None:
                    # Calculate the time since the end of the previous request,
                    # i.e. the time we spent processing the response.  Note:
                    # start and end are flipped because we just read the start
                    # time but we have the end time from the last loop.
                    non_req_time = req_start_time - req_end_time
                    non_req_time_stat.store_reading(non_req_time * 1000)
                _log.debug("Waiting on etcd index %s", next_index)
                try:
                    try:
                        resp = self._etcd_request(http,
                                                  VERSION_DIR,
                                                  recursive=True,
                                                  wait_index=next_index,
                                                  timeout=90)
                    finally:
                        # Make sure the time is available to both exception and
                        # mainline code paths.
                        req_end_time = monotonic_time()
                        etcd_response_time = req_end_time - req_start_time
                    if resp.status != 200:
                        _log.warning("etcd watch returned bad HTTP status to"
                                     "poll on index %s: %s", next_index,
                                     resp.status)
                    self._check_cluster_id(resp)
                    resp_body = resp.data  # Force read inside try block.
                except urllib3.exceptions.ReadTimeoutError:
                    # 100% expected when there are no events.
                    _log.debug("Watch read timed out, restarting watch at "
                               "index %s", next_index)
                    # Workaround urllib3 bug #718.  After a ReadTimeout, the
                    # connection is incorrectly recycled.
                    http = None
                    continue
                except (urllib3.exceptions.HTTPError,
                        httplib.HTTPException,
                        socket.error) as e:
                    # Not so expected but still possible to recover:  etcd
                    # being restarted, for example.
                    assert etcd_response_time is not None
                    if etcd_response_time < REQ_TIGHT_LOOP_THRESH:
                        # Failed fast, make sure we don't tight loop.
                        delay = REQ_TIGHT_LOOP_THRESH - etcd_response_time
                        _log.warning("Connection to etcd failed with %r, "
                                     "restarting watch at index %s after "
                                     "delay %.3f", e, next_index, delay)
                        time.sleep(delay)
                    else:
                        _log.warning("Connection to etcd failed with %r, "
                                     "restarting watch at index %s "
                                     "immediately", e, next_index)
                    # If available, connect to a different etcd URL in case
                    # only the previous one has failed.
                    self._rotate_etcd_url()
                    # Workaround urllib3 bug #718.  After a ReadTimeout, the
                    # connection is incorrectly recycled.
                    http = None
                    continue
                # If we get to this point, we've got an etcd response to
                # process; try to parse it.
                try:
                    etcd_resp = json.loads(resp_body)
                    if "errorCode" in etcd_resp:
                        _log.error("Error from etcd for index %s: %s; "
                                   "triggering a resync.",
                                   next_index, etcd_resp)
                        if etcd_resp["errorCode"] == 401:
                            # Index cleared
                            ETCD_INDEX_CLEARED.inc()
                        else:
                            ETCD_OTHER_ERROR.inc()
                        break
                    node = etcd_resp["node"]
                    key = node["key"]
                    action = ACTION_MAPPING[etcd_resp["action"]]
                    is_dir = node.get("dir", False)
                    value = node.get("value")
                    dir_creation = False
                    if is_dir:
                        if action == "delete":
                            if key.rstrip("/") in (VERSION_DIR, ROOT_DIR):
                                # Special case: if the whole keyspace is
                                # deleted, that implies the ready flag is gone
                                # too.  Break out of the loop to trigger a
                                # resync.  This avoids queuing up a bunch of
                                # events that would be discarded by the
                                # resync thread.
                                _log.warning("Whole %s deleted, resyncing",
                                             VERSION_DIR)
                                break
                        else:
                            # Just ignore sets to directories, we only track
                            # leaves.
                            _log.debug("Skipping non-delete to dir %s", key)
                            dir_creation = True
                    modified_index = node["modifiedIndex"]
                except (KeyError, TypeError, ValueError):
                    _log.exception("Unexpected format for etcd response to"
                                   "index %s: %r; triggering a resync.",
                                   next_index, resp_body)
                    break
                else:
                    # We successfully parsed the response, hand it off to the
                    # resync thread.  Now we know that we got a response,
                    # we record that in the stat.
                    etcd_response_time_stat.store_reading(etcd_response_time *
                                                          1000)
                    if not dir_creation:
                        # The resync thread doesn't need to know about
                        # directory creations so we skip them.  (It does need
                        # to know about deletions in order to clean up
                        # sub-keys.)
                        event_queue.put((modified_index, key, value))
                    next_index = modified_index + 1

                    # Opportunistically log stats.
                    now = monotonic_time()
                    if now - last_log_time > STATS_LOG_INTERVAL:
                        for stat in stats:
                            _log.info("STAT: Watcher %s", stat)
                            stat.reset()
                        _log.info("STAT: Watcher queue length: %s",
                                  event_queue.qsize())
                        last_log_time = now
        except DriverShutdown:
            _log.warning("Watcher thread stopping due to driver shutdown.")
        except:
            _log.exception("Exception finishing watcher thread.")
            raise
        finally:
            # Signal to the resync thread that we've exited.
            event_queue.put(None)
            # Make sure we get some stats output from the watcher.
            for stat in stats:
                _log.info("STAT: Final watcher %s", stat)
            _log.info("Watcher thread finished. Signalled to resync thread. "
                      "Was at index %s.  Queue length is %s.", next_index,
                      event_queue.qsize())


def parse_snapshot(resp, callback):
    """
    Iteratively parses the response to the etcd snapshot, calling the
    callback with each key/value pair found.

    :raises ResyncRequired if the snapshot contains an error response.
    """
    _log.debug("Parsing snapshot response...")
    if resp.status != 200:
        raise ResyncRequired("Read from etcd failed.  HTTP status code %s",
                             resp.status)
    parser = ijson.parse(resp)  # urllib3 response is file-like.

    try:
        prefix, event, value = next(parser)
        _log.debug("Read first token from response %s, %s, %s", prefix, event,
                   value)
        if event == "start_map":
            # As expected, response is a map.
            _parse_map(parser, callback)
        else:
            _log.error("Response from etcd did non contain a JSON map.")
            raise ResyncRequired("Bad response from etcd")
    except JSONError:
        _log.exception("Response from etcd containers bad JSON.")
        raise ResyncRequired("Bad JSON from etcd")


def _parse_map(parser, callback):
    """
    Searches the stream of JSON tokens for key/value pairs.

    Calls itself recursively to handle subdirectories.

    :param parser: iterator, returning JSON parse event tuples.
    :param callback: callback to call when a key/value pair is found.
    """
    # Expect a sequence of keys and values terminated by an "end_map" event.
    mod_index = None
    node_key = None
    node_value = None
    while True:
        prefix, event, value = next(parser)
        _log.debug("Parsing %s, %s, %s", prefix, event, value)
        if event == "map_key":
            map_key = value
            prefix, event, value = next(parser)
            if map_key == "modifiedIndex":
                mod_index = value
            elif map_key == "key":
                node_key = value
            elif map_key == "value":
                node_value = value
            elif map_key == "errorCode":
                raise ResyncRequired("Error from etcd, etcd error code %s",
                                     value)
            elif map_key == "nodes":
                while True:
                    prefix, event, value = next(parser)
                    if event == "start_map":
                        _parse_map(parser, callback)
                    elif event == "end_array":
                        break
                    else:
                        raise ValueError("Unexpected: %s" % event)
        else:
            assert event == "end_map", ("Unexpected JSON event %s %s %s" %
                                        (prefix, event, value))
            if (node_key is not None and
                    node_value is not None and
                    mod_index is not None):
                callback(mod_index, node_key, node_value)
            break


class WatcherDied(Exception):
    pass


class DriverShutdown(Exception):
    pass


class ResyncRequired(Exception):
    pass


class ResyncRequested(Exception):
    pass
