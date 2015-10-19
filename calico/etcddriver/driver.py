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

import sys

from Queue import Queue, Empty

from httplib import HTTPException
import socket
import string
from ijson.backends import yajl2 as ijson
import logging
import urllib3

from json import loads
from urllib3 import HTTPConnectionPool
from datrie import Trie
from threading import Thread, Event
import time
from msgpack import dumps
from urllib3.exceptions import ReadTimeoutError

_log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s][%(process)s/%(thread)d] %(name)s %(lineno)d: %(message)s')
events_processed = 0
snapshot_events = 0
watcher_events = 0
snap_skipped = 0


def report_status():
    while True:
        start_tot = events_processed
        start_snap = snapshot_events
        start_watch = watcher_events
        start_skip = snap_skipped
        time.sleep(1)
        end_tot = events_processed
        end_snap = snapshot_events
        end_watch = watcher_events
        end_skip = snap_skipped
        _log.info(
            "Events/s: %s Snap: %s, Watch %s, Skip: %s",
            end_tot - start_tot,
            end_snap - start_snap,
            end_watch - start_watch,
            end_skip - start_skip
        )


x = {u'action': u'set',
     u'node': {u'createdIndex': 2095663, u'modifiedIndex': 2095663,
               u'value': u'{"name": "tap000174", "profile_id": "prof-174", "state": "active", "ipv6_nets": [], "mac": "63:4e:60:d9:91:a6", "ipv4_nets": ["1.0.0.174/32"]}',
               u'key': u'/calico/v1/host/host_bloop/workload/orch/endpoint_175/endpoint/endpoint_175'},
     u'prevNode': {u'createdIndex': 2025647, u'modifiedIndex': 2025647,
                   u'value': u'{"name": "tap000174", "profile_id": "prof-174", "state": "active", "ipv6_nets": [], "mac": "37:95:03:e2:f3:6c", "ipv4_nets": ["1.0.0.174/32"]}',
                   u'key': u'/calico/v1/host/host_bloop/workload/orch/endpoint_175/endpoint/endpoint_175'}}


http = HTTPConnectionPool("localhost", 4001, maxsize=2)


def watch_etcd(next_index, result_queue, stop_event):
    http = None
    try:
        while not stop_event.is_set():
            if not http:
                http = HTTPConnectionPool("localhost", 4001, maxsize=1)
            try:
                _log.info("About to call http.request...")
                resp = http.request("GET", "http://localhost:4001/v2/keys/calico/v1",
                                    fields={"recursive": "true", "wait": "true",
                                            "waitIndex": next_index},
                                    timeout=5)
                resp_body = loads(resp.data)
            except ReadTimeoutError:
                _log.exception("Watch read timed out, restarting watch at index %s",
                               next_index)
                http = None  # Workaround issue where connection isn't properly timed out by urllib3
                continue
            except:
                _log.exception("Unexpected exception")
                raise
            else:
                node = resp_body["node"]
                key = node["key"]
                value = node.get("value")
                modified_index = node["modifiedIndex"]
                result_queue.put((modified_index, key, value))
                next_index = modified_index + 1
    finally:
        result_queue.put(None)


def resync_and_merge(update_sock):
    global events_processed, snapshot_events, watcher_events, snap_skipped
    hwms = Trie(string.printable)
    stop_worker = None
    event_hwm = 0
    best_hwm = 0
    first_resync = True

    while True:
        if stop_worker:
            stop_worker.set()
        # Load the recursive get as far as the headers...
        #http = HTTPConnectionPool("localhost", 4001, maxsize=1)
        resp = http.request("GET", "http://localhost:4001/v2/keys/calico/v1",
                            fields={"recursive": "true"},
                            timeout=120,
                            preload_content=False)

        # ASAP, start the background thread to listen for events and queue
        # them up...
        snapshot_index = int(resp.getheader("x-etcd-index", 1))
        watcher_queue = Queue()
        stop_worker = Event()
        watcher_thread = Thread(target=watch_etcd,
                                args=(snapshot_index + 1,
                                      watcher_queue,
                                      stop_worker))
        watcher_thread.daemon = True
        watcher_thread.start()

        # Then plough through the update incrementally.
        deletes_during_snapshot = Trie(string.printable)
        try:
            parser = ijson.parse(resp)  # urllib3 response is file-like.
            stack = []
            frame = Node()
            count = 0
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
                    if frame.current_key == "key":
                        frame.key = value
                    elif frame.current_key == "value":
                        frame.value = value
                    if (frame.key is not None and
                            frame.value is not None and
                            frame.modifiedIndex is not None):
                        frame.done = True
                        # We have all the data for a node.  See if it's fresh.
                        key_parts = frame.key

                        # See if the key or its directory has been deleted.
                        del_hwm = deletes_during_snapshot.longest_prefix_value(
                            key_parts,
                            None
                        )

                        if frame.modifiedIndex <= del_hwm:
                            # Update to a key that's already been deleted.
                            _log.debug("Skipping: %s deleted at %s",
                                       key_parts, del_hwm)
                            snap_skipped += 1
                            continue

                        # Check if this is a newer version of the node than
                        # what we've seen before.
                        try:
                            hwm = hwms[key_parts]
                        except KeyError:
                            hwm = None
                        if snapshot_index > hwm:
                            # We have to update the HWM to allow us to spot
                            # deletions below.
                            hwms[key_parts] = snapshot_index
                        if frame.modifiedIndex <= hwm:
                            snap_skipped += 1
                            continue

                        # This is a fresh value for the key.
                        update_sock.sendall(dumps((frame.key, frame.value)))
                        events_processed += 1
                        snapshot_events += 1
                    frame.current_key = None
                elif event == "end_map":
                    frame = stack.pop(-1)
                if count % 100 == 0:
                    try:
                        while True:
                            try:
                                (mod, key, val) = watcher_queue.get_nowait()
                            except TypeError:
                                print "Queue finished"
                                break
                            key_parts = key
                            if val is None:
                                # Mark this item as deleted post-snapshot.  If this
                                # is a dir then we'll squash every snapshot update
                                # to this whole dir.
                                _log.debug("Storing deletion of %s at %s",
                                           key_parts, mod)
                                # FIXME: need to add "/" here but that only works for dirs
                                deletes_during_snapshot[key_parts + "/"] = mod
                                # Simulate a delete for all the keys under the
                                # deleted key.
                                for child_key_parts, child_mod in hwms.items(key_parts + "/"):
                                    del hwms[child_key_parts]
                                    child_key = child_key_parts
                                    #print "Simulating delete of", child_key
                                    update_sock.sendall(
                                        dumps((child_key, None))
                                    )
                            else:
                                hwms[key_parts] = mod
                                update_sock.sendall(dumps((key, val)))
                            events_processed += 1
                            watcher_events += 1
                            event_hwm = mod
                    except Empty:
                        pass
                count += 1

            # Done applying snapshot.  If we need to do a snapshot again, we
            # can skip any keys that have a modifiedIndex <= to best_hwm.
            best_hwm = max(snapshot_index, event_hwm)

            # Only used to resolve deleted during a snapshot so we can throw
            # away.
            del deletes_during_snapshot

            if not first_resync:
                # Find any keys that were deleted while we were down.
                _log.info("Scanning for deletions")
                # TODO Interleave with processing more watcher keys?
                for key_parts, value in hwms.items():
                    if value < snapshot_index:
                        # We didn't see the value during the snapshot or via the
                        # event queue.  It must have been deleted.
                        del hwms[key_parts]
                        update_sock.sendall(
                            dumps((key_parts, None))
                        )
                        events_processed += 1
            else:
                _log.info("First resync, skipping delete check.")

            _log.info("In sync, processing events only")
            while True:
                try:
                    mod, key, val = watcher_queue.get()
                except TypeError:
                    print "Queue finished"
                    break
                key_parts = key
                if val is None:
                    # Simulate a delete for all the keys under the
                    # deleted key.
                    for child_key, child_mod in hwms.items(key_parts):
                        del hwms[child_key]
                        update_sock.sendall(
                            dumps((child_key, None))
                        )
                else:
                    # At this point, we're using hwms only to track existence
                    # so we can generate deletions when whole directories are
                    # deleted.  However, we may as well keep the modifiedIndex
                    # up to date.
                    hwms[key_parts] = mod
                    update_sock.sendall(dumps((key, val)))
                events_processed += 1
                watcher_events += 1
                event_hwm = mod
                best_hwm = mod
            _log.warning("Worker stopped, resyncing...")
        except socket.error as e:
            if e.errno == 32:
                # FIXME Magic number
                _log.error("Broken pipe, exiting")
                sys.exit(1)
        except (urllib3.exceptions.HTTPError,
                HTTPException,
                socket.error) as e:
            _log.error("Request to etcd failed: %r", e)
        finally:
            first_resync = False


class Node(object):
    __slots__ = ("key", "value", "action", "current_key", "modifiedIndex", "done")

    def __init__(self):
        self.modifiedIndex = None
        self.key = None
        self.value = None
        self.action = None
        self.current_key = None
        self.done = False

