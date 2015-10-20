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
from json import loads
import socket
import logging
from Queue import Queue, Empty
import sys
from threading import Thread, Event
import time

from ijson.backends import yajl2 as ijson
from io import BytesIO
from msgpack import dumps
import urllib3
from urllib3 import HTTPConnectionPool
from urllib3.exceptions import ReadTimeoutError

from calico.etcddriver.hwm import HighWaterTracker

_log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]'
                           '[%(process)s/%(thread)d] %(name)s %(lineno)d: '
                           '%(message)s')
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


# etcd response data looks like this:
# {u'action': u'set',
#      u'node': {u'createdIndex': 2095663, u'modifiedIndex': 2095663,
#                u'value': u'{"name": "tap000174", "profile_id": "prof-174", '
#                          u'"state": "active", "ipv6_nets": [], '
#                          u'"mac": "63:4e:60:d9:91:a6", "ipv4_nets": '
#                          u'["1.0.0.174/32"]}',
#                u'key': u'/calico/v1/host/host_bloop/workload/orch/'
#                        u'endpoint_175/endpoint/endpoint_175'},
#      u'prevNode': {u'createdIndex': 2025647, u'modifiedIndex': 2025647,
#                    u'value': u'{"name": "tap000174", "profile_id": '
#                              u'"prof-174", "state": "active", '
#                              u'"ipv6_nets": [], "mac": "37:95:03:e2:f3:6c", '
#                              u'"ipv4_nets": ["1.0.0.174/32"]}',
#                    u'key': u'/calico/v1/host/host_bloop/workload/orch/'
#                            u'endpoint_175/endpoint/endpoint_175'}}


def watch_etcd(next_index, result_queue, stop_event):
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
                )
                resp_body = loads(resp.data)
            except ReadTimeoutError:
                _log.exception("Watch read timed out, restarting watch at "
                               "index %s", next_index)
                # Workaround urllib3 bug #718.  After a ReadTimeout, the
                # connection is incorrectly recycled.
                http = None
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
    _log.info("Resync thread started")
    global events_processed, snapshot_events, watcher_events, snap_skipped
    hwms = HighWaterTracker()
    stop_watcher = None
    first_resync = True

    while True:
        if stop_watcher:
            _log.info("Watcher was running before, stopping it")
            stop_watcher.set()

        # Load the recursive get as far as the headers...
        _log.info("Loading snapshot headers...")
        http = HTTPConnectionPool("localhost", 4001, maxsize=1)
        resp = http.request("GET", "http://localhost:4001/v2/keys/calico/v1",
                            fields={"recursive": "true"},
                            timeout=120,
                            preload_content=False)

        # ASAP, start the background thread to listen for events and queue
        # them up...
        snapshot_index = int(resp.getheader("x-etcd-index", 1))
        _log.info("Got snapshot headers, snapshot index is %s; starting "
                  "watcher...", snapshot_index)
        watcher_queue = Queue()
        stop_watcher = Event()
        watcher_thread = Thread(target=watch_etcd,
                                args=(snapshot_index + 1,
                                      watcher_queue,
                                      stop_watcher))
        watcher_thread.daemon = True
        watcher_thread.start()

        # Then plough through the update incrementally.
        hwms.start_tracking_deletions()
        try:
            buf = BytesIO()
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

                        old_hwm = hwms.update_hwm(frame.key, snapshot_index)
                        hwm = frame.modifiedIndex
                        if hwm > old_hwm:
                            # This specific key's HWM is newer than the
                            # previous version we've seen.
                            buf.write(
                                dumps((frame.key, frame.value))
                            )
                            events_processed += 1
                            snapshot_events += 1
                        else:
                            snap_skipped += 1

                    frame.current_key = None
                elif event == "end_map":
                    frame = stack.pop(-1)
                if count % 100 == 0:  # Avoid checking the queue on every loop.
                    for _ in xrange(100):  # Don't starve the snapshot.
                        try:
                            data = watcher_queue.get_nowait()
                        except Empty:
                            break
                        if data is None:
                            _log.warning("Watcher thread finished")
                            break
                        (mod, key, val) = data
                        if val is None:
                            # Deletion.
                            deleted_keys = hwms.store_deletion(key, mod)
                            for child_key in deleted_keys:
                                buf.write(dumps((child_key, None)))
                        else:
                            # Normal update.
                            hwms.update_hwm(key, mod)
                            buf.write(dumps((key, val)))
                        events_processed += 1
                        watcher_events += 1
                    buf_contents = buf.getvalue()
                    if buf_contents:
                        update_sock.sendall(buf_contents)
                        buf = BytesIO()
                count += 1

            # Save occupancy by throwing away the deletion tracking metadata.
            hwms.stop_tracking_deletions()

            if not first_resync:
                # Find any keys that were deleted while we were unable to
                # keep up with etcd.
                _log.info("Scanning for deletions")
                deleted_keys = hwms.remove_old_keys(snapshot_index)
                for key in deleted_keys:
                    # We didn't see the value during the snapshot or via the
                    # event queue.  It must have been deleted.
                    buf.write(dumps((key, None)))
                    events_processed += 1
            else:
                _log.info("First resync, skipping delete check.")

            buf_contents = buf.getvalue()
            if buf_contents:
                update_sock.sendall(buf_contents)
            del buf

            _log.info("In sync, processing events only")
            while True:
                data = watcher_queue.get()
                if data is None:
                    _log.warning("Watcher thread finished, resyncing...")
                    break
                mod, key, val = data
                if val is None:
                    # Deletion.
                    deleted_keys = hwms.store_deletion(key, mod)
                    for child_key in deleted_keys:
                        update_sock.sendall(
                            dumps((child_key, None))
                        )
                else:
                    # Normal update.
                    hwms.update_hwm(key, mod)
                    update_sock.sendall(dumps((key, val)))
                events_processed += 1
                watcher_events += 1
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
        except:
            _log.exception("Unexpected exception")
            raise
        finally:
            first_resync = False


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

