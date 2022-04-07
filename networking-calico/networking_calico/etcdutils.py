# Copyright (c) 2016, 2018 Tigera, Inc. All rights reserved.

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

# Change to trigger CI

import collections
import eventlet
import json
import re

from etcd3gw.exceptions import ConnectionFailedError
from networking_calico.common import intern_string
from networking_calico.compat import log
from networking_calico import etcdv3
from networking_calico.monotonic import monotonic_time

LOG = log.getLogger(__name__)

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
WATCH_TIMEOUT_SECS = 10


# Replacement for "if isinstance(v, StringTypes)" that works with
# Python 2 and 3, as advised by
# https://github.com/mk-fg/layered-yaml-attrdict-config/pull/5 and
# https://stackoverflow.com/questions/4232111/stringtype-and-nonetype-in-python3-x.
def _is_string_instance(obj):
    try:
        return isinstance(obj, basestring)
    except NameError:
        return isinstance(obj, str)


class PathDispatcher(object):
    def __init__(self):
        self.handler_root = {}

    def register(self, path, on_set=None, on_del=None):
        LOG.info("Registering path %s set=%s del=%s", path, on_set, on_del)
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

        :param Response: A python-etcd response object for a watch.
        """
        LOG.debug("etcd event %s for key %s", response.action, response.key)
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
                LOG.debug("No matching sub-handler for %s", response.key)
                return
        # We've reached the end of the key.
        action = ACTION_MAPPING.get(response.action)
        if action in handler_node:
            LOG.debug("Found handler for event %s for %s, captures: %s",
                      action, response.key, captures)
            handler_node[action](response, **captures)
        else:
            LOG.debug("No handler for event %s on %s. Handler node %s.",
                      action, response.key, handler_node)


Response = collections.namedtuple(
    'Response', ['action', 'key', 'value', 'mod_revision']
)


class EtcdWatcher(object):
    """A class that watches an etcdv3 subtree.

    Entrypoints:
    - EtcdWatcher() (constructor)
    - watcher.start()
    - watcher.stop()
    """

    def __init__(self, prefix, round_trip_suffix=None):
        LOG.debug("Creating EtcdWatcher for %s", prefix)
        self.prefix = prefix
        self.round_trip_suffix = round_trip_suffix
        self.dispatcher = PathDispatcher()
        self._stopped = False
        self.debug_reporter = lambda msg: msg

    def register_path(self, *args, **kwargs):
        self.dispatcher.register(*args, **kwargs)

    def _pre_snapshot_hook(self):
        return None

    def _post_snapshot_hook(self, _):
        pass

    def start(self):
        LOG.info("Start watching %s", self.prefix)
        self._stopped = False

        # The current etcd cluster ID.
        current_cluster_id = None

        while not self._stopped:
            # Get the current etcdv3 cluster ID and revision, so (a) we can
            # detect if the cluster ID changes, and (b) we know when to start
            # watching from.
            try:
                cluster_id, last_revision = etcdv3.get_status()
                last_revision = int(last_revision)
                LOG.debug("Current cluster_id %s, revision %d",
                          cluster_id, last_revision)
                if cluster_id != current_cluster_id:
                    # No particular handling here; but keep track of the
                    # current cluster ID and log if it changes.  (In the
                    # circumstances that can cause a cluster ID change, our
                    # watch (below) for the old cluster ID would have timed out
                    # - either because of connection loss, or because of no
                    # further events coming - and then we would have looped
                    # back round to here; and the next watch will be created
                    # against the new cluster.)
                    if current_cluster_id is not None:
                        LOG.warning("Cluster ID changed")
                    current_cluster_id = cluster_id
            except ConnectionFailedError as e:
                LOG.debug("%r", e)
                LOG.warning("etcd not available, will retry in 5s")
                eventlet.sleep(5)
                continue

            # Allow subclass to do pre-snapshot processing, and to return any
            # data that it will need for reconciliation after the snapshot.
            my_name = self.__class__.__name__
            LOG.debug("%s Calling pre-snapshot hook", my_name)
            snapshot_data = self._pre_snapshot_hook()

            try:
                # Get all existing values and process them through the
                # dispatcher.
                LOG.debug("%s Loading snapshot", my_name)
                for result in etcdv3.get_prefix(self.prefix,
                                                revision=last_revision):
                    key, value, mod_revision = result
                    # Convert to what the dispatcher expects - see below.
                    response = Response(
                        action='set',
                        key=key,
                        value=value,
                        mod_revision=mod_revision,
                    )
                    LOG.debug("status event: %s", response)
                    self.dispatcher.handle_event(response)
            except ConnectionFailedError as e:
                LOG.debug("%r", e)
                LOG.warning("etcd not available, will retry in 5s")
                eventlet.sleep(5)
                continue

            # Allow subclass to do post-snapshot reconciliation.
            LOG.debug("%s Done loading snapshot, calling post snapshot hook",
                      my_name)
            self._post_snapshot_hook(snapshot_data)

            # Now watch for any changes, starting after the revision above.
            try:
                # Start a watch from just after the last known revision.
                LOG.debug("%s Starting to watch for updates", my_name)
                event_stream, cancel = etcdv3.watch_subtree(
                    self.prefix,
                    str(last_revision + 1))

                # It is possible for that watch call to be affected by an etcd
                # compaction, if there is a sequence of events as follows.
                #
                # 1. EtcdWatcher calls get_status (39 lines above) and finds
                # that the etcd revision at that time is N.
                #
                # 2. There are at least 2 changes to the database (by any etcd
                # writer, including other threads/forks of the Neutron server),
                # such that the etcd revision is >= N+2, before our watch call.
                #
                # 3. etcd is then compacted at revision >= N+2, also before our
                # watch call.
                #
                # 4. Our watch call then tries to create a watch starting at
                # revision N+1, which is no longer available.
                #
                # If that happens, the etcd server sends these responses to the
                # etcd3gw client, and then does NOT send any events for the
                # prefix that we are monitoring:
                #
                # {"result":{"header":{"cluster_id":"14841639068965178418",
                # "member_id":"10276657743932975437","revision":"33",
                # "raft_term":"2"},"created":true}}
                #
                # {"result":{"header":{"cluster_id":"14841639068965178418",
                # "member_id":"10276657743932975437","raft_term":"2"},
                # "compact_revision":"32"}}
                #
                # Both of those response lines are consumed by the etcd3gw
                # client/watch code, with nothing reported up to this code
                # here.  Hence the next thing that will happen here is timing
                # out after WATCH_TIMEOUT_SECS (10s).  Then we'll loop round,
                # get the current revision, and start watching again from
                # there.
                #
                # Given the things that EtcdWatcher is used for, I think that's
                # good enough without more specific handling.  EtcdWatcher is
                # used for:
                #
                # - agent status, where the impacts are placing a VM on a
                #   compute host where Felix has died, or not using a compute
                #   host where Felix has just become available.  For Felix
                #   death there is a window (TTL) of 90s anyway, so another 10s
                #   doesn't make a big difference.
                #
                # - port status, where the impact is just correct presentation
                #   in the OpenStack UI.
                #
                # - DHCP info, where the impact is dnsmasq not being able to
                #   answer a DHCP request.  But any sensible guest OS will
                #   retry anyway for at least 10s, so I think we're still OK.
            except Exception:
                # Log and handle by restarting the loop, which means we'll get
                # the tree again and then try watching again.  E.g. it could be
                # that the DB has just been compacted and so the revision is no
                # longer available that we asked to start watching from.
                LOG.exception("Exception watching status tree")
                continue

            # Record time of last activity on the successfully created watch.
            # (This is updated below as we see watch events.)
            last_event_time = monotonic_time()

            def _cancel_watch_if_broken():
                # Loop until we should cancel the watch, either because of
                # inactivity or because of stop() having been called.
                while not self._stopped:
                    self.debug_reporter("Start of loop")
                    # If WATCH_TIMEOUT_SECS has now passed since the last watch
                    # event, break out of this loop.  If we are also writing a
                    # key within the tree every WATCH_TIMEOUT_SECS / 3 seconds,
                    # this can only happen either if there is some roundtrip
                    # connectivity problem, or if the watch is invalid because
                    # of a recent compaction.  Whatever the reason, we need to
                    # terminate this watch and take a new overall status and
                    # snapshot of the tree.
                    time_now = monotonic_time()
                    if time_now > last_event_time + WATCH_TIMEOUT_SECS:
                        if self.round_trip_suffix is not None:
                            LOG.warning("Watch is not working")
                            self.debug_reporter("Watch is not working")
                        else:
                            LOG.debug("Watch timed out")
                        break

                    if self.round_trip_suffix is not None:
                        # Write to a key in the tree that we are watching.  If
                        # the watch is working normally, it will report this
                        # event.
                        try:
                            etcdv3.put(self.prefix + self.round_trip_suffix,
                                       str(time_now))
                            self.debug_reporter("Wrote round-trip key")
                        except ConnectionFailedError:
                            LOG.exception(
                                "etcd not available for watch round trip check"
                            )

                    # Sleep until time for next write.
                    eventlet.sleep(WATCH_TIMEOUT_SECS / 3)
                    LOG.debug("Checked %s watch at %r", self.prefix, time_now)

                # Cancel the watch
                cancel()
                return

            # Spawn a greenlet to cancel the watch if it stops working, or if
            # stop() is called.  Cancelling the watch adds None to the event
            # stream, so the following for loop will see that.
            self.debug_reporter("Start _cancel_watch_if_broken")
            eventlet.spawn(_cancel_watch_if_broken)

            for event in event_stream:
                LOG.debug("Event: %s", event)
                last_event_time = monotonic_time()

                # If the EtcdWatcher has been stopped, return from the whole
                # loop.
                if self._stopped:
                    LOG.info("EtcdWatcher has been stopped")
                    return

                # Otherwise a None event means that the watch has been
                # cancelled owing to inactivity.  In that case we break out
                # from this loop, and the watch will be restarted.
                if event is None:
                    LOG.debug("Watch cancelled owing to inactivity")
                    break

                # An event at this point has a form like
                #
                # {'kv': {
                #     'mod_revision': '4',
                #     'value': '...',
                #     'create_revision': '4',
                #     'version': '1',
                #     'key': '/calico/felix/v1/host/ubuntu-xenial...'
                # }}
                #
                # when a key/value pair is created or updated, and like
                #
                # {'type': 'DELETE',
                #  'kv': {
                #     'mod_revision': '88',
                #     'key': '/calico/felix/v1/host/ubuntu-xenial-...'
                # }}
                #
                # when a key/value pair is deleted.
                #
                # Convert that to the form that the dispatcher expects;
                # namely a response object, with:
                # - response.key giving the etcd key
                # - response.action being "set" or "delete"
                # - whole response being passed on to the handler method.
                # Handler methods here expect
                # - response.key
                # - response.value
                key = event['kv']['key'].decode()
                mod_revision = int(event['kv'].get('mod_revision', '0'))
                response = Response(
                    action=event.get('type', 'SET').lower(),
                    key=key,
                    value=event['kv'].get('value', b'').decode(),
                    mod_revision=mod_revision,
                )
                LOG.info("Event: %s", response)
                self.dispatcher.handle_event(response)

                # Update last known revision.
                if mod_revision > last_revision:
                    last_revision = mod_revision
                    LOG.debug("Last known revision is now %d",
                              last_revision)

    def stop(self):
        LOG.info("Stop watching status tree")
        self._stopped = True


def intern_dict(d):
    """intern_dict

    Return a copy of the input dict where all its string/unicode keys
    and some of its values are interned.

    Caveat: assumes that it is safe to convert the keys and interned values
    to str by calling .encode("utf8") on each string.

    :param dict[StringTypes,...] d: Input dict.
    :return: new dict with interned keys/values.
    """
    fields_to_intern = set([
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
    out = {}
    for k, v in d.items():
        k = intern_string(k)
        if k in fields_to_intern:
            if _is_string_instance(v):
                v = intern_string(v)
            elif isinstance(v, list):
                v = intern_list(v)
        out[k] = v
    return out


def intern_list(l):
    """intern_list

    Returns a new list with interned versions of the input list's contents.
    Non-strings are copied to the new list verbatim.
    """
    out = []
    for item in l:
        if _is_string_instance(item):
            item = intern_string(item)
        out.append(item)
    return out


json_decoder = json.JSONDecoder(object_hook=intern_dict)


def safe_decode_json(raw_json, log_tag=None):
    try:
        return json_decoder.decode(raw_json)
    except (TypeError, ValueError):
        LOG.warning("Failed to decode JSON for %s: %r.  Returning None.",
                    log_tag, raw_json)
        return None
