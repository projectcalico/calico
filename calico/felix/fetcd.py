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
felix.fetcd
~~~~~~~~~~~~

Our API to etcd.  Contains function to synchronize felix with etcd
as well as reporting our status into etcd.
"""
import functools
import os
import random
import json
import logging
import socket
import subprocess
import msgpack
import select
from calico.etcddriver.protocol import *
from calico.monotonic import monotonic_time

from etcd import EtcdException, EtcdKeyNotFound
import gevent
import sys
from gevent.event import Event

from calico import common
from calico.common import ValidationFailed, validate_ip_addr, canonicalise_ip
from calico.datamodel_v1 import (VERSION_DIR, CONFIG_DIR,
                                 RULES_KEY_RE, TAGS_KEY_RE,
                                 dir_for_per_host_config,
                                 PROFILE_DIR, HOST_DIR, EndpointId,
                                 HOST_IP_KEY_RE, IPAM_V4_CIDR_KEY_RE,
                                 key_for_last_status, key_for_status,
                                 FELIX_STATUS_DIR, get_endpoint_id_from_key,
                                 dir_for_felix_status, ENDPOINT_STATUS_ERROR,
                                 ENDPOINT_STATUS_DOWN, ENDPOINT_STATUS_UP)
from calico.etcdutils import (
    EtcdClientOwner, delete_empty_parents, PathDispatcher
)
from calico.felix.actor import Actor, actor_message
from calico.felix.futils import (intern_dict, intern_list, logging_exceptions,
                                 iso_utc_timestamp, IPV4, IPV6)

_log = logging.getLogger(__name__)


RETRY_DELAY = 5

# Etcd paths that we care about for use with the PathDispatcher class.
# We use angle-brackets to name parameters that we want to capture.
PER_PROFILE_DIR = PROFILE_DIR + "/<profile_id>"
TAGS_KEY = PER_PROFILE_DIR + "/tags"
RULES_KEY = PER_PROFILE_DIR + "/rules"
PER_HOST_DIR = HOST_DIR + "/<hostname>"
HOST_IP_KEY = PER_HOST_DIR + "/bird_ip"
WORKLOAD_DIR = PER_HOST_DIR + "/workload"
PER_ORCH_DIR = WORKLOAD_DIR + "/<orchestrator>"
PER_WORKLOAD_DIR = PER_ORCH_DIR + "/<workload_id>"
ENDPOINT_DIR = PER_WORKLOAD_DIR + "/endpoint"
PER_ENDPOINT_KEY = ENDPOINT_DIR + "/<endpoint_id>"
CONFIG_PARAM_KEY = CONFIG_DIR + "/<config_param>"
PER_HOST_CONFIG_PARAM_KEY = PER_HOST_DIR + "/config/<config_param>"

IPAM_DIR = VERSION_DIR + "/ipam"
IPAM_V4_DIR = IPAM_DIR + "/v4"
POOL_V4_DIR = IPAM_V4_DIR + "/pool"
CIDR_V4_KEY = POOL_V4_DIR + "/<pool_id>"

# Max number of events from driver process before we yield to another greenlet.
MAX_EVENTS_BEFORE_YIELD = 200


class EtcdAPI(EtcdClientOwner, Actor):
    """
    Our API to etcd.

    Since the python-etcd API is blocking, we defer API watches to
    a worker greenlet and communicate with it via Events.

    We use a second worker for writing our status back to etcd.  This
    avoids sharing the etcd client between reads and writes, which is
    problematic because we need to handle EtcdClusterIdChanged for polls
    but not for writes.
    """

    def __init__(self, config, hosts_ipset):
        super(EtcdAPI, self).__init__(config.ETCD_ADDR)
        self._config = config

        # Timestamp storing when the EtcdAPI started. This info is needed
        # in order to report uptime to etcd.
        self._start_time = monotonic_time()

        # Create an Actor to report per-endpoint status into etcd.
        self.status_reporter = EtcdStatusReporter(config)

        # Start up the main etcd-watching greenlet.  It will wait for an
        # event from us before doing anything.
        self._watcher = _FelixEtcdWatcher(config,
                                          self,
                                          self.status_reporter,
                                          hosts_ipset)
        self._watcher.link(self._on_worker_died)
        self._watcher.start()

        # Start up a greenlet to trigger periodic resyncs.
        self._resync_greenlet = gevent.spawn(self._periodically_resync)
        self._resync_greenlet.link_exception(self._on_worker_died)

        # Start up greenlet to report felix's liveness into etcd.
        self.done_first_status_report = False
        self._status_reporting_greenlet = gevent.spawn(
            self._periodically_report_status
        )
        self._status_reporting_greenlet.link_exception(self._on_worker_died)

        # Start the status reporter.
        self.status_reporter.start()
        self.status_reporter.greenlet.link(self._on_worker_died)

    @logging_exceptions
    def _periodically_resync(self):
        """
        Greenlet: if enabled, periodically triggers a resync from etcd.

        :return: Does not return, unless periodic resync disabled.
        """
        _log.info("Started periodic resync thread, waiting for config.")
        self._watcher.configured.wait()
        interval = self._config.RESYNC_INTERVAL
        _log.info("Config loaded, resync interval %s.", interval)
        if interval == 0:
            _log.info("Interval is 0, periodic resync disabled.")
            return
        while True:
            # Jitter by 20% of interval.
            jitter = random.random() * 0.2 * interval
            sleep_time = interval + jitter
            _log.debug("After jitter, next periodic resync will be in %.1f "
                       "seconds.", sleep_time)
            gevent.sleep(sleep_time)
            self.force_resync(reason="periodic resync", async=True)

    @logging_exceptions
    def _periodically_report_status(self):
        """
        Greenlet: periodically writes Felix's status into etcd.

        :return: Does not return, unless reporting disabled.
        """
        _log.info("Started status reporting thread. Waiting for config.")
        self._watcher.configured.wait()
        ttl = self._config.REPORTING_TTL_SECS
        interval = self._config.REPORTING_INTERVAL_SECS
        _log.debug("Reporting interval: %s, TTL: %s", interval, ttl)

        if interval == 0:
            _log.info("Interval is 0, status reporting disabled.")
            return

        while True:
            try:
                self._update_felix_status(ttl)
            except EtcdException as e:
                _log.warning("Error when trying to check into etcd (%r), "
                             "retrying after %s seconds.", e, RETRY_DELAY)
                self.reconnect()
                gevent.sleep(RETRY_DELAY)
            else:
                # Jitter by 10% of interval.
                jitter = random.random() * 0.1 * interval
                sleep_time = interval + jitter
                gevent.sleep(sleep_time)

    def _update_felix_status(self, ttl):
        """
        Writes two keys to etcd:

        * uptime in secs
        * felix status in JSON - containing current time in ISO 8601 Zulu
          format

        :param: ttl int: time to live in sec - lifetime of the status report
        """
        time_formatted = iso_utc_timestamp()
        uptime = monotonic_time() - self._start_time
        status = {
            "time": time_formatted,
            "uptime": uptime,
            "first_update": not self.done_first_status_report,
        }

        status_value = json.dumps(status)

        _log.debug("Reporting felix status/uptime (%.1fs) using hostname %s",
                   uptime, self._config.HOSTNAME)
        status_key = key_for_last_status(self._config.HOSTNAME)
        self.client.set(status_key, status_value)
        status_key = key_for_status(self._config.HOSTNAME)
        self.client.set(status_key, status_value, ttl=ttl)
        self.done_first_status_report = True

    @actor_message()
    def load_config(self):
        """
        Loads our config from etcd, should only be called once.

        :return: an event which is triggered when the config has been loaded.
        """
        self._watcher.load_config.set()
        return self._watcher.configured

    @actor_message()
    def start_watch(self, splitter):
        """
        Starts watching etcd for changes.  Implicitly loads the config
        if it hasn't been loaded yet.
        """
        self._watcher.load_config.set()
        self._watcher.splitter = splitter
        self._watcher.begin_polling.set()

    @actor_message()
    def force_resync(self, reason="unknown"):
        """
        Force a resync with etcd after the current poll completes.

        :param str reason: Optional reason to log out.
        """
        _log.info("Forcing a resync with etcd.  Reason: %s.", reason)
        self._watcher.resync_requested = True

        if self._config.REPORT_ENDPOINT_STATUS:
            _log.info("Endpoint status reporting enabled, marking existing "
                      "endpoints as dirty so they'll be resynced.")
            self.status_reporter.resync(async=True)

    def _on_worker_died(self, watch_greenlet):
        """
        Greenlet: spawned by the gevent Hub if the etcd watch loop ever
        stops, kills the process.
        """
        _log.critical("Worker greenlet died: %s; exiting.", watch_greenlet)
        sys.exit(1)


class _FelixEtcdWatcher(gevent.Greenlet):
    """
    Greenlet that communicates with the etcd driver over a socket.

    * Handles initial configuration of the driver.
    * Processes the initial config responses.
    * Then fans out the stream of updates.
    """

    def __init__(self, config, etcd_api, status_reporter, hosts_ipset):
        super(_FelixEtcdWatcher, self).__init__()
        self._config = config
        self._etcd_api = etcd_api
        self._status_reporter = status_reporter
        self.hosts_ipset = hosts_ipset

        # Whether we've been in sync with etcd at some point.
        self._been_in_sync = False

        # Keep track of the config loaded from etcd so we can spot if it
        # changes.
        self.last_global_config = None
        self.last_host_config = None
        self.my_config_dir = dir_for_per_host_config(self._config.HOSTNAME)

        # Events triggered by the EtcdAPI Actor to tell us to load the config
        # and start polling.  These are one-way flags.
        self.load_config = Event()
        self.begin_polling = Event()

        # Event that we trigger once the config is loaded.
        self.configured = Event()

        # Polling state initialized at poll start time.
        self.splitter = None

        # Next-hop IP addresses of our hosts, if populated in etcd.
        self.ipv4_by_hostname = {}

        # Forces a resync after the current poll if set.  Safe to set from
        # another thread.  Automatically reset to False after the resync is
        # triggered.
        self.resync_requested = False
        self.dispatcher = PathDispatcher()

        # Register for events when values change.
        self._register_paths()

        self.read_count = 0
        self.last_rate_log_time = monotonic_time()

    def _register_paths(self):
        """
        Program the dispatcher with the paths we care about.

        Since etcd gives us a single event for a recursive directory
        deletion, we have to handle deletes for lots of directories that
        we otherwise wouldn't care about.
        """
        reg = self.dispatcher.register
        # Profiles and their contents.
        reg(TAGS_KEY, on_set=self.on_tags_set, on_del=self.on_tags_delete)
        reg(RULES_KEY, on_set=self.on_rules_set, on_del=self.on_rules_delete)
        # Hosts, workloads and endpoints.
        reg(HOST_IP_KEY,
            on_set=self.on_host_ip_set,
            on_del=self.on_host_ip_delete)
        reg(PER_ENDPOINT_KEY,
            on_set=self.on_endpoint_set, on_del=self.on_endpoint_delete)
        reg(CIDR_V4_KEY,
            on_set=self.on_ipam_v4_pool_set,
            on_del=self.on_ipam_v4_pool_delete)
        # Configuration keys.  If any of these is changed or set a resync is
        # done, including a full reload of configuration. If any field has
        # actually changed (as opposed to being reset to the same value or
        # explicitly set to the default, say), Felix terminates allowing the
        # init daemon to restart it.
        reg(CONFIG_PARAM_KEY,
            on_set=self._on_config_updated,
            on_del=self._on_config_updated)
        reg(PER_HOST_CONFIG_PARAM_KEY,
            on_set=self._on_host_config_updated,
            on_del=self._on_host_config_updated)

    @logging_exceptions
    def _run(self):
        _log.info("Waiting for load_config event...")
        self.load_config.wait()
        _log.info("...load_config set.  Starting driver read %s loop", self)
        driver_sck = self.start_driver()
        unpacker = msgpack.Unpacker()
        msgs_processed = 0
        while True:
            # Use select to impose a timeout on how long we block so that we
            # periodically check the resync flag.
            read_ready, _, _ = select.select([driver_sck], [], [], 1)
            if read_ready:
                data = driver_sck.recv(16384)
                unpacker.feed(data)
            for msg in unpacker:
                # Optimization: put update first in the "switch"
                # block because it's on the critical path.
                msg_type = msg[MSG_KEY_TYPE]
                if msg_type == MSG_TYPE_UPDATE:
                    self.begin_polling.wait()
                    self._on_update_from_driver(msg)
                elif msg_type == MSG_TYPE_CONFIG_LOADED:
                    self._on_config_loaded_from_driver(msg, driver_sck)
                elif msg_type == MSG_TYPE_STATUS:
                    self._on_status_from_driver(msg)
                else:
                    raise RuntimeError("Unexpected message %s" % msg)
                msgs_processed += 1
                if msgs_processed % MAX_EVENTS_BEFORE_YIELD == 0:
                    # Yield to ensure that other actors make progress.
                    # Sleep must be non-zero to work around gevent
                    # issue where we could be immediately rescheduled.
                    gevent.sleep(0.000001)
            if self.resync_requested:
                self.resync_requested = False
                driver_sck.sendall(
                    msgpack.dumps({
                        MSG_KEY_TYPE: MSG_TYPE_RESYNC,
                    })
                )
        _log.info("%s.loop() stopped due to self.stop == True", self)

    def _on_update_from_driver(self, msg):
        """
        Called when the driver sends us a key/value pair update.
        :param dict msg: The message recived from the driver.
        """
        assert self.configured.is_set(), "Received update before config"
        key = msg[MSG_KEY_KEY]
        value = msg[MSG_KEY_VALUE]
        _log.debug("Update from driver: %s -> %s", key, value)
        self.read_count += 1
        if self.read_count % 1000 == 0:
            now = monotonic_time()
            delta = now - self.last_rate_log_time
            _log.info("Processed %s updates from driver "
                      "%.1f/s", self.read_count, 1000.0 / delta)
            self.last_rate_log_time = now
        # Create a fake etcd node object.
        # FIXME: avoid creating fake node.
        n = Node()
        n.action = "set" if value is not None else "delete"
        n.value = value
        n.key = key
        # And dispatch it.
        self.dispatcher.handle_event(n)

    def _on_config_loaded_from_driver(self, msg, driver_sck):
        """
        Called when we receive a config loaded message from the driver.

        Responds to the driver immediately with a config response.

        If the config has changed since a previous call, triggers Felix
        to die.
        """
        global_config = msg[MSG_KEY_GLOBAL_CONFIG]
        host_config = msg[MSG_KEY_HOST_CONFIG]
        _log.info("Config loaded by driver:\n"
                  "Global: %s\nPer-host: %s",
                  global_config,
                  host_config)
        if self.configured.is_set():
            # We've already been configured.  We don't yet support
            # dynamic config update so instead we check if the config
            # has changed and die if it has.
            _log.info("Checking configuration for changes...")
            if (host_config != self.last_host_config or
                    global_config != self.last_global_config):
                _log.warning("Felix configuration has changed, "
                             "felix must restart.")
                _log.info("Old host config: %s", self.last_host_config)
                _log.info("New host config: %s", host_config)
                _log.info("Old global config: %s",
                          self.last_global_config)
                _log.info("New global config: %s", global_config)
                die_and_restart()
        else:
            # First time loading the config.  Report it to the config
            # object.  Take copies because report_etcd_config is
            # destructive.
            self.last_host_config = host_config.copy()
            self.last_global_config = global_config.copy()
            self._config.report_etcd_config(host_config,
                                            global_config)
            # Config now fully resolved, inform the driver.
            felix_log_file = self._config.LOGFILE
            if felix_log_file:
                # FIXME Proper config for driver logfile
                driver_log_file = felix_log_file + "-driver"
            else:
                driver_log_file = None
            driver_sck.sendall(msgpack.dumps({
                MSG_KEY_TYPE: MSG_TYPE_CONFIG,
                MSG_KEY_LOG_FILE: driver_log_file,
                MSG_KEY_SEV_FILE: self._config.LOGLEVFILE,
                MSG_KEY_SEV_SCREEN: self._config.LOGLEVSCR,
                MSG_KEY_SEV_SYSLOG: self._config.LOGLEVSYS,
            }))
            self.configured.set()

    def _on_status_from_driver(self, msg):
        """
        Called when we receive a status update from the driver.

        If the status is in-sync, triggers the relevant processing.
        :param msg:
        :return:
        """
        status = msg[MSG_KEY_STATUS]
        _log.info("etcd driver status changed to %s", status)
        if status == STATUS_IN_SYNC and not self._been_in_sync:
            # We're now in sync, tell the Actors that need to do start-of-day
            # cleanup.
            self.begin_polling.wait()  # Make sure splitter is set.
            self._been_in_sync = True
            self.splitter.on_datamodel_in_sync(async=True)
            if self._config.REPORT_ENDPOINT_STATUS:
                self._status_reporter.clean_up_endpoint_statuses(async=True)
            self._update_hosts_ipset()

    def start_driver(self):
        """
        Starts the driver subprocess, connects to it over the socket
        and sends it the init message.
        :return: the connected socket to the driver.
        """
        _log.info("Creating server socket.")
        try:
            os.unlink("/run/felix-driver.sck")
        except OSError:
            pass
        update_socket = socket.socket(socket.AF_UNIX,
                                      socket.SOCK_STREAM)
        update_socket.bind("/run/felix-driver.sck")
        update_socket.listen(1)
        subprocess.Popen([sys.executable,
                          "-m",
                          "calico.etcddriver",
                          "/run/felix-driver.sck"])
        update_conn, _ = update_socket.accept()
        _log.info("Accepted connection on socket")
        # No longer need the server socket, remove it.
        try:
            os.unlink("/run/felix-driver.sck")
        except OSError:
            _log.exception("Failed to unlink socket")
        else:
            _log.info("Unlinked server socket")

        update_conn.sendall(msgpack.dumps({
            MSG_KEY_TYPE: MSG_TYPE_INIT,
            MSG_KEY_ETCD_URL: "http://" + self._config.ETCD_ADDR,
            MSG_KEY_HOSTNAME: self._config.HOSTNAME,
        }))

        return update_conn

    def on_endpoint_set(self, response, hostname, orchestrator,
                        workload_id, endpoint_id):
        """Handler for endpoint updates, passes the update to the splitter."""
        combined_id = EndpointId(hostname, orchestrator, workload_id,
                                 endpoint_id)
        _log.debug("Endpoint %s updated", combined_id)
        endpoint = parse_endpoint(self._config, combined_id, response.value)
        self.splitter.on_endpoint_update(combined_id, endpoint, async=True)

    def on_endpoint_delete(self, response, hostname, orchestrator,
                           workload_id, endpoint_id):
        """Handler for endpoint deleted, passes the update to the splitter."""
        combined_id = EndpointId(hostname, orchestrator, workload_id,
                                 endpoint_id)
        _log.debug("Endpoint %s deleted", combined_id)
        self.splitter.on_endpoint_update(combined_id, None, async=True)

    def on_rules_set(self, response, profile_id):
        """Handler for rules updates, passes the update to the splitter."""
        _log.debug("Rules for %s set", profile_id)
        rules = parse_rules(profile_id, response.value)
        profile_id = intern(profile_id.encode("utf8"))
        self.splitter.on_rules_update(profile_id, rules, async=True)

    def on_rules_delete(self, response, profile_id):
        """Handler for rules deletes, passes the update to the splitter."""
        _log.debug("Rules for %s deleted", profile_id)
        self.splitter.on_rules_update(profile_id, None, async=True)

    def on_tags_set(self, response, profile_id):
        """Handler for tags updates, passes the update to the splitter."""
        _log.debug("Tags for %s set", profile_id)
        rules = parse_tags(profile_id, response.value)
        profile_id = intern(profile_id.encode("utf8"))
        self.splitter.on_tags_update(profile_id, rules, async=True)

    def on_tags_delete(self, response, profile_id):
        """Handler for tags deletes, passes the update to the splitter."""
        _log.debug("Tags for %s deleted", profile_id)
        self.splitter.on_tags_update(profile_id, None, async=True)

    def on_host_ip_set(self, response, hostname):
        if not self._config.IP_IN_IP_ENABLED:
            _log.debug("Ignoring update to %s because IP-in-IP is disabled",
                       response.key)
            return
        ip = parse_host_ip(hostname, response.value)
        if ip:
            self.ipv4_by_hostname[hostname] = ip
        else:
            _log.warning("Invalid IP for hostname %s: %s, treating as "
                         "deletion", hostname, response.value)
            self.ipv4_by_hostname.pop(hostname, None)
        self._update_hosts_ipset()

    def on_host_ip_delete(self, response, hostname):
        if not self._config.IP_IN_IP_ENABLED:
            _log.debug("Ignoring update to %s because IP-in-IP is disabled",
                       response.key)
            return
        if self.ipv4_by_hostname.pop(hostname, None):
            self._update_hosts_ipset()

    def _update_hosts_ipset(self):
        if not self._been_in_sync:
            _log.debug("Deferring update to hosts ipset until we're in-sync")
            return
        self.hosts_ipset.replace_members(self.ipv4_by_hostname.values(),
                                         async=True)

    def _on_config_updated(self, response, config_param):
        new_value = response.value
        if self.last_global_config.get(config_param) != new_value:
            _log.critical("Global config value %s updated.  Felix must be "
                          "restarted.", config_param)
            die_and_restart()

    def _on_host_config_updated(self, response, hostname, config_param):
        if hostname != self._config.HOSTNAME:
            _log.debug("Ignoring config update for host %s", hostname)
            return
        new_value = response.value
        if self.last_host_config.get(config_param) != new_value:
            _log.critical("Global config value %s updated.  Felix must be "
                          "restarted.", config_param)
            die_and_restart()

    def on_ipam_v4_pool_set(self, response, pool_id):
        pool = parse_ipam_pool(pool_id, response.value)
        self.splitter.on_ipam_pool_update(pool_id, pool, async=True)

    def on_ipam_v4_pool_delete(self, response, pool_id):
        self.splitter.on_ipam_pool_update(pool_id, None, async=True)


class EtcdStatusReporter(EtcdClientOwner, Actor):
    """
    Actor that manages and rate-limits the queue of status reports to
    etcd.
    """

    def __init__(self, config):
        super(EtcdStatusReporter, self).__init__(config.ETCD_ADDR)
        self._config = config
        self._endpoint_status = {IPV4: {}, IPV6: {}}

        # Two sets of dirty endpoints. The "older" set is the set of dirty
        # endpoints that the actor is updating. The "newer" set is the set of
        # dirty endpoints that should be done afterwards, and is kept
        # separate to avoid pathological conditions where the actor never
        # finishes the set.
        self._newer_dirty_endpoints = set()
        self._older_dirty_endpoints = set()

        self._cleanup_pending = False
        self._timer_scheduled = False
        self._reporting_allowed = True

    @actor_message()
    def on_endpoint_status_changed(self, endpoint_id, ip_type, status):
        assert isinstance(endpoint_id, EndpointId)
        if status is not None:
            self._endpoint_status[ip_type][endpoint_id] = status
        else:
            self._endpoint_status[ip_type].pop(endpoint_id, None)
        self._mark_endpoint_dirty(endpoint_id)

    @actor_message()
    def resync(self):
        """
        Triggers a rewrite of all endpoint statuses.
        """
        # Loop over IPv4 and IPv6 statuses.
        for statuses in self._endpoint_status.itervalues():
            for ep_id in statuses.iterkeys():
                self._mark_endpoint_dirty(ep_id)

    @actor_message()
    def _on_timer_pop(self):
        _log.debug("Timer popped, uncorking rate limit")
        self._timer_scheduled = False
        self._reporting_allowed = True

    @actor_message()
    def mark_endpoint_dirty(self, endpoint_id):
        self._mark_endpoint_dirty(endpoint_id)

    def _mark_endpoint_dirty(self, endpoint_id):
        assert isinstance(endpoint_id, EndpointId)
        if endpoint_id in self._older_dirty_endpoints:
            # Optimization: if the endpoint is already queued up in
            # _older_dirty_endpoints then there's no point in queueing it up a
            # second time in _newer_dirty_endpoints.
            _log.debug("Endpoint %s already marked dirty", endpoint_id)
            return
        else:
            _log.debug("Marking endpoint %s dirty", endpoint_id)
            self._newer_dirty_endpoints.add(endpoint_id)

    @actor_message()
    def clean_up_endpoint_statuses(self):
        """
        Note that we need to do cleanup.  We'll then try/retry from
        _finish_msg_batch().
        """
        self._cleanup_pending = True

    def _finish_msg_batch(self, batch, results):
        if not self._config.REPORT_ENDPOINT_STATUS:
            _log.warning("StatusReporter called even though status reporting "
                         "disabled.  Ignoring.")
            self._endpoint_status[IPV4].clear()
            self._endpoint_status[IPV6].clear()
            self._newer_dirty_endpoints.clear()
            self._older_dirty_endpoints.clear()
            return

        if self._cleanup_pending:
            try:
                self._attempt_cleanup()
            except EtcdException as e:
                _log.error("Cleanup failed: %r", e)
            else:
                self._cleanup_pending = False

        if self._reporting_allowed:
            # We're not rate limited, go ahead and do a write to etcd.
            _log.debug("Status reporting is allowed by rate limit.")
            if not self._older_dirty_endpoints and self._newer_dirty_endpoints:
                _log.debug("_older_dirty_endpoints empty, promoting"
                           "_newer_dirty_endpoints")
                self._older_dirty_endpoints = self._newer_dirty_endpoints
                self._newer_dirty_endpoints = set()
            if self._older_dirty_endpoints:
                ep_id = self._older_dirty_endpoints.pop()
                status_v4 = self._endpoint_status[IPV4].get(ep_id)
                status_v6 = self._endpoint_status[IPV6].get(ep_id)
                status = combine_statuses(status_v4, status_v6)
                try:
                    self._write_endpoint_status_to_etcd(ep_id, status)
                except EtcdException:
                    _log.error("Failed to report status for %s, will retry",
                               ep_id)
                    # Add it into the next dirty set.  Retrying in the next
                    # batch ensures that we try to update all of the dirty
                    # endpoints before we do any retries, ensuring fairness.
                    self._newer_dirty_endpoints.add(ep_id)
                # Reset the rate limit flag.
                self._reporting_allowed = False

        if not self._timer_scheduled and ((not self._reporting_allowed) or
                                          self._cleanup_pending):
            # Schedule a timer to stop our rate limiting or retry cleanup.
            timeout = self._config.ENDPOINT_REPORT_DELAY
            timeout *= 0.9 + (random.random() * 0.2)  # Jitter by +/- 10%.
            gevent.spawn_later(timeout,
                               self._on_timer_pop,
                               async=True)
            self._timer_scheduled = True

    def _attempt_cleanup(self):
        our_host_dir = "/".join([FELIX_STATUS_DIR, self._config.HOSTNAME,
                                 "workload"])
        try:
            # Grab all the existing status reports.
            response = self.client.read(our_host_dir,
                                        recursive=True)
        except EtcdKeyNotFound:
            _log.info("No endpoint statuses found, nothing to clean up")
        else:
            # Mark all statuses we find as dirty.  This will result in any
            # unknown endpoints being cleaned up.
            for node in response.leaves:
                combined_id = get_endpoint_id_from_key(node.key)
                if combined_id:
                    _log.debug("Endpoint %s removed by resync, marking "
                               "status key for cleanup",
                               combined_id)
                    self._mark_endpoint_dirty(combined_id)
                elif node.dir:
                    # This leaf is an empty directory, try to clean it up.
                    # This is safe even if another thread is adding keys back
                    # into the directory.
                    _log.debug("Found empty directory %s, cleaning up",
                               node.key)
                    delete_empty_parents(self.client, node.key, our_host_dir)

    def _write_endpoint_status_to_etcd(self, ep_id, status):
        """
        Try to actually write the status dict into etcd or delete the key
        if it is no longer needed.
        """
        status_key = ep_id.path_for_status
        if status:
            _log.debug("Writing endpoint status %s = %s", ep_id, status)
            self.client.set(status_key,
                            json.dumps(status))
        else:
            _log.debug("Removing endpoint status %s", ep_id)
            try:
                self.client.delete(status_key)
            except EtcdKeyNotFound:
                _log.debug("Tried to delete %s but it was already gone",
                           status_key)
            # Clean up any now-empty parent directories.
            delete_empty_parents(
                self.client,
                status_key.rsplit("/", 1)[0],  # Snip off final path segment.
                dir_for_felix_status(self._config.HOSTNAME)
            )


def combine_statuses(status_a, status_b):
    """
    Combines a pair of status reports for the same interface.

    If one status is None, the other is returned.  Otherwise, the worst
    status wins.
    """
    if not status_a:
        return status_b
    if not status_b:
        return status_a
    a = status_a["status"]
    b = status_b["status"]
    if a == ENDPOINT_STATUS_ERROR or b == ENDPOINT_STATUS_ERROR:
        return {"status": ENDPOINT_STATUS_ERROR}
    elif a == ENDPOINT_STATUS_DOWN or b == ENDPOINT_STATUS_DOWN:
        return {"status": ENDPOINT_STATUS_DOWN}
    else:
        return {"status": ENDPOINT_STATUS_UP}


def die_and_restart():
    # Sleep so that we can't die more than 5 times in 10s even if someone is
    # churning the config.  This prevents our upstart/systemd jobs from giving
    # up on us.
    gevent.sleep(2)
    # Use a failure code to tell systemd that we expect to be restarted.  We
    # use os._exit() because it is bullet-proof.
    os._exit(1)


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
    "src_tag",
    "dst_tag",
    "action",
])
json_decoder = json.JSONDecoder(
    object_hook=functools.partial(intern_dict,
                                  fields_to_intern=FIELDS_TO_INTERN)
)


def parse_if_endpoint(config, etcd_node):
    combined_id = get_endpoint_id_from_key(etcd_node.key)
    if combined_id:
        # Got an endpoint.
        if etcd_node.action == "delete":
            _log.debug("Found deleted endpoint %s", combined_id)
            endpoint = None
        else:
            endpoint = parse_endpoint(config, combined_id, etcd_node.value)
        # EndpointId does the interning for us.
        return combined_id, endpoint
    return None, None


def parse_endpoint(config, combined_id, raw_json):
    endpoint = safe_decode_json(raw_json,
                                log_tag="endpoint %s" % combined_id.endpoint)
    try:
        common.validate_endpoint(config, combined_id, endpoint)
    except ValidationFailed as e:
        _log.warning("Validation failed for endpoint %s, treating as "
                     "missing: %s; %r", combined_id, e.message, raw_json)
        endpoint = None
    else:
        _log.debug("Validated endpoint : %s", endpoint)
    return endpoint


def parse_if_rules(etcd_node):
    m = RULES_KEY_RE.match(etcd_node.key)
    if m:
        # Got some rules.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            rules = None
        else:
            rules = parse_rules(profile_id, etcd_node.value)
        return intern(profile_id.encode("utf8")), rules
    return None, None


def parse_rules(profile_id, raw_json):
    rules = safe_decode_json(raw_json, log_tag="rules %s" % profile_id)
    try:
        common.validate_rules(profile_id, rules)
    except ValidationFailed as e:
        _log.exception("Validation failed for profile %s rules: %s; %r",
                       profile_id, rules, e)
        return None
    else:
        return rules


def parse_if_tags(etcd_node):
    m = TAGS_KEY_RE.match(etcd_node.key)
    if m:
        # Got some tags.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            tags = None
        else:
            tags = parse_tags(profile_id, etcd_node.value)
        return intern(profile_id.encode("utf8")), tags
    return None, None


def parse_tags(profile_id, raw_json):
    tags = safe_decode_json(raw_json, log_tag="tags %s" % profile_id)
    try:
        common.validate_tags(profile_id, tags)
    except ValidationFailed:
        _log.exception("Validation failed for profile %s tags : %s",
                       profile_id, tags)
        return None
    else:
        # The tags aren't in a top-level object so we need to manually
        # intern them here.
        return intern_list(tags)


def parse_if_host_ip(etcd_node):
    m = HOST_IP_KEY_RE.match(etcd_node.key)
    if m:
        # Got some rules.
        hostname = m.group("hostname")
        if etcd_node.action == "delete":
            ip = None
        else:
            ip = parse_host_ip(hostname, etcd_node.value)
        return hostname, ip
    return None, None


def parse_host_ip(hostname, raw_value):
    if raw_value is None or validate_ip_addr(raw_value):
        return canonicalise_ip(raw_value, None)
    else:
        _log.debug("%s has invalid IP: %r", hostname, raw_value)
        return None


def parse_if_ipam_v4_pool(etcd_node):
    m = IPAM_V4_CIDR_KEY_RE.match(etcd_node.key)
    if m:
        # Got some rules.
        pool_id = m.group("encoded_cidr")
        if etcd_node.action == "delete":
            pool = None
        else:
            pool = parse_ipam_pool(pool_id, etcd_node.value)
        return pool_id, pool
    return None, None


def parse_ipam_pool(pool_id, raw_json):
    pool = safe_decode_json(raw_json, log_tag="ipam pool %s" % pool_id)
    try:
        common.validate_ipam_pool(pool_id, pool, 4)
    except ValidationFailed as e:
        _log.exception("Validation failed for ipam pool %s: %s; %r",
                       pool_id, pool, e)
        return None
    else:
        return pool


def safe_decode_json(raw_json, log_tag=None):
    try:
        return json_decoder.decode(raw_json)
    except (TypeError, ValueError):
        _log.warning("Failed to decode JSON for %s: %r.  Returning None.",
                     log_tag, raw_json)
        return None


class Node(object):
    __slots__ = ("key", "value", "action", "current_key", "modifiedIndex")

    def __init__(self):
        self.modifiedIndex = None
        self.key = None
        self.value = None
        self.action = None
        self.current_key = None
