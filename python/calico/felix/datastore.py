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
felix.datastore
~~~~~~~~~~~~

Our API to etcd.  Contains function to synchronize felix with etcd
as well as reporting our status into etcd.
"""
import logging
import os
import random
import sys

import gevent
from calico.datamodel_v1 import (
    WloadEndpointId, ENDPOINT_STATUS_ERROR,
    ENDPOINT_STATUS_DOWN, ENDPOINT_STATUS_UP,
    TieredPolicyId, HostEndpointId, EndpointId)
from calico.felix import felixbackend_pb2
from calico.felix.actor import Actor, actor_message, TimedGreenlet
from calico.felix.futils import (
    logging_exceptions, iso_utc_timestamp, IPV4,
    IPV6, StatCounter
)
from calico.felix.protocol import *
from calico.monotonic import monotonic_time
from gevent.event import Event
from google.protobuf.descriptor import FieldDescriptor

_log = logging.getLogger(__name__)


RETRY_DELAY = 5

# Max number of events from driver process before we yield to another greenlet.
MAX_EVENTS_BEFORE_YIELD = 200


# Global diagnostic counters.
_stats = StatCounter("Etcd counters")


class DatastoreAPI(Actor):
    """
    Our API to the datastore via the backend driver process.
    """

    def __init__(self, config, pipe_from_parent, pipe_to_parent, hosts_ipset):
        super(DatastoreAPI, self).__init__()
        self._config = config
        self.pipe_from_parent = pipe_from_parent
        self.pipe_to_parent = pipe_to_parent
        self.hosts_ipset = hosts_ipset

        # Timestamp storing when the DatastoreAPI started. This info is needed
        # in order to report uptime to etcd.
        self._start_time = monotonic_time()

        # The main etcd-watching greenlet.
        self._reader = None

        # One-way flag indicating we're being shut down.
        self.killed = False

    def _on_actor_started(self):
        _log.info("%s starting worker threads", self)
        reader, writer = self._connect_to_driver()

        self.write_api = DatastoreWriter(self._config, writer)
        self.write_api.start()  # Sends the init message to the back-end.

        self._reader = DatastoreReader(
            self._config,
            reader,
            self.write_api,
            self.hosts_ipset,
        )
        self._reader.link(self._on_worker_died)
        self._reader.start()

    def _connect_to_driver(self):
        # Wrap the pipes in reader/writer objects that simplify using the
        # protocol.
        reader = MessageReader(self.pipe_from_parent)
        writer = MessageWriter(self.pipe_to_parent)
        return reader, writer

    def driver_cmd(self, sck_filename):
        if getattr(sys, "frozen", False):
            # We're running under pyinstaller, where we share our
            # executable with the etcd driver.  Re-run this executable
            # with the "driver" argument to invoke the etcd driver.
            cmd = [sys.argv[0], "driver"]
        else:
            # Not running under pyinstaller, execute the etcd driver
            # directly.
            cmd = [sys.executable, "-m", "calico.etcddriver"]
        # etcd driver takes the felix socket name as argument.
        cmd = ["/home/gulfstream/go-work/src/github.com/tigera/"
               "libcalico-go/bin/felix-backend"]
        cmd += [sck_filename]
        return cmd

    @actor_message()
    def load_config(self):
        """
        Loads our config from etcd, should only be called once.

        :return: an Event which is triggered when the config has been loaded.
        """
        self._reader.load_config.set()
        return self._reader.configured

    @actor_message()
    def start_watch(self, splitter):
        """
        Starts watching etcd for changes.  Implicitly loads the config
        if it hasn't been loaded yet.
        """
        assert self._reader.load_config.is_set(), (
            "load_config() should be called before start_watch()."
        )
        self._reader.splitter = splitter
        self._reader.begin_polling.set()

    @actor_message()
    def kill(self):
        self.killed = True
        self._reader.kill_watcher()

    def _on_worker_died(self, watch_greenlet):
        """
        Greenlet: spawned by the gevent Hub if the etcd watch loop ever
        stops, kills the process.
        """
        _log.critical("Worker greenlet died: %s; exiting.", watch_greenlet)
        sys.exit(1)


class DatastoreReader(TimedGreenlet):
    """
    Greenlet that read from the etcd driver over a socket.

    * Does the initial handshake with the driver, sending it the init
      message.
    * Receives the pre-loaded config from the driver and uses that
      to do Felix's one-off configuration.
    * Sends the relevant config back to the driver.
    * Processes the event stream from the driver, sending it on to
      the splitter.

    This class is similar to the EtcdWatcher class in that it uses
    a PathDispatcher to fan out updates but it doesn't own an etcd
    connection of its own.
    """

    def __init__(self, config, msg_reader, datastore_writer, hosts_ipset):
        super(DatastoreReader, self).__init__()
        self._config = config
        self.hosts_ipset = hosts_ipset
        self._msg_reader = msg_reader
        self._datastore_writer = datastore_writer
        # Whether we've been in sync with etcd at some point.
        self._been_in_sync = False
        # Keep track of the config loaded from etcd so we can spot if it
        # changes.
        self.last_global_config = None
        self.last_host_config = None
        # Events triggered by the DatastoreAPI Actor to tell us to load the
        # config and start polling.  These are one-way flags.
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
        # True if we've been shut down.
        self.killed = False
        # Stats.
        self.read_count = 0
        self.ip_upd_count = 0
        self.ip_remove_count = 0
        self.msgs_processed = 0
        self.last_rate_log_time = monotonic_time()
        self.last_ip_upd_log_time = monotonic_time()
        self.last_ip_remove_log_time = monotonic_time()

    @logging_exceptions
    def _run(self):
        # Don't do anything until we're told to load the config.
        _log.info("Waiting for load_config event...")
        self.load_config.wait()
        _log.info("...load_config set.  Starting driver read %s loop", self)
        # Loop reading from the socket and processing messages.
        self._loop_reading_from_driver()

    def _loop_reading_from_driver(self):
        while True:
            try:
                # Note: self._msg_reader.new_messages() returns iterator so
                # whole for loop must be inside the try.
                for msg_type, msg, seq_no in self._msg_reader.new_messages():
                    self._dispatch_msg_from_driver(msg_type, msg, seq_no)
            except SocketClosed:
                _log.critical("The driver process closed its socket, Felix "
                              "must exit.")
                die_and_restart()

    def _dispatch_msg_from_driver(self, msg_type, msg, seq_no):
        _log.debug("Dispatching message (%s) of type: %s", seq_no, msg_type)
        if msg_type not in {MSG_TYPE_CONFIG_UPDATE,
                            MSG_TYPE_INIT,
                            MSG_TYPE_IN_SYNC}:
            if not self.begin_polling.is_set():
                _log.info("Non-init message, waiting for begin_polling flag")
            self.begin_polling.wait()

        if msg_type == MSG_TYPE_IPSET_DELTA:
            _stats.increment("IP set delta messages")
            self._on_ipset_delta_msg_from_driver(msg)
        elif msg_type == MSG_TYPE_IPSET_REMOVED:
            _stats.increment("IP set removed messages")
            self._on_ipset_removed_msg_from_driver(msg)
        elif msg_type == MSG_TYPE_IPSET_UPDATE:
            _stats.increment("IP set added messages")
            self._on_ipset_update_msg_from_driver(msg)
        elif msg_type == MSG_TYPE_WL_EP_UPDATE:
            _stats.increment("Workload endpoint update messages")
            self.on_wl_endpoint_update(msg)
        elif msg_type == MSG_TYPE_WL_EP_REMOVE:
            _stats.increment("Workload endpoint remove messages")
            self.on_wl_endpoint_remove(msg)
        elif msg_type == MSG_TYPE_HOST_EP_UPDATE:
            _stats.increment("Host endpoint update messages")
            self.on_host_ep_update(msg)
        elif msg_type == MSG_TYPE_HOST_EP_REMOVE:
            _stats.increment("Host endpoint update remove")
            self.on_host_ep_remove(msg)
        elif msg_type == MSG_TYPE_HOST_METADATA_UPDATE:
            _stats.increment("Host endpoint update messages")
            self.on_host_meta_update(msg)
        elif msg_type == MSG_TYPE_HOST_METADATA_REMOVE:
            _stats.increment("Host endpoint remove messages")
            self.on_host_meta_remove(msg)
        elif msg_type == MSG_TYPE_IPAM_POOL_UPDATE:
            _stats.increment("IPAM pool update messagess")
            self.on_ipam_pool_update(msg)
        elif msg_type == MSG_TYPE_IPAM_POOL_REMOVE:
            _stats.increment("IPAM pool remove messages")
            self.on_ipam_pool_remove(msg)
        elif msg_type == MSG_TYPE_POLICY_UPDATE:
            _stats.increment("Policy update messages")
            self.on_tiered_policy_update(msg)
        elif msg_type == MSG_TYPE_POLICY_REMOVED:
            _stats.increment("Policy update messages")
            self.on_tiered_policy_remove(msg)
        elif msg_type == MSG_TYPE_PROFILE_UPDATE:
            _stats.increment("Profile update messages")
            self.on_prof_rules_update(msg)
        elif msg_type == MSG_TYPE_PROFILE_REMOVED:
            _stats.increment("Profile update messages")
            self.on_prof_rules_remove(msg)
        elif msg_type == MSG_TYPE_CONFIG_UPDATE:
            _stats.increment("Config loaded messages")
            self._on_config_update(msg)
        elif msg_type == MSG_TYPE_IN_SYNC:
            _stats.increment("Status messages")
            self._on_in_sync(msg)
        else:
            _log.error("Unexpected message %r %s", msg_type, msg)
            raise RuntimeError("Unexpected message %s" % msg)
        self.msgs_processed += 1
        if self.msgs_processed % MAX_EVENTS_BEFORE_YIELD == 0:
            # Yield to ensure that other actors make progress.  (gevent only
            # yields for us if the socket would block.)  The sleep must be
            # non-zero to work around gevent issue where we could be
            # immediately rescheduled.
            gevent.sleep(0.000001)

    def _on_config_update(self, msg):
        """
        Called when we receive a config loaded message from the driver.

        This message is expected once per resync, when the config is
        pre-loaded by the driver.

        On the first call, responds to the driver synchronously with a
        config response.

        If the config has changed since a previous call, triggers Felix
        to die.
        """
        global_config = dict(msg.config)
        host_config = dict(msg.config)
        _log.info("Config loaded by driver: %s", msg.config)
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
            self._config.update_from(msg.config)
            _log.info("Config loaded: %s", self._config.__dict__)
            self.configured.set()
        self._datastore_writer.on_config_resolved(async=True)
        _log.info("Config loaded by driver: %s", msg.config)

    def _on_in_sync(self, msg):
        """
        Called when we receive a status update from the driver.

        The driver sends us status messages whenever its status changes.
        It moves through these states:

        (1) wait-for-ready (waiting for the global ready flag to become set)
        (2) resync (resyncing with etcd, processing a snapshot and any
            concurrent events)
        (3) in-sync (snapshot processsing complete, now processing only events
            from etcd)

        If the driver falls out of sync with etcd then it will start again
        from (1).

        If the status is in-sync, triggers the relevant processing.
        """
        _log.info("Datastore now in sync")
        # We're now in sync, tell the Actors that need to do start-of-day
        # cleanup.
        self.begin_polling.wait()  # Make sure splitter is set.
        self._been_in_sync = True
        self.splitter.on_datamodel_in_sync()
        self._update_hosts_ipset()

    def _on_ipset_update_msg_from_driver(self, msg):
        self.splitter.on_ipset_update(msg.id,
                                      msg.members or [])

    def _on_ipset_removed_msg_from_driver(self, msg):
        self.splitter.on_ipset_removed(msg.id)

    def _on_ipset_delta_msg_from_driver(self, msg):
        _log.debug("IP set delta updates: %s", msg)
        # Output some very coarse stats.
        self.ip_upd_count += 1
        if self.ip_upd_count % 1000 == 0:
            now = monotonic_time()
            delta = now - self.last_ip_upd_log_time
            _log.info("Processed %s IP updates from driver "
                      "%.1f/s", self.ip_upd_count, 1000.0 / delta)
            self.last_ip_upd_log_time = now
        self.splitter.on_ipset_delta_update(msg.id,
                                            msg.added_members or [],
                                            msg.removed_members or [])

    def on_wl_endpoint_update(self, msg):
        """Handler for endpoint updates, passes the update to the splitter.
        :param msg felixbackend_pb2.WorkloadEndpointUpdate"""
        hostname = self._config.HOSTNAME
        orchestrator = msg.id.orchestrator_id
        workload_id = msg.id.workload_id
        endpoint_id = msg.id.endpoint_id
        combined_id = WloadEndpointId(hostname, orchestrator, workload_id,
                                      endpoint_id)
        _log.debug("Endpoint %s updated", combined_id)
        _stats.increment("Endpoint created/updated")
        endpoint = {
            "state": msg.endpoint.state,
            "name": msg.endpoint.name,
            "mac": msg.endpoint.mac or None,
            "profile_ids": msg.endpoint.profile_ids,
            "ipv4_nets": msg.endpoint.ipv4_nets,
            "ipv6_nets": msg.endpoint.ipv6_nets,
            "tiers": convert_pb_tiers(msg.endpoint.tiers),
        }
        self.splitter.on_endpoint_update(combined_id, endpoint)

    def on_wl_endpoint_remove(self, msg):
        """Handler for endpoint updates, passes the update to the splitter.
        :param msg felixbackend_pb2.WorkloadEndpointUpdate"""
        hostname = self._config.HOSTNAME
        orchestrator = msg.id.orchestrator_id
        workload_id = msg.id.workload_id
        endpoint_id = msg.id.endpoint_id
        combined_id = WloadEndpointId(hostname, orchestrator, workload_id,
                                      endpoint_id)
        _log.debug("Endpoint %s removed", combined_id)
        _stats.increment("Endpoint removed")
        self.splitter.on_endpoint_update(combined_id, None)

    def on_host_ep_update(self, msg):
        """Handler for create/update of host endpoint."""
        hostname = self._config.HOSTNAME
        endpoint_id = msg.id.endpoint_id
        combined_id = HostEndpointId(hostname, endpoint_id)
        _log.debug("Host endpoint %s updated", combined_id)
        _stats.increment("Host endpoint created/updated")
        endpoint = {
            "name": msg.endpoint.name or None,
            "profile_ids": msg.endpoint.profile_ids,
            "expected_ipv4_addrs": msg.endpoint.expected_ipv4_addrs,
            "expected_ipv6_addrs": msg.endpoint.expected_ipv6_addrs,
            "tiers": convert_pb_tiers(msg.endpoint.tiers),
        }
        self.splitter.on_host_ep_update(combined_id, endpoint)

    def on_host_ep_remove(self, msg):
        """Handler for create/update of host endpoint."""
        hostname = self._config.HOSTNAME
        endpoint_id = msg.id.endpoint_id
        combined_id = HostEndpointId(hostname, endpoint_id)
        _log.debug("Host endpoint %s removed", combined_id)
        _stats.increment("Host endpoint removed")
        self.splitter.on_host_ep_update(combined_id, None)

    def on_prof_rules_update(self, msg):
        """Handler for rules updates, passes the update to the splitter."""
        profile_id = msg.id.name
        _log.debug("Rules for %s set", profile_id)
        _stats.increment("Rules created/updated")
        profile_id = intern(profile_id.encode("utf8"))
        rules = {
            "inbound_rules": convert_pb_rules(msg.profile.inbound_rules),
            "outbound_rules": convert_pb_rules(msg.profile.outbound_rules),
        }
        self.splitter.on_rules_update(profile_id, rules)

    def on_prof_rules_remove(self, msg):
        """Handler for rules updates, passes the update to the splitter."""
        profile_id = msg.id.name
        _log.debug("Rules for %s set", profile_id)
        _stats.increment("Rules created/updated")
        profile_id = intern(profile_id.encode("utf8"))
        self.splitter.on_rules_update(profile_id, None)

    def on_tiered_policy_update(self, msg):
        _log.debug("Rules for %s/%s set", msg.id.tier, msg.id.name)
        _stats.increment("Tiered rules created/updated")
        policy_id = TieredPolicyId(msg.id.tier, msg.id.name)
        rules = {
            "inbound_rules": convert_pb_rules(msg.policy.inbound_rules),
            "outbound_rules": convert_pb_rules(msg.policy.outbound_rules),
        }
        self.splitter.on_rules_update(policy_id, rules)

    def on_tiered_policy_remove(self, msg):
        _log.debug("Rules for %s/%s set", msg.id.tier, msg.id.name)
        _stats.increment("Tiered rules created/updated")
        policy_id = TieredPolicyId(msg.id.tier, msg.id.name)
        self.splitter.on_rules_update(policy_id, None)

    def on_host_meta_update(self, msg):
        if not self._config.IP_IN_IP_ENABLED:
            _log.debug("Ignoring update to host IP because IP-in-IP disabled")
            return
        _stats.increment("Host IP created/updated")
        self.ipv4_by_hostname[msg.hostname] = msg.ipv4_addr
        self._update_hosts_ipset()

    def on_host_meta_remove(self, msg):
        if not self._config.IP_IN_IP_ENABLED:
            _log.debug("Ignoring update to host IP because IP-in-IP is "
                       "disabled")
            return
        _stats.increment("Host IP removed")
        if self.ipv4_by_hostname.pop(msg.hostname, None):
            self._update_hosts_ipset()

    def _update_hosts_ipset(self):
        if not self._been_in_sync:
            _log.debug("Deferring update to hosts ipset until we're in-sync")
            return
        self.hosts_ipset.replace_members(
            frozenset(self.ipv4_by_hostname.values()),
            async=True
        )

    def on_ipam_pool_update(self, msg):
        _stats.increment("IPAM pool created/updated")
        pool = {
            "cidr": msg.pool.cidr,
            "masquerade": msg.pool.masquerade,
        }
        self.splitter.on_ipam_pool_updated(msg.id, pool)

    def on_ipam_pool_remove(self, msg):
        _stats.increment("IPAM pool deleted")
        self.splitter.on_ipam_pool_updated(msg.id, None)

    def kill_watcher(self):
        self.killed = True


class DatastoreWriter(Actor):
    """
    Actor that manages and rate-limits the queue of status reports to
    etcd.
    """

    def __init__(self, config, message_writer):
        super(DatastoreWriter, self).__init__()
        self._config = config
        self._start_time = monotonic_time()
        self._writer = message_writer
        self._endpoint_status = {IPV4: {}, IPV6: {}}
        self.config_resolved = False
        self._dirty_endpoints = set()
        self._reporting_allowed = True
        self._status_reporting_greenlet = None

    @logging_exceptions
    def _periodically_report_status(self):
        """
        Greenlet: periodically writes Felix's status into the datastore.

        :return: Does not return, unless reporting disabled.
        """
        interval = self._config.REPORTING_INTERVAL_SECS
        _log.info("Reporting Felix status at interval: %s", interval)

        # Do a short initial sleep before we report in.  This ensures that
        # we're stably up before we check in.
        jitter = random.random() * 0.1 * interval
        sleep_time = interval/2.0 + jitter
        _log.info("Delay before initial status report: %.1f", sleep_time)
        gevent.sleep(sleep_time)

        while True:
            self.update_felix_status(async=True)
            # Jitter by 10% of interval.
            jitter = random.random() * 0.1 * interval
            sleep_time = interval + jitter
            gevent.sleep(sleep_time)

    @actor_message()
    def on_config_resolved(self):
        # Config now fully resolved, inform the driver.
        self.config_resolved = True

        if self._config.REPORTING_INTERVAL_SECS > 0:
            self._status_reporting_greenlet = TimedGreenlet(
                self._periodically_report_status
            )
            self._status_reporting_greenlet.link_exception(
                self._on_worker_died
            )
            self._status_reporting_greenlet.start()

    @actor_message()
    def on_endpoint_status_changed(self, endpoint_id, ip_type, status):
        assert isinstance(endpoint_id, EndpointId)
        if status is not None:
            _stats.increment("Endpoint status updated")
            self._endpoint_status[ip_type][endpoint_id] = status
        else:
            _stats.increment("Endpoint status deleted")
            self._endpoint_status[ip_type].pop(endpoint_id, None)
        self._mark_endpoint_dirty(endpoint_id)

    @actor_message()
    def update_felix_status(self):
        """Sends Felix's status to the backend driver."""
        time_formatted = iso_utc_timestamp()
        uptime = monotonic_time() - self._start_time
        envelope = felixbackend_pb2.FromDataplane()
        payload = envelope.process_status_update
        payload.iso_timestamp = time_formatted
        payload.uptime = uptime
        self._writer.send_message(envelope)

    def _mark_endpoint_dirty(self, endpoint_id):
        assert isinstance(endpoint_id, EndpointId)
        _log.debug("Marking endpoint %s dirty", endpoint_id)
        self._dirty_endpoints.add(endpoint_id)

    def _finish_msg_batch(self, batch, results):
        if not self.config_resolved:
            _log.debug("Still waiting for config, skipping endpoint status "
                       "updates")
            return

        if not self._config.REPORT_ENDPOINT_STATUS:
            _log.debug("Endpoint reporting disabled, clearing any state.")
            self._endpoint_status[IPV4].clear()
            self._endpoint_status[IPV6].clear()
            self._dirty_endpoints.clear()
            return

        for ep_id in self._dirty_endpoints:
            status_v4 = self._endpoint_status[IPV4].get(ep_id)
            status_v6 = self._endpoint_status[IPV6].get(ep_id)
            status = combine_statuses(status_v4, status_v6)
            self._write_endpoint_status(ep_id, status)

        self._dirty_endpoints.clear()

    def _write_endpoint_status(self, ep_id, status):
        _stats.increment("Per-port status report writes")
        envelope = felixbackend_pb2.FromDataplane()
        if isinstance(ep_id, WloadEndpointId):
            if status is not None:
                payload = envelope.workload_endpoint_status_update
                payload.id.orchestrator_id = ep_id.orchestrator
                payload.id.workload_id = ep_id.workload
                payload.id.endpoint_id = ep_id.endpoint
                payload.status.status = status["status"]
            else:
                payload = envelope.workload_endpoint_status_remove
                payload.id.orchestrator_id = ep_id.orchestrator
                payload.id.workload_id = ep_id.workload
                payload.id.endpoint_id = ep_id.endpoint
        else:
            if status is not None:
                payload = envelope.host_endpoint_status_update
                payload.id.endpoint_id = ep_id.endpoint
                payload.status.status = status["status"]
            else:
                payload = envelope.host_endpoint_status_remove
                payload.id.endpoint_id = ep_id.endpoint
        self._writer.send_message(envelope)

    def _on_worker_died(self, watch_greenlet):
        """
        Greenlet: spawned by the gevent Hub if the worker ever stops, kills
        the process.
        """
        _log.critical("Worker greenlet died: %s; exiting.",
                      watch_greenlet)
        sys.exit(1)


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


def convert_pb_tiers(tiers):
    dict_tiers = []
    for pb_tier in tiers:
        d_tier = {"name": pb_tier.name, "policies": pb_tier.policies}
        dict_tiers.append(d_tier)
    return dict_tiers


def convert_pb_rules(pb_rules):
    dict_rules = []
    for pb_rule in pb_rules:
        _log.debug("Converting protobuf rule: %r type: %s",
                   pb_rule, pb_rule.__class__)
        d_rule = {}
        for fd, value in pb_rule.ListFields():
            if value is None:
                continue
            if fd.type == FieldDescriptor.TYPE_STRING and value == "":
                continue
            if fd.type in (FieldDescriptor.TYPE_INT32,
                           FieldDescriptor.TYPE_INT64) and value == 0:
                continue
            _log.debug("Field %s = %s", fd.name, value)
            negated = fd.name.startswith("not_")
            stem = fd.name if not negated else fd.name[4:]
            dict_name = "!" + stem if negated else stem

            if stem.endswith("_ports"):
                value = convert_pb_ports(value)
            elif stem.endswith("protocol"):
                value = convert_pb_protocol(value)
            elif stem.endswith("ip_set_ids"):
                value = list(value)

            if stem == "icmp_type_code":
                # Special case: ICMP is represented by an object, unpack it.
                d_rule[("!" if negated else "") + "icmp_type"] = value.type
                d_rule[("!" if negated else "") + "icmp_code"] = value.code
            else:
                d_rule[dict_name] = value

        dict_rules.append(d_rule)
    return dict_rules


def convert_pb_ports(pb_ports):
    _log.debug("Converting ports: %s", pb_ports)
    return map(convert_port, pb_ports)


def convert_port(pb_port):
    if pb_port.first == pb_port.last:
        return pb_port.first
    else:
        return "%s:%s" % (pb_port.first, pb_port.last)


def convert_pb_protocol(pb_proto):
    if pb_proto.HasField("number"):
        return pb_proto.number
    else:
        return pb_proto.name


def die_and_restart():
    # Sleep so that we can't die more than 5 times in 10s even if someone is
    # churning the config.  This prevents our upstart/systemd jobs from giving
    # up on us.
    gevent.sleep(2)
    # Use a failure code to tell systemd that we expect to be restarted.  We
    # use os._exit() because it is bullet-proof.
    os._exit(1)
