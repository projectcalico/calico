# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Metaswitch Networks
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# Etcd-based transport for the Calico/OpenStack Plugin.

from datetime import datetime, timezone
import json

from oslo_log import log

from networking_calico import datamodel_v2
from networking_calico import etcdutils
from networking_calico.common import config as calico_config
from networking_calico.monotonic import monotonic_time


# If a Felix status update we receive from etcd has a "time" field more than this many
# seconds in the past, we are running behind and should warn the operator.  Felix writes
# status updates every 30s by default, so anything materially above that indicates a
# processing backlog.
STALE_STATUS_WARN_SECS = 300

# Rate-limit stale-status warnings to at most one per this many seconds, to avoid
# flooding the log when every update in a large batch is stale.
STALE_STATUS_WARN_INTERVAL_SECS = 300


LOG = log.getLogger(__name__)


class StatusWatcher(etcdutils.EtcdWatcher):
    """A class that watches our status-reporting subtree.

    Status events use the Calico v1 data model, under
    datamodel_v2.felix_status_dir, but are written and read over etcdv3.

    This class parses events within that subtree and passes corresponding
    updates to the mechanism driver.

    Entrypoints:
    - StatusWatcher(calico_driver) (constructor)
    - watcher.start()
    - watcher.stop()

    Callbacks (from the thread of watcher.start()):
    - calico_driver.on_port_status_changed
    - calico_driver.on_felix_alive
    """

    def __init__(self, calico_driver):
        self.region_string = calico_config.get_region_string()
        self.status_path = datamodel_v2.felix_status_dir(self.region_string)
        super(StatusWatcher, self).__init__(self.status_path, "/round-trip-check")
        self.calico_driver = calico_driver

        self.processing_snapshot = False

        # Monotonic time of the last stale-status WARNING we logged.  Used to rate-limit
        # the warning so we do not flood the log when the whole cluster is backlogged.
        # Initialised to -inf so the first stale-update encountered always passes the
        # rate-limit check, regardless of system uptime: on Linux ``monotonic_time()``
        # is seconds-since-boot, so a 0.0 sentinel would suppress the first warning on
        # any host with uptime below STALE_STATUS_WARN_INTERVAL_SECS.
        self._last_stale_warn = float("-inf")

    def _pre_snapshot_hook(self):
        self.processing_snapshot = True

    def _post_snapshot_hook(self, _):
        self.processing_snapshot = False

    def _check_for_stale_status(self, hostname, value):
        """Warn the operator if we are processing materially stale updates.

        If the "time" field inside the status value is significantly older than
        wall-clock now, this StatusWatcher is processing events slower than Felix is
        producing them, and a backlog is building up.  Left unaddressed this causes
        Neutron to see agent up/down transitions hours after they actually happened.
        Warn the operator so they can tune ReportingIntervalSecs / agent_down_time or
        investigate why processing is slow.

        Rate-limited to one warning per ``STALE_STATUS_WARN_INTERVAL_SECS``.
        """
        if self.processing_snapshot:
            # During an initial-snapshot replay the "time" values will legitimately look
            # old: Felix wrote them some time ago and we are only now reading the
            # subtree.  That is not evidence of a processing backlog -- skip the check
            # in this case.
            return

        status_time_str = value.get("time")
        if not status_time_str:
            return

        try:
            # Felix writes the time in RFC3339 with a trailing "Z"; convert to a +00:00
            # offset for datetime.fromisoformat (which has only accepted the bare "Z"
            # suffix since Python 3.11).
            status_time = datetime.fromisoformat(status_time_str.replace("Z", "+00:00"))
        except ValueError:
            LOG.warning(
                "Could not parse status time %r for host %s",
                status_time_str,
                hostname,
            )
            return

        if status_time.tzinfo is None:
            # Treat naive timestamps (no timezone info) as UTC so that the subtraction
            # below does not raise TypeError.
            status_time = status_time.replace(tzinfo=timezone.utc)

        lag = (datetime.now(tz=timezone.utc) - status_time).total_seconds()
        if lag <= STALE_STATUS_WARN_SECS:
            return

        now_mono = monotonic_time()
        if now_mono - self._last_stale_warn < STALE_STATUS_WARN_INTERVAL_SECS:
            return

        self._last_stale_warn = now_mono
        LOG.warning(
            "Processing stale Felix status update for host %s: the update"
            " was written %.0fs ago (threshold %ds).  StatusWatcher is not"
            " keeping up with the rate of updates; consider raising"
            " ReportingIntervalSecs and agent_down_time in Neutron / Felix"
            " config.",
            hostname,
            lag,
            STALE_STATUS_WARN_SECS,
        )


class AgentStatusWatcher(StatusWatcher):

    def __init__(self, calico_driver):
        super().__init__(calico_driver)

        # Map of live Felix notifications: hostname -> the latest mod_revision
        # that we have handled for that host.  We track mod_revision because
        # EtcdWatcher has to emit duplicate notifications to us, and we want to
        # deduplicate before passing on to the Neutron DB.
        self._felix_live_rev = {}

        # Register for felix uptime updates.
        self.register_path(
            self.status_path + "/<hostname>/status",
            on_set=self._on_status_set,
            on_del=self._on_status_del,
        )

    def _on_status_set(self, response, hostname):
        """Called when a felix uptime report is inserted/updated."""
        try:
            value = json.loads(response.value)
            new = bool(value.get("first_update"))
        except (ValueError, TypeError):
            LOG.warning("Bad JSON data for key %s: %s", response.key, response.value)
        else:
            self._check_for_stale_status(hostname, value)
            mod_revision = response.mod_revision
            if self._felix_live_rev.get(hostname) != mod_revision:
                self.calico_driver.on_felix_alive(
                    hostname,
                    new=new,
                )
                self._felix_live_rev[hostname] = mod_revision

    def _on_status_del(self, response, hostname):
        """Called when Felix's status key expires.  Implies felix is dead."""
        # Notes:
        #
        # - we used to mark the ports that Felix was managing as in-ERROR
        #   here but, at high scale, that can cause a DoS if the failure is
        #   not limited to a single Felix (an etcd connectivity outage, for
        #   example).
        #
        # - There's no way to report the failure to neutron; neutron spots
        #   agent failures by timeout.
        LOG.error("Felix on host %s failed to check in.", hostname)


class EndpointStatusWatcher(StatusWatcher):

    def __init__(self, calico_driver):
        super().__init__(calico_driver)

        # The port statuses currently in etcd, so that a new snapshot can spot those
        # removed while we weren't watching.
        self._status_ids = set()

        # The statuses to check against while a snapshot is under way.  A snapshot that
        # fails partway is retried without finishing, and the statuses from before it
        # still need checking then, not just those it had loaded.
        self._unreconciled_status_ids = set()

        self.register_path(
            self.status_path
            + "/<hostname>/workload/openstack/<workload>/endpoint/<endpoint>",
            on_set=self._on_ep_set,
            on_del=self._on_ep_delete,
        )

    def _pre_snapshot_hook(self):
        # Save off the current statuses, then start afresh, so that we can spot which
        # are missing from the new snapshot.
        old_status_ids = self._unreconciled_status_ids | self._status_ids
        self._unreconciled_status_ids = old_status_ids
        self._status_ids = set()
        super()._pre_snapshot_hook()
        return old_status_ids

    def _post_snapshot_hook(self, old_status_ids):
        # Signal the statuses that have disappeared.
        for status_id in old_status_ids - self._status_ids:
            LOG.info("signal None for %s", status_id)
            self.calico_driver.on_port_status_changed(
                status_id.host,
                status_id.port_id,
                None,
                device_id=status_id.device_id,
                priority="low",
            )
        self._unreconciled_status_ids = set()
        super()._post_snapshot_hook(None)

    def _on_ep_set(self, response, hostname, workload, endpoint):
        """Called when the status key for a particular endpoint is updated.

        Reports the status to the driver and caches the existence of the
        endpoint.
        """
        status_id = datamodel_v2.get_port_status_id_from_key(
            self.region_string, response.key
        )
        if not status_id:
            LOG.error(
                "Failed to extract endpoint ID from: %s.  Ignoring update!",
                response.key,
            )
            return
        self._report_status(status_id, response.value)

    def _report_status(self, status_id, raw_json):
        try:
            status_dict = json.loads(raw_json)
        except (ValueError, TypeError):
            LOG.error("Bad JSON data for %s: %s", status_id, raw_json)
            status = None  # As if the status were deleted.
            self._status_ids.discard(status_id)
        else:
            self._status_ids.add(status_id)

            # Unwrap the dict around the actual status.
            status = (
                status_dict.get("status") if isinstance(status_dict, dict) else None
            )
        LOG.debug("Port %s updated to status %s", status_id, status)
        self.calico_driver.on_port_status_changed(
            status_id.host,
            status_id.port_id,
            status,
            device_id=status_id.device_id,
            priority="low" if self.processing_snapshot else "high",
        )

    def _on_ep_delete(self, response, hostname, workload, endpoint):
        """Called when the status key for an endpoint is deleted.

        This typically means the endpoint has been deleted.  Reports
        the deletion to the driver.
        """
        LOG.debug("Port %s/%s/%s deleted", hostname, workload, endpoint)
        status_id = datamodel_v2.get_port_status_id_from_key(
            self.region_string, response.key
        )
        if not status_id:
            # As on a set, which would have ignored this key too.
            LOG.error(
                "Failed to extract endpoint ID from: %s.  Ignoring deletion!",
                response.key,
            )
            return
        self._status_ids.discard(status_id)
        self.calico_driver.on_port_status_changed(
            status_id.host,
            status_id.port_id,
            None,
            device_id=status_id.device_id,
            priority="low" if self.processing_snapshot else "high",
        )
