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

import collections
from datetime import datetime, timezone
import json

from oslo_log import log

from networking_calico import datamodel_v2
from networking_calico import etcdutils
from networking_calico.common import config as calico_config
from networking_calico.monotonic import monotonic_time


# If a Felix status update we receive from etcd has a "time" field more than
# this many seconds in the past, we are running behind and should warn the
# operator.  Felix writes status updates every 30s by default, so anything
# materially above that indicates a processing backlog.
STALE_STATUS_WARN_SECS = 300

# Rate-limit stale-status warnings to at most one per this many seconds, to
# avoid flooding the log when every update in a large batch is stale.
STALE_STATUS_WARN_INTERVAL_SECS = 300


LOG = log.getLogger(__name__)

# Objects for lightly wrapping etcd return values for use in the mechanism
# driver.
# These namedtuples are getting pretty heavyweight at this point. If you find
# yourself wanting to add more fields to them, consider rewriting them as full
# classes. Note that several of the properties of namedtuples are desirable for
# these objects (immutability being the biggest), so if you rewrite as classes
# attempt to preserve those properties.
Endpoint = collections.namedtuple(
    "Endpoint", ["id", "key", "mod_revision", "host", "data"]
)


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
        status_path = datamodel_v2.felix_status_dir(self.region_string)
        super(StatusWatcher, self).__init__(status_path, "/round-trip-check")
        self.calico_driver = calico_driver

        self.processing_snapshot = False

        # Track the set of endpoints that are on each host so we can spot
        # removed endpoints during a resync.
        self._endpoints_by_host = collections.defaultdict(set)

        # Map of live Felix notifications: hostname -> the latest mod_revision
        # that we have handled for that host.  We track mod_revision because
        # EtcdWatcher has to emit duplicate notifications to us, and we want to
        # deduplicate before passing on to the Neutron DB.
        self._felix_live_rev = {}

        # Monotonic time of the last stale-status WARNING we logged.  Used to
        # rate-limit the warning so we do not flood the log when the whole
        # cluster is backlogged.
        self._last_stale_warn = 0.0

        # Register for felix uptime updates.
        self.register_path(
            status_path + "/<hostname>/status",
            on_set=self._on_status_set,
            on_del=self._on_status_del,
        )
        # Register for per-port status updates.
        self.register_path(
            status_path
            + "/<hostname>/workload/openstack/<workload>/endpoint/<endpoint>",
            on_set=self._on_ep_set,
            on_del=self._on_ep_delete,
        )
        LOG.info("StatusWatcher created")

    def _pre_snapshot_hook(self):
        # Save off current endpoint status, then reset current state, so we
        # will be able to identify any changes in the new snapshot.
        old_endpoints_by_host = self._endpoints_by_host
        self._endpoints_by_host = collections.defaultdict(set)
        self.processing_snapshot = True
        return old_endpoints_by_host

    def _post_snapshot_hook(self, old_endpoints_by_host):
        # Look for previous endpoints that are no longer present...
        for hostname, ep_ids in old_endpoints_by_host.items():
            LOG.info("host: %s", hostname)
            # Avoid self._endpoints_by_host[hostname] since that would
            # auto-create the entry in the new dict, which would cause a
            # leak.
            new_ep_ids = self._endpoints_by_host.get(hostname, set())
            # Check for particular endpoints that have disappeared, and
            # signal those.
            for ep_id in ep_ids.difference(new_ep_ids):
                LOG.info("signal None for %s", ep_id.endpoint)
                self.calico_driver.on_port_status_changed(
                    hostname, ep_id.endpoint, None, priority="low"
                )
        self.processing_snapshot = False

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

    def _check_for_stale_status(self, hostname, value):
        """Warn the operator if we are processing materially stale updates.

        If the "time" field inside the status value is significantly older
        than wall-clock now, this StatusWatcher is processing events slower
        than Felix is producing them, and a backlog is building up.  Left
        unaddressed this causes neutron to see agent up/down transitions
        hours after they actually happened.  Warn the operator so they can
        tune ReportingIntervalSecs / agent_down_time or investigate why
        processing is slow.

        Rate-limited to one warning per STALE_STATUS_WARN_INTERVAL_SECS.
        """
        if self.processing_snapshot:
            # During an initial-snapshot replay the "time" values will
            # legitimately look old: Felix wrote them some time ago and
            # we're only now reading the subtree.  That is not evidence of
            # a processing backlog - skip the check in this case.
            return
        status_time_str = value.get("time")
        if not status_time_str:
            return
        try:
            # Felix writes the time in RFC3339 with a trailing "Z"; convert
            # to a +00:00 offset for datetime.fromisoformat (which has only
            # accepted the bare "Z" suffix since Python 3.11).
            status_time = datetime.fromisoformat(status_time_str.replace("Z", "+00:00"))
        except ValueError:
            LOG.warning(
                "Could not parse status time %r for host %s",
                status_time_str,
                hostname,
            )
            return
        lag = (datetime.now(tz=timezone.utc) - status_time).total_seconds()
        if lag <= STALE_STATUS_WARN_SECS:
            return
        now_mono = monotonic_time()
        if now_mono - self._last_stale_warn < STALE_STATUS_WARN_INTERVAL_SECS:
            return
        self._last_stale_warn = now_mono
        LOG.warning(
            "Processing stale Felix status update for host %s: the update was"
            " written %.0fs ago (threshold %ds).  StatusWatcher is not keeping"
            " up with the rate of updates; consider raising ReportingIntervalSecs"
            " and agent_down_time in Neutron / Felix config.",
            hostname,
            lag,
            STALE_STATUS_WARN_SECS,
        )

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

    def _on_ep_set(self, response, hostname, workload, endpoint):
        """Called when the status key for a particular endpoint is updated.

        Reports the status to the driver and caches the existence of the
        endpoint.
        """
        ep_id = datamodel_v2.get_endpoint_id_from_key(self.region_string, response.key)
        if not ep_id:
            LOG.error(
                "Failed to extract endpoint ID from: %s.  Ignoring update!",
                response.key,
            )
            return
        self._report_status(ep_id, response.value)

    def _report_status(self, endpoint_id, raw_json):
        try:
            status = json.loads(raw_json)
        except (ValueError, TypeError):
            LOG.error("Bad JSON data for %s: %s", endpoint_id, raw_json)
            status = None  # Report as error
            self._endpoints_by_host[endpoint_id.host].discard(endpoint_id)
            if not self._endpoints_by_host[endpoint_id.host]:
                del self._endpoints_by_host[endpoint_id.host]
        else:
            self._endpoints_by_host[endpoint_id.host].add(endpoint_id)
        LOG.debug("Port %s updated to status %s", endpoint_id, status)
        self.calico_driver.on_port_status_changed(
            endpoint_id.host,
            endpoint_id.endpoint,
            status,
            priority="low" if self.processing_snapshot else "high",
        )

    def _on_ep_delete(self, response, hostname, workload, endpoint):
        """Called when the status key for an endpoint is deleted.

        This typically means the endpoint has been deleted.  Reports
        the deletion to the driver.
        """
        LOG.debug("Port %s/%s/%s deleted", hostname, workload, endpoint)
        endpoint_id = datamodel_v2.get_endpoint_id_from_key(
            self.region_string, response.key
        )
        self._endpoints_by_host[hostname].discard(endpoint_id)
        if not self._endpoints_by_host[hostname]:
            del self._endpoints_by_host[hostname]
        self.calico_driver.on_port_status_changed(
            hostname,
            endpoint,
            None,
            priority="low" if self.processing_snapshot else "high",
        )
