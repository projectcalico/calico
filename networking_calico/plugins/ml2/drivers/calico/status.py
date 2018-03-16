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
import json

from networking_calico.compat import log
from networking_calico import datamodel_v1
from networking_calico import etcdutils


LOG = log.getLogger(__name__)

# Objects for lightly wrapping etcd return values for use in the mechanism
# driver.
# These namedtuples are getting pretty heavyweight at this point. If you find
# yourself wanting to add more fields to them, consider rewriting them as full
# classes. Note that several of the properties of namedtuples are desirable for
# these objects (immutability being the biggest), so if you rewrite as classes
# attempt to preserve those properties.
Endpoint = collections.namedtuple(
    'Endpoint', ['id', 'key', 'mod_revision', 'host', 'data']
)


class StatusWatcher(etcdutils.EtcdWatcher):
    """A class that watches our status-reporting subtree.

    Status events use the Calico v1 data model, under
    datamodel_v1.FELIX_STATUS_DIR, but are written and read over etcdv3.

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
        super(StatusWatcher, self).__init__(datamodel_v1.FELIX_STATUS_DIR,
                                            "/round-trip-check")
        self.calico_driver = calico_driver

        # Track the set of endpoints that are on each host so we can generate
        # endpoint notifications if a Felix goes down.
        self._endpoints_by_host = collections.defaultdict(set)

        # Track the hosts with a live Felix.
        self._hosts_with_live_felix = set()

        # Map of live Felix notifications: hostname -> the latest mod_revision
        # that we have handled for that host.  We track mod_revision because
        # EtcdWatcher has to emit duplicate notifications to us, and we want to
        # deduplicate before passing on to the Neutron DB.
        self._felix_live_rev = {}

        # Register for felix uptime updates.
        self.register_path(datamodel_v1.FELIX_STATUS_DIR +
                           "/<hostname>/status",
                           on_set=self._on_status_set,
                           on_del=self._on_status_del)
        # Register for per-port status updates.
        self.register_path(datamodel_v1.FELIX_STATUS_DIR +
                           "/<hostname>/workload/openstack/"
                           "<workload>/endpoint/<endpoint>",
                           on_set=self._on_ep_set,
                           on_del=self._on_ep_delete)
        LOG.info("StatusWatcher created")

    def _pre_snapshot_hook(self):
        # Save off current endpoint status, then reset current state, so we
        # will be able to identify any changes in the new snapshot.
        old_endpoints_by_host = self._endpoints_by_host
        self._hosts_with_live_felix = set()
        self._endpoints_by_host = collections.defaultdict(set)
        return old_endpoints_by_host

    def _post_snapshot_hook(self, old_endpoints_by_host):
        # Collect hosts for each old endpoint status.  For each of those hosts
        # we will check if we now have a Felix status.
        all_hosts_with_endpoint_status = set()
        for hostname in old_endpoints_by_host.keys():
            all_hosts_with_endpoint_status.add(hostname)

        # There might be new endpoint statuses with new hosts, for which we
        # should also check if we also have Felix status for those hosts.
        for hostname in self._endpoints_by_host.keys():
            all_hosts_with_endpoint_status.add(hostname)

        # For each of those hosts...
        for hostname in all_hosts_with_endpoint_status:
            LOG.info("host: %s", hostname)
            if hostname not in self._hosts_with_live_felix:
                # Status for a Felix has disappeared in the new snapshot.
                # Signal port status None for both the endpoints that we had
                # for that Felix _before_ the snapshot, _and_ those that we
                # have in the new snapshot.
                LOG.info("has disappeared")
                for ep_id in (old_endpoints_by_host[hostname] |
                              self._endpoints_by_host[hostname]):
                    LOG.info("signal None for %s", ep_id.endpoint)
                    self.calico_driver.on_port_status_changed(
                        hostname,
                        ep_id.endpoint,
                        None)
            else:
                # Felix is still there, but we should check for particular
                # endpoints that have disappeared, and signal those.
                LOG.info("is still alive")
                for ep_id in (old_endpoints_by_host[hostname] -
                              self._endpoints_by_host[hostname]):
                    LOG.info("signal None for %s", ep_id.endpoint)
                    self.calico_driver.on_port_status_changed(
                        hostname,
                        ep_id.endpoint,
                        None)

    def _on_status_set(self, response, hostname):
        """Called when a felix uptime report is inserted/updated."""
        try:
            value = json.loads(response.value)
            new = bool(value.get("first_update"))
        except (ValueError, TypeError):
            LOG.warning("Bad JSON data for key %s: %s",
                        response.key, response.value)
        else:
            self._hosts_with_live_felix.add(hostname)
            mod_revision = response.mod_revision
            if self._felix_live_rev.get(hostname) != mod_revision:
                self.calico_driver.on_felix_alive(
                    hostname,
                    new=new,
                )
                self._felix_live_rev[hostname] = mod_revision

    def _on_status_del(self, response, hostname):
        """Called when Felix's status key expires.  Implies felix is dead."""
        LOG.error("Felix on host %s failed to check in.  Marking the "
                  "ports it was managing as in-error.", hostname)
        self._hosts_with_live_felix.discard(hostname)
        for endpoint_id in self._endpoints_by_host[hostname]:
            # Flag all the ports as being in error.  They're no longer
            # receiving security updates.
            self.calico_driver.on_port_status_changed(
                hostname,
                endpoint_id.endpoint,
                None,
            )
        # Then discard our cache of endpoints.  If felix comes back up, it will
        # repopulate.
        self._endpoints_by_host.pop(hostname)

    def _on_ep_set(self, response, hostname, workload, endpoint):
        """Called when the status key for a particular endpoint is updated.

        Reports the status to the driver and caches the existence of the
        endpoint.
        """
        ep_id = datamodel_v1.get_endpoint_id_from_key(response.key)
        if not ep_id:
            LOG.error("Failed to extract endpoint ID from: %s.  Ignoring "
                      "update!", response.key)
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
        )

    def _on_ep_delete(self, response, hostname, workload, endpoint):
        """Called when the status key for an endpoint is deleted.

        This typically means the endpoint has been deleted.  Reports
        the deletion to the driver.
        """
        LOG.debug("Port %s/%s/%s deleted", hostname, workload, endpoint)
        endpoint_id = datamodel_v1.get_endpoint_id_from_key(response.key)
        self._endpoints_by_host[hostname].discard(endpoint_id)
        if not self._endpoints_by_host[hostname]:
            del self._endpoints_by_host[hostname]
        self.calico_driver.on_port_status_changed(
            hostname,
            endpoint,
            None,
        )
