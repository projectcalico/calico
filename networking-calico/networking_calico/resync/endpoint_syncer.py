# -*- coding: utf-8 -*-
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

"""Resync-specific WorkloadEndpoint logic.

The :class:`EndpointSyncer` here drives a full reconcile of WorkloadEndpoint and
LiveMigration state between Neutron ports and etcd.  It is only used from the resync
runner.

The per-port write/delete operations (``write_endpoint``, ``delete_endpoint``,
``write_live_migration``, ``delete_live_migration``, plus the helpers that build a
port_extra from a port) live on :class:`EndpointWriter` in the driver-side endpoints
module - because the driver's port and SG postcommit hooks also call them.
``EndpointSyncer`` wraps an existing ``EndpointWriter`` (the same instance used by the
postcommit hooks) and just adds the resync orchestration on top.
"""

from neutron_lib import exceptions as n_exc

from oslo_log import log

from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.plugins.ml2.drivers.calico.endpoints import (
    _port_is_endpoint_port,
    endpoint_annotations,
    endpoint_labels,
    endpoint_name,
    endpoint_name_without_host,
    endpoint_spec,
    live_migration_spec,
)

from networking_calico.resync.syncer import ResourceGone
from networking_calico.resync.syncer import ResourceSyncer

LOG = log.getLogger(__name__)


class EndpointSyncer(ResourceSyncer):
    """Resync WorkloadEndpoint and LiveMigration state.

    Wraps an :class:`EndpointWriter` and reuses it for everything per-port (translating
    a Neutron port into etcd write data, writing a destination WEP for a migrating port,
    etc.).  Adds:

      * the ResourceSyncer overrides that the full-reconcile path in
        :meth:`ResourceSyncer.resync` needs (etcd reads, neutron reads, comparison-aware
        writes/deletes); and

      * a LiveMigration reconcile pass that runs after the WEP reconcile.
    """

    def __init__(self, writer, txn_from_context):
        super(EndpointSyncer, self).__init__(
            writer.db, txn_from_context, "WorkloadEndpoint"
        )
        self.writer = writer
        self.namespace = writer.namespace
        # LiveMigration write/delete counts for the in-progress resync.
        # Reset at the start of each resync() and merged into the summary at the end,
        # so callers can distinguish LM activity from WorkloadEndpoint activity (the
        # base class only reports a single set of counters covering both).
        self._lm_counts = {"created": 0, "updated": 0, "deleted": 0}

    def resync(self, context, scope):
        self._lm_counts = {"created": 0, "updated": 0, "deleted": 0}
        summary = super(EndpointSyncer, self).resync(context, scope)
        summary["lm_created"] = self._lm_counts["created"]
        summary["lm_updated"] = self._lm_counts["updated"]
        summary["lm_deleted"] = self._lm_counts["deleted"]
        return summary

    def get_from_neutron(self, context, scope):
        if scope.all():
            ports = self.db.get_ports(context)
        else:
            ports = self.db.get_ports(context, filters={"id": list(scope.ids())})

        neutron_map = {}
        for port in ports:
            if not _port_is_endpoint_port(port):
                continue
            neutron_map["wep " + endpoint_name(port)] = port
            if "binding:profile" in port and "migrating_to" in port["binding:profile"]:
                dest_host = port["binding:profile"]["migrating_to"]
                dest_port = port.copy()
                dest_port["binding:host_id"] = dest_host
                dest_wep_name = endpoint_name(dest_port)
                neutron_map["wep " + dest_wep_name] = dest_port
                neutron_map["lm " + dest_wep_name] = (port, dest_port)

        return neutron_map

    def get_from_etcd(self, scope, neutron_map):
        if scope.all():
            etcd_map = {
                "wep " + name: (spec, revision)
                for name, spec, revision in datamodel_v3.get_all(
                    "WorkloadEndpoint", self.namespace, with_labels_and_annotations=True
                )
            }
            etcd_map.update(
                {
                    "lm " + name: (spec, revision)
                    for name, spec, revision in datamodel_v3.get_all(
                        "LiveMigration", self.namespace
                    )
                }
            )
            return etcd_map

        live_migrations_without_host = {}
        if scope.clean_live_migrations:
            for name, spec, revision in datamodel_v3.get_all(
                "LiveMigration", self.namespace
            ):
                without_host = endpoint_name_without_host(name)
                live_migrations_without_host.setdefault(without_host, []).append(
                    (name, spec, revision)
                )

        etcd_map = {}
        for name in neutron_map:
            try:
                if name.startswith("wep "):
                    wep_name = remove_prefix(name, "wep ")
                    for etcd_name, spec, revision in live_migrations_without_host.get(
                        endpoint_name_without_host(wep_name), []
                    ):
                        etcd_map["lm " + etcd_name] = (spec, revision)
                    etcd_map[name] = datamodel_v3.get_namespaced(
                        "WorkloadEndpoint",
                        self.namespace,
                        wep_name,
                        with_labels_and_annotations=True,
                    )
                elif name.startswith("lm "):
                    etcd_map[name] = datamodel_v3.get_namespaced(
                        "LiveMigration",
                        self.namespace,
                        remove_prefix(name, "lm "),
                    )
            except etcdv3.KeyNotFound:
                pass

        return etcd_map

    def delete_legacy_etcd_data(self):
        if self.namespace != datamodel_v3.NO_REGION_NAMESPACE:
            datamodel_v3.delete_legacy("WorkloadEndpoint", "")

    # The following methods differ from those for other resources for two reasons.
    #
    # 1. For endpoints we need to read, compare and write labels and annotations as well
    # as spec.
    #
    # 2. This syncer writes LiveMigration resources as well as WorkloadEndpoints.  These
    # are distinguished by a "wep " or "lm " prefix on the name.

    def create_in_etcd(self, name, write_data):
        if name.startswith("wep "):
            spec, labels, annotations = write_data
            return datamodel_v3.put(
                "WorkloadEndpoint",
                self.namespace,
                remove_prefix(name, "wep "),
                spec,
                labels=labels,
                annotations=annotations,
                mod_revision=0,
            )

        # LiveMigration case.
        self._lm_counts["created"] += 1
        return datamodel_v3.put(
            "LiveMigration",
            self.namespace,
            remove_prefix(name, "lm "),
            write_data,
            mod_revision=0,
        )

    def update_in_etcd(self, name, write_data, mod_revision=etcdv3.MUST_UPDATE):
        if name.startswith("wep "):
            spec, labels, annotations = write_data
            return datamodel_v3.put(
                "WorkloadEndpoint",
                self.namespace,
                remove_prefix(name, "wep "),
                spec,
                labels=labels,
                annotations=annotations,
                mod_revision=mod_revision,
            )

        # LiveMigration case.
        self._lm_counts["updated"] += 1
        return datamodel_v3.put(
            "LiveMigration",
            self.namespace,
            remove_prefix(name, "lm "),
            write_data,
            mod_revision=mod_revision,
        )

    def delete_from_etcd(self, name, mod_revision):
        if name.startswith("wep "):
            return datamodel_v3.delete(
                "WorkloadEndpoint",
                self.namespace,
                remove_prefix(name, "wep "),
                mod_revision=mod_revision,
            )

        # LiveMigration case.
        self._lm_counts["deleted"] += 1
        return datamodel_v3.delete(
            "LiveMigration",
            self.namespace,
            remove_prefix(name, "lm "),
            mod_revision=mod_revision,
        )

    def neutron_to_etcd_write_data(self, name, value, context, reread=False):
        if name.startswith("lm "):
            port, dest_port = value
            return self.neutron_to_live_migration_etcd_write_data(
                port, dest_port, context, reread
            )
        else:
            return self.neutron_to_port_etcd_write_data(value, context, reread)

    def neutron_to_port_etcd_write_data(self, port, context, reread):
        if reread:
            try:
                port = self.db.get_port(context, port["id"])
            except n_exc.PortNotFound:
                raise ResourceGone()
        port_extra = self.writer.get_extra_port_information(context, port)
        return (
            endpoint_spec(port, port_extra),
            endpoint_labels(port, self.namespace, port_extra),
            endpoint_annotations(port),
        )

    def neutron_to_live_migration_etcd_write_data(
        self, port, dest_port, context, reread
    ):
        if reread:
            try:
                port = self.db.get_port(context, port["id"])
            except n_exc.PortNotFound:
                raise ResourceGone()
        return live_migration_spec(self.namespace, port, dest_port)


# This can be replaced by `s.removeprefix(prefix)` in Python 3.9+, but for OpenStack
# Caracal the minimum Python version is 3.8, so we should remain compatible with that.
def remove_prefix(s, prefix):
    return s[len(prefix) :] if s.startswith(prefix) else s
