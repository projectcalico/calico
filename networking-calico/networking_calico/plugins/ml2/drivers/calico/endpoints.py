# -*- coding: utf-8 -*-
# Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
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

import re

from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneclient.v3.client import Client as KeystoneClient

from neutron.db import models_v2
from neutron.db.models.l3 import FloatingIP
from neutron.db.qos import models as qos_models
from neutron_lib import exceptions as n_exc
from neutron_lib.db import api as db_api

from oslo_config import cfg

from oslo_log import log

from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.common import config as calico_config
from networking_calico.plugins.ml2.drivers.calico.policy import SG_LABEL_PREFIX
from networking_calico.plugins.ml2.drivers.calico.policy import SG_NAME_LABEL_PREFIX
from networking_calico.plugins.ml2.drivers.calico.policy import SG_NAME_MAX_LENGTH
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceGone
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceSyncer


LOG = log.getLogger(__name__)


# A lightweight class to hold all of the additional information that we gather
# when translating from a Neutron port to a Calico WorkloadEndpoint.
class PortExtra(object):
    def __init__(self):
        self.fixed_ips = None
        self.floating_ips = None
        self.interface_name = None
        self.network_name = None
        self.project_data = None
        self.qos = None
        self.security_groups = None
        self.security_group_names = {}


# The Calico WorkloadEndpoint that represents an OpenStack VM gets a pair of
# labels to indicate the project (aka tenant) that the VM belongs to.  The
# label names are as follows, and the label values are the actual project ID
# and name at the time of VM creation.
#
# (OpenStack allows a project's name to be updated subsequently; if that
# happens, it is unspecified whether or not we reflect that by updating labels
# of existing WorkloadEndpoints.  In practice the project name label will
# probably change when the WorkloadEndpoint is next rewritten for some other
# reason.  Deployments that use these labels are recommended not to change
# project names post-creation.)
PROJECT_ID_LABEL_NAME = "projectcalico.org/openstack-project-id"
PROJECT_NAME_LABEL_NAME = "projectcalico.org/openstack-project-name"
PROJECT_NAME_MAX_LENGTH = datamodel_v3.SANITIZE_LABEL_MAX_LENGTH
PROJECT_PARENT_ID_LABEL_NAME = "projectcalico.org/openstack-project-parent-id"
NETWORK_NAME_LABEL_NAME = "projectcalico.org/openstack-network-name"
NETWORK_NAME_MAX_LENGTH = datamodel_v3.SANITIZE_LABEL_MAX_LENGTH

# Note: Calico requires a label value to be an empty string, or to consist of
# alphanumeric characters, '-', '_' or '.', starting and ending with an
# alphanumeric character.  If a project name does not already meet that, we
# substitute problem characters so that it does.


class WorkloadEndpointSyncer(ResourceSyncer):
    def __init__(self, db, policy_syncer, inject_per_item_delay_ms=0):
        super(WorkloadEndpointSyncer, self).__init__(
            db,
            "WorkloadEndpoint",
            inject_per_item_delay_ms=inject_per_item_delay_ms,
        )
        self.policy_syncer = policy_syncer
        self.keystone = make_keystone_client()
        self.proj_data_cache = {}
        self.region_string = calico_config.get_region_string()
        self.namespace = datamodel_v3.get_namespace(self.region_string)

        # Bulk-prefetched per-port data.  Set to a dict for the duration
        # of a resync by _prefetch_bulk_port_data(); read by
        # get_extra_port_information() which falls back to per-port
        # queries when this is None (e.g. postcommit hooks, single-port
        # writes via write_endpoint()).
        #
        # Concurrency note: this cache is process-local and assumes the
        # resync runs in a different OS process from the API / RPC forks
        # that handle dynamic postcommit hooks.  That is how the driver
        # is wired today: CalicoStartupResyncWorker (and the calico-resync
        # CLI) get their own WorkloadEndpointSyncer instance, distinct
        # from the one used by the API forks' postcommit handlers, so a
        # concurrent dynamic update cannot transitively read stale data
        # from this cache.  If the architecture ever shares a single
        # syncer instance across resync and postcommit paths in the same
        # process, this needs revisiting -- a concurrent postcommit could
        # then read self._bulk and produce a stale WEP write.
        self._bulk = None

        # Prime the project data cache now so that we do not pay a fill
        # penalty the first time we need to annotate a port on a cold start.
        self.cache_port_project_data()

    def resync(self, context, scope):
        # Clear the bulk-port-data cache after the resync completes.  In
        # production this is dead code: ``_do_startup_resync`` builds a
        # fresh syncer instance via ``Scope(self.db).run()`` (no
        # ``driver=``), and that instance gets GC'd as ``Scope.run()``
        # returns.  But the test framework reuses the driver's syncer
        # across resync and postcommit calls (``_trigger_resync(
        # driver=self.driver)``), and in that scenario a subsequent
        # ``get_extra_port_information()`` on the postcommit-hook path
        # would otherwise read stale prefetch data from a previous
        # resync.  Reset is cheap, test-correct, and defensive against
        # any future architecture that shares the instance.
        try:
            return super(WorkloadEndpointSyncer, self).resync(context, scope)
        finally:
            self._bulk = None

    def get_from_neutron(self, context, scope):
        if scope.all():
            ports = self.db.get_ports(context)
        else:
            ports = self.db.get_ports(context, filters={"id": list(scope.ids())})

        endpoint_ports = [p for p in ports if _port_is_endpoint_port(p)]

        # Pre-fetch every piece of per-port side data we need during the
        # compare phase in a handful of bulk queries, indexed by port_id /
        # network_id / qos_policy_id.  get_extra_port_information() then
        # uses the cache in O(1) instead of doing N+1 DB round-trips.
        self._prefetch_bulk_port_data(context, endpoint_ports)

        # neutron_map keys carry one of three prefixes:
        #
        # * "wep <name>"      - source-side WorkloadEndpoint for the port at its
        #                       current binding:host_id.  Value is the port dict.
        # * "dest-wep <name>" - destination-side WorkloadEndpoint for a port
        #                       that's mid-migration (binding:profile
        #                       migrating_to set).  Value is (port, dest_host) -
        #                       carrying dest_host as scope-defined data rather
        #                       than baking it into a port-dict copy means a
        #                       reread inside the update path can refetch the
        #                       port without losing the destination binding.
        # * "lm <name>"       - LiveMigration resource, paired with the
        #                       dest-side WEP.  Value is (port, dest_host) for
        #                       the same reason as dest-wep.
        neutron_map = {}
        for port in endpoint_ports:
            neutron_map["wep " + endpoint_name(port)] = port
            # binding:profile may carry migrating_to=None (or be missing entirely) after
            # a migration completes or is cancelled.  Only generate destination-side
            # entries when migrating_to is a truthy host string - calling endpoint_name
            # with host_id=None would raise.  Matches the truthy-check pattern used in
            # mech_calico.py's update_port_postcommit / status handling.
            dest_host = port.get("binding:profile", {}).get("migrating_to")
            if dest_host:
                # Compute the dest-side WEP name using a transient copy with the dest
                # host overlaid.  We don't keep the copy - the neutron_map value is
                # (port, dest_host) so the dest_host survives a reread inside the update
                # path.
                dest_wep_name = endpoint_name({**port, "binding:host_id": dest_host})
                neutron_map["dest-wep " + dest_wep_name] = (port, dest_host)
                neutron_map["lm " + dest_wep_name] = (port, dest_host)

        return neutron_map

    def _prefetch_bulk_port_data(self, context, endpoint_ports):
        """Populate self._bulk with all per-port side data in one pass.

        The five session.query() calls in get_extra_port_information()
        (plus the plugin-API calls for subnets and SG names) are
        replaced here by bulk queries indexed by port_id / network_id /
        policy_id.  get_extra_port_information() then looks them up in
        O(1) per port from self._bulk.
        """
        port_ids = [p["id"] for p in endpoint_ports]
        network_ids = list({p["network_id"] for p in endpoint_ports})
        qos_ids = {
            p.get("qos_policy_id") or p.get("qos_network_policy_id")
            for p in endpoint_ports
        }
        qos_ids.discard(None)
        qos_ids = list(qos_ids)

        # The ``context.session.query(...)`` calls below need
        # ``session.in_transaction()`` to be True, or SQLAlchemy emits "ORM session: SQL
        # execution without transaction in progress" warnings and (depending on the
        # Neutron release) drops their results.  We arrange that here via
        # ``CONTEXT_READER.using(...)`` -- mirroring the wrap in
        # ``get_extra_port_information`` for the per-port (non-bulk) path.  The wrap is
        # scoped to this function alone so it does not subsume the resync's other
        # ``self.db.get_*`` calls (in the subnet / policy syncers, and in the resync
        # compare loop), which are ``@retry_if_session_inactive``-decorated and manage
        # their own transactions -- per the Neutron devref, an outer transaction would
        # render that retry "useless".
        with db_api.CONTEXT_READER.using(context):
            # IPAllocation rows, grouped by port_id.
            ip_allocs_by_port = {}
            if port_ids:
                q = context.session.query(models_v2.IPAllocation).filter(
                    models_v2.IPAllocation.port_id.in_(port_ids)
                )
                for ip in q:
                    ip_allocs_by_port.setdefault(ip.port_id, []).append(
                        {
                            "subnet_id": ip.subnet_id,
                            "ip_address": ip.ip_address,
                        }
                    )

            # FloatingIP rows, grouped by fixed_port_id.
            float_ips_by_port = {}
            if port_ids:
                q = context.session.query(FloatingIP).filter(
                    FloatingIP.fixed_port_id.in_(port_ids)
                )
                for fip in q:
                    float_ips_by_port.setdefault(fip.fixed_port_id, []).append(
                        {
                            "int_ip": fip.fixed_ip_address,
                            "ext_ip": fip.floating_ip_address,
                        }
                    )

            # Network rows, indexed by id.  We materialise just the columns we need
            # ({"name": ...}) inside the reader, rather than caching the ORM instance:
            # that way the downstream attribute access happens while the row is
            # guaranteed attached to an active session, and we do not rely on oslo.db's
            # expire_on_commit / detached-attribute behaviour after the reader exits.
            networks_by_id = {}
            if network_ids:
                q = context.session.query(models_v2.Network).filter(
                    models_v2.Network.id.in_(network_ids)
                )
                for net in q:
                    networks_by_id[net.id] = {"name": net.name}

            # SG bindings, grouped by port_id (a port can have multiple SGs).  Use the
            # plugin API (with a list filter) rather than
            # session.query(SecurityGroupPortBinding) so this path is consistent with
            # the per-port code that uses the same API.
            sg_ids_by_port = {}
            if port_ids:
                bindings = self.db._get_port_security_group_bindings(
                    context, filters={"port_id": port_ids}
                )
                for b in bindings:
                    sg_ids_by_port.setdefault(b["port_id"], []).append(
                        b["security_group_id"]
                    )

            # QoS bandwidth + packet-rate rules, grouped by qos_policy_id.  Materialise
            # each rule into a plain dict containing only the columns build_qos_controls
            # reads, so that subsequent access (in
            # _get_extra_port_information_from_bulk, after the reader exits) does not
            # depend on the ORM instances still being attached to a live session.  This
            # mirrors the per-port path's choice to call build_qos_controls inside its
            # CONTEXT_READER block.
            qos_bw_by_policy = {}
            qos_pr_by_policy = {}
            if qos_ids:
                q = context.session.query(qos_models.QosBandwidthLimitRule).filter(
                    qos_models.QosBandwidthLimitRule.qos_policy_id.in_(qos_ids)
                )
                for r in q:
                    qos_bw_by_policy.setdefault(r.qos_policy_id, []).append(
                        {
                            "direction": r.direction,
                            "max_kbps": r.max_kbps,
                            "max_burst_kbps": r.max_burst_kbps,
                        }
                    )
                q = context.session.query(qos_models.QosPacketRateLimitRule).filter(
                    qos_models.QosPacketRateLimitRule.qos_policy_id.in_(qos_ids)
                )
                for r in q:
                    qos_pr_by_policy.setdefault(r.qos_policy_id, []).append(
                        {
                            "direction": r.direction,
                            "max_kpps": r.max_kpps,
                        }
                    )

        # Subnet rows for every subnet referenced by any fixed IP (for gateway_ip).
        subnet_ids = list(
            {ip["subnet_id"] for ips in ip_allocs_by_port.values() for ip in ips}
        )
        subnets_by_id = {}
        if subnet_ids:
            for s in self.db.get_subnets(context, filters={"id": subnet_ids}):
                subnets_by_id[s["id"]] = s

        # Names of every security group referenced by any port.
        all_sg_ids = list(
            {sg_id for sg_ids in sg_ids_by_port.values() for sg_id in sg_ids}
        )
        sg_names_by_id = {}
        if all_sg_ids:
            sgs = self.db.get_security_groups(
                context, filters={"id": all_sg_ids}, default_sg=True
            )
            for sg in sgs:
                sg_names_by_id[sg["id"]] = sg["name"]

        self._bulk = {
            "ip_allocs_by_port": ip_allocs_by_port,
            "float_ips_by_port": float_ips_by_port,
            "networks_by_id": networks_by_id,
            "sg_ids_by_port": sg_ids_by_port,
            "qos_bw_by_policy": qos_bw_by_policy,
            "qos_pr_by_policy": qos_pr_by_policy,
            "subnets_by_id": subnets_by_id,
            "sg_names_by_id": sg_names_by_id,
        }

    def get_from_etcd(self, scope):
        # Scan all WEPs and LMs from etcd.  At scale this is cheap: in our benchmarks
        # even 3000 WEPs read in ~270ms, two orders of magnitude less than the per-port
        # DB queries in the compare phase.  All entries are keyed "wep <name>" / "lm
        # <name>" initially; the WEP syncer's post_process_etcd_map relabels
        # destination-side entries once neutron_map is known.
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

        if scope.all():
            return etcd_map

        # Narrow port scope.  WEP and LM etcd names can't be synthesised from a port_id
        # alone (the name also encodes host and device_id), so we filter the scanned
        # entries by trailing port_id rather than fetching by name.  This also
        # automatically picks up any stale WEPs at old binding hosts or stale LMs from
        # cancelled migrations, which would otherwise be invisible to a narrow resync.
        escaped_port_ids = {pid.replace("-", "--") for pid in scope.ids()}

        def _key_matches_scope(key):
            # The "wep " / "lm " prefix can't itself match "-<escaped port_id>" (the
            # prefixes end with a space), so endswith on the full key gives the same
            # answer as stripping the prefix first.
            return any(
                key.endswith("-" + escaped_pid) for escaped_pid in escaped_port_ids
            )

        return {
            key: value for key, value in etcd_map.items() if _key_matches_scope(key)
        }

    def post_process_etcd_map(self, scope, etcd_map, neutron_map):
        # Rekey any WEPs whose name corresponds to a dest-wep entry in neutron_map, so
        # the compare loop sees both sides of the dest WEP under the same key.  Etcd has
        # no source/dest distinction; the rekey lets the compare branch on the dest-wep
        # prefix and apply the dest_host overlay when computing write_data.
        for name in list(neutron_map):
            if name.startswith("dest-wep "):
                wep_name = remove_prefix(name, "dest-wep ")
                src_key = "wep " + wep_name
                if src_key in etcd_map:
                    etcd_map[name] = etcd_map.pop(src_key)
        return etcd_map

    def delete_legacy_etcd_data(self):
        if self.namespace != datamodel_v3.NO_REGION_NAMESPACE:
            datamodel_v3.delete_legacy("WorkloadEndpoint", "")

    # The following methods differ from those for other resources for two reasons.
    #
    # 1. For endpoints we need to read, compare and write labels and annotations as well
    # as spec.
    #
    # 2. This syncer writes LiveMigration resources as well as WorkloadEndpoints, and
    # distinguishes source- and dest-side WEPs of a live migration.  These all share
    # the WorkloadEndpoint etcd kind and key shape; the "wep ", "dest-wep " and "lm "
    # prefixes on the neutron_map / etcd_map keys are what disambiguate them inside
    # the resync.

    @staticmethod
    def _wep_etcd_name(name):
        """If `name` is a "wep " or "dest-wep " entry, return the bare WEP
        etcd name (i.e. without prefix); otherwise return None."""
        if name.startswith("wep "):
            return remove_prefix(name, "wep ")
        if name.startswith("dest-wep "):
            return remove_prefix(name, "dest-wep ")
        return None

    def create_in_etcd(self, name, write_data):
        wep_name = self._wep_etcd_name(name)
        if wep_name is not None:
            spec, labels, annotations = write_data
            return datamodel_v3.put(
                "WorkloadEndpoint",
                self.namespace,
                wep_name,
                spec,
                labels=labels,
                annotations=annotations,
                mod_revision=0,
            )

        # LiveMigration case.
        return datamodel_v3.put(
            "LiveMigration",
            self.namespace,
            remove_prefix(name, "lm "),
            write_data,
            mod_revision=0,
        )

    def update_in_etcd(self, name, write_data, mod_revision=etcdv3.MUST_UPDATE):
        wep_name = self._wep_etcd_name(name)
        if wep_name is not None:
            spec, labels, annotations = write_data
            return datamodel_v3.put(
                "WorkloadEndpoint",
                self.namespace,
                wep_name,
                spec,
                labels=labels,
                annotations=annotations,
                mod_revision=mod_revision,
            )

        # LiveMigration case.
        return datamodel_v3.put(
            "LiveMigration",
            self.namespace,
            remove_prefix(name, "lm "),
            write_data,
            mod_revision=mod_revision,
        )

    def delete_from_etcd(self, name, mod_revision):
        wep_name = self._wep_etcd_name(name)
        if wep_name is not None:
            return datamodel_v3.delete(
                "WorkloadEndpoint",
                self.namespace,
                wep_name,
                mod_revision=mod_revision,
            )

        # LiveMigration case.
        return datamodel_v3.delete(
            "LiveMigration",
            self.namespace,
            remove_prefix(name, "lm "),
            mod_revision=mod_revision,
        )

    def neutron_to_etcd_write_data(self, name, value, context, reread=False):
        if name.startswith("lm "):
            port, dest_host = value
            return self.neutron_to_live_migration_etcd_write_data(
                port, dest_host, context, reread
            )
        if name.startswith("dest-wep "):
            port, dest_host = value
            return self.neutron_to_port_etcd_write_data(
                port, context, reread, dest_host=dest_host
            )
        # "wep " - plain source-side WEP.
        return self.neutron_to_port_etcd_write_data(value, context, reread)

    def neutron_to_port_etcd_write_data(self, port, context, reread, dest_host=None):
        """Build the etcd write-data tuple for a WEP from a Neutron port.

        If ``dest_host`` is given, this is the destination-side WEP of a live migration;
        on reread we additionally verify the migration is still in progress to that
        host, and overlay ``dest_host`` onto the (possibly rereaded) port so
        endpoint_spec/labels/annotations see the dest binding.  A reread that finds the
        port has stopped migrating to ``dest_host`` raises ResourceGone, letting the
        resync skip the entry -- the next pass sees no matching dest-wep in neutron_map
        and the in-etcd-only branch deletes the orphan dest WEP.
        """
        if reread:
            try:
                port = self.db.get_port(context, port["id"])
            except n_exc.PortNotFound:
                raise ResourceGone()
            if dest_host is not None:
                current_dest = port.get("binding:profile", {}).get("migrating_to")
                if current_dest != dest_host:
                    raise ResourceGone()
        if dest_host is not None:
            port = {**port, "binding:host_id": dest_host}
        port_extra = self.get_extra_port_information(context, port)
        return (
            endpoint_spec(port, port_extra),
            endpoint_labels(port, self.namespace, port_extra),
            endpoint_annotations(port),
        )

    def neutron_to_live_migration_etcd_write_data(
        self, port, dest_host, context, reread
    ):
        """Build the etcd write-data dict for a LiveMigration resource.

        ``dest_host`` is the scope-defined destination host; reconstructing the
        dest_port copy here (rather than carrying a stale fork in the neutron_map value)
        means a reread is always safe -- the dest_host survives, and an interrupted
        migration is detected and skipped via ResourceGone.
        """
        if reread:
            try:
                port = self.db.get_port(context, port["id"])
            except n_exc.PortNotFound:
                raise ResourceGone()
            current_dest = port.get("binding:profile", {}).get("migrating_to")
            if current_dest != dest_host:
                raise ResourceGone()
        dest_port = {**port, "binding:host_id": dest_host}
        return live_migration_spec(self.namespace, port, dest_port)

    def write_endpoint(self, port, context, must_update=False, reread=True):
        if reread:
            # Reread the current port. This protects against concurrent writes
            # breaking our state.
            port = self.db.get_port(context, port["id"])

        # Fill out other information we need on the port.
        port_extra = self.get_extra_port_information(context, port)

        # Write the security policies for this port.
        self.policy_syncer.write_sgs_to_etcd(port_extra.security_groups, context)

        # Implementation note: we could arguably avoid holding the transaction
        # for this length and instead release it here, then use atomic CAS. The
        # problem there is that we potentially have to repeatedly respin and
        # regain the transaction. Let's not do that for now, and performance
        # test to see if it's a problem later.
        mod_revision = etcdv3.MUST_UPDATE if must_update else None
        datamodel_v3.put(
            "WorkloadEndpoint",
            self.namespace,
            endpoint_name(port),
            endpoint_spec(port, port_extra),
            labels=endpoint_labels(port, self.namespace, port_extra),
            annotations=endpoint_annotations(port),
            mod_revision=mod_revision,
        )

    def delete_endpoint(self, port):
        return datamodel_v3.delete(
            "WorkloadEndpoint", self.namespace, endpoint_name(port)
        )

    def write_live_migration(self, source_port, dest_port):
        """Write a LiveMigration resource for a migrating port.

        The LiveMigration name is derived from the destination WEP name.
        Returns the UID assigned by etcd (or the existing UID if already
        present).
        """
        namespace = self.namespace
        return datamodel_v3.put(
            "LiveMigration",
            namespace,
            endpoint_name(dest_port),
            live_migration_spec(namespace, source_port, dest_port),
        )

    def delete_live_migration(self, name, mod_revision=None):
        """Delete a LiveMigration resource by name."""
        return datamodel_v3.delete(
            "LiveMigration", self.namespace, name, mod_revision=mod_revision
        )

    def add_port_interface_name(self, port, port_extra):
        port_extra.interface_name = "tap" + port["id"][:11]

    def get_extra_port_information(self, context, port):
        """get_extra_port_information

        Gets extra information for a port that is needed before sending it to
        etcd.
        """
        LOG.debug("port = %r", port)
        if self._bulk is not None:
            return self._get_extra_port_information_from_bulk(context, port)
        port_extra = PortExtra()

        # Collect information that uses raw queries into the Neutron DB.  These queries
        # need ``session.in_transaction()`` to be True, or else SQLAlchemy drops huge
        # WARNING tracebacks saying "ORM session: SQL execution without transaction in
        # progress".  We arrange for that by using the ``CONTEXT_READER`` wrapper.
        with db_api.CONTEXT_READER.using(context):
            # We may have an out of date or incomplete port dict at this point.
            # Explicitly query the IPAllocation table to get latest fixed IP data.
            port_extra.fixed_ips = [
                {"subnet_id": ip["subnet_id"], "ip_address": ip["ip_address"]}
                for ip in context.session.query(models_v2.IPAllocation).filter_by(
                    port_id=port["id"]
                )
            ]

            # Similarly for floating IPs.
            port_extra.floating_ips = [
                {"int_ip": ip["fixed_ip_address"], "ext_ip": ip["floating_ip_address"]}
                for ip in context.session.query(FloatingIP).filter_by(
                    fixed_port_id=port["id"]
                )
            ]

            # And security groups.
            port_extra.security_groups = [
                binding["security_group_id"]
                for binding in self.db._get_port_security_group_bindings(
                    context, filters={"port_id": [port["id"]]}
                )
            ]

            # Read the Network so we can get its name.
            network = (
                context.session.query(models_v2.Network)
                .filter_by(id=port["network_id"])
                .first()
            )
            try:
                port_extra.network_name = datamodel_v3.sanitize_label_name_value(
                    network["name"],
                    NETWORK_NAME_MAX_LENGTH,
                )
            except Exception:
                LOG.warning("Failed to find network name for port %s", port["id"])

            # Read QoS rules.  We build port_extra.qos here, inside the reader, so that
            # the per-rule attribute accesses inside build_qos_controls happen while the
            # rule ORM objects are still attached to the session.  Calling
            # build_qos_controls after the reader exited would work today (the columns
            # we access are simple eager-loaded ones, and oslo.db's reader mode
            # typically leaves detached attributes readable), but would tie our
            # correctness to oslo.db's expire_on_commit / rollback_reader_sessions
            # configuration.  Calling build_qos_controls inside the reader is cheap and
            # decouples us from those internals.
            qos_policy_id = port.get("qos_policy_id") or port.get(
                "qos_network_policy_id"
            )
            LOG.debug("QoS Policy ID = %r", qos_policy_id)
            if qos_policy_id:
                bw_rules = context.session.query(
                    qos_models.QosBandwidthLimitRule
                ).filter_by(qos_policy_id=qos_policy_id)
                pr_rules = context.session.query(
                    qos_models.QosPacketRateLimitRule
                ).filter_by(qos_policy_id=qos_policy_id)
            else:
                bw_rules = []
                pr_rules = []
            port_extra.qos = self.build_qos_controls(bw_rules, pr_rules)

        # Now processing that either MUST be outside of any transaction - because it
        # will call @retry_if_session_inactive-decorated calls that only work correctly
        # when not in an outer transaction - or that doesn't involve the DB at all and
        # so doesn't care about transaction state.
        self.add_port_gateways(context, port_extra)
        self.add_port_interface_name(port, port_extra)
        self.add_port_project_data(port, context, port_extra)
        self.add_port_sg_names(context, port_extra)

        return port_extra

    def _get_extra_port_information_from_bulk(self, context, port):
        """Build a PortExtra for `port` using self._bulk prefetched data.

        Assumes _prefetch_bulk_port_data() has populated self._bulk at
        the start of resync.  Produces the same result as the per-port
        code path, but without any per-port DB round-trips.
        """
        bulk = self._bulk
        port_id = port["id"]

        port_extra = PortExtra()

        # Fixed IPs, with gateway filled in from the subnet cache.  Fall
        # back to a per-subnet get_subnet() for IDs the bulk prefetch
        # didn't see -- matches the per-port path in add_port_gateways
        # which always uses the singular API.
        port_extra.fixed_ips = []
        for ip in bulk["ip_allocs_by_port"].get(port_id, []):
            subnet = bulk["subnets_by_id"].get(ip["subnet_id"])
            if subnet is None:
                subnet = self.db.get_subnet(context, ip["subnet_id"])
            port_extra.fixed_ips.append(
                {
                    "subnet_id": ip["subnet_id"],
                    "ip_address": ip["ip_address"],
                    "gateway": subnet["gateway_ip"] if subnet else None,
                }
            )

        # Floating IPs.
        port_extra.floating_ips = bulk["float_ips_by_port"].get(port_id, [])

        # Security groups + names.
        port_extra.security_groups = bulk["sg_ids_by_port"].get(port_id, [])
        for sg_id in port_extra.security_groups:
            name = bulk["sg_names_by_id"].get(sg_id)
            if name is not None:
                port_extra.security_group_names[sg_id] = (
                    datamodel_v3.sanitize_label_name_value(name, SG_NAME_MAX_LENGTH)
                )

        # Network name.
        network = bulk["networks_by_id"].get(port["network_id"])
        if network is not None:
            try:
                port_extra.network_name = datamodel_v3.sanitize_label_name_value(
                    network["name"],
                    NETWORK_NAME_MAX_LENGTH,
                )
            except Exception:
                LOG.warning("Failed to sanitize network name for port %s", port_id)

        # Interface name.
        self.add_port_interface_name(port, port_extra)

        # Project data — still uses the keystone-backed in-process cache;
        # no DB round-trip in the common case.
        self.add_port_project_data(port, context, port_extra)

        # QoS — use bulk-prefetched rules.
        qos_policy_id = port.get("qos_policy_id") or port.get("qos_network_policy_id")
        LOG.debug("QoS Policy ID = %r", qos_policy_id)
        if qos_policy_id:
            bw_rules = bulk["qos_bw_by_policy"].get(qos_policy_id, [])
            pr_rules = bulk["qos_pr_by_policy"].get(qos_policy_id, [])
        else:
            bw_rules = []
            pr_rules = []

        port_extra.qos = self.build_qos_controls(bw_rules, pr_rules)

        return port_extra

    def add_port_gateways(self, context, port_extra):
        """add_port_gateways

        Determine the gateway IP addresses for a given port's IP addresses, and adds
        them to the port dict.

        The ``self.db.get_subnet`` call is ``@retry_if_session_inactive`` +
        ``@CONTEXT_READER``-decorated, so this method MUST run without any outer
        transaction we own (otherwise the retry decorator would be disabled).  Each call
        opens and closes its own reader transaction internally.
        """
        for ip in port_extra.fixed_ips:
            subnet = self.db.get_subnet(context, ip["subnet_id"])
            ip["gateway"] = subnet["gateway_ip"]

    def add_port_sg_names(self, context, port_extra):
        """add_port_sg_names

        Determine and store the name of each security group that a port uses.

        The ``self.db.get_security_groups`` call is ``@retry_if_session_inactive`` +
        ``@CONTEXT_READER``-decorated, so this method MUST run without any outer
        transaction we own.  The retry decorator does the recovery for the
        ``_ensure_default_security_group`` race that ``default_sg=True`` (below) is
        meant to side-step.
        """
        # Oddly, get_security_groups normally tries to create the default SG for the
        # current tenant, and that can hit a NeutronDbObjectDuplicateEntry exception -
        # presumably if there's a race with multiple servers or threads trying to do
        # this at the same time.  Adding "default_sg=True" here suppresses that creation
        # attempt.
        filters = {"id": port_extra.security_groups}
        for sg in self.db.get_security_groups(
            context, filters=filters, default_sg=True
        ):
            sg_name = datamodel_v3.sanitize_label_name_value(
                sg["name"], SG_NAME_MAX_LENGTH
            )
            port_extra.security_group_names[sg["id"]] = sg_name

    @staticmethod
    def build_qos_controls(bw_rules, pr_rules):
        """Build QoSControls dict, from the given rules and config."""
        qos = {}

        # Minima, maxima and defaults as specified in the WorkloadEndpoint API,
        # and implemented for the Kubernetes case in
        # libcalico-go/lib/backend/k8s/conversion/workload_endpoint_default.go.
        MINMAX_BANDWIDTH = (1000, 10**15)
        MINMAX_BW_BURST = (1000, 34359738360)
        MINMAX_BW_PEAKRATE = (1010, 10**15 + 10**13)
        MINMAX_BW_MINBURST = (1000, 10**8)

        MINMAX_PACKET_RATE = (1, 10**4)
        MINMAX_PR_BURST = (1, 10**4)

        MINMAX_CONNECTIONS = (1, 4294967295)

        def cap(setting, minmax):
            (min, max) = minmax
            if setting < min:
                setting = min
            elif setting > max:
                setting = max
            return setting

        for r in bw_rules:
            LOG.debug("BW rule = %r", r)
            direction = r.get("direction", "egress")
            if r["max_kbps"] != 0:
                qos[direction + "Bandwidth"] = cap(
                    r["max_kbps"] * 1000, MINMAX_BANDWIDTH
                )
            if r["max_burst_kbps"] != 0:
                qos[direction + "Peakrate"] = cap(
                    r["max_burst_kbps"] * 1000, MINMAX_BW_PEAKRATE
                )

        for r in pr_rules:
            LOG.debug("PR rule = %r", r)
            direction = r.get("direction", "egress")
            if r["max_kpps"] != 0:
                qos[direction + "PacketRate"] = cap(
                    r["max_kpps"] * 1000, MINMAX_PACKET_RATE
                )

        if cfg.CONF.calico.max_ingress_connections_per_port != 0:
            qos["ingressMaxConnections"] = cap(
                cfg.CONF.calico.max_ingress_connections_per_port, MINMAX_CONNECTIONS
            )
        if cfg.CONF.calico.max_egress_connections_per_port != 0:
            qos["egressMaxConnections"] = cap(
                cfg.CONF.calico.max_egress_connections_per_port, MINMAX_CONNECTIONS
            )

        if "ingressBandwidth" in qos:
            if cfg.CONF.calico.ingress_burst_bits != 0:
                qos["ingressBurst"] = cap(
                    cfg.CONF.calico.ingress_burst_bits, MINMAX_BW_BURST
                )
            else:
                qos["ingressBurst"] = calico_config.DEFAULT_BW_BURST
            if cfg.CONF.calico.ingress_minburst_bytes != 0 and "ingressPeakrate" in qos:
                qos["ingressMinburst"] = cap(
                    cfg.CONF.calico.ingress_minburst_bytes, MINMAX_BW_MINBURST
                )

        if "egressBandwidth" in qos:
            if cfg.CONF.calico.egress_burst_bits != 0:
                qos["egressBurst"] = cap(
                    cfg.CONF.calico.egress_burst_bits, MINMAX_BW_BURST
                )
            else:
                qos["egressBurst"] = calico_config.DEFAULT_BW_BURST
            if cfg.CONF.calico.egress_minburst_bytes != 0 and "egressPeakrate" in qos:
                qos["egressMinburst"] = cap(
                    cfg.CONF.calico.egress_minburst_bytes, MINMAX_BW_MINBURST
                )

        if "ingressPacketRate" in qos:
            if cfg.CONF.calico.ingress_burst_packets != 0:
                qos["ingressPacketBurst"] = cap(
                    cfg.CONF.calico.ingress_burst_packets, MINMAX_PR_BURST
                )
            else:
                qos["ingressPacketBurst"] = calico_config.DEFAULT_PR_BURST

        if "egressPacketRate" in qos:
            if cfg.CONF.calico.egress_burst_packets != 0:
                qos["egressPacketBurst"] = cap(
                    cfg.CONF.calico.egress_burst_packets, MINMAX_PR_BURST
                )
            else:
                qos["egressPacketBurst"] = calico_config.DEFAULT_PR_BURST

        return qos

    def add_port_project_data(self, port, context, port_extra):
        """add_port_project_data

        Determine the OpenStack project name and parent ID for a given
        port's project/tenant ID, and add it as port_extra.project_data.
        """
        proj_id = port.get("project_id", port.get("tenant_id"))
        if proj_id is None:
            LOG.warning("Port with no project ID: %r", port)
            return

        # If we've already cached the corresponding project data, we're done.
        proj_data = self.proj_data_cache.get(proj_id)
        if proj_data is not None:
            LOG.debug("Project data %r was cached", proj_data)
            port_extra.project_data = proj_data
            return

        # Not cached, so look up the port's project in the Keystone DB.
        self.cache_port_project_data()
        proj_data = self.proj_data_cache.get(proj_id)
        if proj_data is None:
            LOG.warning("Unable to find project data for port: %r", port)
            return

        port_extra.project_data = proj_data

    def cache_port_project_data(self):
        """cache_port_project_data

        Invoked when should populate the project cache for port annotations.
        """
        # Flush the cache if it has reached its maximum allowed size.
        if len(self.proj_data_cache) >= cfg.CONF.calico.project_name_cache_max:
            self.proj_data_cache = {}
        try:
            for proj in self.keystone.projects.list():
                if proj.id not in self.proj_data_cache:
                    LOG.info("Got project name %r from Keystone", proj.name)
                    proj_name = datamodel_v3.sanitize_label_name_value(
                        proj.name, PROJECT_NAME_MAX_LENGTH
                    )
                    self.proj_data_cache[proj.id] = (proj_name, proj.parent_id)
        except Exception:
            # Probably don't have right credentials for that lookup.
            LOG.exception("Failed to query Keystone DB")


# This can be replaced by `s.removeprefix(prefix)` in Python 3.9+, but for OpenStack
# Caracal the minimum Python version is 3.8, so we should remain compatible with that.
def remove_prefix(s, prefix):
    return s[len(prefix) :] if s.startswith(prefix) else s


def endpoint_name(port):
    def escape_dashes(s):
        return s.replace("-", "--")

    return "%s-openstack-%s-%s" % (
        escape_dashes(port["binding:host_id"]),
        escape_dashes(port["device_id"]),
        escape_dashes(port["id"]),
    )


def endpoint_name_without_host(name):
    # The `device_id` and `id` parts of the name are UUIDs and so cannot contain
    # "openstack".  Hence...
    parts = name.split("-")
    try:
        openstack_pos = len(parts) - 1 - parts[::-1].index("openstack")
    except ValueError:
        # No "openstack" segment in the name.  Can happen if etcd contains a legacy or
        # hand-edited resource with a non-standard name; return the input unchanged so
        # the caller's dict lookup misses cleanly and the bad entry is left for an
        # operator to deal with.
        return name
    return "-".join(parts[openstack_pos:])


def endpoint_labels(port, namespace, port_extra):
    labels = {}
    for sg_id in port_extra.security_groups:
        sg_name = port_extra.security_group_names.get(sg_id, "")
        labels[SG_LABEL_PREFIX + sg_id] = sg_name
        if sg_name:
            labels[SG_NAME_LABEL_PREFIX + sg_name] = sg_id
    labels["projectcalico.org/namespace"] = namespace
    labels["projectcalico.org/orchestrator"] = "openstack"

    proj_id = port.get("project_id", port.get("tenant_id"))
    if proj_id is not None:
        labels[PROJECT_ID_LABEL_NAME] = proj_id
    if port_extra.project_data:
        name, parent_id = port_extra.project_data
        labels[PROJECT_NAME_LABEL_NAME] = name
        labels[PROJECT_PARENT_ID_LABEL_NAME] = parent_id

    network_name = port_extra.network_name
    if network_name is not None:
        labels[NETWORK_NAME_LABEL_NAME] = network_name
    return labels


# Represent a Neutron port as a Calico v3 WorkloadEndpoint spec.
def endpoint_spec(port, port_extra):
    """endpoint_spec

    Generate JSON WorkloadEndpointSpec for the given Neutron port.
    """

    # Construct the simpler spec data.
    data = {
        "orchestrator": "openstack",
        "workload": port["device_id"],
        "node": port["binding:host_id"],
        "endpoint": port["id"],
        "interfaceName": port_extra.interface_name,
        "mac": port["mac_address"],
    }

    # Collect IPv4 and IPv6 addresses.  On the way, also set the corresponding
    # gateway fields.  If there is more than one IPv4 or IPv6 gateway, the last
    # one (in port_extra.fixed_ips) wins.
    ip_nets = []
    for ip in port_extra.fixed_ips:
        if ":" in ip["ip_address"]:
            ip_nets.append(ip["ip_address"] + "/128")
            if ip["gateway"] is not None:
                data["ipv6Gateway"] = ip["gateway"]
        else:
            ip_nets.append(ip["ip_address"] + "/32")
            if ip["gateway"] is not None:
                data["ipv4Gateway"] = ip["gateway"]

    # we need to store allowedIPs twice, because
    # dhcp agent creates dhcp record only for fixed IP
    # but felix have to create route for both (fixed and allowed ips)
    allowed_ips = []
    for aap in port.get("allowed_address_pairs", []):
        ip_addr = str(aap["ip_address"])
        if ":" in ip_addr:
            ip_nets.append(ip_addr + "/128")
            allowed_ips.append(ip_addr + "/128")
        else:
            ip_nets.append(ip_addr + "/32")
            allowed_ips.append(ip_addr + "/32")

    data["ipNetworks"] = ip_nets
    data["allowedIps"] = allowed_ips

    ip_nats = []
    for ip in port_extra.floating_ips:
        ip_nats.append(
            {
                "internalIP": ip["int_ip"],
                "externalIP": ip["ext_ip"],
            }
        )
    if ip_nats:
        data["ipNATs"] = ip_nats

    if port_extra.qos:
        data["qosControls"] = port_extra.qos

    # Return that data.
    return data


def endpoint_annotations(port):
    annotations = {datamodel_v3.ANN_KEY_NETWORK_ID: port["network_id"]}

    # If the port has a DNS assignment, represent that as an FQDN annotation.
    dns_assignment = port.get("dns_assignment")
    if dns_assignment:
        # Note: the Neutron server generates a list of assignment entries, one
        # for each fixed IP, but all with the same FQDN, for slightly
        # historical reasons.  We're fine getting the FQDN from the first
        # entry.
        annotations[datamodel_v3.ANN_KEY_FQDN] = dns_assignment[0]["fqdn"]

    return annotations


def _port_is_endpoint_port(port):
    # Return True if port is a VM port.
    if port["device_owner"].startswith("compute:"):
        return True

    # Also return True if port is for a Kuryr container.
    if port["device_owner"].startswith("kuryr:container"):
        return True

    # Otherwise log and return False.
    LOG.debug("Not a VM port: %s" % port)
    return False


def make_keystone_client():
    """Build a Keystone v3 client from oslo.config.

    Used both by mech_calico (when constructing the driver's EndpointWriter) and by the
    resync runner (when constructing a fresh EndpointWriter for the CLI).  Tests inject
    a mock by patching this function.
    """
    authcfg = cfg.CONF.keystone_authtoken
    LOG.debug("authcfg = %r", authcfg)
    for key in authcfg:
        if "password" in key:
            LOG.debug("authcfg[%s] = %s", key, "***")
        else:
            LOG.debug("authcfg[%s] = %s", key, authcfg[key])

    auth = v3.Password(
        user_domain_name=authcfg.user_domain_name,
        username=authcfg.username,
        password=authcfg.password,
        project_domain_name=authcfg.project_domain_name,
        project_name=authcfg.project_name,
        auth_url=re.sub(r"/v3/?$", "", authcfg.auth_url) + "/v3",
    )
    return KeystoneClient(session=session.Session(auth=auth))


def live_migration_spec(namespace, source_port, dest_port):
    wep_id_fields = {
        "orchestratorID": "openstack",
        "workloadID": namespace + "/" + source_port["device_id"],
        "endpointID": source_port["id"],
    }
    return {
        "source": {
            "workloadEndpoint": dict(
                hostname=source_port["binding:host_id"],
                **wep_id_fields,
            ),
        },
        "target": {
            "workloadEndpoint": dict(
                hostname=dest_port["binding:host_id"],
                **wep_id_fields,
            ),
        },
    }
