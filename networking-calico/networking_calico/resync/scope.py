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

"""Scope object describing what a resync should cover."""

import dataclasses
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from neutron.db import models_v2
from neutron_lib import context as ctx
from neutron_lib.db import api as db_api

from oslo_log import log

from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.plugins.ml2.drivers.calico.endpoints import (
    WorkloadEndpointSyncer,
)
from networking_calico.plugins.ml2.drivers.calico.policy import PolicySyncer
from networking_calico.plugins.ml2.drivers.calico.subnets import SubnetSyncer

LOG = log.getLogger(__name__)


# Scope for a "single" resource type, i.e. just one of:
# - OpenStack security groups -> Calico NetworkPolicy
# - OpenStack ports -> Calico WorkloadEndpoints and LiveMigrations
# - OpenStack subnets -> Calico subnets.
# In each case the scope can be limited to a specific set of security group / port /
# subnet IDs, or else will resync all instances of that type of resource.
class ResourceScope(object):
    def __init__(self, parent, limited_ids=None):
        self.parent = parent
        self.limited_ids = limited_ids

    def ids(self):
        return self.limited_ids

    def __str__(self):
        return "all" if self.limited_ids is None else "%d ids" % len(self.limited_ids)

    # Delegate other methods to the parent Scope object.
    def __getattr__(self, name):
        return getattr(self.parent, name)


@dataclasses.dataclass
class ResyncResult:
    """Structured outcome of a single ``run_resync`` call."""

    scope: Dict[str, Any]
    phases: Dict[str, Dict[str, Any]]
    started_at: str
    finished_at: str
    total_ms: int
    ok: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# Scope for an entire resync operation, potentially covering all of the above resource
# types.
class Scope:
    """What to resync.

    A Scope with no specific IDs requests a resync of every Calico resource that this
    driver writes to etcd.  Otherwise the resync is limited to the specified IDs, with
    expansion:

      * each network in ``networks`` expands to that network plus every subnet and
        port within it;
      * each subnet in ``subnets`` expands to that subnet plus every port on it;
      * each port in ``ports`` is resynced as-is.

    If ``include_security_groups_for_ports`` is true, the security groups bound to each
    (expanded) port are added to the security group set.  Default is false because
    port-to-SG coupling in Calico is loose: a port carries SG labels and the policy
    selectors match them, so a port-only resync is usually enough to repair port
    incidents without touching SG NetworkPolicy resources.
    """

    def __init__(
        self,
        db,
        driver=None,
        admin_context=None,
        networks=None,
        subnets=None,
        ports=None,
        security_groups=None,
        include_security_groups_for_ports=False,
    ):
        self.db = db
        self.driver = driver
        self.admin_context = admin_context
        self.networks = set(networks or [])
        self.subnets = set(subnets or [])
        self.ports = set(ports or [])
        self.security_groups = set(security_groups or [])
        self.include_security_groups_for_ports = include_security_groups_for_ports

    def all(self):
        return not (self.networks or self.subnets or self.ports or self.security_groups)

    def run(self) -> ResyncResult:
        """Drive one resync pass against Neutron DB and etcd.

        Returns ResyncResult
          A JSON-serialisable record of what happened.  ``ok`` is False and ``error`` is
          set if the pass raised; the caller decides whether to propagate.  Phases bail
          out on the first exception rather than continuing, because they share state
          via etcd and running a later phase on top of a half-failed earlier one risks
          compounding the problem.
        """
        started = datetime.now(timezone.utc)
        started_mono = time.monotonic()
        phases: Dict[str, Dict[str, Any]] = {}

        ok = True
        error: Optional[str] = None

        try:
            if self.admin_context is None:
                self.admin_context = ctx.get_admin_context()
            if self.driver is not None:
                subnet_syncer = self.driver.subnet_syncer
                policy_syncer = self.driver.policy_syncer
                endpoint_syncer = self.driver.endpoint_syncer
            else:
                subnet_syncer = SubnetSyncer(self.db)
                policy_syncer = PolicySyncer(self.db)
                endpoint_syncer = WorkloadEndpointSyncer(self.db, policy_syncer)

            phases["expand"] = _run_phase(self.expand)
            phases["subnets"] = _run_phase(
                lambda: subnet_syncer.resync(self.admin_context, self.subnet_scope())
            )
            phases["policy"] = _run_phase(
                lambda: policy_syncer.resync(self.admin_context, self.policy_scope())
            )
            phases["endpoints"] = _run_phase(
                lambda: endpoint_syncer.resync(
                    self.admin_context, self.endpoint_scope()
                )
            )
            if self.all():
                phases["felix_config"] = _run_phase(provide_felix_config)

        except Exception as exc:
            ok = False
            error = "%s: %s" % (type(exc).__name__, exc)
            LOG.exception("run_resync failed")

        finished = datetime.now(timezone.utc)
        return ResyncResult(
            scope=self.to_dict(),
            phases=phases,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            total_ms=int((time.monotonic() - started_mono) * 1000),
            ok=ok,
            error=error,
        )

    def to_dict(self) -> dict:
        return {
            "all": self.all(),
            "networks": sorted(self.networks),
            "subnets": sorted(self.subnets),
            "ports": sorted(self.ports),
            "security_groups": sorted(self.security_groups),
            "include_sgs_for_ports": self.include_security_groups_for_ports,
        }

    def expand(self):
        """Resolve this Scope's network/subnet IDs to the contained subnets/ports."""
        if self.all():
            return

        # Start with the IDs that were explicitly specified.  Use `set()` again here to
        # take an independent copy of the sets and avoid mutating the originals.
        self.all_subnet_ids = set(self.subnets)
        self.all_port_ids = set(self.ports)
        self.all_sg_ids = set(self.security_groups)

        # Resync of a network includes its subnets and ports.  Track the subnets we
        # discover here so the subnet block below can skip them: their ports were
        # already added via the network_id port query.
        network_subnet_ids = set()
        if self.networks:
            for subnet in self.db.get_subnets(
                self.admin_context, filters={"network_id": list(self.networks)}
            ):
                network_subnet_ids.add(subnet["id"])
            for port in self.db.get_ports(
                self.admin_context, filters={"network_id": list(self.networks)}
            ):
                self.all_port_ids.add(port["id"])
        self.all_subnet_ids |= network_subnet_ids

        # Resync of a subnet includes its ports.  Query IPAllocation directly rather
        # than going via port["fixed_ips"]: the port dict's fixed_ips field is populated
        # from a join and can be out of date, and the driver elsewhere
        # (WorkloadEndpointSyncer.get_fixed_ips_for_port) explicitly re-queries
        # IPAllocation for the same reason.  We only need to do this for subnets that
        # weren't already covered by the network expansion above; for those we already
        # added all their ports.
        remaining_subnet_ids = self.subnets - network_subnet_ids
        if remaining_subnet_ids:
            with db_api.CONTEXT_WRITER.using(self.admin_context):
                # Iterate directly rather than calling .all() so this matches
                # the bulk-prefetch pattern in WorkloadEndpointSyncer.  Real
                # SQLAlchemy Query supports iteration; the test mocks return
                # plain lists, which would refuse a .all().
                for allocation in self.admin_context.session.query(
                    models_v2.IPAllocation
                ).filter(models_v2.IPAllocation.subnet_id.in_(remaining_subnet_ids)):
                    self.all_port_ids.add(allocation.port_id)

        # include-sgs-for-ports: read security-group bindings authoritatively via
        # _get_port_security_group_bindings rather than relying on
        # port["security_groups"], which is also populated by a join and can be stale --
        # the driver's get_security_groups_for_port goes through the same binding query
        # for the same reason.
        if self.include_security_groups_for_ports and self.all_port_ids:
            for binding in self.db._get_port_security_group_bindings(
                self.admin_context, filters={"port_id": list(self.all_port_ids)}
            ):
                self.all_sg_ids.add(binding["security_group_id"])

    def subnet_scope(self):
        if self.all():
            return ResourceScope(self)

        return ResourceScope(self, limited_ids=self.all_subnet_ids)

    def policy_scope(self):
        if self.all():
            return ResourceScope(self)

        return ResourceScope(self, limited_ids=self.all_sg_ids)

    def endpoint_scope(self):
        if self.all():
            return ResourceScope(self)

        return ResourceScope(self, limited_ids=self.all_port_ids)


def _run_phase(fn) -> Dict[str, Any]:
    """Time ``fn`` and return a phase summary dict.

    If ``fn`` itself returns a dict (the resource syncers do, with item counts and
    per-step timings), it is merged into the summary so callers see both the wall-clock
    total and the syncer-internal breakdown.

    Exceptions are not caught here: they propagate to ``Scope.run``, which records them
    in the top-level ResyncResult.error and bails out of the remaining phases.
    """
    t0 = time.monotonic()
    detail = fn()
    summary = {"total_ms": int((time.monotonic() - t0) * 1000)}
    if isinstance(detail, dict):
        summary.update(detail)
    return summary


def provide_felix_config():
    """Write/refresh the global ClusterInformation and FelixConfiguration.

    Lifted unchanged in semantics from the original mech_calico implementation, with
    ``time.sleep`` substituted for ``eventlet.sleep`` so the function is safe to call
    from the CLI as well as from a greenthread.  Exceptions propagate to
    :meth:`Scope.run`, which records the message in the top-level ResyncResult.error and
    skips the remaining phases.
    """
    LOG.info("Providing Felix configuration")

    rewrite_cluster_info = True
    while rewrite_cluster_info:
        # Get existing global ClusterInformation.  We will add to this, rather than
        # trampling on anything that may already be there, and will also take care to
        # avoid an overlapping write with some other orchestrator.
        try:
            cluster_info, ci_mod_revision = datamodel_v3.get(
                "ClusterInformation", "default"
            )
        except etcdv3.KeyNotFound:
            cluster_info = {}
            ci_mod_revision = 0
        if cluster_info is None:
            # Existing etcd entry has corrupt JSON.  Treat as empty so we rebuild from
            # scratch, but keep ci_mod_revision so the put() below overwrites under CAS.
            cluster_info = {}
        rewrite_cluster_info = False
        LOG.info(
            "Read ClusterInformation %s mod_revision %r",
            cluster_info,
            ci_mod_revision,
        )

        # Generate a cluster GUID if there isn't one already.
        if not cluster_info.get(datamodel_v3.CLUSTER_GUID):
            cluster_info[datamodel_v3.CLUSTER_GUID] = uuid.uuid4().hex
            rewrite_cluster_info = True

        # Add "openstack" to the cluster type, unless there already.
        cluster_type = cluster_info.get(datamodel_v3.CLUSTER_TYPE, "")
        if cluster_type:
            if "openstack" not in cluster_type:
                cluster_info[datamodel_v3.CLUSTER_TYPE] = cluster_type + ",openstack"
                rewrite_cluster_info = True
        else:
            cluster_info[datamodel_v3.CLUSTER_TYPE] = "openstack"
            rewrite_cluster_info = True

        # Note, we don't touch the Calico version field here, as we don't know it.
        # (With other orchestrators, it is calico/node's responsibility to set the
        # Calico version.  But we don't run calico/node in Calico for OpenStack.)

        # Set the datastore to ready, if the datastore readiness state isn't already set
        # at all.  This field is intentionally tri-state, i.e. it can be explicitly
        # True, explicitly False, or not set.  If it has been set explicitly to False,
        # that is probably because another orchestrator is doing an upgrade or wants for
        # some other reason to suspend processing of the Calico datastore.
        if datamodel_v3.DATASTORE_READY not in cluster_info:
            cluster_info[datamodel_v3.DATASTORE_READY] = True
            rewrite_cluster_info = True

        # Rewrite ClusterInformation, if we changed anything above.
        if rewrite_cluster_info:
            LOG.info("New ClusterInformation: %s", cluster_info)
            if datamodel_v3.put(
                "ClusterInformation",
                datamodel_v3.NOT_NAMESPACED,
                "default",
                cluster_info,
                mod_revision=ci_mod_revision,
            ):
                rewrite_cluster_info = False
            else:
                # Short sleep to avoid a tight loop.
                time.sleep(1)

    rewrite_felix_config = True
    while rewrite_felix_config:
        # Get existing global FelixConfiguration.  We will add to this, rather than
        # trampling on anything that may already be there, and will also take care to
        # avoid an overlapping write with some other orchestrator.
        try:
            felix_config, fc_mod_revision = datamodel_v3.get(
                "FelixConfiguration", "default"
            )
        except etcdv3.KeyNotFound:
            felix_config = {}
            fc_mod_revision = 0
        if felix_config is None:
            # Existing etcd entry has corrupt JSON.  Same treatment as cluster_info
            # above.
            felix_config = {}
        rewrite_felix_config = False
        LOG.info(
            "Read FelixConfiguration %s mod_revision %r",
            felix_config,
            fc_mod_revision,
        )

        # Enable endpoint reporting.
        if not felix_config.get(datamodel_v3.ENDPOINT_REPORTING_ENABLED, False):
            felix_config[datamodel_v3.ENDPOINT_REPORTING_ENABLED] = True
            rewrite_felix_config = True

        # Ensure that interface prefixes include 'tap'.
        interface_prefix = felix_config.get(datamodel_v3.INTERFACE_PREFIX)
        prefixes = interface_prefix.split(",") if interface_prefix else []
        if "tap" not in prefixes:
            prefixes.append("tap")
            felix_config[datamodel_v3.INTERFACE_PREFIX] = ",".join(prefixes)
            rewrite_felix_config = True

        # Rewrite FelixConfiguration, if we changed anything above.
        if rewrite_felix_config:
            LOG.info("New FelixConfiguration: %s", felix_config)
            if datamodel_v3.put(
                "FelixConfiguration",
                datamodel_v3.NOT_NAMESPACED,
                "default",
                felix_config,
                mod_revision=fc_mod_revision,
            ):
                rewrite_felix_config = False
            else:
                # Short sleep to avoid a tight loop.
                time.sleep(1)
