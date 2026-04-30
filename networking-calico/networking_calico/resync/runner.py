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
"""Drive a single resync pass.

``run_resync`` is the single entry point.  It builds the three syncers
(Subnet, Policy, WorkloadEndpoint) against the supplied Neutron core
plugin and either:

  * runs the full resync (``Scope.all()``); or
  * iterates the (expanded) IDs and calls the corresponding write path
    on each syncer (``write_endpoint`` for ports, ``write_sgs_to_etcd``
    for security groups, ``subnet_created``/``subnet_deleted`` for
    subnets).

In either case the function returns a ``ResyncResult`` describing what
was attempted, how long each phase took and whether the overall pass
succeeded.  The result is JSON-serialisable so the CLI can print it
directly and the driver can log it as one structured line.
"""

import contextlib
import dataclasses
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneclient.v3.client import Client as KeystoneClient

from neutron_lib import context as ctx
from neutron_lib.plugins import directory as plugin_dir

from oslo_config import cfg
from oslo_log import log

from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.plugins.ml2.drivers.calico.endpoints import (
    WorkloadEndpointSyncer,
)
from networking_calico.plugins.ml2.drivers.calico.policy import PolicySyncer
from networking_calico.plugins.ml2.drivers.calico.subnets import SubnetSyncer
from networking_calico.resync import scope as scope_mod

LOG = log.getLogger(__name__)


@dataclasses.dataclass
class ResyncResult:
    """Structured outcome of a single ``run_resync`` call."""

    scope: Dict[str, Any]
    expanded: Dict[str, Any]
    phases: Dict[str, Dict[str, Any]]
    started_at: str
    finished_at: str
    total_ms: int
    ok: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def run_resync(
    scope: scope_mod.Scope,
    db_plugin=None,
    keystone_client=None,
    admin_context=None,
    subnet_syncer=None,
    policy_syncer=None,
    endpoint_syncer=None,
) -> ResyncResult:
    """Drive one resync pass against ``db_plugin`` and etcd.

    Parameters
    ----------
    scope:
        What to resync.  An "all" scope drives the full
        :class:`ResourceSyncer.resync` path on each of the three
        syncers, plus :func:`provide_felix_config`.  A narrow scope is
        expanded (network -> subnets+ports, subnet -> ports, optionally
        ports -> SGs) and then each ID has its write path called.

    db_plugin:
        The Neutron core plugin.  ``None`` to look it up from
        ``directory.get_plugin()``; that requires the Neutron plugin
        registry to have been initialised already (true in
        neutron-server, true after ``manager.init()`` in a CLI).

    keystone_client:
        Keystone v3 client.  Only used when this function constructs
        the syncers itself (i.e. when ``endpoint_syncer`` is not
        supplied).  ``None`` to build one from
        ``cfg.CONF.keystone_authtoken``.

    admin_context:
        Neutron admin context.  ``None`` to build one with
        ``ctx.get_admin_context()``.

    subnet_syncer / policy_syncer / endpoint_syncer:
        Pre-built syncer instances.  When supplied they are used in
        place of fresh ones; this lets the driver reuse the syncers it
        already built for postcommit hooks, and lets tests inject
        syncers wired against mocked DB and Keystone clients.  When
        ``None`` (the CLI path) the runner constructs fresh syncers.

    Returns
    -------
    ResyncResult
        A JSON-serialisable record of what happened.  ``ok`` is False
        and ``error`` is set if the pass raised; the caller decides
        whether to propagate.
    """
    started = datetime.now(timezone.utc)
    started_mono = time.monotonic()
    phases: Dict[str, Dict[str, Any]] = {}

    if db_plugin is None:
        db_plugin = _get_plugin()
    if admin_context is None:
        admin_context = ctx.get_admin_context()

    expanded = scope_mod.expand(scope, db_plugin, admin_context)

    ok = True
    error: Optional[str] = None

    try:
        if policy_syncer is None:
            policy_syncer = PolicySyncer(db_plugin, _txn_from_context)
        if subnet_syncer is None:
            subnet_syncer = SubnetSyncer(db_plugin, _txn_from_context)
        if endpoint_syncer is None:
            if keystone_client is None:
                keystone_client = _make_keystone_client()
            endpoint_syncer = WorkloadEndpointSyncer(
                db_plugin, _txn_from_context, policy_syncer, keystone_client
            )

        if scope.is_all:
            phases["subnets"] = _run_phase(lambda: subnet_syncer.resync(admin_context))
            phases["policy"] = _run_phase(lambda: policy_syncer.resync(admin_context))
            phases["endpoints"] = _run_phase(
                lambda: endpoint_syncer.resync(admin_context)
            )
            phases["felix_config"] = _run_phase(provide_felix_config)
        else:
            phases.update(
                _run_narrow(
                    expanded,
                    admin_context,
                    db_plugin,
                    subnet_syncer,
                    policy_syncer,
                    endpoint_syncer,
                )
            )

    except Exception as exc:
        ok = False
        error = "%s: %s" % (type(exc).__name__, exc)
        LOG.exception("run_resync failed")

    finished = datetime.now(timezone.utc)
    return ResyncResult(
        scope=scope.to_dict(),
        expanded=expanded.to_dict(),
        phases=phases,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        total_ms=int((time.monotonic() - started_mono) * 1000),
        ok=ok,
        error=error,
    )


def _run_phase(fn) -> Dict[str, Any]:
    """Time ``fn`` and return a phase summary dict.

    If ``fn`` itself returns a dict (the resource syncers do, with
    item counts and per-step timings), it is merged into the
    summary so callers see both the wall-clock total and the
    syncer-internal breakdown.
    """
    t0 = time.monotonic()
    detail = fn()
    summary = {"total_ms": int((time.monotonic() - t0) * 1000), "error": None}
    if isinstance(detail, dict):
        summary.update(detail)
    return summary


def _run_narrow(
    expanded: scope_mod.ExpandedScope,
    admin_context,
    db_plugin,
    subnet_syncer,
    policy_syncer,
    endpoint_syncer,
) -> Dict[str, Dict[str, Any]]:
    """Run write-only phases for the IDs in ``expanded``.

    Each phase is reported even if empty so the JSON output has a
    stable shape.
    """
    phases: Dict[str, Dict[str, Any]] = {
        "subnets": {"writes": 0, "deletes": 0, "total_ms": 0, "error": None},
        "policy": {"writes": 0, "total_ms": 0, "error": None},
        "endpoints": {"writes": 0, "total_ms": 0, "error": None},
    }

    if expanded.subnet_ids:
        phases["subnets"] = _resync_subnets(
            sorted(expanded.subnet_ids),
            admin_context,
            db_plugin,
            subnet_syncer,
        )

    if expanded.port_ids:
        phases["endpoints"] = _resync_ports(
            sorted(expanded.port_ids),
            admin_context,
            db_plugin,
            endpoint_syncer,
        )

    if expanded.security_group_ids:
        phases["policy"] = _resync_security_groups(
            sorted(expanded.security_group_ids),
            admin_context,
            policy_syncer,
        )

    return phases


def _resync_subnets(
    subnet_ids, admin_context, db_plugin, subnet_syncer
) -> Dict[str, Any]:
    t0 = time.monotonic()
    writes = 0
    deletes = 0
    error = None
    try:
        subnets_by_id = {
            s["id"]: s
            for s in db_plugin.get_subnets(admin_context, filters={"id": subnet_ids})
        }
        for sid in subnet_ids:
            subnet = subnets_by_id.get(sid)
            if subnet is None or not subnet.get("enable_dhcp"):
                subnet_syncer.subnet_deleted(sid)
                deletes += 1
            else:
                subnet_syncer.subnet_created(subnet, admin_context)
                writes += 1
    except Exception as exc:
        error = "%s: %s" % (type(exc).__name__, exc)
        LOG.exception("Narrow subnet resync failed")
    return {
        "writes": writes,
        "deletes": deletes,
        "total_ms": int((time.monotonic() - t0) * 1000),
        "error": error,
    }


def _resync_ports(
    port_ids, admin_context, db_plugin, endpoint_syncer
) -> Dict[str, Any]:
    t0 = time.monotonic()
    writes = 0
    error = None
    try:
        ports_by_id = {
            p["id"]: p
            for p in db_plugin.get_ports(admin_context, filters={"id": port_ids})
        }
        for pid in port_ids:
            port = ports_by_id.get(pid)
            if port is None:
                endpoint_syncer.delete_endpoint({"id": pid})
                continue
            endpoint_syncer.write_endpoint(
                port, admin_context, must_update=False, reread=False
            )
            writes += 1
    except Exception as exc:
        error = "%s: %s" % (type(exc).__name__, exc)
        LOG.exception("Narrow port resync failed")
    return {
        "writes": writes,
        "total_ms": int((time.monotonic() - t0) * 1000),
        "error": error,
    }


def _resync_security_groups(sg_ids, admin_context, policy_syncer) -> Dict[str, Any]:
    t0 = time.monotonic()
    error = None
    writes = 0
    try:
        policy_syncer.write_sgs_to_etcd(sg_ids, admin_context)
        writes = len(sg_ids)
    except Exception as exc:
        error = "%s: %s" % (type(exc).__name__, exc)
        LOG.exception("Narrow security-group resync failed")
    return {
        "writes": writes,
        "total_ms": int((time.monotonic() - t0) * 1000),
        "error": error,
    }


def provide_felix_config():
    """Write/refresh the global ClusterInformation and FelixConfiguration.

    Lifted unchanged in semantics from the original mech_calico
    implementation, with ``time.sleep`` substituted for
    ``eventlet.sleep`` so the function is safe to call from the CLI as
    well as from a greenthread.  Exceptions propagate; the caller
    (``_run_phase`` in this module) records them in the result.
    """
    LOG.info("Providing Felix configuration")

    rewrite_cluster_info = True
    while rewrite_cluster_info:
        try:
            cluster_info, ci_mod_revision = datamodel_v3.get(
                "ClusterInformation", "default"
            )
        except etcdv3.KeyNotFound:
            cluster_info = {}
            ci_mod_revision = 0
        rewrite_cluster_info = False
        LOG.info(
            "Read ClusterInformation %s mod_revision %r",
            cluster_info,
            ci_mod_revision,
        )

        if not cluster_info.get(datamodel_v3.CLUSTER_GUID):
            cluster_info[datamodel_v3.CLUSTER_GUID] = uuid.uuid4().hex
            rewrite_cluster_info = True

        cluster_type = cluster_info.get(datamodel_v3.CLUSTER_TYPE, "")
        if cluster_type:
            if "openstack" not in cluster_type:
                cluster_info[datamodel_v3.CLUSTER_TYPE] = cluster_type + ",openstack"
                rewrite_cluster_info = True
        else:
            cluster_info[datamodel_v3.CLUSTER_TYPE] = "openstack"
            rewrite_cluster_info = True

        if datamodel_v3.DATASTORE_READY not in cluster_info:
            cluster_info[datamodel_v3.DATASTORE_READY] = True
            rewrite_cluster_info = True

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
                time.sleep(1)

    rewrite_felix_config = True
    while rewrite_felix_config:
        try:
            felix_config, fc_mod_revision = datamodel_v3.get(
                "FelixConfiguration", "default"
            )
        except etcdv3.KeyNotFound:
            felix_config = {}
            fc_mod_revision = 0
        rewrite_felix_config = False
        LOG.info(
            "Read FelixConfiguration %s mod_revision %r",
            felix_config,
            fc_mod_revision,
        )

        if not felix_config.get(datamodel_v3.ENDPOINT_REPORTING_ENABLED, False):
            felix_config[datamodel_v3.ENDPOINT_REPORTING_ENABLED] = True
            rewrite_felix_config = True

        interface_prefix = felix_config.get(datamodel_v3.INTERFACE_PREFIX)
        prefixes = interface_prefix.split(",") if interface_prefix else []
        if "tap" not in prefixes:
            prefixes.append("tap")
            felix_config[datamodel_v3.INTERFACE_PREFIX] = ",".join(prefixes)
            rewrite_felix_config = True

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
                time.sleep(1)


@contextlib.contextmanager
def _txn_from_context(context, tag="<unset>"):
    """Open a Neutron DB transaction on ``context``.

    Equivalent to the ``CalicoMechanismDriver._txn_from_context``
    method.  Living here lets the resync runner be used without an
    instance of the driver.
    """
    sess = context.session
    if getattr(sess, "bind", None):
        conn_url = str(sess.bind.url).lower()
    else:
        conn_url = str(sess.connection().engine.url).lower()

    if conn_url.startswith("mysql:") or conn_url.startswith("mysql+mysqldb:"):
        msg = (
            "Unsupported MySQL driver detected in SQLAlchemy connection "
            "URL: %s.  Please use the 'mysql+pymysql' driver to avoid "
            "known issues.  See "
            "https://bugs.launchpad.net/oslo.db/+bug/1350149 for "
            "details." % conn_url
        )
        LOG.error(msg)
        raise RuntimeError(msg)

    with context.session.begin(subtransactions=True) as txn:
        yield txn


def _get_plugin():
    return plugin_dir.get_plugin()


def _make_keystone_client():
    """Build a Keystone v3 client from oslo.config."""
    authcfg = cfg.CONF.keystone_authtoken
    auth = v3.Password(
        user_domain_name=authcfg.user_domain_name,
        username=authcfg.username,
        password=authcfg.password,
        project_domain_name=authcfg.project_domain_name,
        project_name=authcfg.project_name,
        auth_url=re.sub(r"/v3/?$", "", authcfg.auth_url) + "/v3",
    )
    return KeystoneClient(session=session.Session(auth=auth))
