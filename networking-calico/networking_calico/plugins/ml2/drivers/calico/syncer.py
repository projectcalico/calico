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

import time

from oslo_log import log

LOG = log.getLogger(__name__)

# Retry budget for attempts to sync dynamic Neutron resource updates with etcd; for
# example see the get-then-CAS-put loop in ``sync_subnet``.  Sized to tolerate moderate
# per-key contention while bounding the worst case.  Drift beyond this is left for the
# next resync (whether startup or on-demand) to repair.
MAX_CAS_ATTEMPTS = 5


class ResourceGone(Exception):
    pass


class ResourceSyncer(object):
    """Logic for syncing one kind of Calico resource to etcd.

    Different instances of this class are responsible for the WorkloadEndpoint,
    NetworkPolicy and Subnet resources that this driver writes into etcd, as
    the Calico equivalent of the subset of the Neutron data model that we
    support.  WorkloadEndpoint and NetworkPolicy resources are written
    according to the v3 Calico data model; necessarily so because that is the
    data format that Felix now expects.  Subnet resources are written according
    to an adhoc v1 format that is essentially private within networking-calico;
    which is OK because they are only read by the Calico DHCP agent.

    Calico resource types are currently 1:1 with Neutron resource types:

    - 1 Neutron VM port         ->  1 Calico WorkloadEndpoint
    - 1 Neutron security group  ->  1 Calico NetworkPolicy
    - 1 Neutron subnet          ->  1 Calico Subnet

    For each Calico resource type, the instance of this class for that kind of
    resource manages those resources as a set of name/data pairs, where:

    - The name uniquely identifies a particular resource of that type.

    - The name is sufficient to construct the etcd key where that resource is
      stored in etcd, and conversely can be constructed from a resource's etcd
      key.  (So the name could be the complete etcd key; but it doesn't have to
      be, and for the v3 resources here it is just the metadata name field -
      which works because we only use a single namespace.)

    - The data needs to be in some form that is comparable, between the data
      that exists in etcd for a given resource name, and the data for that same
      resource name that is generated from relevant Neutron data.  Each
      ResourceSyncer subclass has methods for those two things, and they just
      need to be consistent in how they return that 'data'.

    The resync logic uses a mixture of etcd and Neutron transaction semantics
    to ensure that it never writes obsolete data to etcd - bearing in mind that
    other forks of the Neutron server can process dynamic changes to relevant
    Neutron resources concurrently with our resyncing, and that resyncing can
    take a relatively long time in a non-trivial deployment.

    When writing a resource that was missing in etcd, it:

    - holds a transaction on the Neutron DB

    - rereads the relevant Neutron object, and jumps out if it no longer exists

    - submits an etcd transaction to write corresponding Calico data only if
      that _creates_ the relevant etcd key

    - releases the Neutron DB transaction.

    When writing a resource that was present but incorrect in etcd, it uses an
    etcd transaction that only writes new data if the mod_revision of the
    relevant etcd key is still what it was when the syncer read the incorrect
    data.

    When deleting a stale etcd resource, it uses an etcd transaction that only
    deletes if the mod_revision of the relevant etcd key is still what it was
    when the syncer read the incorrect data.
    """

    def __init__(self, db, resource_kind, inject_per_item_delay_ms=0):
        self.db = db
        self.resource_kind = resource_kind
        # Test-only: when positive, sleep this many ms after each
        # iteration of the compare loop below.  Used by the resync-
        # concurrency test (CORE-12037).  Always 0 in production.  Clamp
        # to 0 defensively: time.sleep() raises ValueError on a negative
        # argument, which would silently turn a misconfigured test knob
        # into a resync failure.  The two call sites (mech_calico's
        # IntOpt and the calico-resync --inject-per-item-delay-ms flag)
        # both have their own non-negativity checks, but a single guard
        # here covers any future caller too.
        self._inject_per_item_delay_secs = max(0, inject_per_item_delay_ms) / 1000.0

    def resync(self, context, scope):
        """Reconcile this resource type's etcd state with Neutron.

        When ``scope.all()`` is True, we read every resource of this kind from both
        sides, and reconcile in both directions (writing missing/incorrect etcd
        resources and deleting etcd resources whose Neutron counterpart is gone).

        Alternatively, ``scope.ids()`` is a set of specific Neutron resource IDs, in
        which case the reconcile is restricted to just those resources.  The decision
        tree per resource is the same:

          * in Neutron, in etcd, data matches  -> no-op (correct)
          * in Neutron, in etcd, data differs  -> update
          * in Neutron, not in etcd            -> create
          * not in Neutron, in etcd            -> delete

        Read order is etcd-first.  This gives natural CAS-based protection against
        a concurrent dynamic update happening between our two reads: any etcd write
        that lands between get_from_etcd and get_from_neutron leaves the etcd key at
        a newer mod_revision than the one we recorded, so the in-neutron-only-create
        and in-etcd-only-delete branches' CAS operations fail harmlessly.  Reading
        Neutron first would expose both the delete (a concurrent create makes us
        think the etcd entry is orphan) and the update (a concurrent edit makes us
        clobber the newer etcd value with stale data) to that race.

        Returns a structured summary dict of what happened: per-phase timings
        (etcd_read, neutron_read, compare, create) plus item counts (etcd_items,
        neutron_items, correct, updated, deleted, created).  The runner exposes these in
        the JSON ResyncResult; the same numbers are also logged in a single summary line
        on completion.

        For each resource that needs fixing -- create, update or delete -- a single
        per-item INFO line is emitted naming the resource kind and name.  Resources
        whose etcd data already matches Neutron are not enumerated at INFO; they are
        only logged at DEBUG.  This is the per-item observability surface for
        CORE-12922 / PMREQ-839 User Story #2.
        """
        resync_start = time.monotonic()

        LOG.info(
            "Starting resync for %s (scope=%s); getting data from etcd...",
            self.resource_kind,
            scope,
        )

        # Short-circuit: narrow scope that expanded to no IDs (e.g. `calico-resync
        # --port <pid>` without --include-sgs-for-ports leaves the SG scope empty) means
        # nothing to read or compare.
        if not scope.all() and not scope.ids():
            etcd_map = {}
            neutron_map = {}
            t_etcd_read = t_neutron_read = resync_start
        else:
            etcd_map = self.get_from_etcd(scope)
            t_etcd_read = time.monotonic()

            # ``get_from_neutron`` calls ``self.db.get_*`` methods (or, in the endpoint
            # syncer's case, an internal helper that wraps its own raw queries in a
            # CONTEXT_READER), all of which are ``@retry_if_session_inactive``-decorated
            # and manage their own transactions.  We deliberately do NOT wrap them in an
            # outer writer/reader: the Neutron devref calls that pattern an anti-pattern
            # because the inner retry "would be always called from inside an active
            # transaction making it useless".
            neutron_map = self.get_from_neutron(context, scope)
            t_neutron_read = time.monotonic()

            # Resource-specific post-processing of etcd_map now that we have neutron_map
            # (e.g. the WEP syncer uses this to relabel destination-side WEPs).  The
            # default implementation is a no-op.
            etcd_map = self.post_process_etcd_map(scope, etcd_map, neutron_map)

        LOG.info(
            "Resync for %s: %d items from etcd in %.3fs, "
            "%d items from neutron in %.3fs, comparing...",
            self.resource_kind,
            len(etcd_map),
            t_etcd_read - resync_start,
            len(neutron_map),
            t_neutron_read - t_etcd_read,
        )

        n_correct = 0
        n_updated = 0
        n_deleted = 0
        n_created = 0

        # Process "lm <name>" entries before everything else so that, when a
        # mid-migration port is being created from scratch in etcd, Felix sees the
        # LiveMigration resource before the destination WorkloadEndpoint -- matching the
        # ordering the dynamic postcommit path uses on migration start.  The key is a
        # no-op for resource kinds that don't have "lm " prefixed names; the secondary
        # sort by name keeps the order deterministic across runs.
        def _iter_order(n):
            return (0 if n.startswith("lm ") else 1, n)

        # Compare-loop marker.  The resync-concurrency test (CORE-12037) waits
        # for this line in the resync log before firing its in-resync burst, so
        # the burst lands inside the test-injected per-item delay window rather
        # than during the etcd read or the neutron read.
        LOG.info("Resync for %s: starting compare loop", self.resource_kind)

        for name in sorted(set(etcd_map) | set(neutron_map), key=_iter_order):
            in_etcd = name in etcd_map
            in_neutron = name in neutron_map

            if in_neutron and in_etcd:
                # Compare and update if different.  reread=False because we just read
                # this name from Neutron, and etcd-first ordering means our Neutron read
                # is at least as fresh as our etcd read; the CAS on mod_revision
                # protects against any etcd change since.
                data, mod_revision = etcd_map[name]
                write_data = self.neutron_to_etcd_write_data(
                    name, neutron_map[name], context, reread=False
                )
                if self.etcd_write_data_matches_existing(write_data, data):
                    # CORE-12922: items already correct are not enumerated
                    # at INFO -- only ones that need fixing (the create /
                    # update / delete branches below) get a per-item line.
                    LOG.debug("etcd data good for %s %s", self.resource_kind, name)
                    n_correct += 1
                else:
                    # Include the existing etcd data and the new Neutron-derived
                    # data so the operator can see what changed.  The shape of
                    # each varies by resource kind -- for endpoints it's a
                    # (spec, labels, annotations) tuple, for the others just the
                    # spec dict -- but in every case both halves are comparable
                    # because they're what etcd_write_data_matches_existing
                    # just declared unequal.
                    LOG.info(
                        "Resync updating %s %s in etcd: old=%s, new=%s",
                        self.resource_kind,
                        name,
                        data,
                        write_data,
                    )
                    if self.update_in_etcd(name, write_data, mod_revision):
                        n_updated += 1
                    else:
                        LOG.warning(
                            "failed etcd write for %s %s; presume"
                            " data updated by another writer",
                            self.resource_kind,
                            name,
                        )
            elif in_neutron:
                # In Neutron but not in etcd: create.  reread=True so we don't race with
                # a concurrent dynamic delete.
                try:
                    write_data = self.neutron_to_etcd_write_data(
                        name, neutron_map[name], context, reread=True
                    )
                    LOG.info(
                        "Resync creating %s %s in etcd",
                        self.resource_kind,
                        name,
                    )
                    if self.create_in_etcd(name, write_data):
                        n_created += 1
                    else:
                        LOG.warning(
                            "failed etcd write for %s %s; presume"
                            " data created by another writer",
                            self.resource_kind,
                            name,
                        )
                except ResourceGone:
                    LOG.warning(
                        "Neutron resource gone for %s %s; presume"
                        " deleted by another writer",
                        self.resource_kind,
                        name,
                    )
            elif in_etcd:
                # In etcd but not in Neutron: delete.
                _, mod_revision = etcd_map[name]
                LOG.info(
                    "Resync deleting %s %s from etcd",
                    self.resource_kind,
                    name,
                )
                if self.delete_from_etcd(name, mod_revision):
                    n_deleted += 1
                else:
                    LOG.warning(
                        "failed etcd delete for %s %s; presume"
                        " data updated by another writer",
                        self.resource_kind,
                        name,
                    )
            # else: name was in scope but neither side has it -- nothing to do.
            if self._inject_per_item_delay_secs:
                time.sleep(self._inject_per_item_delay_secs)
        t_compare = time.monotonic()

        # Delete any legacy etcd data for this kind of resource.  Only makes sense in
        # the all-scope path.
        if scope.all():
            self.delete_legacy_etcd_data()
        t_end = time.monotonic()

        summary = {
            "etcd_read_ms": int((t_etcd_read - resync_start) * 1000),
            "neutron_read_ms": int((t_neutron_read - t_etcd_read) * 1000),
            "compare_ms": int((t_compare - t_neutron_read) * 1000),
            "create_ms": int((t_end - t_compare) * 1000),
            "etcd_items": len(etcd_map),
            "neutron_items": len(neutron_map),
            "correct": n_correct,
            "updated": n_updated,
            "deleted": n_deleted,
            "created": n_created,
        }
        LOG.info(
            "Resync for %s done in %.3fs: "
            "etcd_read=%.3fs neutron_read=%.3fs compare=%.3fs create=%.3fs "
            "| %d etcd items, %d neutron items "
            "| %d correct, %d updated, %d deleted, %d created",
            self.resource_kind,
            t_end - resync_start,
            t_etcd_read - resync_start,
            t_neutron_read - t_etcd_read,
            t_compare - t_neutron_read,
            t_end - t_compare,
            len(etcd_map),
            len(neutron_map),
            n_correct,
            n_updated,
            n_deleted,
            n_created,
        )
        return summary

    def post_process_etcd_map(self, scope, etcd_map, neutron_map):
        """Optional hook for subclasses to refine etcd_map once neutron_map is known.
        Default is a no-op.  WorkloadEndpointSyncer uses this to relabel
        destination-side WEPs that the etcd read didn't know to distinguish from
        source-side WEPs.
        """
        return etcd_map

    def delete_legacy_etcd_data(self):
        # By default this is a no-op, but subclasses may override.
        pass

    def etcd_write_data_matches_existing(self, write_data, existing):
        """Test whether data that we would write is the same as existing.

        For most resource types this is a simple equality comparison, as here.
        The exception is for WorkloadEndpoints, where write_data includes
        annotations, but existing doesn't (because datamodel_v3 doesn't return
        annotations when reading from etcd); hence this is broken out into a
        method that WorkloadEndpointSyncer can override.
        """
        return write_data == existing
