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

    def __init__(self, db, txn_from_context, resource_kind):
        self.db = db
        self.txn_from_context = txn_from_context
        self.resource_kind = resource_kind

    def resync(self, context, scope):
        """Reconcile this resource type's etcd state with Neutron.

        When ``scope.all()`` is True, we read every resource of this kind from both
        sides, and reconcile in both directions (writing missing/incorrect etcd
        resources and deleting etcd resources whose Neutron counterpart is gone).

        Alternatively, ``scope.ids()`` is a set of specific Neutron resource IDs, in
        which case the reconcile is restricted to just those resources: we read only
        their Neutron data (in one filtered query) and only their etcd entries (one read
        per name).  The decision tree per resource is the same:

          * in Neutron, in etcd, data matches  -> no-op (correct)
          * in Neutron, in etcd, data differs  -> update
          * in Neutron, not in etcd            -> create
          * not in Neutron, in etcd            -> delete

        For the narrow case, deletes are only implemented to the extent that etcd keys
        can be deterministically inferred from the resource IDs.

        Returns a structured summary dict of what happened: per-phase timings
        (etcd_read, neutron_read, compare, create) plus item counts (etcd_items,
        neutron_items, correct, updated, deleted, created).  The runner exposes these in
        the JSON ResyncResult; the same numbers are also logged in a single summary line
        on completion.
        """
        resync_start = time.monotonic()

        LOG.info(
            "Starting resync for %s (scope=%s); getting data from neutron...",
            self.resource_kind,
            scope,
        )

        # Read Neutron state first.  Narrow scope that expanded to no IDs (e.g.
        # `calico-resync --port <pid>` without --include-sgs-for-ports leaves the
        # SG scope empty) means there are no Neutron rows to fetch — skip the
        # call and avoid passing an empty list to SQLAlchemy's column.in_()
        # (well defined in 1.4+, but older versions matched all rows).  The
        # rest of resync runs through naturally on an empty neutron_map.
        if not scope.all() and not scope.ids():
            neutron_map = {}
        else:
            with self.txn_from_context(context, "get-all-" + self.resource_kind):
                neutron_map = self.get_from_neutron(context, scope)
        t_neutron_read = time.monotonic()

        # Read etcd state.  When the scope is not "all", this means the etcd data
        # corresponding to the Neutron resources that we just read, and possibly - when
        # etcd keys can be directly inferred from scope IDs - the etcd data for any IDs
        # that are in scope but not found in Neutron.
        etcd_map = self.get_from_etcd(scope, neutron_map)
        t_etcd_read = time.monotonic()

        LOG.info(
            "Resync for %s: %d items from neutron in %.3fs, "
            "%d items from etcd in %.3fs, comparing...",
            self.resource_kind,
            len(neutron_map),
            t_neutron_read - resync_start,
            len(etcd_map),
            t_etcd_read - t_neutron_read,
        )

        n_correct = 0
        n_updated = 0
        n_deleted = 0
        n_created = 0

        for name in set(etcd_map) | set(neutron_map):
            in_etcd = name in etcd_map
            in_neutron = name in neutron_map

            if in_neutron and in_etcd:
                # Compare using a write_data derived from our cached Neutron
                # read.  In steady state most resources match and we never go
                # past this branch, so we save the per-resource get_port call
                # that reread=True would cost.
                data, mod_revision = etcd_map[name]
                with self.txn_from_context(context, "compare-" + self.resource_kind):
                    cached_write_data = self.neutron_to_etcd_write_data(
                        name, neutron_map[name], context, reread=False
                    )
                if self.etcd_write_data_matches_existing(cached_write_data, data):
                    LOG.debug("etcd data good for %s %s", self.resource_kind, name)
                    n_correct += 1
                else:
                    # Mismatch.  A concurrent dynamic update may have changed
                    # Neutron between get_from_neutron and now; if so, our
                    # cached_write_data is stale and writing it would clobber
                    # the newer etcd value.  Etcd's CAS catches concurrent etcd
                    # changes but not Neutron-only ones, so reread Neutron in a
                    # fresh txn before doing the actual write.
                    LOG.warning(
                        "etcd rewrite needed for %s %s", self.resource_kind, name
                    )
                    try:
                        with self.txn_from_context(
                            context, "update-" + self.resource_kind
                        ):
                            write_data = self.neutron_to_etcd_write_data(
                                name, neutron_map[name], context, reread=True
                            )
                    except ResourceGone:
                        # Port was deleted between our read and this update.
                        # The next resync will see it as etcd-only and delete
                        # the entry; skip for now.
                        LOG.warning(
                            "Neutron resource gone for %s %s during update;"
                            " next resync will delete the etcd entry",
                            self.resource_kind,
                            name,
                        )
                        continue
                    if self.etcd_write_data_matches_existing(write_data, data):
                        # Cached read was stale; fresh read matches etcd.
                        # No write needed.
                        LOG.debug(
                            "etcd data good for %s %s after reread",
                            self.resource_kind,
                            name,
                        )
                        n_correct += 1
                    else:
                        if not self.update_in_etcd(name, write_data, mod_revision):
                            LOG.warning(
                                "failed etcd write for %s %s; presume"
                                " data updated by another writer",
                                self.resource_kind,
                                name,
                            )
                        n_updated += 1
            elif in_neutron:
                # In Neutron but not in etcd: create.  reread=True so
                # we don't race with a concurrent dynamic delete.
                with self.txn_from_context(context, "create-" + self.resource_kind):
                    try:
                        write_data = self.neutron_to_etcd_write_data(
                            name, neutron_map[name], context, reread=True
                        )
                        if not self.create_in_etcd(name, write_data):
                            LOG.warning(
                                "failed etcd write for %s %s; presume"
                                " data created by another writer",
                                self.resource_kind,
                                name,
                            )
                        n_created += 1
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
                LOG.warning("etcd deletion needed for %s %s", self.resource_kind, name)
                if not self.delete_from_etcd(name, mod_revision):
                    LOG.warning(
                        "failed etcd delete for %s %s; presume"
                        " data updated by another writer",
                        self.resource_kind,
                        name,
                    )
                n_deleted += 1
            # else: name was in scope but neither side has it -- nothing to do.
        t_compare = time.monotonic()

        # Delete any legacy etcd data for this kind of resource.  Only
        # makes sense in the all-scope path.
        if scope.all():
            self.delete_legacy_etcd_data()
        t_end = time.monotonic()

        summary = {
            "etcd_read_ms": int((t_etcd_read - t_neutron_read) * 1000),
            "neutron_read_ms": int((t_neutron_read - resync_start) * 1000),
            "compare_ms": int((t_compare - t_etcd_read) * 1000),
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
            "neutron_read=%.3fs etcd_read=%.3fs compare=%.3fs create=%.3fs "
            "| %d etcd items, %d neutron items "
            "| %d correct, %d updated, %d deleted, %d created",
            self.resource_kind,
            t_end - resync_start,
            t_neutron_read - resync_start,
            t_etcd_read - t_neutron_read,
            t_compare - t_etcd_read,
            t_end - t_compare,
            len(etcd_map),
            len(neutron_map),
            n_correct,
            n_updated,
            n_deleted,
            n_created,
        )
        return summary

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
