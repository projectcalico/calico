# -*- coding: utf-8 -*-
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

from networking_calico.compat import log

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
    Neutron resources concurrently with our periodic resyncing, and that
    periodic resyncing can take a relatively long time in a non-trivial
    deployment.

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

    def resync(self, context):
        LOG.info("Starting resync for %s; getting data from etcd...",
                 self.resource_kind)

        # Get all resources of this type from etcd - as an array of (name,
        # data, mod_revision) tuples.
        etcd_resources = self.get_all_from_etcd()

        # Get the corresponding Neutron resources - as a map from resource name
        # to <relevant Neutron data>.
        LOG.info("Resync for %s; got etcd data (%s items), "
                 "getting data from neutron...",
                 self.resource_kind, len(etcd_resources))
        with self.txn_from_context(context, "get-all-" + self.resource_kind):
            neutron_map = self.get_all_from_neutron(context)

        # The set of resource names that should exist and for which we've
        # already compared the existing etcd data against Neutron.
        names_compared = set()

        LOG.info("Resync for %s; got neutron data (%s items), look for "
                 "incorrect data...", self.resource_kind, len(neutron_map))
        for etcd_resource in etcd_resources:
            name, data, mod_revision = etcd_resource
            if name in neutron_map:
                # Note that we're looking at this name, so we don't try to add
                # etcd data again for it below.
                names_compared.add(name)

                # Translate the Neutron resource to what we would write into
                # etcd.  Take a transaction here in case the subclass method
                # needs more Neutron DB reads.
                with self.txn_from_context(context,
                                           "update-" + self.resource_kind):
                    write_data = self.neutron_to_etcd_write_data(
                        neutron_map[name],
                        context,
                        reread=False
                    )

                # Compare that against what we already have in etcd.
                if self.etcd_write_data_matches_existing(write_data, data):
                    LOG.debug("etcd data good for %s %s",
                              self.resource_kind, name)
                else:
                    # There's a difference, so do the write.
                    LOG.warning("etcd rewrite needed for %s %s",
                                self.resource_kind, name)
                    if not self.update_in_etcd(name, write_data, mod_revision):
                        LOG.warning("failed etcd write for %s %s; presume" +
                                    " data updated by another writer",
                                    self.resource_kind, name)
            else:
                # This name is in etcd but now has nothing corresponding in
                # Neutron, so remember it for deletion from etcd.
                LOG.warning("etcd deletion needed for %s %s",
                            self.resource_kind, name)
                if not self.delete_from_etcd(name, mod_revision):
                    LOG.warning("failed etcd delete for %s %s; presume" +
                                " data updated by another writer",
                                self.resource_kind, name)

        LOG.info("Resync for %s; got etcd data, look for deletions...",
                 self.resource_kind)
        for name, neutron_data in neutron_map.items():
            # Skip this name if we already handled it above - i.e. if we
            # already had data for it in etcd.
            if name in names_compared:
                continue

            with self.txn_from_context(context,
                                       "create-" + self.resource_kind):
                try:
                    # Reread the Neutron resource and translate it to what we
                    # would write into etcd.
                    write_data = self.neutron_to_etcd_write_data(neutron_data,
                                                                 context,
                                                                 reread=True)
                    # Create etcd resource with that data.
                    if not self.create_in_etcd(name, write_data):
                        LOG.warning("failed etcd write for %s %s; presume" +
                                    " data created by another writer",
                                    self.resource_kind, name)
                except ResourceGone:
                    LOG.warning("Neutron resource gone for %s %s; presume" +
                                " deleted by another writer",
                                self.resource_kind, name)

        # Delete any legacy etcd data for this kind of resource.  (For example,
        # how this resource was represented in a previous release.)
        self.delete_legacy_etcd_data()

        LOG.info("Resync for %s; done.", self.resource_kind)

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
