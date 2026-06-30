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

import json

import netaddr

from oslo_log import log

from networking_calico import datamodel_v1
from networking_calico import datamodel_v2
from networking_calico import etcdv3
from networking_calico.common import config as calico_config
from networking_calico.plugins.ml2.drivers.calico.syncer import MAX_CAS_ATTEMPTS
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceGone
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceSyncer

LOG = log.getLogger(__name__)


class SubnetSyncer(ResourceSyncer):
    """Logic for syncing Subnets.

    For Subnet resources, the name is the full etcd key, and the data is the etcd value
    as a string, i.e. not JSON-decoded into a dict.
    """

    def __init__(self, db):
        super(SubnetSyncer, self).__init__(db, "Subnet")
        self.region_string = calico_config.get_region_string()

    def get_from_neutron(self, context, scope):
        if scope.all():
            subnets = self.db.get_subnets(context)
        else:
            subnets = self.db.get_subnets(context, filters={"id": list(scope.ids())})
        return dict(
            (datamodel_v2.key_for_subnet(subnet["id"], self.region_string), subnet)
            for subnet in subnets
            if subnet["enable_dhcp"]
        )

    def get_from_etcd(self, scope):
        if scope.all():
            return {
                name: (spec, revision)
                for name, spec, revision in etcdv3.get_prefix(
                    datamodel_v2.subnet_dir(self.region_string)
                )
            }

        # Narrow scope: read just the etcd keys we can compute directly from
        # scope.ids().
        etcd_map = {}
        for sid in scope.ids():
            name = datamodel_v2.key_for_subnet(sid, self.region_string)
            try:
                etcd_map[name] = etcdv3.get(name)
            except etcdv3.KeyNotFound:
                pass
        return etcd_map

    def delete_legacy_etcd_data(self):
        etcdv3.delete_prefix(datamodel_v1.SUBNET_DIR)

    def neutron_to_etcd_write_data(self, name, subnet, context, reread=False):
        if reread:
            subnets = self.db.get_subnets(context, filters={"id": [subnet["id"]]})
            if len(subnets) != 1:
                raise ResourceGone()
            subnet = subnets[0]
        if not subnet["enable_dhcp"]:
            raise ResourceGone()
        return json.dumps(subnet_etcd_data(subnet))

    def create_in_etcd(self, key, value):
        return etcdv3.put(key, value, mod_revision=0)

    def update_in_etcd(self, key, value, mod_revision=None):
        return etcdv3.put(key, value, mod_revision=mod_revision)

    def delete_from_etcd(self, key, mod_revision=None):
        return etcdv3.delete(key, mod_revision=mod_revision)

    @etcdv3.logging_exceptions
    def sync_subnet(self, subnet, context):
        """Sync data in etcd to describe a Neutron subnet.

        Uses CAS-against-mod_revision with retry so a concurrent dynamic write to the
        same subnet key cannot get overwritten by a later out-of-order write from
        another worker.  See ``sync_wep`` in endpoints.py for the same retry pattern on
        a Calico v3 resource; this implementation is inlined because Subnet data is
        stored as JSON-as-string (not as a Calico v3 resource) and so uses ``etcdv3``
        directly rather than ``datamodel_v3``.
        """
        # ``cidr`` is here only for log context; some delete-path callers (or future
        # Neutron versions) may hand us a minimal subnet dict, so look it up defensively
        # rather than risk a KeyError that would mask the actual CAS-delete work below.
        LOG.info(
            "Sync subnet %s %s to etcd", subnet["id"], subnet.get("cidr", "<unknown>")
        )
        subnet_id = subnet["id"]
        key = datamodel_v2.key_for_subnet(subnet_id, self.region_string)
        for attempt in range(MAX_CAS_ATTEMPTS):
            try:
                _, mod_revision = etcdv3.get(key)
            except etcdv3.KeyNotFound:
                mod_revision = 0
            try:
                # Re-read the subnet from the Neutron DB so that we can be sure of
                # writing subnet data (if necessary) that post-dates what we just read
                # from etcd.
                write_data = self.neutron_to_etcd_write_data(
                    "", subnet, context, reread=True
                )
            except ResourceGone:
                # The DB re-read says this subnet should not be in Calico (either gone
                # entirely, or enable_dhcp is now False).  Either drop the etcd entry
                # via CAS at the mod_revision we just read, or -- if no entry was
                # there -- we are done.  CAS on the delete is essential: an
                # unconditional delete would clobber a re-create that landed between
                # our etcd read and our delete.  On CAS failure, fall through to the
                # next loop iteration and re-evaluate from scratch.
                LOG.info("Subnet %s should not exist in Calico datastore", subnet_id)
                if mod_revision == 0:
                    return
                if self.delete_from_etcd(key, mod_revision=mod_revision):
                    return
                LOG.debug(
                    "Subnet delete CAS retry %d/%d for %s",
                    attempt + 1,
                    MAX_CAS_ATTEMPTS,
                    subnet_id,
                )
                continue
            if self.update_in_etcd(key, write_data, mod_revision=mod_revision):
                return
            LOG.debug(
                "Subnet CAS retry %d/%d for %s",
                attempt + 1,
                MAX_CAS_ATTEMPTS,
                subnet_id,
            )
        LOG.warning(
            "Subnet CAS exhausted %d retries for %s; relying on startup"
            " resync to repair any drift",
            MAX_CAS_ATTEMPTS,
            subnet_id,
        )
        return


def subnet_etcd_data(subnet):
    """Translate a Neutron subnet dict to its etcd representation."""
    data = {
        "network_id": subnet["network_id"],
        "cidr": str(netaddr.IPNetwork(subnet["cidr"])),
        "host_routes": subnet["host_routes"],
        "gateway_ip": subnet["gateway_ip"],
    }
    if subnet["dns_nameservers"]:
        data["dns_servers"] = subnet["dns_nameservers"]
    if subnet.get("ipv6_ra_mode") and subnet.get("ipv6_address_mode"):
        data["ipv6_ra_mode"] = subnet["ipv6_ra_mode"]
        data["ipv6_address_mode"] = subnet["ipv6_address_mode"]

    return data
