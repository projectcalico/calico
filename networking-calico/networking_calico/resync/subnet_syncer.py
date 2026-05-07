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

"""Resync-specific subnet logic.

The :class:`SubnetSyncer` here drives a full reconcile of subnet state between Neutron
and etcd.  It is only used from the resync runner (start-of-day inside neutron-server,
or out-of-band from the ``calico-resync`` CLI).  Dynamic update of a single subnet from
a Neutron postcommit hook does not go through this class - it calls
:func:`networking_calico.plugins.ml2.drivers.calico.subnets.write_subnet` /
``delete_subnet`` directly.
"""

import json

from oslo_log import log

from networking_calico import datamodel_v1
from networking_calico import datamodel_v2
from networking_calico import etcdv3
from networking_calico.common import config as calico_config
from networking_calico.plugins.ml2.drivers.calico.subnets import subnet_etcd_data
from networking_calico.resync.syncer import ResourceGone
from networking_calico.resync.syncer import ResourceSyncer

LOG = log.getLogger(__name__)


class SubnetSyncer(ResourceSyncer):
    """Logic for syncing Subnets.

    For Subnet resources, the name is the full etcd key, and the data is the etcd value
    as a string, i.e. not JSON-decoded into a dict.
    """

    def __init__(self, db, txn_from_context):
        super(SubnetSyncer, self).__init__(db, txn_from_context, "Subnet")
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

    def get_from_etcd(self, scope, neutron_map):
        if scope.all():
            return {
                name: (spec, revision)
                for name, spec, revision in etcdv3.get_prefix(
                    datamodel_v2.subnet_dir(self.region_string)
                )
            }

        neutron_ids_read = {subnet["id"] for subnet in neutron_map.values()}
        names_for_missing_scope_ids = {
            datamodel_v2.key_for_subnet(subnet_id, self.region_string)
            for subnet_id in scope.ids() - neutron_ids_read
        }
        names = set(neutron_map) | names_for_missing_scope_ids
        etcd_map = {}
        for name in names:
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
        return json.dumps(subnet_etcd_data(subnet))

    def create_in_etcd(self, key, value):
        return etcdv3.put(key, value, mod_revision=0)

    def update_in_etcd(self, key, value, mod_revision=None):
        return etcdv3.put(key, value, mod_revision=mod_revision)

    def delete_from_etcd(self, key, mod_revision=None):
        return etcdv3.delete(key, mod_revision=mod_revision)
