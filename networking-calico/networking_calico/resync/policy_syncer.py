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

"""Resync-specific NetworkPolicy logic.

The :class:`PolicySyncer` here drives a full reconcile of NetworkPolicy state between
Neutron security groups and etcd.  It is only used from the resync runner.  Dynamic
update of the NetworkPolicy for one or more security groups goes through the free
function :func:`networking_calico.plugins.ml2.drivers.calico.policy.write_sgs_to_etcd`
instead.
"""

from oslo_log import log

from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.common import config as calico_config
from networking_calico.plugins.ml2.drivers.calico.policy import policy_spec
from networking_calico.plugins.ml2.drivers.calico.policy import SG_NAME_PREFIX
from networking_calico.resync.syncer import ResourceSyncer

LOG = log.getLogger(__name__)


class PolicySyncer(ResourceSyncer):

    def __init__(self, db, txn_from_context):
        super(PolicySyncer, self).__init__(db, txn_from_context, "NetworkPolicy")
        self.region_string = calico_config.get_region_string()
        self.namespace = datamodel_v3.get_namespace(self.region_string)

    def get_from_neutron(self, context, scope):
        if scope.all():
            sgs = self.db.get_security_groups(context)
        else:
            sgs = self.db.get_security_groups(
                context, filters={"id": list(scope.ids())}
            )
        return dict((SG_NAME_PREFIX + sg["id"], sg) for sg in sgs)

    def get_from_etcd(self, scope, neutron_map):
        if scope.all():
            return {
                name: (spec, revision)
                for name, spec, revision in datamodel_v3.get_all(
                    self.resource_kind, self.namespace
                )
                if name.startswith(SG_NAME_PREFIX)
            }

        neutron_ids_read = {sg["id"] for sg in neutron_map.values()}
        names_for_missing_scope_ids = {
            SG_NAME_PREFIX + sgid for sgid in scope.ids() - neutron_ids_read
        }
        names = set(neutron_map) | names_for_missing_scope_ids
        etcd_map = {}
        for name in names:
            try:
                etcd_map[name] = datamodel_v3.get_namespaced(
                    self.resource_kind, self.namespace, name
                )
            except etcdv3.KeyNotFound:
                pass
        return etcd_map

    def delete_legacy_etcd_data(self):
        if self.namespace != datamodel_v3.NO_REGION_NAMESPACE:
            datamodel_v3.delete_legacy(self.resource_kind, SG_NAME_PREFIX)

    def create_in_etcd(self, name, spec):
        return datamodel_v3.put(
            self.resource_kind, self.namespace, name, spec, mod_revision=0
        )

    def update_in_etcd(self, name, spec, mod_revision=None):
        return datamodel_v3.put(
            self.resource_kind, self.namespace, name, spec, mod_revision=mod_revision
        )

    def delete_from_etcd(self, name, mod_revision):
        return datamodel_v3.delete(
            self.resource_kind, self.namespace, name, mod_revision=mod_revision
        )

    def neutron_to_etcd_write_data(self, name, sg, context, reread=False):
        if reread:
            # We don't need to reread the SG row itself here, because we don't
            # use any information from it, apart from its ID as a key for the
            # following rules.
            pass
        rules = self.db.get_security_group_rules(
            context, filters={"security_group_id": [sg["id"]]}
        )
        return policy_spec(sg["id"], rules)
