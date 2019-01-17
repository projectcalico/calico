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

import json
import netaddr

from networking_calico.common import config as calico_config
from networking_calico.compat import log
from networking_calico import datamodel_v1
from networking_calico import datamodel_v2
from networking_calico import etcdv3
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceGone
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceSyncer

LOG = log.getLogger(__name__)


class SubnetSyncer(ResourceSyncer):
    """Logic for syncing Subnets.

    For Subnet resources, the name is the full etcd key, and the data is the
    etcd value as a string, i.e. not JSON-decoded into a dict.
    """
    def __init__(self, db, txn_from_context):
        super(SubnetSyncer, self).__init__(db, txn_from_context, "Subnet")
        self.region_string = calico_config.get_region_string()

    def delete_legacy_etcd_data(self):
        etcdv3.delete_prefix(datamodel_v1.SUBNET_DIR)

    def get_all_from_etcd(self):
        return etcdv3.get_prefix(datamodel_v2.subnet_dir(self.region_string))

    def get_all_from_neutron(self, context):
        return dict((datamodel_v2.key_for_subnet(subnet['id'],
                                                 self.region_string), subnet)
                    for subnet in self.db.get_subnets(context)
                    if subnet['enable_dhcp'])

    def neutron_to_etcd_write_data(self, subnet, context, reread=False):
        if reread:
            subnets = self.db.get_subnets(context,
                                          filters={'id': [subnet['id']]})
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

    @etcdv3.logging_exceptions
    def subnet_created(self, subnet, context):
        """Write data to etcd to describe a DHCP-enabled subnet."""
        LOG.info("Write subnet %s %s to etcd", subnet['id'], subnet['cidr'])
        write_data = self.neutron_to_etcd_write_data(subnet,
                                                     context,
                                                     reread=False)
        return self.update_in_etcd(
            datamodel_v2.key_for_subnet(subnet['id'], self.region_string),
            write_data)

    @etcdv3.logging_exceptions
    def subnet_deleted(self, subnet_id):
        """Delete data from etcd for a subnet that is no longer wanted."""
        LOG.info("Deleting subnet %s", subnet_id)
        # Delete the etcd key for this subnet.
        key = datamodel_v2.key_for_subnet(subnet_id, self.region_string)
        if not self.delete_from_etcd(key):
            # Already gone, treat as success.
            LOG.debug("Key %s, which we were deleting, disappeared", key)


def subnet_etcd_data(subnet):
    data = {'network_id': subnet['network_id'],
            'cidr': str(netaddr.IPNetwork(subnet['cidr'])),
            'host_routes': subnet['host_routes'],
            'gateway_ip': subnet['gateway_ip']}
    if subnet['dns_nameservers']:
        data['dns_servers'] = subnet['dns_nameservers']
    return data
