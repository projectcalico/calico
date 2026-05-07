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
"""Common subnet -> etcd write/delete code.

These free functions are the single source of truth for "translate a Neutron subnet to
its etcd representation, and write or delete it in etcd".  They are called from two
places:

* the mech_calico driver's create/update/delete subnet postcommit hooks, when a Neutron
  API request notifies us of a subnet change;

* :class:`networking_calico.resync.subnet_syncer.SubnetSyncer`, when start-of-day or
  on-demand resync rebuilds etcd state from Neutron.
"""

import json

import netaddr

from oslo_log import log

from networking_calico import datamodel_v2
from networking_calico import etcdv3
from networking_calico.common import config as calico_config

LOG = log.getLogger(__name__)


@etcdv3.logging_exceptions
def write_subnet(subnet):
    """Write etcd data for a DHCP-enabled subnet."""
    LOG.info("Write subnet %s %s to etcd", subnet["id"], subnet["cidr"])
    region_string = calico_config.get_region_string()
    return etcdv3.put(
        datamodel_v2.key_for_subnet(subnet["id"], region_string),
        json.dumps(subnet_etcd_data(subnet)),
    )


@etcdv3.logging_exceptions
def delete_subnet(subnet_id):
    """Delete data from etcd for a subnet that is no longer wanted."""
    LOG.info("Deleting subnet %s", subnet_id)
    region_string = calico_config.get_region_string()
    key = datamodel_v2.key_for_subnet(subnet_id, region_string)
    if not etcdv3.delete(key):
        LOG.debug("Key %s, which we were deleting, disappeared", key)


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
