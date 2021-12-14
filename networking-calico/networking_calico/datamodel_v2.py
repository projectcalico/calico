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
"""
Shared etcd data-model definitions for version 2 of the data model.

Version 2 is similar to version 1 but with region-awareness added into
some of the etcd key paths.

The wider Calico data model is now v3.  The legacy definitions here
are private to networking-calico (i.e. the Neutron driver and the
Calico DHCP agent) and Felix's status-reporting code.  However, when
changing these, we still need to consider upgrading an existing
Calico/OpenStack deployment.

"""
import re

from networking_calico import datamodel_v1

# Region string used when no region name has been configured.
NO_REGION = "no-region"

# Region string prefix used when a region name has been configured.
REGION_PREFIX = "region-"


# Subtree used by Felix to report its own status (as an OpenStack
# 'agent') and the status of each endpoint (or OpenStack 'port') that
# it is responsible for.
#
# Agent status is at /calico/felix/v2/<region_string>/host/<hostname>/status.
#
# Port status is at /calico/felix/v2/<region_string>//host/<hostname>/
#                    workload/openstack/<workload>/endpoint/<endpoint>.
def felix_status_dir(region_string=NO_REGION):
    return "/calico/felix/v2/%s/host" % region_string


# Regex to match endpoints, captures "hostname" and "endpoint_id".
# Works for endpoint status paths.
_cached_endpoint_key_re = None


def get_endpoint_id_from_key(region_string, key):
    global _cached_endpoint_key_re
    if _cached_endpoint_key_re is None:
        _cached_endpoint_key_re = re.compile(
            r'^(?:' + felix_status_dir(region_string) + r')'
            r'/(?P<hostname>[^/]+)/'
            r'workload/'
            r'(?P<orchestrator>[^/]+)/'
            r'(?P<workload_id>[^/]+)/'
            r'endpoint/(?P<endpoint_id>[^/]+)')
    m = _cached_endpoint_key_re.match(key)
    if m:
        # Got an endpoint.
        host = m.group("hostname")
        orch = m.group("orchestrator")
        workload_id = m.group("workload_id")
        endpoint_id = m.group("endpoint_id")
        combined_id = datamodel_v1.WloadEndpointId(host,
                                                   orch,
                                                   workload_id,
                                                   endpoint_id)
        return combined_id
    else:
        return None


def _reset_globals():
    global _cached_endpoint_key_re
    _cached_endpoint_key_re = None


# Region-aware subnet path.
def subnet_dir(region_string=NO_REGION):
    return "/calico/dhcp/v2/%s/subnet" % region_string


def key_for_subnet(subnet_id, region_string):
    return subnet_dir(region_string) + "/%s" % subnet_id


# Key used for leader election by Neutron mechanism drivers.
def neutron_election_key(region_string):
    return "/calico/openstack/v2/%s/neutron_election" % region_string
