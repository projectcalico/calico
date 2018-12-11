# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
Shared etcd data-model definitions for version 1 of the data model.

The wider Calico data model is now v3.  The legacy v1 definitions here
are private to networking-calico (i.e. the Neutron driver and the
Calico DHCP agent) and Felix's status-reporting code.  However, when
changing these, we still need to consider upgrading an existing
Calico/OpenStack deployment.
"""
import re

# Subtree used by Felix to report its own status (as an OpenStack
# 'agent') and the status of each endpoint (or OpenStack 'port') that
# it is responsible for.
#
# Agent status is at /calico/felix/v1/host/<hostname>/status.
#
# Port status is at /calico/felix/v1/host/<hostname>/
#                    workload/openstack/<workload>/endpoint/<endpoint>.
FELIX_STATUS_DIR = "/calico/felix/v1/host"

# Key used for leader election by Neutron mechanism drivers.
NEUTRON_ELECTION_KEY = "/calico/openstack/v1/neutron_election"

# Regex to match endpoints, captures "hostname" and "endpoint_id".
# Works for endpoint status paths.
ENDPOINT_KEY_RE = re.compile(
    r'^(?:' + FELIX_STATUS_DIR + r')'
    r'/(?P<hostname>[^/]+)/'
    r'workload/'
    r'(?P<orchestrator>[^/]+)/'
    r'(?P<workload_id>[^/]+)/'
    r'endpoint/(?P<endpoint_id>[^/]+)')

ENDPOINT_STATUS_UP = "up"
ENDPOINT_STATUS_DOWN = "down"
ENDPOINT_STATUS_ERROR = "error"

# Subtree used by the Neutron driver to pass subnet information to the
# DHCP agent.
SUBNET_DIR = "/calico/dhcp/v1/subnet"


def key_for_subnet(subnet_id):
    return SUBNET_DIR + "/%s" % subnet_id


def get_endpoint_id_from_key(key):
    m = ENDPOINT_KEY_RE.match(key)
    if m:
        # Got an endpoint.
        host = m.group("hostname")
        orch = m.group("orchestrator")
        workload_id = m.group("workload_id")
        endpoint_id = m.group("endpoint_id")
        combined_id = WloadEndpointId(host, orch, workload_id, endpoint_id)
        return combined_id
    else:
        return None


class EndpointId(object):
    __slots__ = ["host", "endpoint"]

    def __init__(self, host, endpoint):
        # We intern these strings since they can occur in many IDs.  The
        # host and orchestrator are trivially repeated for all endpoints
        # on a host.  The others get repeated over time.
        self.host = intern(host.encode("utf8"))
        self.endpoint = intern(endpoint.encode("utf8"))

    def __str__(self):
        return self.__class__.__name__ + ("<%s>" % self.endpoint)

    def __repr__(self):
        return self.__class__.__name__ + ("(%r,%r)" % (self.host,
                                                       self.endpoint))

    def __ne__(self, other):
        return not (self == other)


class WloadEndpointId(EndpointId):
    __slots__ = ["orchestrator", "workload"]

    def __init__(self, host, orchestrator, workload, endpoint):
        # We intern these strings since they can occur in many IDs.  The
        # host and orchestrator are trivially repeated for all endpoints
        # on a host.  The others get repeated over time.
        super(WloadEndpointId, self).__init__(host, endpoint)
        self.orchestrator = intern(orchestrator.encode("utf8"))
        self.workload = intern(workload.encode("utf8"))

    def __repr__(self):
        return self.__class__.__name__ + ("(%r,%r,%r,%r)" % (self.host,
                                                             self.orchestrator,
                                                             self.workload,
                                                             self.endpoint))

    def __eq__(self, other):
        if other is self:
            return True
        if not isinstance(other, WloadEndpointId):
            return False
        return (other.endpoint == self.endpoint and
                other.workload == self.workload and
                other.host == self.host and
                other.orchestrator == self.orchestrator)

    def __hash__(self):
        return hash(self.endpoint) + hash(self.workload)
