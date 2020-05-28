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
from networking_calico.common import intern_string

# Key used for leader election by Neutron mechanism drivers.
NEUTRON_ELECTION_KEY = "/calico/openstack/v1/neutron_election"

ENDPOINT_STATUS_UP = "up"
ENDPOINT_STATUS_DOWN = "down"
ENDPOINT_STATUS_ERROR = "error"

# Subtree used by the Neutron driver to pass subnet information to the
# DHCP agent.
SUBNET_DIR = "/calico/dhcp/v1/subnet"


class EndpointId(object):
    __slots__ = ["host", "endpoint"]

    def __init__(self, host, endpoint):
        # We intern these strings since they can occur in many IDs.  The
        # host and orchestrator are trivially repeated for all endpoints
        # on a host.  The others get repeated over time.
        self.host = intern_string(host)
        self.endpoint = intern_string(endpoint)

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
        self.orchestrator = intern_string(orchestrator)
        self.workload = intern_string(workload)

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
