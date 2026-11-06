# Copyright (c) 2014-2025 Tigera, Inc. All rights reserved.
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

import logging

from calicotest.openstack.topology import (
    Topology2Networks,
    TopologyBasic,
    TopologyBasicTenants,
)

_log = logging.getLogger(__name__)


class TestBasicSetup(TopologyBasic):
    """
    Sets up VMs in the same tenant, network and security group on
    all hosts and checks they can all connect to each other.
    """

    def test_basic_connectivity(self):
        self.check_mutual_connectivity(pass_list=self.vms)


class TestBasicNetworks(Topology2Networks):
    """
    Sets up VMs in the same tenant and security group, across 2
    networks and all hosts and checks they can all connect to each other.
    """

    def test_basic_network_connectivity(self):
        vms = self.net1_vms + self.net2_vms
        self.check_mutual_connectivity(pass_list=vms)


class TestBasicTenants(TopologyBasicTenants):
    """
    Sets up VMs in the same security group and network, across 2
    tenants and all hosts and checks they can all connect to each other.
    """

    def test_basic_tenant_connectivity(self):
        self.check_mutual_connectivity(
            pass_list=self.tenant1_vms, fail_list=self.tenant2_vms
        )
        self.check_mutual_connectivity(
            pass_list=self.tenant2_vms, fail_list=self.tenant1_vms
        )
