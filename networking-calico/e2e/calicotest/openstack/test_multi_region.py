# Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
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

from calicotest.common import datamodel_v3
from calicotest.openstack.topology import Topology

_log = logging.getLogger(__name__)


class TestMultiRegion(Topology):
    """
    Tests that require multiple OpenStack regions.  In a multi-region
    topology, each OpenStack region has its own nova/neutron etc but
    the regions share keystone and horizon.  The Calico deployment
    spans multiple regions.  I.e. there is a shared etcd.

    In a multi-region set-up, each instance of neutron has its own
    Calico plugin and Calico is configured with the name of the region.
    It then writes its resources (endpoints and policies, for example)
    in a namespace named by that region.

    The namespace is exposed as the projectcalico.org/namespace
    label, which is set to either "openstack" or
    "openstack-region-<region-name>".

    """

    def setUp(self):
        super(TestMultiRegion, self).setUp()

        if len(self.regions) < 2:
            self.skipTest("This test requires multiple regions")

        self.r1 = self.regions[0]
        self.r2 = self.regions[1]
        _log.info("Using '%s' as region 1 and '%s' as region 2", self.r1, self.r2)

        r1_vm_threads = [
            self.create_vm_parallel(region=self.regions[0]) for _ in range(3)
        ]
        r2_vm_threads = [
            self.create_vm_parallel(region=self.regions[1]) for _ in range(3)
        ]
        self.vms_by_region = {}
        self.r1_vms = [t.join() for t in r1_vm_threads]
        self.vms_by_region[self.r1] = self.r1_vms
        self.r2_vms = [t.join() for t in r2_vm_threads]
        self.vms_by_region[self.r2] = self.r2_vms
        self.all_vms = self.r1_vms + self.r2_vms
        self.clean_up_policies()

    def tearDown(self):
        self.clean_up_policies()

        for r, vms in self.vms_by_region.items():
            for vm in vms:
                self.delete_vm(vm.name, region=r)

        super(TestMultiRegion, self).tearDown()

    def clean_up_policies(self):
        datamodel_v3.delete("GlobalNetworkPolicy", "default.r1ingress")
        datamodel_v3.delete("GlobalNetworkPolicy", "default.alphaingress")
        datamodel_v3.delete("NetworkPolicy", "default.r1ingress", region=self.r1)

    def test_namespaced_network_policy(self):
        """
        Test that a namespaced network policy can refer to VMs in
        another region.
        """
        self.check_baseline_connectivity()

        # Configure Calico policy to allow traffic from region 2 to region 1.
        r2_selector = "projectcalico.org/namespace == 'openstack-region-%s'" % self.r2
        r1_ingress_from_r2 = {
            "selector": "all()",
            "types": ["Ingress"],
            "ingress": [
                {
                    "action": "Allow",
                    "source": {
                        "namespaceSelector": "all()",
                        "selector": r2_selector,
                    },
                },
            ],
        }
        datamodel_v3.put(
            "NetworkPolicy", "default.r1ingress", r1_ingress_from_r2, region=self.r1
        )

        self.check_mutual_connectivity(
            source_list=self.r1_vms,
            pass_list=self.r1_vms,
            fail_list=self.r2_vms,
        )
        self.check_mutual_connectivity(
            source_list=self.r2_vms,
            pass_list=self.r1_vms + self.r2_vms,
        )

    def check_baseline_connectivity(self):
        # By default we create a security group for each project that
        # only allows internal connectivity, so check that.
        self.check_mutual_connectivity(pass_list=self.r1_vms, fail_list=self.r2_vms)
        self.check_mutual_connectivity(pass_list=self.r2_vms, fail_list=self.r1_vms)

    def test_global_network_policy_region_selector(self):
        """
        Test that a global network policy can match on region namespace.
        """
        self.check_baseline_connectivity()

        # Configure Calico policy to allow traffic from region 2 to region 1.
        r1_selector = "projectcalico.org/namespace == 'openstack-region-%s'" % self.r1
        r2_selector = "projectcalico.org/namespace == 'openstack-region-%s'" % self.r2
        r1_ingress_from_r2 = {
            "selector": r1_selector,
            "types": ["Ingress"],
            "ingress": [
                {
                    "action": "Allow",
                    "source": {
                        "selector": r2_selector,
                    },
                },
            ],
        }
        datamodel_v3.put("GlobalNetworkPolicy", "default.r1ingress", r1_ingress_from_r2)

        self.check_mutual_connectivity(
            source_list=self.r1_vms,
            pass_list=self.r1_vms,
            fail_list=self.r2_vms,
        )
        self.check_mutual_connectivity(
            source_list=self.r2_vms,
            pass_list=self.r1_vms + self.r2_vms,
        )

    def test_regions_and_sgs(self):
        """
        Test that a global network policy can match on SG name
        across regions.
        """
        self.create_security_group_with_basic_rules("alpha", region=self.r1)
        self.create_security_group_with_basic_rules("alpha", region=self.r2)
        self.create_security_group_with_basic_rules("beta", region=self.r1)
        self.create_security_group_with_basic_rules("beta", region=self.r2)

        r1_vms = self.vms_by_region[self.r1]
        r2_vms = self.vms_by_region[self.r2]

        # Move VM 0 into a security group "alpha" and VMs 1 & 2 in "beta" in
        # each region.
        self.add_sec_group_to_vm(r1_vms[0].name, "alpha", region=self.r1)
        self.remove_sec_group_from_vm(r1_vms[0].name, "default", region=self.r1)
        self.add_sec_group_to_vm(r2_vms[0].name, "alpha", region=self.r2)
        self.remove_sec_group_from_vm(r2_vms[0].name, "default", region=self.r2)
        self.add_sec_group_to_vm(r1_vms[1].name, "beta", region=self.r1)
        self.remove_sec_group_from_vm(r1_vms[1].name, "default", region=self.r1)
        self.add_sec_group_to_vm(r2_vms[1].name, "beta", region=self.r2)
        self.remove_sec_group_from_vm(r2_vms[1].name, "default", region=self.r2)
        self.add_sec_group_to_vm(r1_vms[2].name, "beta", region=self.r1)
        self.remove_sec_group_from_vm(r1_vms[2].name, "default", region=self.r1)
        self.add_sec_group_to_vm(r2_vms[2].name, "beta", region=self.r2)
        self.remove_sec_group_from_vm(r2_vms[2].name, "default", region=self.r2)

        # Check we only have connectivity within the SGs.
        r1_beta_vms = r1_vms[1:2]
        r1_alpha_vms = r1_vms[:1]
        self.check_mutual_connectivity(r1_beta_vms, r1_alpha_vms + r2_vms)
        r2_beta_vms = r2_vms[1:2]
        r2_alpha_vms = r2_vms[:1]
        self.check_mutual_connectivity(r2_beta_vms, r2_alpha_vms + r1_vms)

        # Configure Calico policy to allow traffic from beta to alpha.
        alpha_sel = "has(sg-name.projectcalico.org/openstack-alpha)"
        beta_sel = "has(sg-name.projectcalico.org/openstack-beta)"
        alpha_ingress_from_beta = {
            "selector": alpha_sel,
            "types": ["Ingress"],
            "ingress": [
                {
                    "action": "Allow",
                    "source": {
                        "selector": beta_sel,
                    },
                },
            ],
        }
        datamodel_v3.put(
            "GlobalNetworkPolicy", "default.alphaingress", alpha_ingress_from_beta
        )

        # Check we now have connectivity from beta to alpha.
        all_alpha_vms = r1_alpha_vms + r2_alpha_vms
        self.check_mutual_connectivity(
            source_list=r1_beta_vms,
            pass_list=r1_beta_vms + all_alpha_vms,
            fail_list=r2_beta_vms,
        )
        self.check_mutual_connectivity(
            source_list=r2_beta_vms,
            pass_list=r2_beta_vms + all_alpha_vms,
            fail_list=r1_beta_vms,
        )
        # But not from alpha to anywhere else.
        self.check_mutual_connectivity(
            pass_list=r1_alpha_vms, fail_list=r1_beta_vms + r2_vms
        )
        self.check_mutual_connectivity(
            pass_list=r2_alpha_vms, fail_list=r2_beta_vms + r1_vms
        )
