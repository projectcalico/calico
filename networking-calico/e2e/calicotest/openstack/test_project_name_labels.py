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

import logging
import time

from calicotest.common import datamodel_v3
from calicotest.openstack.topology import Topology

_log = logging.getLogger(__name__)


class TestProjectNameLabels(Topology):
    """
    Do testing that relies on each endpoint being given a label for
    the OpenStack project name that the endpoint VM belongs to.

    Add the "admin" role to the "neutron" user, so that Neutron server
    code is able to list projects in the Keystone DB.

    Create two particular projects for this test, "xanthe" and
    "yellow".

    Launch 3 VMs for each project.

    Verify that projects are initially isolated.  This is a
    consequence of the default SG that the test code sets up.

    Modify the default SGs, for our two projects, to allow ingress
    from anywhere.

    Verify connectivity between all 6 VMs.

    Configure Calico NetworkPolicy to isolate each project using
    one selector that matches "xanthe" and one that matches
    "yellow":

    selector: projectcalico.org/openstack-project-name == xanthe
    ingress:
    - allow from projectcalico.org/openstack-project-name == xanthe
    - otherwise deny

    selector: projectcalico.org/openstack-project-name == yellow
    ingress:
    - allow from projectcalico.org/openstack-project-name == yellow
    - otherwise deny

    Verify that there is connectivity within each project, but not
    between them.

    Terminate VMs.

    Remove the "admin" role from the "neutron" user, so that we are
    back to normal credentials.
    """

    def setUp(self):
        self.x_vms = []
        self.y_vms = []
        datamodel_v3.delete("GlobalNetworkPolicy", "default.xanthe")
        datamodel_v3.delete("GlobalNetworkPolicy", "default.yellow")

    def tearDown(self):
        datamodel_v3.delete("GlobalNetworkPolicy", "default.xanthe")
        datamodel_v3.delete("GlobalNetworkPolicy", "default.yellow")
        for vm in self.x_vms:
            self.delete_vm(vm.name, tenant="xanthe")
        for vm in self.y_vms:
            self.delete_vm(vm.name, tenant="yellow")
        self.delete_tenant("xanthe")
        self.delete_tenant("yellow")
        self.controller.tenants["admin"].delete_tenant("greek")

    def test_project_name_labels_equal(self):
        """Xanthe/Yellow test using == operator in selector"""
        self._do_project_name_labels_test(
            x_selector="projectcalico.org/openstack-project-name == 'xanthe'",
            y_selector="projectcalico.org/openstack-project-name == 'yellow'",
        )

    def test_project_name_labels_contains(self):
        """Xanthe/Yellow test using contains operator in selector"""
        self._do_project_name_labels_test(
            x_selector="projectcalico.org/openstack-project-name contains 'anth'",
            y_selector="projectcalico.org/openstack-project-name contains 'ello'",
        )

    def test_project_name_labels_start_end_with(self):
        """Xanthe/Yellow test using start/ends with operators in selectors"""
        self._do_project_name_labels_test(
            x_selector="projectcalico.org/openstack-project-name starts with 'xanth'",
            y_selector="projectcalico.org/openstack-project-name ends with 'ellow'",
        )

    def test_project_parent_id_label(self):
        """Test using one of the project's parent_id label"""
        self._do_project_name_labels_test(
            x_selector="projectcalico.org/openstack-project-parent-id == '<parent_id>'",
            y_selector="projectcalico.org/openstack-project-name == 'yellow'",
        )

    def _do_project_name_labels_test(self, x_selector, y_selector):

        # Create two dedicated projects for this test, with one of
        # them having a non-default parent.
        _, parent_id = self.controller.tenants["admin"].create_tenant(
            "greek", password="password"
        )
        self.create_tenant("xanthe", project_parent_id=parent_id)
        self.create_tenant("yellow")

        # Substitute '<parent_id>' in the selectors for the actual parent_id.
        x_selector = x_selector.replace("<parent_id>", parent_id)
        y_selector = y_selector.replace("<parent_id>", parent_id)

        # Launch 3 VMs in each project.
        x_vm_threads = [self.create_vm_parallel(tenant="xanthe") for _ in range(3)]
        y_vm_threads = [self.create_vm_parallel(tenant="yellow") for _ in range(3)]
        self.x_vms = [t.join() for t in x_vm_threads]
        self.y_vms = [t.join() for t in y_vm_threads]
        all_vms = self.x_vms + self.y_vms

        # By default we create a security group for each project that
        # only allows internal connectivity, so check that.
        self.check_mutual_connectivity(pass_list=self.x_vms, fail_list=self.y_vms)
        self.check_mutual_connectivity(pass_list=self.y_vms, fail_list=self.x_vms)

        # Now open up the security groups to allow connectivity
        # between the projects.
        self.controller.tenants["xanthe"].add_security_group_rule(
            "default", cidr="0.0.0.0/0"
        )
        self.controller.tenants["yellow"].add_security_group_rule(
            "default", cidr="0.0.0.0/0"
        )

        # Check connectivity between all 6 VMs.
        self.check_mutual_connectivity(pass_list=all_vms)

        # Configure Calico policy to isolate each project again.
        x_pol_spec = {
            "selector": x_selector,
            "types": ["Ingress"],
            "ingress": [
                {
                    "action": "Allow",
                    "source": {
                        "selector": x_selector,
                    },
                },
                {
                    "action": "Deny",
                },
            ],
        }
        datamodel_v3.put("GlobalNetworkPolicy", "default.xanthe", x_pol_spec)

        y_pol_spec = {
            "selector": y_selector,
            "types": ["Ingress"],
            "ingress": [
                {
                    "action": "Allow",
                    "source": {
                        "selector": y_selector,
                    },
                },
                {
                    "action": "Deny",
                },
            ],
        }
        datamodel_v3.put("GlobalNetworkPolicy", "default.yellow", y_pol_spec)
        time.sleep(10)

        # Check that the projects still have internal connectivity,
        # but are isolated from each other.
        self.check_mutual_connectivity(pass_list=self.x_vms, fail_list=self.y_vms)
        self.check_mutual_connectivity(pass_list=self.y_vms, fail_list=self.x_vms)
