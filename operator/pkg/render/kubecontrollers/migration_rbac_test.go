// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kubecontrollers_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/common"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/kubecontrollers"
)

var _ = Describe("MigrationRBACComponent", func() {
	Context("when migration is active", func() {
		var toCreate, toDelete []client.Object

		BeforeEach(func() {
			component := kubecontrollers.MigrationRBACComponent(true)
			toCreate, toDelete = component.Objects()
		})

		It("should create the ClusterRole and ClusterRoleBinding", func() {
			Expect(toCreate).To(HaveLen(2))
			Expect(toDelete).To(BeEmpty())

			rtest.ExpectResourceInList(toCreate, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
			rtest.ExpectResourceInList(toCreate, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		})

		It("should grant access to calico API groups", func() {
			cr := rtest.GetResource(toCreate, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(cr.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"*"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			}))
		})

		It("should grant access to apiservices", func() {
			cr := rtest.GetResource(toCreate, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(cr.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"apiregistration.k8s.io"},
				Resources: []string{"apiservices"},
				Verbs:     []string{"get", "list", "watch", "create", "delete"},
			}))
		})

		It("should grant access to CRDs", func() {
			cr := rtest.GetResource(toCreate, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(cr.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"apiextensions.k8s.io"},
				Resources: []string{"customresourcedefinitions"},
				Verbs:     []string{"get", "list", "watch", "delete"},
			}))
		})

		It("should grant access to daemonsets and deployments", func() {
			cr := rtest.GetResource(toCreate, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(cr.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"apps"},
				Resources: []string{"daemonsets", "deployments"},
				Verbs:     []string{"get", "list", "watch"},
			}))
		})

		It("should grant access to Installations", func() {
			cr := rtest.GetResource(toCreate, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(cr.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"operator.tigera.io"},
				Resources: []string{"installations"},
				Verbs:     []string{"get", "list", "watch"},
			}))
		})

		It("should bind to the calico-kube-controllers service account", func() {
			crb := rtest.GetResource(toCreate, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(crb.RoleRef).To(Equal(rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "calico-kube-controllers-migration",
			}))
			Expect(crb.Subjects).To(ConsistOf(rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "calico-kube-controllers",
				Namespace: common.CalicoNamespace,
			}))
		})
	})

	Context("when migration is not active", func() {
		var toCreate, toDelete []client.Object

		BeforeEach(func() {
			component := kubecontrollers.MigrationRBACComponent(false)
			toCreate, toDelete = component.Objects()
		})

		It("should delete the ClusterRole and ClusterRoleBinding", func() {
			Expect(toCreate).To(BeEmpty())
			Expect(toDelete).To(HaveLen(2))

			rtest.ExpectResourceInList(toDelete, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
			rtest.ExpectResourceInList(toDelete, "calico-kube-controllers-migration", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		})
	})
})
