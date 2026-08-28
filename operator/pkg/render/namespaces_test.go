// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package render_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Namespace rendering tests", func() {
	var cfg *render.NamespaceConfiguration
	BeforeEach(func() {
		cfg = &render.NamespaceConfiguration{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico, KubernetesProvider: operatorv1.ProviderNone},
		}
	})

	It("should render a namespace", func() {
		component := render.Namespaces(cfg)
		resources, _ := component.Objects()

		expectedCreateResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "calico-system"}},
		}

		rtest.ExpectResources(resources, expectedCreateResources)

		namespace := rtest.GetResource(resources, "calico-system", "", "", "v1", "Namespace").(*corev1.Namespace)

		Expect(namespace.Labels["name"]).To(Equal("calico-system"))
		Expect(namespace.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(namespace.GetLabels()).NotTo(ContainElement("control-plane"))
		Expect(namespace.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))
	})

	It("should render a namespace for openshift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		component := render.Namespaces(cfg)
		resources, _ := component.Objects()

		expectedCreateResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "calico-system"}},
		}

		rtest.ExpectResources(resources, expectedCreateResources)

		namespace := rtest.GetResource(resources, "calico-system", "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(namespace.GetLabels()["openshift.io/run-level"]).To(Equal("0"))
		Expect(namespace.GetLabels()).NotTo(ContainElement("control-plane"))
		Expect(namespace.GetAnnotations()["openshift.io/node-selector"]).To(Equal(""))
		Expect(namespace.GetAnnotations()["security.openshift.io/scc.podSecurityLabelSync"]).To(Equal("false"))
	})

	It("should render a namespace for aks with control-plane label when Azure is nil and PodSecurityStandard is privileged", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderAKS
		component := render.Namespaces(cfg)
		resources, _ := component.Objects()

		expectedCreateResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "calico-system"}},
		}

		rtest.ExpectResources(resources, expectedCreateResources)
		namespace := rtest.GetResource(resources, "calico-system", "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(namespace.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(namespace.GetLabels()["control-plane"]).To(Equal("true"))
	})

	It("should render a namespace for aks with control-plane label when Azure.PolicyMode is nil and PodSecurityStandard is privileged", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderAKS
		cfg.Installation.Azure = &operatorv1.Azure{}
		component := render.Namespaces(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(2))
		rtest.ExpectResourceTypeAndObjectMetadata(resources[0], "calico-system", "", "", "v1", "Namespace")
		meta := resources[0].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetLabels()["control-plane"]).To(Equal("true"))
		rtest.ExpectResourceTypeAndObjectMetadata(resources[1], "tigera-operator-secrets", "calico-system", "rbac.authorization.k8s.io", "v1", "RoleBinding")
	})

	It("should render a namespace for aks with control-plane label when Azure.PolicyMode is Default and PodSecurityStandard is privileged", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderAKS
		policyMode := operatorv1.PolicyModeDefault
		cfg.Installation.Azure = &operatorv1.Azure{
			PolicyMode: &policyMode,
		}
		component := render.Namespaces(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(2))
		rtest.ExpectResourceTypeAndObjectMetadata(resources[0], "calico-system", "", "", "v1", "Namespace")
		meta := resources[0].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetLabels()["control-plane"]).To(Equal("true"))
		rtest.ExpectResourceTypeAndObjectMetadata(resources[1], "tigera-operator-secrets", "calico-system", "rbac.authorization.k8s.io", "v1", "RoleBinding")
	})

	It("should render a namespace for aks without control-plane label when Azure.PolicyMode is Manual", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderAKS
		policyMode := operatorv1.PolicyModeManual
		cfg.Installation.Azure = &operatorv1.Azure{
			PolicyMode: &policyMode,
		}
		component := render.Namespaces(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(2))
		rtest.ExpectResourceTypeAndObjectMetadata(resources[0], "calico-system", "", "", "v1", "Namespace")
		meta := resources[0].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetLabels()).NotTo(ContainElement("control-plane"))
		rtest.ExpectResourceTypeAndObjectMetadata(resources[1], "tigera-operator-secrets", "calico-system", "rbac.authorization.k8s.io", "v1", "RoleBinding")
	})
})
