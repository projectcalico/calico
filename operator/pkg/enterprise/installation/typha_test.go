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

package installation_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/extensions/extensionstest"
	"github.com/projectcalico/calico/operator/pkg/render"
)

// These run the real typha render output through the registered modifier. A
// hand-built fixture would keep passing if render renamed what the modifier
// reaches for.
var _ = Describe("typha enterprise modifier", func() {
	multiMode := operatorv1.MultiInterfaceModeMultus

	var typhaNodeTLS *render.TyphaNodeTLS

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certManager, err := certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		nodeKeyPair, err := certManager.GetOrCreateKeyPair(cli, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())
		typhaKeyPair, err := certManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.TyphaCommonName})
		Expect(err).NotTo(HaveOccurred())

		typhaNodeTLS = &render.TyphaNodeTLS{
			TrustedBundle:   certManager.CreateTrustedBundle(nodeKeyPair, typhaKeyPair),
			TyphaSecret:     typhaKeyPair,
			TyphaCommonName: render.TyphaCommonName,
			NodeSecret:      nodeKeyPair,
			NodeCommonName:  render.FelixCommonName,
		}
	})

	// renderTypha renders the real typha component and runs the extension over it,
	// exactly as the installation controller does.
	renderTypha := func(r extensions.Extensions, install *operatorv1.InstallationSpec, ri render.Inputs) []client.Object {
		component := render.Typha(&render.TyphaConfiguration{
			K8sServiceEp:       k8sapi.ServiceEndpoint{},
			Installation:       install,
			TLS:                typhaNodeTLS,
			ClusterDomain:      dns.DefaultClusterDomain,
			FelixConfiguration: &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)}},
		})
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		objs, del := component.Objects()

		out, _ := r.Installation().Modify(extensionstest.TyphaStub{StubComponent: extensionstest.StubComponent{Create: objs, Delete: del}, Cfg: nil}, ri).Objects()
		return out
	}

	typhaClusterRole := func(objs []client.Object) *rbacv1.ClusterRole {
		role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, render.TyphaClusterRoleName)
		Expect(ok).To(BeTrue())
		return role
	}

	typhaContainer := func(objs []client.Object) *corev1.Container {
		dep, ok := extensions.FindObject[*appsv1.Deployment](objs, common.TyphaDeploymentName)
		Expect(ok).To(BeTrue())
		c, ok := render.Container(&dep.Spec.Template.Spec, render.TyphaContainerName)
		Expect(ok).To(BeTrue())
		return c
	}

	It("adds enterprise RBAC and MULTI_INTERFACE_MODE for the enterprise variant", func() {
		install := &operatorv1.InstallationSpec{
			Variant:       operatorv1.CalicoEnterprise,
			CNI:           &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{MultiInterfaceMode: &multiMode},
		}
		objs := renderTypha(ext, install, render.Inputs{Installation: install})

		Expect(typhaClusterRole(objs).Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))
		Expect(typhaContainer(objs).Env).To(ContainElement(corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: multiMode.Value()}))
	})

	It("is a no-op when the operator runs as Calico", func() {
		install := &operatorv1.InstallationSpec{
			Variant:       operatorv1.Calico,
			CNI:           &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{MultiInterfaceMode: &multiMode},
		}
		objs := renderTypha(calicoExt, install, render.Inputs{Installation: install})

		Expect(typhaClusterRole(objs).Rules).NotTo(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))
		Expect(typhaContainer(objs).Env).NotTo(ContainElement(HaveField("Name", "MULTI_INTERFACE_MODE")))
	})
})
