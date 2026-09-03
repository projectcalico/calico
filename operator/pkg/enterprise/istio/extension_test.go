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

package istio

import (
	"context"

	netattachv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/render"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	ristio "github.com/projectcalico/calico/operator/pkg/render/istio"
)

var _ = Describe("Istio extension", func() {
	var (
		ext *Extension
		cfg *ristio.Configuration
		ri  render.Inputs
	)

	// enterpriseImageSet pins every tigera istio image, plus the combined calico image
	// the waypoint l7-collector runs from.
	enterpriseImageSet := func() *operatorv1.ImageSet {
		return &operatorv1.ImageSet{
			ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
			Spec: operatorv1.ImageSetSpec{
				Images: []operatorv1.Image{
					{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
					{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
					{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
					{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					{Image: "tigera/calico", Digest: "sha256:test-calico-digest"},
				},
			},
		}
	}

	testScheme := func() *runtime.Scheme {
		s := runtime.NewScheme()
		Expect(scheme.AddToScheme(s)).ShouldNot(HaveOccurred())
		Expect(operatorv1.AddToScheme(s)).ShouldNot(HaveOccurred())
		Expect(v3.AddToScheme(s)).ShouldNot(HaveOccurred())
		Expect(apiextv1.AddToScheme(s)).ShouldNot(HaveOccurred())
		Expect(netattachv1.AddToScheme(s)).ShouldNot(HaveOccurred())
		return s
	}

	BeforeEach(func() {
		ext = New(operatorv1.CalicoEnterprise)
		install := &operatorv1.InstallationSpec{
			Variant:            operatorv1.CalicoEnterprise,
			KubernetesProvider: operatorv1.ProviderNone,
			Registry:           "myregistry.io/",
		}
		cfg = &ristio.Configuration{
			Installation: install,
			Istio: &operatorv1.Istio{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.IstioSpec{
					DSCPMark: func() *numorstring.DSCP { d := numorstring.DSCPFromInt(11); return &d }(),
				},
			},
			IstioNamespace: ristio.IstioNamespace,
			Scheme:         testScheme(),
		}
		ri = render.Inputs{Installation: install}
	})

	// modify renders the istio component and runs it through the extension.
	modify := func(is *operatorv1.ImageSet) ([]client.Object, []client.Object) {
		_, component, err := ristio.Istio(cfg)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(component.ResolveImages(is)).To(Succeed())
		return ext.Modify(component, ri).Objects()
	}

	It("resolves the Enterprise istio images", func() {
		is := enterpriseImageSet()
		objs, _ := modify(is)

		istiod, err := rtest.GetResourceOfType[*appsv1.Deployment](objs, ristio.IstioIstiodDeploymentName, ristio.IstioNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(rtest.GetContainer(istiod.Spec.Template.Spec.Containers, "discovery").Image).To(
			Equal(expectedImage(components.ComponentIstioPilot, cfg.Installation, is)))

		cni, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objs, ristio.IstioCNIDaemonSetName, ristio.IstioNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(rtest.GetContainer(cni.Spec.Template.Spec.Containers, "install-cni").Image).To(
			Equal(expectedImage(components.ComponentIstioInstallCNI, cfg.Installation, is)))

		ztunnel, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objs, ristio.IstioZTunnelDaemonSetName, ristio.IstioNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(rtest.GetContainer(ztunnel.Spec.Template.Spec.Containers, "istio-proxy").Image).To(
			Equal(expectedImage(components.ComponentIstioZTunnel, cfg.Installation, is)))
	})

	It("patches the sidecar injector ConfigMap with the Enterprise proxyv2 image", func() {
		objs, _ := modify(enterpriseImageSet())

		cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, "istio-sidecar-injector", ristio.IstioNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		for _, data := range cm.Data {
			Expect(data).NotTo(ContainSubstring("fake.io/fakeimg/proxyv2:faketag"))
		}
		Expect(cm.Data["values"]).To(ContainSubstring("myregistry.io/tigera/istio-proxyv2@"))
	})

	It("resolves the waypoint l7-collector image from the installation", func() {
		c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(enterpriseImageSet()).Build()
		ci, err := ext.ExtendInputs(context.Background(), controller.Inputs{
			RenderInputs: render.Inputs{Installation: cfg.Installation},
			Client:       c,
		})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(istioData(ci.RenderInputs).l7CollectorImage).To(ContainSubstring("myregistry.io/tigera/calico"))
	})

	It("renders the waypoint L7 logging resources by default", func() {
		ri.Extension = istioRenderData{l7CollectorImage: "myregistry.io/tigera/calico:latest"}
		objs, _ := modify(enterpriseImageSet())

		cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, L7WaypointDefaultsConfigMapName, ristio.IstioNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cm.Labels).To(HaveKeyWithValue("gateway.istio.io/defaults-for-class", IstioWaypointGatewayClass))
		_, err = rtest.GetResourceOfType[*ristio.EnvoyFilter](objs, L7WaypointALSFilterName, ristio.IstioNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		_, err = rtest.GetResourceOfType[*ristio.EnvoyFilter](objs, L7WaypointSrcPortFilterName, ristio.IstioNamespace)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("renders the waypoint L7 logging resources when WaypointLogging is Enabled", func() {
		enabled := operatorv1.L7LogCollectionEnabled
		cfg.Istio.Spec.WaypointLogging = &enabled

		objs, _ := modify(enterpriseImageSet())
		for _, name := range []string{L7WaypointDefaultsConfigMapName, L7WaypointALSFilterName, L7WaypointSrcPortFilterName} {
			Expect(names(objs)).To(ContainElement(name))
		}
	})

	It("queues the waypoint L7 logging resources for deletion when WaypointLogging is Disabled", func() {
		disabled := operatorv1.L7LogCollectionDisabled
		cfg.Istio.Spec.WaypointLogging = &disabled

		objs, toDelete := modify(enterpriseImageSet())
		for _, name := range []string{L7WaypointDefaultsConfigMapName, L7WaypointALSFilterName, L7WaypointSrcPortFilterName} {
			Expect(names(objs)).NotTo(ContainElement(name))
			Expect(names(toDelete)).To(ContainElement(name))
		}

		// Delete the EnvoyFilters before the Role and RoleBinding, otherwise the grant
		// goes first and the EnvoyFilter deletes fail with Forbidden.
		idxOf := func(kind, name string) int {
			for i, o := range toDelete {
				if o.GetObjectKind().GroupVersionKind().Kind == kind && o.GetName() == name {
					return i
				}
			}
			return -1
		}
		als := idxOf("EnvoyFilter", L7WaypointALSFilterName)
		src := idxOf("EnvoyFilter", L7WaypointSrcPortFilterName)
		role := idxOf("Role", L7WaypointEnvoyFilterRoleName)
		binding := idxOf("RoleBinding", L7WaypointEnvoyFilterRoleName)
		Expect([]int{als, src, role, binding}).NotTo(ContainElement(-1))
		Expect(als).To(BeNumerically("<", role))
		Expect(als).To(BeNumerically("<", binding))
		Expect(src).To(BeNumerically("<", role))
		Expect(src).To(BeNumerically("<", binding))
	})

	It("makes no changes when the installation is Calico", func() {
		cfg.Installation.Variant = operatorv1.Calico
		ri.Installation = cfg.Installation

		objs, toDelete := modify(nil)
		for _, name := range []string{L7WaypointDefaultsConfigMapName, L7WaypointALSFilterName, L7WaypointSrcPortFilterName} {
			Expect(names(objs)).NotTo(ContainElement(name))
			Expect(names(toDelete)).NotTo(ContainElement(name))
		}
	})
})

func names(objs []client.Object) []string {
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		out = append(out, o.GetName())
	}
	return out
}

func expectedImage(c components.Component, in *operatorv1.InstallationSpec, is *operatorv1.ImageSet) string {
	image, err := components.GetReference(c, in.Registry, in.ImagePath, in.ImagePrefix, is)
	Expect(err).ShouldNot(HaveOccurred())
	return image
}
