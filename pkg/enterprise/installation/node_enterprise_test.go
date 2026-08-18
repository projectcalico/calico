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
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/extensions/extensionstest"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// getTyphaNodeTLS builds the node/typha TLS bundle the node render expects.
func getTyphaNodeTLS(cli client.Client, certificateManager certificatemanager.CertificateManager) *render.TyphaNodeTLS {
	nodeKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
	Expect(err).NotTo(HaveOccurred())

	typhaKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle(nodeKeyPair, typhaKeyPair)

	return &render.TyphaNodeTLS{
		TrustedBundle:   trustedBundle,
		TyphaSecret:     typhaKeyPair,
		TyphaCommonName: render.TyphaCommonName,
		NodeSecret:      nodeKeyPair,
		NodeCommonName:  render.FelixCommonName,
	}
}

// These tests run the real node/typha render output through the registered
// enterprise modifiers. The render suite registers the enterprise extensions in
// its BeforeSuite, so this exercises the same integrated behavior the operator
// binary produces - and, importantly, catches a modifier whose FindObject stops
// matching because render renamed an object or container.
var _ = Describe("node enterprise modifier integration", func() {
	var (
		cli               client.Client
		certManager       certificatemanager.CertificateManager
		typhaNodeTLS      *render.TyphaNodeTLS
		instance          *operatorv1.InstallationSpec
		renderInputs      render.Inputs
		nodePrometheusTLS certificatemanagement.KeyPairInterface
	)

	nodeContainer := func(ds *appsv1.DaemonSet) *corev1.Container {
		for i := range ds.Spec.Template.Spec.Containers {
			if ds.Spec.Template.Spec.Containers[i].Name == render.CalicoNodeObjectName {
				return &ds.Spec.Template.Spec.Containers[i]
			}
		}
		return nil
	}

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		var err error
		certManager, err = certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		typhaNodeTLS = getTyphaNodeTLS(cli, certManager)

		nodePrometheusTLS, err = certManager.GetOrCreateKeyPair(cli, render.NodePrometheusTLSServerSecret, common.OperatorNamespace(), []string{"calico-node-metrics"})
		Expect(err).NotTo(HaveOccurred())
		typhaNodeTLS.TrustedBundle.AddCertificates(nodePrometheusTLS)

		confDir, binDir := render.DefaultCNIDirectories(operatorv1.ProviderNone)
		bgp := operatorv1.BGPEnabled
		instance = &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
			CNI: &operatorv1.CNISpec{
				Type:    operatorv1.PluginCalico,
				IPAM:    &operatorv1.IPAMSpec{Type: operatorv1.IPAMPluginCalico},
				BinDir:  &binDir,
				ConfDir: &confDir,
			},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{
				BGP:     &bgp,
				IPPools: []operatorv1.IPPool{{CIDR: "192.168.1.0/16"}},
			},
		}

		// Build the render inputs the way the controller does: run the enterprise
		// controller extension, which stashes the node prometheus keypair in the
		// context for the node modifier to read.
		ci := controller.Inputs{
			RenderInputs: render.Inputs{
				Installation:  instance,
				TrustedBundle: typhaNodeTLS.TrustedBundle,
				ClusterDomain: dns.DefaultClusterDomain,
			},
			Client:             cli,
			CertificateManager: certManager,
		}
		eci, _, err := ext.Installation().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())
		renderInputs = eci.RenderInputs
	})

	// renderNodeObjects renders the real node component and applies the registered
	// modifier, exactly as the componentHandler does.
	renderNodeObjects := func(ri render.Inputs) []client.Object {
		cfg := &render.NodeConfiguration{
			K8sServiceEp:    k8sapi.ServiceEndpoint{},
			Installation:    instance,
			TLS:             typhaNodeTLS,
			ClusterDomain:   dns.DefaultClusterDomain,
			FelixHealthPort: 9099,
			IPPools:         instance.CalicoNetwork.IPPools,
		}
		comp := render.Node(cfg)
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		objs, _ := comp.Objects()
		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: objs, Delete: nil}, Cfg: nil}, ri).Objects()
		return out
	}

	It("appends the node metrics service to the real render output", func() {
		objs := renderNodeObjects(renderInputs)
		svc, ok := extensions.FindObject[*corev1.Service](objs, render.CalicoNodeMetricsService)
		Expect(ok).To(BeTrue(), "expected the modifier to append %s", render.CalicoNodeMetricsService)
		Expect(svc.Namespace).To(Equal(common.CalicoNamespace))
	})

	It("adds MULTI_INTERFACE_MODE to the real node and install-cni containers", func() {
		mode := operatorv1.MultiInterfaceModeMultus
		instance.CalicoNetwork.MultiInterfaceMode = &mode

		objs := renderNodeObjects(renderInputs)
		ds, ok := extensions.FindObject[*appsv1.DaemonSet](objs, common.NodeDaemonSetName)
		Expect(ok).To(BeTrue())

		want := corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: mode.Value()}
		Expect(nodeContainer(ds).Env).To(ContainElement(want))

		cni, ok := render.Container(&ds.Spec.Template.Spec, render.InstallCNIContainerName)
		Expect(ok).To(BeTrue())
		Expect(cni.Env).To(ContainElement(want))
	})

	It("adds the enterprise rules to the real cluster roles", func() {
		objs := renderNodeObjects(renderInputs)

		nodeRole, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, render.CalicoNodeObjectName)
		Expect(ok).To(BeTrue())
		Expect(nodeRole.Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))

		cniRole, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, render.CalicoCNIPluginObjectName)
		Expect(ok).To(BeTrue())
		Expect(cniRole.Rules).To(ContainElement(HaveField("Resources", ContainElement("networks"))))
	})

	It("rewrites the real node daemonset for enterprise", func() {
		objs := renderNodeObjects(renderInputs)
		ds, ok := extensions.FindObject[*appsv1.DaemonSet](objs, common.NodeDaemonSetName)
		Expect(ok).To(BeTrue())

		c := nodeContainer(ds)
		Expect(c).NotTo(BeNil())

		Expect(c.Env).To(ContainElements(
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			corev1.EnvVar{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
		))
		// The reporter cert env is wired from the NodePrometheusTLS keypair the
		// builder creates, and the modifier mounts that keypair onto the daemonset.
		Expect(c.Env).To(ContainElement(HaveField("Name", "FELIX_PROMETHEUSREPORTERCERTFILE")))
		Expect(ds.Spec.Template.Spec.Volumes).To(ContainElement(nodePrometheusTLS.Volume()))
		Expect(c.VolumeMounts).To(ContainElement(nodePrometheusTLS.VolumeMount(rmeta.OSTypeLinux)))
		Expect(ds.Spec.Template.Annotations).To(HaveKey(nodePrometheusTLS.HashAnnotationKey()))

		// BGP is enabled, so the bird readiness check is present and the modifier
		// adds the BGP metrics check.
		Expect(c.ReadinessProbe.Exec.Command).To(ContainElement("--bgp-metrics-ready"))
		Expect(c.StartupProbe.Exec.Command).To(ContainElement("--bgp-metrics-ready"))
	})

	It("enables process-path collection when the LogCollector requests it", func() {
		enable := operatorv1.CollectProcessPathEnable
		Expect(cli.Create(context.Background(), &operatorv1.LogCollector{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.LogCollectorSpec{CollectProcessPath: &enable},
		})).NotTo(HaveOccurred())

		eci, _, err := ext.Installation().ExtendInputs(ctx, controller.Inputs{
			RenderInputs: render.Inputs{
				Installation:  instance,
				TrustedBundle: typhaNodeTLS.TrustedBundle,
				ClusterDomain: dns.DefaultClusterDomain,
			},
			Client:             cli,
			CertificateManager: certManager,
		})
		Expect(err).NotTo(HaveOccurred())
		ri := eci.RenderInputs

		ds, ok := extensions.FindObject[*appsv1.DaemonSet](renderNodeObjects(ri), common.NodeDaemonSetName)
		Expect(ok).To(BeTrue())
		Expect(ds.Spec.Template.Spec.HostPID).To(BeTrue())
		Expect(nodeContainer(ds).Env).To(ContainElement(corev1.EnvVar{Name: "FELIX_FLOWLOGSCOLLECTPROCESSPATH", Value: "true"}))
	})

	It("adds the enterprise rules to the real typha cluster role", func() {
		comp := render.Typha(&render.TyphaConfiguration{
			K8sServiceEp:    k8sapi.ServiceEndpoint{},
			Installation:    instance,
			TLS:             typhaNodeTLS,
			ClusterDomain:   dns.DefaultClusterDomain,
			FelixHealthPort: 9099,
		})
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		objs, _ := comp.Objects()
		objs, _ = ext.Installation().Modify(extensionstest.TyphaStub{StubComponent: extensionstest.StubComponent{Create: objs, Delete: nil}, Cfg: nil}, renderInputs).Objects()

		role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "calico-typha")
		Expect(ok).To(BeTrue())
		Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))
	})
})
