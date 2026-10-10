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

package render_test

import (
	"slices"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	netattachv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/render"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/gatewayapi"
	"github.com/projectcalico/calico/operator/pkg/render/goldmane"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
	"github.com/projectcalico/calico/operator/pkg/render/kubecontrollers"
	"github.com/projectcalico/calico/operator/pkg/render/webhooks"
	"github.com/projectcalico/calico/operator/pkg/render/whisker"
	"github.com/projectcalico/calico/operator/pkg/tls"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// overrideRenderEnv holds the inputs every Overridable component renders from,
// with certificate management on so the provisioner init containers render.
type overrideRenderEnv struct {
	cli          client.Client
	certManager  certificatemanager.CertificateManager
	installation *operatorv1.InstallationSpec
	tls          *render.TyphaNodeTLS
}

func newOverrideRenderEnv() *overrideRenderEnv {
	s := runtime.NewScheme()
	Expect(apis.AddToScheme(s, false)).NotTo(HaveOccurred())
	cli := ctrlrfake.DefaultFakeClientBuilder(s).Build()

	ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
	Expect(err).NotTo(HaveOccurred())
	caCert, _, err := ca.Config.GetPEMBytes()
	Expect(err).NotTo(HaveOccurred())

	confDir, binDir := render.DefaultCNIDirectories(operatorv1.ProviderNone)
	bgp := operatorv1.BGPEnabled
	installation := &operatorv1.InstallationSpec{
		Variant:               operatorv1.Calico,
		CertificateManagement: &operatorv1.CertificateManagement{CACert: caCert},
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
		ServiceCIDRs: []string{"10.96.0.0/12"},
		WindowsNodes: &operatorv1.WindowsNodeSpec{
			CNIBinDir:    "/opt/cni/bin",
			CNIConfigDir: "/etc/cni/net.d",
			CNILogDir:    "/var/log/calico/cni",
		},
	}
	certManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())
	return &overrideRenderEnv{cli: cli, certManager: certManager, installation: installation, tls: getTyphaNodeTLS(cli, certManager)}
}

func (e *overrideRenderEnv) keyPair(name string) certificatemanagement.KeyPairInterface {
	kp, err := e.certManager.GetOrCreateKeyPair(e.cli, name, common.OperatorNamespace(), []string{name})
	Expect(err).NotTo(HaveOccurred())
	return kp
}

func overrideScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	Expect(scheme.AddToScheme(s)).NotTo(HaveOccurred())
	Expect(operatorv1.AddToScheme(s)).NotTo(HaveOccurred())
	Expect(v3.AddToScheme(s)).NotTo(HaveOccurred())
	Expect(apiextv1.AddToScheme(s)).NotTo(HaveOccurred())
	Expect(netattachv1.AddToScheme(s)).NotTo(HaveOccurred())
	return s
}

// overrideEntry fills one override field with sentinels, renders the component
// that reads it, and returns the component and the workload the field targets.
type overrideEntry struct {
	crd    string
	path   string
	render func(e *overrideRenderEnv, fill func(field any)) (render.Component, func([]client.Object) client.Object)
}

func named[T client.Object](name string) func([]client.Object) client.Object {
	return func(objs []client.Object) client.Object {
		i := slices.IndexFunc(objs, func(o client.Object) bool {
			_, ok := o.(T)
			return ok && o.GetName() == name
		})
		if i < 0 {
			return nil
		}
		return objs[i]
	}
}

func ofType[T client.Object](objs []client.Object) client.Object {
	i := slices.IndexFunc(objs, func(o client.Object) bool {
		_, ok := o.(T)
		return ok
	})
	if i < 0 {
		return nil
	}
	return objs[i]
}

func istioEntry(path string, field func(*operatorv1.IstioSpec) any, target func([]client.Object) client.Object) overrideEntry {
	return overrideEntry{
		crd:  "istios.operator.tigera.io",
		path: path,
		render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
			cfg := &istio.Configuration{
				Installation: e.installation,
				Istio: &operatorv1.Istio{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec:       operatorv1.IstioSpec{DSCPMark: ptr.To(numorstring.DSCPFromInt(23))},
				},
				IstioNamespace: istio.IstioNamespace,
				Scheme:         overrideScheme(),
			}
			fill(field(&cfg.Istio.Spec))
			_, comp, err := istio.Istio(cfg)
			Expect(err).NotTo(HaveOccurred())
			return comp, target
		},
	}
}

func gatewayEntry(path string, kind operatorv1.GatewayKind, field func(*operatorv1.GatewayAPISpec) any, target func([]client.Object) client.Object) overrideEntry {
	return overrideEntry{
		crd:  "gatewayapis.operator.tigera.io",
		path: path,
		render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
			gw := &operatorv1.GatewayAPI{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class", GatewayKind: ptr.To(kind)}},
				},
			}
			fill(field(&gw.Spec))
			comp, err := gatewayapi.GatewayAPIImplementationComponent(&gatewayapi.GatewayAPIImplementationConfig{
				Scheme:        overrideScheme(),
				Installation:  e.installation,
				GatewayAPI:    gw,
				TrustedBundle: e.tls.TrustedBundle,
			})
			Expect(err).NotTo(HaveOccurred())
			return comp, target
		},
	}
}

var _ = Describe("Overridable components", func() {
	felix := &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)}}

	DescribeTable("apply every override field to the workload it targets",
		func(entry overrideEntry) {
			containers, inits := rtest.CRDContainerNames(operatorv1.Calico, entry.crd, entry.path)
			e := newOverrideRenderEnv()
			var filled rtest.FilledOverrides
			comp, target := entry.render(e, func(field any) {
				filled = rtest.FillOverrides(field, containers, inits)
			})
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			o, ok := comp.(render.Overridable)
			Expect(ok).To(BeTrue(), "%T declares no override targets", comp)
			for _, t := range o.OverrideTargets() {
				Expect(slices.ContainsFunc(objs, t.Matches)).To(BeTrue(), "%T declares override target %s but didn't render it", comp, t)
			}

			// Istio's pod-level resources field is never applied (CORE-13783).
			delete(filled.Fields, "Spec.Template.Spec.Resources")

			obj := target(objs)
			Expect(obj).NotTo(BeNil(), "%s rendered no target workload", entry.path)
			rtest.ExpectOverridesApplied(obj, filled, map[string]string{"mount-bpffs": "ebpf-bootstrap"})
		},
		Entry("calicoNodeDaemonSet", overrideEntry{
			crd:  "installations.operator.tigera.io",
			path: "spec.calicoNodeDaemonSet",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				fill(&e.installation.CalicoNodeDaemonSet)
				return render.Node(&render.NodeConfiguration{
					K8sServiceEp:       k8sapi.ServiceEndpoint{},
					Installation:       e.installation,
					TLS:                e.tls,
					ClusterDomain:      dns.DefaultClusterDomain,
					FelixConfiguration: felix,
					IPPools:            e.installation.CalicoNetwork.IPPools,
				}), named[*appsv1.DaemonSet](common.NodeDaemonSetName)
			},
		}),
		Entry("typhaDeployment", overrideEntry{
			crd:  "installations.operator.tigera.io",
			path: "spec.typhaDeployment",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				fill(&e.installation.TyphaDeployment)
				return render.Typha(&render.TyphaConfiguration{
					K8sServiceEp:       k8sapi.ServiceEndpoint{},
					Installation:       e.installation,
					TLS:                e.tls,
					ClusterDomain:      dns.DefaultClusterDomain,
					FelixConfiguration: felix,
				}), named[*appsv1.Deployment](common.TyphaDeploymentName)
			},
		}),
		Entry("calicoKubeControllersDeployment", overrideEntry{
			crd:  "installations.operator.tigera.io",
			path: "spec.calicoKubeControllersDeployment",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				fill(&e.installation.CalicoKubeControllersDeployment)
				return kubecontrollers.NewCalicoKubeControllers(&kubecontrollers.KubeControllersConfiguration{
					Installation:      e.installation,
					ClusterDomain:     dns.DefaultClusterDomain,
					TrustedBundle:     e.tls.TrustedBundle,
					MetricsPort:       9094,
					Namespace:         common.CalicoNamespace,
					BindingNamespaces: []string{common.CalicoNamespace},
				}), named[*appsv1.Deployment](kubecontrollers.KubeController)
			},
		}),
		Entry("calicoNodeWindowsDaemonSet", overrideEntry{
			crd:  "installations.operator.tigera.io",
			path: "spec.calicoNodeWindowsDaemonSet",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				fill(&e.installation.CalicoNodeWindowsDaemonSet)
				return render.Windows(&render.WindowsConfiguration{
					K8sServiceEp:  k8sapi.ServiceEndpoint{Host: "1.2.3.4", Port: "6443"},
					K8sDNSServers: []string{"10.96.0.10"},
					Installation:  e.installation,
					ClusterDomain: dns.DefaultClusterDomain,
					TLS:           e.tls,
					VXLANVNI:      4096,
				}), named[*appsv1.DaemonSet](common.WindowsDaemonSetName)
			},
		}),
		Entry("csiNodeDriverDaemonSet", overrideEntry{
			crd:  "installations.operator.tigera.io",
			path: "spec.csiNodeDriverDaemonSet",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				fill(&e.installation.CSINodeDriverDaemonSet)
				return render.CSI(&render.CSIConfiguration{Installation: e.installation}), named[*appsv1.DaemonSet](render.CSIDaemonSetName)
			},
		}),
		Entry("apiServerDeployment", overrideEntry{
			crd:  "apiservers.operator.tigera.io",
			path: "spec.apiServerDeployment",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				spec := &operatorv1.APIServerSpec{}
				fill(&spec.APIServerDeployment)
				comp, err := render.APIServer(&render.APIServerConfiguration{
					RequiresAggregationServer: true,
					K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
					Installation:              e.installation,
					APIServer:                 spec,
					TLSKeyPair:                e.keyPair(render.CalicoAPIServerTLSSecretName),
					TrustedBundle:             e.tls.TrustedBundle,
					KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
				})
				Expect(err).NotTo(HaveOccurred())
				return comp, named[*appsv1.Deployment](render.APIServerName)
			},
		}),
		Entry("calicoWebhooksDeployment", overrideEntry{
			crd:  "apiservers.operator.tigera.io",
			path: "spec.calicoWebhooksDeployment",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				spec := &operatorv1.APIServerSpec{}
				fill(&spec.CalicoWebhooksDeployment)
				return webhooks.Component(&webhooks.Configuration{
					KeyPair:      e.keyPair(webhooks.WebhooksTLSSecretName),
					Installation: e.installation,
					APIServer:    spec,
				}), named[*appsv1.Deployment](webhooks.WebhooksName)
			},
		}),
		Entry("guardianDeployment", overrideEntry{
			crd:  "managementclusterconnections.operator.tigera.io",
			path: "spec.guardianDeployment",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				mcc := &operatorv1.ManagementClusterConnection{}
				fill(&mcc.Spec.GuardianDeployment)
				return render.Guardian(&render.GuardianConfiguration{
					URL:          "mgmt.example.com:9449",
					Installation: e.installation,
					TunnelSecret: &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()},
						Data: map[string][]byte{
							"cert": []byte("foo"),
							"key":  []byte("bar"),
						},
					},
					TrustedCertBundle:           e.tls.TrustedBundle,
					ManagementClusterConnection: mcc,
				}), named[*appsv1.Deployment](render.GuardianDeploymentName)
			},
		}),
		Entry("goldmaneDeployment", overrideEntry{
			crd:  "goldmanes.operator.tigera.io",
			path: "spec.goldmaneDeployment",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				gm := &operatorv1.Goldmane{}
				fill(&gm.Spec.GoldmaneDeployment)
				return goldmane.Goldmane(&goldmane.Configuration{
					Installation:          e.installation,
					GoldmaneServerKeyPair: e.keyPair(goldmane.GoldmaneKeyPairSecret),
					TrustedCertBundle:     e.tls.TrustedBundle,
					ClusterDomain:         dns.DefaultClusterDomain,
					Goldmane:              gm,
				}), named[*appsv1.Deployment](goldmane.GoldmaneDeploymentName)
			},
		}),
		Entry("whiskerDeployment", overrideEntry{
			crd:  "whiskers.operator.tigera.io",
			path: "spec.whiskerDeployment",
			render: func(e *overrideRenderEnv, fill func(any)) (render.Component, func([]client.Object) client.Object) {
				w := &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}}
				fill(&w.Spec.WhiskerDeployment)
				return whisker.Whisker(&whisker.Configuration{
					Installation:          e.installation,
					WhiskerKeyPair:        e.keyPair(whisker.WhiskerKeyPairSecret),
					WhiskerBackendKeyPair: e.keyPair(whisker.WhiskerBackendKeyPairSecret),
					TrustedCertBundle:     e.tls.TrustedBundle,
					ClusterDomain:         dns.DefaultClusterDomain,
					Whisker:               w,
				}), named[*appsv1.Deployment](whisker.WhiskerDeploymentName)
			},
		}),
		Entry("istiod", istioEntry("spec.istiod", func(s *operatorv1.IstioSpec) any { return &s.IstiodDeployment }, named[*appsv1.Deployment]("istiod"))),
		Entry("istioCNI", istioEntry("spec.istioCNI", func(s *operatorv1.IstioSpec) any { return &s.IstioCNIDaemonset }, named[*appsv1.DaemonSet]("istio-cni-node"))),
		Entry("ztunnel", istioEntry("spec.ztunnel", func(s *operatorv1.IstioSpec) any { return &s.ZTunnelDaemonset }, named[*appsv1.DaemonSet]("ztunnel"))),
		Entry("gatewayControllerDeployment", gatewayEntry(
			"spec.gatewayControllerDeployment",
			operatorv1.GatewayKindDeployment,
			func(s *operatorv1.GatewayAPISpec) any { return &s.GatewayControllerDeployment },
			ofType[*appsv1.Deployment],
		)),
		Entry("gatewayCertgenJob", gatewayEntry(
			"spec.gatewayCertgenJob",
			operatorv1.GatewayKindDeployment,
			func(s *operatorv1.GatewayAPISpec) any { return &s.GatewayCertgenJob },
			ofType[*batchv1.Job],
		)),
		Entry("gatewayDeployment", gatewayEntry(
			"spec.gatewayClasses.[].gatewayDeployment",
			operatorv1.GatewayKindDeployment,
			func(s *operatorv1.GatewayAPISpec) any { return &s.GatewayClasses[0].GatewayDeployment },
			named[*envoyapi.EnvoyProxy]("tigera-gateway-class"),
		)),
		Entry("gatewayDaemonSet", gatewayEntry(
			"spec.gatewayClasses.[].gatewayDaemonSet",
			operatorv1.GatewayKindDaemonSet,
			func(s *operatorv1.GatewayAPISpec) any { return &s.GatewayClasses[0].GatewayDaemonSet },
			named[*envoyapi.EnvoyProxy]("tigera-gateway-class"),
		)),
	)
})
