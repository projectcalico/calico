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

package windows_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	client "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/extensions/extensionstest"
	"github.com/projectcalico/calico/operator/pkg/render"
)

var _ = Describe("windows enterprise modifier", func() {
	// newObjs returns a windows daemonset with the node containers and the OSS
	// cni-log-dir mount the modifier swaps out.
	newObjs := func() []client.Object {
		nodeContainer := func(name string) corev1.Container {
			return corev1.Container{
				Name:         name,
				VolumeMounts: []corev1.VolumeMount{{MountPath: "/var/log/calico/cni", Name: "cni-log-dir"}},
			}
		}
		return []client.Object{
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.WindowsDaemonSetName},
				Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{nodeContainer("felix"), nodeContainer("node"), nodeContainer("confd")},
				}}},
			},
		}
	}

	ds := func(objs []client.Object) *appsv1.DaemonSet {
		d, _ := extensions.FindObject[*appsv1.DaemonSet](objs, common.WindowsDaemonSetName)
		return d
	}
	container := func(d *appsv1.DaemonSet, name string) *corev1.Container {
		for i := range d.Spec.Template.Spec.Containers {
			if d.Spec.Template.Spec.Containers[i].Name == name {
				return &d.Spec.Template.Spec.Containers[i]
			}
		}
		return nil
	}

	ctxFor := func(provider operatorv1.Provider) render.Inputs {
		return render.Inputs{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise, KubernetesProvider: provider},
		}
	}

	It("appends the node-metrics service", func() {
		out, _ := ext.Windows().Modify(extensionstest.WindowsStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ctxFor(operatorv1.ProviderNone)).Objects()
		svc, ok := extensions.FindObject[*corev1.Service](out, render.WindowsNodeMetricsService)
		Expect(ok).To(BeTrue())
		Expect(svc.Namespace).To(Equal(common.CalicoNamespace))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(9081)))
	})

	It("swaps the cni log mount for the calico log volume and adds enterprise env", func() {
		out, _ := ext.Windows().Modify(extensionstest.WindowsStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ctxFor(operatorv1.ProviderNone)).Objects()
		d := ds(out)

		Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(HaveField("Name", "var-log-calico")))
		for _, name := range []string{"felix", "node", "confd"} {
			c := container(d, name)
			Expect(c.VolumeMounts).To(ContainElement(HaveField("Name", "var-log-calico")))
			Expect(c.VolumeMounts).NotTo(ContainElement(HaveField("Name", "cni-log-dir")))
			Expect(c.Env).To(ContainElements(
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
				corev1.EnvVar{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			))
		}
	})

	It("sets the trusted DNS server on openshift", func() {
		out, _ := ext.Windows().Modify(extensionstest.WindowsStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ctxFor(operatorv1.ProviderOpenShift)).Objects()
		Expect(container(ds(out), "node").Env).To(ContainElement(corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"}))
	})

	It("degrades with a create error when the prometheus reporter keypair cannot be read", func() {
		readErr := fmt.Errorf("the API server is having a bad day")
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		cm, err := certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		failing := ctrlrfake.DefaultFakeClientBuilder(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Secret); ok && key.Name == render.NodePrometheusTLSServerSecret {
					return readErr
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).Build()

		ci := controller.Inputs{
			RenderInputs: render.Inputs{
				Installation:  ctxFor(operatorv1.ProviderNone).Installation,
				TrustedBundle: cm.CreateTrustedBundle(),
				ClusterDomain: dns.DefaultClusterDomain,
			},
			Client:             failing,
			CertificateManager: cm,
		}
		_, _, err = ext.Windows().ExtendInputs(ctx, ci)
		Expect(err).To(MatchError(readErr))
		reason, ok := extensions.DegradedReason(err)
		Expect(ok).To(BeTrue())
		Expect(reason).To(Equal(operatorv1.ResourceCreateError))
	})

	It("rejects a zero prometheus reporter port", func() {
		ci := controller.Inputs{
			RenderInputs: render.Inputs{
				Installation:       ctxFor(operatorv1.ProviderNone).Installation,
				FelixConfiguration: &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{PrometheusReporterPort: ptr.To(0)}},
			},
		}
		_, _, err := ext.Windows().ExtendInputs(ctx, ci)
		reason, ok := extensions.DegradedReason(err)
		Expect(ok).To(BeTrue())
		Expect(reason).To(Equal(operatorv1.InvalidConfigurationError))
	})

	It("mounts the prometheus reporter keypair when present", func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		cm, err := certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		tls, err := cm.GetOrCreateKeyPair(cli, render.NodePrometheusTLSServerSecret, common.OperatorNamespace(), []string{"calico-node-metrics-windows"})
		Expect(err).NotTo(HaveOccurred())
		// The installation controller persists the secret; do the same here so the
		// windows extension's GetKeyPair finds it.
		Expect(cli.Create(context.Background(), tls.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		bundle := cm.CreateTrustedBundle()

		// Build the render inputs the way the windows controller does: run the
		// windows extension, which fetches the keypair into the inputs.
		ci := controller.Inputs{
			RenderInputs: render.Inputs{
				Installation:  ctxFor(operatorv1.ProviderNone).Installation,
				TrustedBundle: bundle,
				ClusterDomain: dns.DefaultClusterDomain,
			},
			Client:             cli,
			CertificateManager: cm,
		}
		eci, _, err := ext.Windows().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		out, _ := ext.Windows().Modify(extensionstest.WindowsStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ri).Objects()
		d := ds(out)

		Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(tls.Volume()))
		Expect(d.Spec.Template.Annotations).To(HaveKey(tls.HashAnnotationKey()))
		Expect(container(d, "node").Env).To(ContainElement(HaveField("Name", "FELIX_PROMETHEUSREPORTERCERTFILE")))
		Expect(container(d, "node").VolumeMounts).To(ContainElement(tls.VolumeMount(render.Windows(&render.WindowsConfiguration{}).SupportedOSType())))
	})

	It("does nothing when the operator runs as Calico", func() {
		ctx := render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}}
		out, _ := calicoExt.Windows().Modify(extensionstest.WindowsStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ctx).Objects()
		_, ok := extensions.FindObject[*corev1.Service](out, render.WindowsNodeMetricsService)
		Expect(ok).To(BeFalse())
		Expect(ds(out).Spec.Template.Spec.Volumes).To(BeEmpty())
	})
})
