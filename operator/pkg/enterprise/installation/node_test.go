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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	client "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/extensions/extensionstest"
	"github.com/projectcalico/calico/operator/pkg/render"
)

var _ = Describe("node enterprise modifier", func() {
	// newObjs returns the subset of rendered node objects the modifier touches.
	newObjs := func() []client.Object {
		return []client.Object{
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoNodeObjectName}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoCNIPluginObjectName}},
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName},
				Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Name: "install-cni"}},
					Containers: []corev1.Container{{
						Name: render.CalicoNodeObjectName,
						ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
							Command: []string{"/bin/calico-node", "-bird-ready", "--bird-ready", "--felix-ready"},
						}}},
						StartupProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
							Command: []string{"/bin/calico-node", "-bird-ready", "--bird-ready", "--felix-ready"},
						}}},
					}},
				}}},
			},
		}
	}

	nodeContainer := func(ds *appsv1.DaemonSet) *corev1.Container {
		for i := range ds.Spec.Template.Spec.Containers {
			if ds.Spec.Template.Spec.Containers[i].Name == render.CalicoNodeObjectName {
				return &ds.Spec.Template.Spec.Containers[i]
			}
		}
		return nil
	}

	entIn := func() render.Inputs {
		return render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}}
	}

	It("adds the enterprise cluster role rules", func() {
		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, entIn()).Objects()

		nodeRole, ok := extensions.FindObject[*rbacv1.ClusterRole](out, render.CalicoNodeObjectName)
		Expect(ok).To(BeTrue())
		Expect(nodeRole.Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))

		cniRole, ok := extensions.FindObject[*rbacv1.ClusterRole](out, render.CalicoCNIPluginObjectName)
		Expect(ok).To(BeTrue())
		Expect(cniRole.Rules).To(ContainElement(HaveField("Resources", ConsistOf("networks"))))
	})

	It("adds the enterprise felix env to the node container", func() {
		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, entIn()).Objects()
		ds, _ := extensions.FindObject[*appsv1.DaemonSet](out, common.NodeDaemonSetName)
		c := nodeContainer(ds)

		Expect(c.Env).To(ContainElements(
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
			corev1.EnvVar{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			corev1.EnvVar{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
		))
	})

	It("derives the reporter port from FelixConfiguration", func() {
		reporter := 7081
		ctx := entIn()
		ctx.FelixConfiguration = &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{PrometheusReporterPort: &reporter}}

		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ctx).Objects()
		ds, _ := extensions.FindObject[*appsv1.DaemonSet](out, common.NodeDaemonSetName)
		Expect(nodeContainer(ds).Env).To(ContainElement(corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "7081"}))
	})

	It("appends the BGP metrics check to the readiness and startup probes when the bird check is present", func() {
		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, entIn()).Objects()
		ds, _ := extensions.FindObject[*appsv1.DaemonSet](out, common.NodeDaemonSetName)
		Expect(nodeContainer(ds).ReadinessProbe.Exec.Command).To(ContainElement("--bgp-metrics-ready"))
		Expect(nodeContainer(ds).StartupProbe.Exec.Command).To(ContainElement("--bgp-metrics-ready"))
	})

	It("does not add the BGP metrics check when the bird check is absent", func() {
		objs := newObjs()
		ds := objs[2].(*appsv1.DaemonSet)
		ds.Spec.Template.Spec.Containers[0].ReadinessProbe.Exec.Command = []string{"/bin/calico-node", "--felix-ready"}
		ds.Spec.Template.Spec.Containers[0].StartupProbe.Exec.Command = []string{"/bin/calico-node", "--felix-ready"}

		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: objs, Delete: nil}, Cfg: nil}, entIn()).Objects()
		got, _ := extensions.FindObject[*appsv1.DaemonSet](out, common.NodeDaemonSetName)
		Expect(nodeContainer(got).ReadinessProbe.Exec.Command).NotTo(ContainElement("--bgp-metrics-ready"))
		Expect(nodeContainer(got).StartupProbe.Exec.Command).NotTo(ContainElement("--bgp-metrics-ready"))
	})

	It("adds MULTI_INTERFACE_MODE to the node and install-cni containers when configured", func() {
		mode := operatorv1.MultiInterfaceModeMultus
		ctx := entIn()
		ctx.Installation.CalicoNetwork = &operatorv1.CalicoNetworkSpec{MultiInterfaceMode: &mode}

		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ctx).Objects()
		ds, _ := extensions.FindObject[*appsv1.DaemonSet](out, common.NodeDaemonSetName)

		want := corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: mode.Value()}
		Expect(nodeContainer(ds).Env).To(ContainElement(want))
		Expect(ds.Spec.Template.Spec.InitContainers[0].Env).To(ContainElement(want))
	})

	It("appends the node metrics service", func() {
		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, entIn()).Objects()
		svc, ok := extensions.FindObject[*corev1.Service](out, render.CalicoNodeMetricsService)
		Expect(ok).To(BeTrue())
		Expect(svc.Spec.Ports).To(HaveLen(2))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(9081)))
		Expect(svc.Spec.Ports[1].Port).To(Equal(int32(9900)))
	})

	It("derives metrics service ports and felix-metrics-port from FelixConfiguration", func() {
		reporter := 7081
		metrics := 7091
		enabled := true
		ctx := entIn()
		ctx.FelixConfiguration = &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{
			PrometheusReporterPort:   &reporter,
			PrometheusMetricsPort:    &metrics,
			PrometheusMetricsEnabled: &enabled,
		}}

		out, _ := ext.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ctx).Objects()
		svc, _ := extensions.FindObject[*corev1.Service](out, render.CalicoNodeMetricsService)
		Expect(svc.Spec.Ports).To(HaveLen(3))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(7081)))
		Expect(svc.Spec.Ports[2].Name).To(Equal("felix-metrics-port"))
		Expect(svc.Spec.Ports[2].Port).To(Equal(int32(7091)))
	})

	It("is a no-op when the operator runs as Calico", func() {
		ctx := render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}}
		out, _ := calicoExt.Installation().Modify(extensionstest.NodeStub{StubComponent: extensionstest.StubComponent{Create: newObjs(), Delete: nil}, Cfg: nil}, ctx).Objects()

		_, ok := extensions.FindObject[*corev1.Service](out, render.CalicoNodeMetricsService)
		Expect(ok).To(BeFalse())
		nodeRole, _ := extensions.FindObject[*rbacv1.ClusterRole](out, render.CalicoNodeObjectName)
		Expect(nodeRole.Rules).To(BeEmpty())
	})
})
