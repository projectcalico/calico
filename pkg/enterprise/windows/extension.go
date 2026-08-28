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

package windows

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/enterprise/installation"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Extension is the Calico Enterprise behavior for the windows controller.
type Extension struct {
	variant operatorv1.ProductVariant
}

var _ extensions.WindowsExtension = &Extension{}

// New returns the windows extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant) *Extension {
	return &Extension{variant: variant}
}

// Modify dispatches over the components the windows controller renders.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	switch c.(type) {
	case render.WindowsComponent:
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyWindows(ri, objs, del)
		})
	default:
		return c
	}
}

// windowsRenderData is the controller-produced data the windows extension hands to
// its modifier through Inputs.Extension.
type windowsRenderData struct {
	prometheusServerTLS certificatemanagement.KeyPairInterface
}

// windowsData pulls the windows extension's render data back out of the render
// context, returning the zero value when none is set.
func windowsData(ri render.Inputs) windowsRenderData {
	return render.ExtractExtensionData[windowsRenderData](ri)
}

// Validate rejects windows installation config Calico Enterprise does not support.
// Watches registers the enterprise secrets the windows controller reconciles on.
func (e *Extension) Watches(c ctrlruntime.Controller) error {
	for _, ns := range []string{common.CalicoNamespace, common.OperatorNamespace()} {
		if err := utils.AddSecretsWatch(c, render.NodePrometheusTLSServerSecret, ns); err != nil {
			return err
		}
		if err := utils.AddSecretsWatch(c, monitor.PrometheusClientTLSSecretName, ns); err != nil {
			return err
		}
	}
	return nil
}

// ExtendInputs fetches the node prometheus keypair the installation controller
// created and stashes it in the render inputs for the windows modifier.
func (e *Extension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	if err := installation.ValidateReporterPort(ci.RenderInputs.FelixConfiguration); err != nil {
		return ci, nil, err
	}

	tls, err := ci.CertificateManager.GetKeyPair(
		ci.Client,
		render.NodePrometheusTLSServerSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(render.WindowsNodeMetricsService, common.CalicoNamespace, ci.RenderInputs.ClusterDomain),
	)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceCreateError, "error getting node prometheus TLS certificate: %w", err)
	}
	ci.RenderInputs.Extension = windowsRenderData{prometheusServerTLS: tls}
	return ci, nil, nil
}

// modifyWindows layers Calico Enterprise behavior onto the rendered
// calico-node-windows objects: the node-metrics Service and the Enterprise
// daemonset configuration (flow/DNS log env, prometheus reporter, trusted DNS
// servers, the calico log volume, and the prometheus reporter keypair mount).
func modifyWindows(ri render.Inputs, objs, del []client.Object) ([]client.Object, []client.Object) {
	modifyWindowsDaemonSet(ri, extensions.MustFindObject[*appsv1.DaemonSet](objs, common.WindowsDaemonSetName))

	return append(objs, windowsNodeMetricsService(ri)), del
}

// windowsNodeContainers are the containers the enterprise layering applies to.
// Confd only renders when BGP is enabled.
func windowsNodeContainers(spec *corev1.PodSpec) []*corev1.Container {
	cs := render.MustContainers(spec, render.WindowsNodeContainerNames...)
	if confd, ok := render.Container(spec, render.WindowsConfdContainerName); ok {
		cs = append(cs, confd)
	}
	return cs
}

func modifyWindowsDaemonSet(ri render.Inputs, ds *appsv1.DaemonSet) {
	dirOrCreate := corev1.HostPathDirectoryOrCreate
	spec := &ds.Spec.Template.Spec

	spec.Volumes = append(spec.Volumes, corev1.Volume{
		Name:         "var-log-calico",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}},
	})

	for _, c := range windowsNodeContainers(spec) {
		c.Env = append(c.Env, windowsEnterpriseEnv(ri)...)

		// Enterprise mounts the calico log directory in place of the OSS CNI log
		// directory, so drop the OSS mount before adding the enterprise one.
		c.VolumeMounts = removeVolumeMount(c.VolumeMounts, "cni-log-dir")
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{MountPath: "/var/log/calico", Name: "var-log-calico"})
	}

	mountWindowsPrometheusTLS(ri, ds)
}

// windowsEnterpriseEnv is the Enterprise felix configuration added to the
// calico-node-windows containers.
func windowsEnterpriseEnv(ri render.Inputs) []corev1.EnvVar {
	tls := windowsData(ri).prometheusServerTLS
	env := []corev1.EnvVar{
		{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
		{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: fmt.Sprintf("%d", installation.NodeReporterPort(ri.FelixConfiguration))},
		{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
		{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
		{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
		{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
		{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
	}

	if tls != nil && ri.TrustedBundle != nil {
		env = append(env,
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCERTFILE", Value: tls.VolumeMountCertificateFilePath()},
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERKEYFILE", Value: tls.VolumeMountKeyFilePath()},
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCAFILE", Value: ri.TrustedBundle.MountPath()},
		)
	}

	// Providers without a kube-dns service need a non-default trusted DNS server.
	switch ri.Installation.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		env = append(env, corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"})
	case operatorv1.ProviderRKE2:
		env = append(env, corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:kube-system/rke2-coredns-rke2-coredns"})
	}

	return env
}

// mountWindowsPrometheusTLS mounts the node prometheus reporter keypair onto the
// windows daemonset: the volume, the volume mount on each node container, and
// the pod hash annotation that rolls the pods on cert rotation.
func mountWindowsPrometheusTLS(ri render.Inputs, ds *appsv1.DaemonSet) {
	tls := windowsData(ri).prometheusServerTLS
	if tls == nil {
		return
	}
	spec := &ds.Spec.Template.Spec

	spec.Volumes = append(spec.Volumes, tls.Volume())

	for _, c := range windowsNodeContainers(spec) {
		c.VolumeMounts = append(c.VolumeMounts, tls.VolumeMount(rmeta.OSTypeWindows))
	}

	if ds.Spec.Template.Annotations == nil {
		ds.Spec.Template.Annotations = map[string]string{}
	}
	ds.Spec.Template.Annotations[tls.HashAnnotationKey()] = tls.HashAnnotationValue()
}

// windowsNodeMetricsService builds the enterprise-only calico-node-metrics-windows
// Service.
func windowsNodeMetricsService(ri render.Inputs) *corev1.Service {
	reporterPort := installation.NodeReporterPort(ri.FelixConfiguration)
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.WindowsNodeMetricsService,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": render.WindowsNodeObjectName},
		},
		Spec: corev1.ServiceSpec{
			Selector:  map[string]string{"k8s-app": render.WindowsNodeObjectName},
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       "calico-metrics-port",
					Port:       int32(reporterPort),
					TargetPort: intstr.FromInt(reporterPort),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "calico-bgp-metrics-port",
					Port:       render.NodeBGPReporterPort,
					TargetPort: intstr.FromInt(int(render.NodeBGPReporterPort)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func removeVolumeMount(mounts []corev1.VolumeMount, name string) []corev1.VolumeMount {
	out := mounts[:0]
	for _, m := range mounts {
		if m.Name != name {
			out = append(out, m)
		}
	}
	return out
}
