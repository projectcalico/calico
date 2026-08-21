// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelcollector_test

import (
	"crypto/x509"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/go-cmp/cmp"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/otelcollector"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

var _ = Describe("OpenTelemetry rendering", func() {
	var defaultInstallation *operatorv1.InstallationSpec

	BeforeEach(func() {
		defaultInstallation = &operatorv1.InstallationSpec{
			Variant:              operatorv1.CalicoEnterprise,
			Registry:             "testregistry.com/",
			KubernetesProvider:   operatorv1.ProviderGKE,
			ControlPlaneReplicas: ptr.To(int32(2)),
		}
	})

	// deleteCount is 3 whenever no exporter names TLS or auth material: the three
	// aggregates are deleted rather than omitted, so removing a credential from the
	// spec does not leave it behind in calico-system. Without logs the receiver
	// keypair is deleted too, making 4.
	DescribeTable("Object counts",
		func(cfg *otelcollector.Configuration, createCount, deleteCount int) {
			component, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			toCreate, toDelete := component.Objects()
			Expect(toCreate).To(HaveLen(createCount))
			Expect(toDelete).To(HaveLen(deleteCount))
		},
		Entry("logs and metrics enabled",
			&otelcollector.Configuration{
				Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderGKE},
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			},
			7, 3,
		),
		Entry("logs only",
			&otelcollector.Configuration{
				Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderGKE},
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryAuditLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			},
			7, 3,
		),
		Entry("metrics only",
			&otelcollector.Configuration{
				Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderGKE},
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			},
			7, 4,
		),
		Entry("no logs, no metrics",
			&otelcollector.Configuration{
				Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderGKE},
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			},
			7, 4,
		),
	)

	Context("StatefulSet rendering", func() {
		It("should render the expected statefulset", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			component, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := component.Objects()

			expected := &appsv1.StatefulSet{
				TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      otelcollector.OpenTelemetryCollectorStatefulSetName,
					Namespace: otelcollector.OpenTelemetryCollectorNamespace,
				},
				Spec: appsv1.StatefulSetSpec{
					// Always one, regardless of ControlPlaneReplicas: extra replicas
					// re-federate the same targets and duplicate every series.
					Replicas:    ptr.To(int32(1)),
					ServiceName: otelcollector.OpenTelemetryCollectorServiceName,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"k8s-app": otelcollector.OpenTelemetryCollectorStatefulSetName},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Name:   otelcollector.OpenTelemetryCollectorStatefulSetName,
							Labels: map[string]string{"k8s-app": otelcollector.OpenTelemetryCollectorStatefulSetName},
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: otelcollector.OpenTelemetryCollectorServiceAccountName,
							Tolerations:        append(rmeta.TolerateCriticalAddonsAndControlPlane, rmeta.TolerateGKEARM64NoSchedule),
							Containers: []corev1.Container{
								{
									Name:    otelcollector.OpenTelemetryCollectorContainerName,
									Image:   "testregistry.com/tigera/calico:master",
									Command: []string{"/usr/bin/otelcol", "--config=/etc/otel/config.yaml"},
									Ports: []corev1.ContainerPort{
										{Name: "otlp-http", ContainerPort: otelcollector.OTLPHTTPPort, Protocol: corev1.ProtocolTCP},
										{Name: "health", ContainerPort: otelcollector.HealthCheckPort, Protocol: corev1.ProtocolTCP},
										{Name: "metrics", ContainerPort: otelcollector.InternalMetricsPort, Protocol: corev1.ProtocolTCP},
									},
									Resources: corev1.ResourceRequirements{
										Limits: corev1.ResourceList{
											corev1.ResourceMemory: resource.MustParse(otelcollector.DefaultMemoryLimit),
										},
										Requests: corev1.ResourceList{
											corev1.ResourceMemory: resource.MustParse(otelcollector.DefaultMemoryRequest),
										},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									ReadinessProbe: &corev1.Probe{
										ProbeHandler: corev1.ProbeHandler{
											HTTPGet: &corev1.HTTPGetAction{
												Path: "/",
												Port: intstr.FromInt32(otelcollector.HealthCheckPort),
											},
										},
										InitialDelaySeconds: 10,
										PeriodSeconds:       10,
									},
									LivenessProbe: &corev1.Probe{
										ProbeHandler: corev1.ProbeHandler{
											HTTPGet: &corev1.HTTPGetAction{
												Path: "/",
												Port: intstr.FromInt32(otelcollector.HealthCheckPort),
											},
										},
										InitialDelaySeconds: 90,
										PeriodSeconds:       10,
									},
									VolumeMounts: []corev1.VolumeMount{
										{Name: "config", MountPath: "/etc/otel", ReadOnly: true},
									},
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "config",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: otelcollector.OpenTelemetryCollectorConfigMapName},
										},
									},
								},
							},
						},
					},
				},
			}

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OpenTelemetryCollectorStatefulSetName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(statefulSet.Spec.Template.Spec.Containers[0].Ports).To(ConsistOf(expected.Spec.Template.Spec.Containers[0].Ports))
			Expect(statefulSet.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expected.Spec.Template.Spec.Containers[0].VolumeMounts))
			Expect(statefulSet.Spec.Template.Spec.Volumes).To(ConsistOf(expected.Spec.Template.Spec.Volumes))
			Expect(statefulSet.Spec.Template.ObjectMeta.Annotations).To(HaveKey("hash.operator.tigera.io/otel-collector-config"))
			expected.Spec.Template.Annotations = statefulSet.Spec.Template.Annotations
			Expect(statefulSet).To(Equal(expected), cmp.Diff(statefulSet, expected))
		})

		It("should include the trusted bundle volume when metrics are enabled", func() {
			trustedBundle := certificatemanagement.CreateTrustedBundle(nil)

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
				TrustedCertBundle: trustedBundle,
			}
			component, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := component.Objects()

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OpenTelemetryCollectorStatefulSetName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(len(statefulSet.Spec.Template.Spec.Volumes)).To(BeNumerically(">", 1))
			Expect(len(statefulSet.Spec.Template.Spec.Containers[0].VolumeMounts)).To(BeNumerically(">", 1))
		})

		It("should include receiver TLS volumes and mounts when logs with certs are enabled", func() {
			receiverKeyPair := certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector-tls"}}, nil, "")
			trustedBundle := certificatemanagement.CreateTrustedBundle(nil)

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
				ReceiverTLSSecret: receiverKeyPair,
				TrustedCertBundle: trustedBundle,
			}
			component, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := component.Objects()

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OpenTelemetryCollectorStatefulSetName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(len(statefulSet.Spec.Template.Spec.Volumes)).To(BeNumerically(">", 1))
			Expect(len(statefulSet.Spec.Template.Spec.Containers[0].VolumeMounts)).To(BeNumerically(">", 1))
		})
	})

	Context("ConfigMap content", func() {
		It("should include otlp receiver when logs are enabled", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("otlp:"))
			Expect(config).To(ContainSubstring("0.0.0.0:4318"))
			Expect(config).To(ContainSubstring("logs:"))
			Expect(config).To(ContainSubstring("receivers: [otlp]"))
		})

		It("should include receiver TLS config when logs with certs are enabled", func() {
			receiverKeyPair := certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector-tls"}}, nil, "")
			trustedBundle := certificatemanagement.CreateTrustedBundle(nil)

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
				ReceiverTLSSecret: receiverKeyPair,
				TrustedCertBundle: trustedBundle,
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("otlp:"))
			Expect(config).To(ContainSubstring("cert_file:"))
			Expect(config).To(ContainSubstring("key_file:"))
			Expect(config).To(ContainSubstring("client_ca_file:"))
		})

		It("should include prometheus receiver when metrics are enabled", func() {
			trustedBundle := certificatemanagement.CreateTrustedBundle(nil)

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
				TrustedCertBundle: trustedBundle,
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("prometheus:"))
			Expect(config).To(ContainSubstring("job_name: 'tigera-prometheus-federate'"))
			Expect(config).To(ContainSubstring("metrics_path: /federate"))
			Expect(config).To(ContainSubstring("honor_labels: true"))
			Expect(config).To(ContainSubstring("credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token"))
			Expect(config).To(ContainSubstring("tls_config:"))
			Expect(config).To(ContainSubstring("targets: ['prometheus-http-api.tigera-prometheus.svc:9090']"))
			Expect(config).To(ContainSubstring("metrics:"))
			Expect(config).To(ContainSubstring("receivers: [prometheus]"))
			Expect(config).To(ContainSubstring("exporters: [otlp_grpc/backend]"))
		})

		It("should not include receivers or pipelines when logs and metrics are disabled", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).NotTo(ContainSubstring("otlp:"))
			Expect(config).NotTo(ContainSubstring("scrape_configs:"))
			Expect(config).NotTo(ContainSubstring("logs:"))
			Expect(config).NotTo(ContainSubstring("receivers: [prometheus]"))
		})

		It("should use otlp_http prefix for HTTP exporters", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "httpbackend", Endpoint: "https://otlp.example.com:443", Protocol: operatorv1.OpenTelemetryProtocolHTTP},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("otlp_http/httpbackend:"))
			Expect(config).To(ContainSubstring("exporters: [otlp_http/httpbackend]"))
		})

		It("should use otlp_grpc prefix for gRPC exporters", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "grpcbackend", Endpoint: "https://otlp.example.com:4317", Protocol: operatorv1.OpenTelemetryProtocolGRPC},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("otlp_grpc/grpcbackend:"))
			Expect(config).To(ContainSubstring("exporters: [otlp_grpc/grpcbackend]"))
		})

		It("should register the receiver keypair's required key usages", func() {
			// Registered via init(). Without it the rotation check has no usages to
			// enforce for this secret, unlike every other operator-minted keypair.
			Expect(certkeyusage.GetCertKeyUsage(otelcollector.OpenTelemetryCollectorServerTLSSecretName)).To(ConsistOf(
				x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth,
			))
		})

		It("should roll the pod when the CA rotates, and reload TLS material in place", func() {
			receiverKeyPair := certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector-tls"}}, nil, "")

			build := func(bundle certificatemanagement.TrustedBundle) (map[string]string, string) {
				cfg := &otelcollector.Configuration{
					Installation:      defaultInstallation,
					ReceiverTLSSecret: receiverKeyPair,
					TrustedCertBundle: bundle,
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				}
				comp, err := otelcollector.OpenTelemetryCollector(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
				objs, _ := comp.Objects()
				ss, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OpenTelemetryCollectorStatefulSetName, otelcollector.OpenTelemetryCollectorNamespace)
				Expect(err).ShouldNot(HaveOccurred())
				cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
				Expect(err).ShouldNot(HaveOccurred())
				return ss.Spec.Template.Annotations, cm.Data["config.yaml"]
			}

			before, config := build(certificatemanagement.CreateTrustedBundle(nil))

			// In-place reload, so a rotation need not wait for the restart.
			Expect(config).To(ContainSubstring("client_ca_file_reload: true"))
			Expect(config).To(ContainSubstring("reload_interval: 1h"))

			// Rotating the CA must change the pod template. The rendered config is
			// byte-identical across a rotation (it holds paths, not PEM), so the
			// config hash alone would never trigger a restart.
			rotatedCA, err := certificatemanagement.CreateSelfSignedSecret("rotated", common.OperatorNamespace(), "rotated", nil)
			Expect(err).NotTo(HaveOccurred())
			rotatedBundle := certificatemanagement.CreateTrustedBundle(
				certificatemanagement.NewCertificate("rotated", common.OperatorNamespace(), rotatedCA.Data[corev1.TLSCertKey], nil),
			)
			after, rotatedConfig := build(rotatedBundle)

			Expect(rotatedConfig).To(Equal(config), "config text must be unchanged, proving the hash alone is insufficient")
			Expect(after).NotTo(Equal(before), "certificate hash annotations must change so the pod rolls")
		})

		It("should derive the memory limiter from the container's memory limit", func() {
			render := func(ss *operatorv1.OpenTelemetryCollectorStatefulSet) string {
				cfg := &otelcollector.Configuration{
					Installation: defaultInstallation,
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:                              &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters:                         []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
						OpenTelemetryCollectorStatefulSet: ss,
					},
				}
				comp, err := otelcollector.OpenTelemetryCollector(cfg)
				Expect(err).NotTo(HaveOccurred())
				objs, _ := comp.Objects()
				cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
				Expect(err).ShouldNot(HaveOccurred())
				return cm.Data["config.yaml"]
			}

			// Default 512Mi: 80% soft limit, spike a quarter of that.
			Expect(render(nil)).To(ContainSubstring("limit_mib: 409"))
			Expect(render(nil)).To(ContainSubstring("spike_limit_mib: 102"))

			// Raising the container limit must raise the collector's own ceiling;
			// otherwise it keeps shedding load at the default while sitting on
			// memory it is allowed to use.
			overridden := render(&operatorv1.OpenTelemetryCollectorStatefulSet{
				Spec: &operatorv1.OpenTelemetryCollectorStatefulSetSpec{
					Template: &operatorv1.OpenTelemetryCollectorStatefulSetPodTemplateSpec{
						Spec: &operatorv1.OpenTelemetryCollectorStatefulSetPodSpec{
							Containers: []operatorv1.OpenTelemetryCollectorStatefulSetContainer{{
								Name: "otel-collector",
								Resources: &corev1.ResourceRequirements{
									Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
								},
							}},
						},
					},
				},
			})
			Expect(overridden).To(ContainSubstring("limit_mib: 1638"))
			Expect(overridden).To(ContainSubstring("spike_limit_mib: 409"))
		})

		It("should never render an exporter without transport security", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "one", Endpoint: "https://otlp.example.com:4317"},
						{Name: "two", Endpoint: "https://other.example.com:4318"},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			config := cm.Data["config.yaml"]

			// http:// is rejected by the API, so there is no path that turns TLS off
			// and none that keeps TLS while skipping verification.
			Expect(config).NotTo(ContainSubstring("insecure: true"))
			Expect(config).NotTo(ContainSubstring("insecure_skip_verify"))
			Expect(strings.Count(config, "include_system_ca_certs_pool: true")).To(Equal(2))
		})

		It("should match in-cluster exporters by service rather than domain", func() {
			cfg := &otelcollector.Configuration{
				Installation:  defaultInstallation,
				ClusterDomain: "cluster.local",
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "incluster", Endpoint: "https://lgtm.otel-demo.svc.cluster.local:4317"},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// Calico resolves Domains rules from observed DNS answers, which does not
			// cover a ClusterIP reached via the cluster domain — a domain rule here
			// silently drops the traffic.
			// No Ports alongside Services: Calico rejects that combination outright
			// ("cannot specify ports with a service selector"), and the service match
			// already scopes the rule to that Service's ports.
			Expect(np.Spec.Egress).To(ContainElement(HaveField("Destination", v3.EntityRule{
				Services: &v3.ServiceMatch{Namespace: "otel-demo", Name: "lgtm"},
			})))
		})

		It("should always verify exporters against the system root pool", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("include_system_ca_certs_pool: true"))
			// Verification must never be disabled: neither knob may ever appear.
			Expect(config).NotTo(ContainSubstring("insecure"))
			// Without a user CA there is nothing to add to the system pool, and
			// no client keypair unless an exporter opts into mutual TLS. Match on
			// the mount paths so the receiver's own cert_file/ca_file don't alias.
			Expect(config).NotTo(ContainSubstring("/certs/exporter-ca"))
			Expect(config).NotTo(ContainSubstring("/certs/exporter-client"))
		})

		It("should give each exporter its own CA rather than one shared trust anchor", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "corp", Endpoint: "https://otlp.corp.example:443", Protocol: operatorv1.OpenTelemetryProtocolHTTP,
							TLS: &operatorv1.OpenTelemetryExporterTLS{CAConfigMapName: "corp-ca"}},
						{Name: "public", Endpoint: "https://otlp.public.example:443", Protocol: operatorv1.OpenTelemetryProtocolHTTP},
					},
				},
				ExporterCAs: map[string]*corev1.ConfigMap{
					"corp": {
						ObjectMeta: metav1.ObjectMeta{Name: "corp-ca", Namespace: common.OperatorNamespace()},
						Data:       map[string]string{corev1.TLSCertKey: "-----BEGIN CERTIFICATE-----"},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			config := cm.Data["config.yaml"]
			// Only the exporter that named a CA gets one.
			Expect(config).To(ContainSubstring("ca_file: /certs/exporter-cas/corp.crt"))
			Expect(strings.Count(config, "ca_file: /certs/exporter-cas/")).To(Equal(1))

			// A pinned CA is the only thing trusted for that exporter: keeping the
			// system roots would let any public authority satisfy it. The exporter
			// without a CA still verifies against them.
			corp := config[strings.Index(config, "otlp_http/corp:"):strings.Index(config, "otlp_http/public:")]
			public := config[strings.Index(config, "otlp_http/public:"):]
			Expect(corp).ToNot(ContainSubstring("include_system_ca_certs_pool"),
				"a pinned CA must not be combined with the system roots")
			Expect(public).To(ContainSubstring("include_system_ca_certs_pool: true"))

			// Gathered into one operator-managed ConfigMap keyed by exporter.
			agg, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorExporterCAsName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(agg.Data).To(HaveKey("corp.crt"))
			Expect(agg.Data).ToNot(HaveKey("public.crt"))

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OpenTelemetryCollectorStatefulSetName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(statefulSet.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
				Name: "exporter-cas", MountPath: "/certs/exporter-cas", ReadOnly: true,
			}))

			Expect(statefulSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/otel-exporter-ca"),
				"CA rotation must trigger a pod roll via the hash annotation")
		})

		It("should give each exporter its own client identity for mutual TLS", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "mtlsbackend", Endpoint: "https://otlp.example.com:4317",
							TLS: &operatorv1.OpenTelemetryExporterTLS{ClientCertSecretName: "backend-mtls"}},
						{Name: "plainbackend", Endpoint: "https://other.example.com:4317"},
					},
				},
				ExporterClientCerts: map[string]*corev1.Secret{
					"mtlsbackend": {
						ObjectMeta: metav1.ObjectMeta{Name: "backend-mtls", Namespace: common.OperatorNamespace()},
						Data: map[string][]byte{
							corev1.TLSCertKey:       []byte("cert"),
							corev1.TLSPrivateKeyKey: []byte("key"),
						},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			config := cm.Data["config.yaml"]

			// Only the exporter that named a keypair presents one.
			Expect(config).To(ContainSubstring("cert_file: /certs/exporter-certs/mtlsbackend.crt"))
			Expect(config).To(ContainSubstring("key_file: /certs/exporter-certs/mtlsbackend.key"))
			Expect(strings.Count(config, "cert_file: /certs/exporter-certs/")).To(Equal(1))

			agg, err := rtest.GetResourceOfType[*corev1.Secret](objs, otelcollector.OpenTelemetryCollectorExporterCertsName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(agg.Data).To(HaveKey("mtlsbackend.crt"))
			Expect(agg.Data).To(HaveKey("mtlsbackend.key"))

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OpenTelemetryCollectorStatefulSetName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(statefulSet.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
				Name: "exporter-certs", MountPath: "/certs/exporter-certs", ReadOnly: true,
			}))

			Expect(statefulSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/otel-exporter-client-tls"),
				"client cert rotation must trigger a pod roll via the hash annotation")
		})

		It("should pass auth headers through the environment, never the rendered config", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{{
						Name: "datadog", Endpoint: "https://otlp.datadoghq.com:4318", Protocol: operatorv1.OpenTelemetryProtocolHTTP,
						Auth: &operatorv1.OpenTelemetryExporterAuth{
							Headers: []operatorv1.OpenTelemetryExporterHeader{{
								Name: "DD-API-KEY",
								ValueFrom: operatorv1.OpenTelemetryHeaderValueSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "otlp-datadog-auth"},
										Key:                  "api-key",
									},
								},
							}},
						},
					}},
				},
				ExporterAuthSecrets: map[string]*corev1.Secret{
					"otlp-datadog-auth": {
						ObjectMeta: metav1.ObjectMeta{Name: "otlp-datadog-auth", Namespace: common.OperatorNamespace()},
						Data:       map[string][]byte{"api-key": []byte("super-secret")},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			config := cm.Data["config.yaml"]

			envName := "OTEL_EXPORTER_DATADOG_DD_API_KEY"
			Expect(config).To(ContainSubstring("DD-API-KEY: ${env:" + envName + "}"))
			// The credential itself must never be readable from the config.
			Expect(config).ToNot(ContainSubstring("super-secret"))

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OpenTelemetryCollectorStatefulSetName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(statefulSet.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: envName,
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: otelcollector.OpenTelemetryCollectorExporterAuthName},
						Key:                  envName,
					},
				},
			}))
			Expect(statefulSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/otel-exporter-auth"),
				"credential rotation must trigger a pod roll")
		})

		It("should list multiple exporters in pipelines", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "first", Endpoint: "first.example.com:4317"},
						{Name: "second", Endpoint: "https://second.example.com", Protocol: operatorv1.OpenTelemetryProtocolHTTP},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("exporters: [otlp_grpc/first, otlp_http/second]"))
		})

		It("should always include the health_check extension", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("extensions:"))
			Expect(config).To(ContainSubstring("health_check:"))
			Expect(config).To(ContainSubstring("0.0.0.0:13133"))
			Expect(config).To(ContainSubstring("extensions: [health_check]"))
		})
	})

	Context("Service", func() {
		It("should expose the OTLP HTTP port", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			svc, err := rtest.GetResourceOfType[*corev1.Service](objs, otelcollector.OpenTelemetryCollectorServiceName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(svc.Spec.Ports).To(HaveLen(2))
			Expect(svc.Spec.Ports[0].Port).To(Equal(int32(otelcollector.OTLPHTTPPort)))
			Expect(svc.Spec.Ports[0].Name).To(Equal("otlp-http"))
			Expect(svc.Spec.Ports[1].Port).To(Equal(int32(otelcollector.InternalMetricsPort)))
			Expect(svc.Spec.Ports[1].Name).To(Equal("metrics"))
			Expect(svc.Spec.Selector).To(Equal(map[string]string{"k8s-app": otelcollector.OpenTelemetryCollectorStatefulSetName}))
		})
	})

	Context("Receiver keypair lifecycle", func() {
		metricsOnly := func() *otelcollector.Configuration {
			return &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
		}

		It("should delete the receiver keypair when logs are turned off", func() {
			// Metrics keep the collector running, so this is not the teardown path:
			// nothing else would remove a copy the previous logs config left behind.
			comp, err := otelcollector.OpenTelemetryCollector(metricsOnly())
			Expect(err).NotTo(HaveOccurred())
			_, toDelete := comp.Objects()
			Expect(toDelete).To(ContainElement(HaveField("ObjectMeta.Name", otelcollector.OpenTelemetryCollectorServerTLSSecretName)))
		})

		It("should keep the receiver keypair while logs are exported", func() {
			cfg := metricsOnly()
			cfg.OpenTelemetry.Logs = &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			_, toDelete := comp.Objects()
			Expect(toDelete).NotTo(ContainElement(HaveField("ObjectMeta.Name", otelcollector.OpenTelemetryCollectorServerTLSSecretName)))
		})
	})

	Context("RBAC", func() {
		It("should render the expected service account, cluster role, and cluster role binding", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			sa, err := rtest.GetResourceOfType[*corev1.ServiceAccount](objs, otelcollector.OpenTelemetryCollectorServiceAccountName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(sa).NotTo(BeNil())

			cr, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objs, otelcollector.OpenTelemetryCollectorClusterRoleName, "")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Rules).To(HaveLen(1))
			Expect(cr.Rules[0].Resources).To(ConsistOf("services/proxy"))
			Expect(cr.Rules[0].ResourceNames).To(ConsistOf("calico-node-prometheus:9090"))

			crb, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objs, otelcollector.OpenTelemetryCollectorClusterRoleName, "")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(crb.RoleRef.Name).To(Equal(otelcollector.OpenTelemetryCollectorClusterRoleName))
			Expect(crb.Subjects).To(HaveLen(1))
			Expect(crb.Subjects[0].Name).To(Equal(otelcollector.OpenTelemetryCollectorServiceAccountName))
		})
	})

	Context("NetworkPolicy", func() {
		It("should allow ingress on the OTLP HTTP port", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(np.Spec.Ingress).To(HaveLen(2))
			Expect(np.Spec.Ingress[0].Action).To(Equal(v3.Allow))
			Expect(np.Spec.Ingress[1].Action).To(Equal(v3.Allow))
			Expect(np.Spec.Types).To(ConsistOf(v3.PolicyTypeIngress, v3.PolicyTypeEgress))
		})

		It("should parse the port from bare host:port exporter endpoints", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			var egressPorts []uint16
			for _, r := range np.Spec.Egress {
				for _, p := range r.Destination.Ports {
					egressPorts = append(egressPorts, p.MinPort)
				}
			}
			Expect(egressPorts).To(ContainElement(uint16(4317)), "should include port from bare host:port endpoint")
		})

		It("should parse the port from URL-style exporter endpoints", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "https-backend", Endpoint: "https://otlp.example.com:9443", Protocol: operatorv1.OpenTelemetryProtocolHTTP},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			var egressPorts []uint16
			for _, r := range np.Spec.Egress {
				for _, p := range r.Destination.Ports {
					egressPorts = append(egressPorts, p.MinPort)
				}
			}
			Expect(egressPorts).To(ContainElement(uint16(9443)), "should include port from URL-style endpoint")
		})

		It("should default to 443 for https endpoints without explicit port", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "https-no-port", Endpoint: "https://otlp.example.com", Protocol: operatorv1.OpenTelemetryProtocolHTTP},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			var egressPorts []uint16
			for _, r := range np.Spec.Egress {
				for _, p := range r.Destination.Ports {
					egressPorts = append(egressPorts, p.MinPort)
				}
			}
			Expect(egressPorts).To(ContainElement(uint16(443)), "should default to 443 for https")
		})

		It("should add kube API server and prometheus egress rules when metrics are enabled", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(np.Spec.Egress).To(ContainElement(HaveField("Destination", networkpolicy.PrometheusEntityRule)))
		})

		It("should restrict ingress by source", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
					Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(np.Spec.Ingress).To(HaveLen(2))

			// The OTLP receiver is reachable only by fluent-bit...
			Expect(np.Spec.Ingress[0].Source).To(Equal(render.FluentBitSourceEntityRule))
			Expect(np.Spec.Ingress[0].Destination.Ports).To(Equal(networkpolicy.Ports(otelcollector.OTLPHTTPPort)))

			// ...and the internal metrics port, which is served without TLS or
			// authn, only by Prometheus.
			Expect(np.Spec.Ingress[1].Source).To(Equal(networkpolicy.PrometheusSourceEntityRule))
			Expect(np.Spec.Ingress[1].Destination.Ports).To(Equal(networkpolicy.Ports(otelcollector.InternalMetricsPort)))
		})

		It("should pin the egress destination to the exporter host", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{
						{Name: "byname", Endpoint: "https://otlp.example.com:4317"},
						{Name: "byip", Endpoint: "https://10.1.2.3:4318"},
					},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// A hostname becomes a domain rule; a literal IP becomes an exact net.
			Expect(np.Spec.Egress).To(ContainElement(HaveField("Destination", v3.EntityRule{
				Domains: []string{"otlp.example.com"}, Ports: networkpolicy.Ports(4317),
			})))
			Expect(np.Spec.Egress).To(ContainElement(HaveField("Destination", v3.EntityRule{
				Nets: []string{"10.1.2.3/32"}, Ports: networkpolicy.Ports(4318),
			})))
		})

		It("should never emit a rule that allows any host", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "byname", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			for _, r := range np.Spec.Egress {
				d := r.Destination
				if len(d.Ports) > 0 && d.Services == nil && len(d.Nets) == 0 && len(d.Domains) == 0 && d.Selector == "" && d.NamespaceSelector == "" {
					Fail("egress rule constrains only the port, allowing any host")
				}
			}
		})

		It("should default the port from the scheme when the endpoint carries none", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "noport", Endpoint: "https://otlp.example.com"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OpenTelemetryCollectorPolicyName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(np.Spec.Egress).To(ContainElement(HaveField("Destination", v3.EntityRule{
				Domains: []string{"otlp.example.com"}, Ports: networkpolicy.Ports(443),
			})))
		})
	})

	Context("StatefulSet overrides", func() {
		It("should apply overrides from the CR", func() {
			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			containerResources := &corev1.ResourceRequirements{
				Limits:   corev1.ResourceList{"cpu": resource.MustParse("500m")},
				Requests: corev1.ResourceList{"cpu": resource.MustParse("100m")},
			}
			nodeSelector := map[string]string{"zone": "us-west-2a"}
			tolerations := []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "otel"}}
			topologyConstraints := []corev1.TopologySpreadConstraint{{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "otel-collector"}},
			}}
			podLabels := map[string]string{"extra-label": "value"}
			podAnnotations := map[string]string{"extra-annotation": "value"}
			priorityClassName := "system-cluster-critical"

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					OpenTelemetryCollectorStatefulSet: &operatorv1.OpenTelemetryCollectorStatefulSet{
						Spec: &operatorv1.OpenTelemetryCollectorStatefulSetSpec{
							Template: &operatorv1.OpenTelemetryCollectorStatefulSetPodTemplateSpec{
								Metadata: &operatorv1.Metadata{
									Labels:      podLabels,
									Annotations: podAnnotations,
								},
								Spec: &operatorv1.OpenTelemetryCollectorStatefulSetPodSpec{
									Affinity: affinity,
									Containers: []operatorv1.OpenTelemetryCollectorStatefulSetContainer{{
										Name:      "otel-collector",
										Resources: containerResources,
									}},
									NodeSelector:              nodeSelector,
									Tolerations:               tolerations,
									TopologySpreadConstraints: topologyConstraints,
									PriorityClassName:         priorityClassName,
								},
							},
						},
					},
				},
			}

			component, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := component.Objects()

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OpenTelemetryCollectorStatefulSetName, otelcollector.OpenTelemetryCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(statefulSet.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue("extra-label", "value"))
			Expect(statefulSet.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue("k8s-app", otelcollector.OpenTelemetryCollectorStatefulSetName))
			Expect(statefulSet.Spec.Template.ObjectMeta.Annotations).To(HaveKeyWithValue("extra-annotation", "value"))
			Expect(statefulSet.Spec.Template.ObjectMeta.Annotations).To(HaveKey("hash.operator.tigera.io/otel-collector-config"))
			Expect(statefulSet.Spec.Template.Spec.Affinity).To(Equal(affinity))
			Expect(statefulSet.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
			Expect(statefulSet.Spec.Template.Spec.Tolerations).To(Equal(tolerations))
			Expect(statefulSet.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologyConstraints))
			Expect(statefulSet.Spec.Template.Spec.PriorityClassName).To(Equal(priorityClassName))
			Expect(statefulSet.Spec.Template.Spec.Containers[0].Resources).To(Equal(*containerResources))
		})
	})

	Context("Pull secrets", func() {
		It("should include pull secrets when configured", func() {
			pullSecrets := []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: "tigera-operator"}},
			}
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				PullSecrets:  pullSecrets,
				OpenTelemetry: &operatorv1.OpenTelemetrySpec{
					Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
				},
			}
			comp, err := otelcollector.OpenTelemetryCollector(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := comp.Objects()
			// 7 base objects + 1 copied pull secret
			Expect(objs).To(HaveLen(8))
		})
	})

	It("should support Linux OS type", func() {
		component, err := otelcollector.OpenTelemetryCollector(&otelcollector.Configuration{
			Installation: defaultInstallation,
			OpenTelemetry: &operatorv1.OpenTelemetrySpec{
				Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(component.SupportedOSType()).To(Equal(rmeta.OSTypeLinux))
	})

})
