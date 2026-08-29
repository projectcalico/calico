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

package otelcollector

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/otelcollector"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	"github.com/projectcalico/calico/operator/test"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("OpenTelemetry controller tests", func() {
	var (
		cli             client.Client
		scheme          *runtime.Scheme
		ctx             context.Context
		mockStatus      *status.MockStatus
		r               *Reconciler
		install         *operatorv1.Installation
		licenseAPIReady *utils.ReadyFlag
		tierWatchReady  *utils.ReadyFlag
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		replicas := int32(2)
		install = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 2},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.CalicoEnterprise,
				Computed: &operatorv1.InstallationSpec{},
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.CalicoEnterprise,
				Registry:             "some.registry.org/",
			},
		}
		Expect(cli.Create(ctx, install)).ToNot(HaveOccurred())

		Expect(cli.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status: v3.LicenseKeyStatus{
				Features: []string{common.OpenTelemetryCollectorFeature},
			},
		})).ToNot(HaveOccurred())

		// Create a CA secret so the certificate manager can issue keypairs.
		cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create the calico-system tier so the controller's tier check passes.
		Expect(cli.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoTierName},
		})).ToNot(HaveOccurred())

		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).ToNot(HaveOccurred())

		licenseAPIReady = &utils.ReadyFlag{}
		licenseAPIReady.MarkAsReady()
		tierWatchReady = &utils.ReadyFlag{}
		tierWatchReady.MarkAsReady()

		mockStatus = &status.MockStatus{}
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		// Teardown path (feature disabled / license expired) stops monitoring the
		// workload it just removed.
		mockStatus.On("RemoveStatefulSets", mock.Anything).Return().Maybe()
		mockStatus.On("RemoveDeployments", mock.Anything).Return().Maybe()
		mockStatus.On("RemoveDaemonsets", mock.Anything).Return().Maybe()
		mockStatus.On("AddCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("SetDegraded", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.AnythingOfType("string")).Return().Maybe()

		r = &Reconciler{
			cli:             cli,
			scheme:          scheme,
			status:          mockStatus,
			licenseAPIReady: licenseAPIReady,
			tierWatchReady:  tierWatchReady,
			opts: options.ControllerOptions{
				DetectedProvider: operatorv1.ProviderNone,
				Variant:          operatorv1.CalicoEnterprise,
				ClusterDomain:    dns.DefaultClusterDomain,
			},
		}
	})

	Context("CR not found", func() {
		It("should call OnCRNotFound and return without error", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "OnCRNotFound")
		})
	})

	Context("LogCollector without OpenTelemetry", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec:       operatorv1.LogCollectorSpec{},
			})).ToNot(HaveOccurred())
		})

		It("should call OnCRNotFound when OpenTelemetry is nil", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "OnCRNotFound")
		})
	})

	Context("happy path", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should reconcile and create resources", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
			mockStatus.AssertCalled(GinkgoT(), "ReadyToMonitor")
			mockStatus.AssertCalled(GinkgoT(), "ClearDegraded")

			ss := appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}}
			Expect(test.GetResource(cli, &ss)).To(BeNil())
			Expect(ss.Spec.Template.Spec.Containers).To(HaveLen(1))
		})

		It("should carry its own trusted bundle rather than the shared one", func() {
			// calico-system/tigera-ca-bundle belongs to the Installation controller
			// and holds a different certificate set. The component handler replaces
			// ConfigMap data wholesale, so writing that name here would have the two
			// controllers overwrite each other every reconcile.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			shared := corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}}
			Expect(test.GetResource(cli, &shared)).ToNot(BeNil(), "must not render the Installation controller's bundle")

			// Named after the collector: TrustedBundleName appends -ca-bundle, so
			// this is otel-collector-ca-bundle, not the collector's config ConfigMap.
			bundleName := certificatemanagement.TrustedBundleName(otelcollector.OpenTelemetryCollectorName, false)
			Expect(bundleName).ToNot(Equal(otelcollector.OpenTelemetryCollectorConfigMapName))
			own := corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: "calico-system"}}
			Expect(test.GetResource(cli, &own)).To(BeNil())
		})
	})

	Context("metrics export", func() {
		It("should wait for the Prometheus serving certificate before rendering", func() {
			// The federation scrape verifies tigera-prometheus against this bundle;
			// without the serving cert a BYO Prometheus certificate never verifies.
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceNotReady, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("partially removed collector", func() {
		It("should finish the teardown when the StatefulSet is already gone", func() {
			// Probing only the StatefulSet read a half-removed collector as
			// "already gone" and stranded its RBAC, ConfigMap, Service and policy.
			lc := &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			}
			Expect(cli.Create(ctx, lc)).ToNot(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			sa := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}}
			Expect(test.GetResource(cli, &sa)).To(BeNil())

			// Simulate the StatefulSet being removed out of band, then disable OTel.
			Expect(cli.Delete(ctx, &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"},
			})).ToNot(HaveOccurred())

			lc.Spec.OpenTelemetry = nil
			Expect(cli.Update(ctx, lc)).ToNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(test.GetResource(cli, &sa)).ToNot(BeNil(), "ServiceAccount should have been cleaned up")
		})
	})

	Context("feature switched off after being enabled", func() {
		It("should remove the collector's resources rather than orphaning them", func() {
			lc := &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			}
			Expect(cli.Create(ctx, lc)).ToNot(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			ss := appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}}
			Expect(test.GetResource(cli, &ss)).To(BeNil(), "collector should exist while enabled")

			// Turn it off. Nothing owns these resources, so without an explicit
			// teardown they would linger indefinitely.
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, lc)).ToNot(HaveOccurred())
			lc.Spec.OpenTelemetry = nil
			Expect(cli.Update(ctx, lc)).ToNot(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(test.GetResource(cli, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).ToNot(BeNil(), "StatefulSet should be gone")
			Expect(test.GetResource(cli, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).ToNot(BeNil(), "Service should be gone")
			Expect(test.GetResource(cli, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).ToNot(BeNil(), "ConfigMap should be gone")
			Expect(test.GetResource(cli, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector"}})).ToNot(BeNil(), "ClusterRole should be gone")
		})
	})

	DescribeTable("license states that must stop forwarding",
		// The degraded message claims forwarding has stopped; these paths make that
		// true rather than leaving the collector running and exporting.
		func(mutate func()) {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(cli, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).To(BeNil())

			mutate()
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(cli, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).ToNot(BeNil(), "collector should be removed")
		},
		Entry("license loses the OpenTelemetry feature", func() {
			lk := &v3.LicenseKey{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "default"}, lk)).ToNot(HaveOccurred())
			lk.Status.Features = []string{"some-other-feature"}
			Expect(cli.Update(ctx, lk)).ToNot(HaveOccurred())
		}),
	)

	Context("spec the collector cannot start from", func() {
		// otelcol validates both of these at boot (service/pipelines/config.go),
		// so without a pre-render check the pod crash-loops with no diagnostic.
		DescribeTable("should degrade instead of rendering an invalid config",
			func(spec *operatorv1.OpenTelemetrySpec) {
				Expect(cli.Create(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec:       operatorv1.LogCollectorSpec{OpenTelemetry: spec},
				})).ToNot(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, "Invalid OpenTelemetry configuration", mock.Anything, mock.Anything)
			},
			Entry("no exporters, so every pipeline would be exporter-less", &operatorv1.OpenTelemetrySpec{
				Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
			}),
			Entry("no data sources, so there would be no pipelines at all", &operatorv1.OpenTelemetrySpec{
				Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
			}),
			Entry("duplicate exporter names, which would emit the same config key twice", &operatorv1.OpenTelemetrySpec{
				Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
				Exporters: []operatorv1.OpenTelemetryExporter{
					{Name: "backend", Endpoint: "https://otlp.example.com:4317"},
					{Name: "backend", Endpoint: "https://other.example.com:4317"},
				},
			}),
			// The CRD Pattern rejects this at the API server; Validate is the backstop
			// for a stale CRD, where the cost is exporting in the clear.
			Entry("an http:// endpoint, which would send telemetry unencrypted", &operatorv1.OpenTelemetrySpec{
				Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
				Exporters: []operatorv1.OpenTelemetryExporter{
					{Name: "backend", Endpoint: "http://otlp.example.com:4318"},
				},
			}),
			Entry("a header with no secret key", &operatorv1.OpenTelemetrySpec{
				Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
				Exporters: []operatorv1.OpenTelemetryExporter{
					{Name: "backend", Endpoint: "https://otlp.example.com:4318",
						Auth: &operatorv1.OpenTelemetryExporterAuth{
							Headers: []operatorv1.OpenTelemetryExporterHeader{{
								Name:      "Authorization",
								ValueFrom: operatorv1.OpenTelemetryHeaderValueSource{},
							}},
						}},
				},
			}),
			Entry("two headers that collide once encoded for the environment", &operatorv1.OpenTelemetrySpec{
				Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
				Exporters: []operatorv1.OpenTelemetryExporter{{
					Name: "backend", Endpoint: "https://otlp.example.com:4318",
					Auth: &operatorv1.OpenTelemetryExporterAuth{
						Headers: []operatorv1.OpenTelemetryExporterHeader{
							{
								Name: "X-API-KEY",
								ValueFrom: operatorv1.OpenTelemetryHeaderValueSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "creds"}, Key: "a",
									},
								},
							},
							{
								// Sanitises to the same env var as the one above, which
								// would send one backend's credential under both headers.
								Name: "X_API_KEY",
								ValueFrom: operatorv1.OpenTelemetryHeaderValueSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "creds"}, Key: "b",
									},
								},
							},
						},
					},
				}},
			}),
		)
	})

	Context("exporter TLS material present but unusable", func() {
		// Rendering a path the mount never materialises makes the collector fail
		// to load it at startup, which is an opaque crash-loop.
		It("should degrade when the exporter CA ConfigMap has no certificate", func() {
			Expect(cli.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "corp-ca", Namespace: common.OperatorNamespace()},
			})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{
							{Name: "backend", Endpoint: "https://otlp.example.com:443",
								TLS: &operatorv1.OpenTelemetryExporterTLS{CAConfigMapName: "corp-ca"}},
						},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})

		It("should degrade when the client keypair Secret is missing its key", func() {
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "backend-mtls", Namespace: common.OperatorNamespace()},
				Data:       map[string][]byte{corev1.TLSCertKey: []byte("cert")},
			})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{
							{Name: "backend", Endpoint: "https://otlp.example.com:4317",
								TLS: &operatorv1.OpenTelemetryExporterTLS{ClientCertSecretName: "backend-mtls"}},
						},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})

		It("should validate every header key, not just the first per Secret", func() {
			// Two headers reading different keys of one Secret: deduping the fetch
			// must not skip validating the second key, or it renders empty.
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-creds", Namespace: common.OperatorNamespace()},
				Data:       map[string][]byte{"token-a": []byte("v")},
			})).ToNot(HaveOccurred())
			ref := func(key string) operatorv1.OpenTelemetryHeaderValueSource {
				return operatorv1.OpenTelemetryHeaderValueSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "shared-creds"}, Key: key,
					},
				}
			}
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{
							{Name: "first", Endpoint: "https://a.example.com:4318",
								Auth: &operatorv1.OpenTelemetryExporterAuth{Headers: []operatorv1.OpenTelemetryExporterHeader{
									{Name: "Authorization", ValueFrom: ref("token-a")}}}},
							// token-b does not exist.
							{Name: "second", Endpoint: "https://b.example.com:4318",
								Auth: &operatorv1.OpenTelemetryExporterAuth{Headers: []operatorv1.OpenTelemetryExporterHeader{
									{Name: "DD-API-KEY", ValueFrom: ref("token-b")}}}},
						},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})

		It("should degrade when a header names a Secret key that does not exist", func() {
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "otlp-auth", Namespace: common.OperatorNamespace()},
				Data:       map[string][]byte{"wrong-key": []byte("v")},
			})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{
							Name: "backend", Endpoint: "https://otlp.example.com:4318",
							Auth: &operatorv1.OpenTelemetryExporterAuth{
								Headers: []operatorv1.OpenTelemetryExporterHeader{{
									Name: "DD-API-KEY",
									ValueFrom: operatorv1.OpenTelemetryHeaderValueSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "otlp-auth"},
											Key:                  "api-key",
										},
									},
								}},
							},
						}},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("mutual TLS without the client keypair", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{
							{Name: "backend", Endpoint: "https://otlp.example.com:4317",
								TLS: &operatorv1.OpenTelemetryExporterTLS{ClientCertSecretName: "missing-secret"}},
						},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should degrade rather than render a config the collector cannot honour", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceReadError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("license missing", func() {
		BeforeEach(func() {
			Expect(cli.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should set degraded status", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceNotFound, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("license feature inactive", func() {
		BeforeEach(func() {
			Expect(cli.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status: v3.LicenseKeyStatus{
					Features: []string{"some-other-feature"},
				},
			})).ToNot(HaveOccurred())

			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should set degraded status for inactive feature", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("installation missing", func() {
		BeforeEach(func() {
			Expect(cli.Delete(ctx, &operatorv1.Installation{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should return error when installation is missing", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
		})
	})
})
