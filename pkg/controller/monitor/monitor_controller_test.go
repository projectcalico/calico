// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package monitor

import (
	"bytes"
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/logcollector"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"
)

var _ = Describe("Monitor controller tests", func() {
	var (
		cli                client.Client
		ctx                context.Context
		mockStatus         *status.MockStatus
		r                  ReconcileMonitor
		scheme             *runtime.Scheme
		installation       *operatorv1.Installation
		certificateManager certificatemanager.CertificateManager
		monitorCR          *operatorv1.Monitor
	)

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Create an object we can use throughout the test to do the monitor reconcile loops.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("AddDaemonsets", mock.Anything)
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything)
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
		mockStatus.On("ClearWarning", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("RemoveDeployments", mock.Anything)
		mockStatus.On("RemoveCertificateSigningRequests", common.TigeraPrometheusNamespace)
		mockStatus.On("SetMetaData", mock.Anything).Return()

		// Create an object we can use throughout the test to do the monitor reconcile loops.
		r = ReconcileMonitor{
			client:          cli,
			scheme:          scheme,
			provider:        operatorv1.ProviderNone,
			status:          mockStatus,
			prometheusReady: &utils.ReadyFlag{},
			tierWatchReady:  &utils.ReadyFlag{},
			licenseAPIReady: &utils.ReadyFlag{},
		}

		// We start off with a 'standard' installation, with nothing special
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Generation: 2,
			},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.CalicoEnterprise,
				Computed: &operatorv1.InstallationSpec{},
			},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.CalicoEnterprise,
				Registry: "some.registry.org/",
			},
		}
		Expect(cli.Create(ctx, installation)).To(BeNil())

		// Apply the Monitor CR to the fake cluster.
		monitorCR = &operatorv1.Monitor{
			TypeMeta:   metav1.TypeMeta{Kind: "Monitor", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.MonitorSpec{
				Alertmanager: &operatorv1.Alertmanager{
					AlertmanagerSpec: &operatorv1.AlertmanagerSpec{
						Replicas: ptr.To(int32(3)),
					},
				},
			},
		}
		Expect(cli.Create(ctx, monitorCR)).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, render.CreateCertificateConfigMap("test", render.TyphaCAConfigMapName, common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())

		// Create a certificate manager and provision the CA to unblock the controller. Generally this would be done by
		// the cluster CA controller and is a prerequisite for the monitor controller to function.
		var err error
		certificateManager, err = certificatemanager.Create(cli, &installation.Spec, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Create a valid (non-expired) license.
		Expect(cli.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default", CreationTimestamp: metav1.Now()},
			Status: v3.LicenseKeyStatus{
				Expiry: metav1.Time{Time: time.Now().Add(24 * time.Hour)},
			},
		})).NotTo(HaveOccurred())

		// Mark that watches were successful.
		r.prometheusReady.MarkAsReady()
		r.tierWatchReady.MarkAsReady()
		r.licenseAPIReady.MarkAsReady()
	})

	Context("controller reconciliation", func() {
		var (
			am = &monitoringv1.Alertmanager{}
			p  = &monitoringv1.Prometheus{}
			pr = &monitoringv1.PrometheusRule{}
			sm = &monitoringv1.ServiceMonitor{}
		)

		BeforeEach(func() {
			// Prometheus related objects should not exist.
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.TigeraPrometheusRule, Namespace: common.TigeraPrometheusNamespace}, pr)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentBitMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
		})

		It("should create Prometheus related resources", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			// Prometheus related objects should be rendered after reconciliation.
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.TigeraPrometheusRule, Namespace: common.TigeraPrometheusNamespace}, pr)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentBitMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())

			// Verify the recommended labels are correct on these resources.
			Expect(p.Labels).To(Equal(map[string]string{
				"k8s-app":                      "tigera-prometheus",
				"app.kubernetes.io/instance":   "tigera-secure",
				"app.kubernetes.io/managed-by": "tigera-operator",
				"app.kubernetes.io/name":       "tigera-prometheus",
				"app.kubernetes.io/part-of":    "Calico",
				"app.kubernetes.io/component":  "",
			}))
			Expect(am.Labels).To(Equal(map[string]string{
				"k8s-app":                      "calico-node-alertmanager",
				"app.kubernetes.io/instance":   "tigera-secure",
				"app.kubernetes.io/managed-by": "tigera-operator",
				"app.kubernetes.io/name":       "calico-node-alertmanager",
				"app.kubernetes.io/part-of":    "Calico",
				"app.kubernetes.io/component":  "",
			}))

		})

		It("should create Prometheus related resources even when a bad cert is configured for another component", func() {
			// fluent-bit metrics are scraped over plain HTTP, so the monitor
			// controller no longer reads the fluent-bit certificate at all; even
			// a key-usage-invalid fluent-bit secret must not affect Prometheus.
			By("Creating a fluent-bit certificate secret without all necessary usages")
			cryptoCA, err := tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix)
			Expect(err).NotTo(HaveOccurred())
			tlsCfg, err := cryptoCA.MakeServerCertForDuration(sets.New[string]("test"), tls.DefaultCertificateDuration, tls.SetServerAuth)
			Expect(err).NotTo(HaveOccurred())
			keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
			Expect(tlsCfg.WriteCertConfig(crtContent, keyContent)).NotTo(HaveOccurred())
			privateKeyPEM, certificatePEM := keyContent.Bytes(), crtContent.Bytes()
			fluentBitCert, err := certificateManager.GetOrCreateKeyPair(cli, logcollector.FluentBitTLSSecretName, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			fluentBitSecret := fluentBitCert.Secret(common.OperatorNamespace())
			fluentBitSecret.Data[corev1.TLSCertKey] = certificatePEM
			fluentBitSecret.Data[corev1.TLSPrivateKeyKey] = privateKeyPEM
			Expect(err).NotTo(HaveOccurred())
			Expect(r.client.Create(ctx, fluentBitSecret)).NotTo(HaveOccurred())

			By("reconciling the controller after a bad secret was created, we expect no problems, because the secret is not read by this controller")
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should render calico-system policy when tier and policy watch are ready", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(6))
			Expect(policies.Items[0].Name).To(Equal("calico-system.calico-node-alertmanager"))
			Expect(policies.Items[1].Name).To(Equal("calico-system.calico-node-alertmanager-mesh"))
			Expect(policies.Items[2].Name).To(Equal("calico-system.default-deny"))
			Expect(policies.Items[3].Name).To(Equal("calico-system.prometheus"))
			Expect(policies.Items[4].Name).To(Equal("calico-system.prometheus-operator"))
			Expect(policies.Items[5].Name).To(Equal("calico-system.tigera-prometheus-api"))
		})

		It("should omit calico-system policy and not degrade when tier is not ready", func() {
			Expect(cli.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should degrade and wait if tier is ready but tier watch is not ready", func() {
			r.tierWatchReady = &utils.ReadyFlag{}
			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
			mockStatus.On("SetMetaData", mock.Anything).Return()
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("RemoveStatefulSets", mock.Anything).Return().Maybe()
			r.status = mockStatus

			test.ExpectWaitForTierWatch(ctx, &r, mockStatus)

			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		Context("controller reconciliation with external monitoring configuration", func() {
			It("should create Prometheus related resources", func() {
				Expect(r.client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "external-prometheus"}})).NotTo(HaveOccurred())
				monitorCR.Spec.ExternalPrometheus = &operatorv1.ExternalPrometheus{
					ServiceMonitor: &operatorv1.ServiceMonitor{},
					Namespace:      "external-prometheus",
				}
				Expect(r.client.Update(ctx, monitorCR)).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).NotTo(HaveOccurred())

				// Prometheus related objects should be rendered after reconciliation.
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.TigeraPrometheusRule, Namespace: common.TigeraPrometheusNamespace}, pr)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentBitMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())

				// External Prometheus related objects should be rendered after reconciliation.
				serviceMonitor := &monitoringv1.ServiceMonitor{}
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, serviceMonitor)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &corev1.ConfigMap{})).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &corev1.Secret{})).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &corev1.ServiceAccount{})).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &rbacv1.ClusterRole{})).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &rbacv1.ClusterRoleBinding{})).NotTo(HaveOccurred())

				Expect(serviceMonitor.Spec.Endpoints).To(HaveLen(1))
				// Verify that the default settings are propagated.
				Expect(serviceMonitor.Labels).Should(And(
					HaveKeyWithValue(render.AppLabelName, monitor.TigeraExternalPrometheus),
					HaveKeyWithValue("app.kubernetes.io/instance", "tigera-secure"),
					HaveKeyWithValue("app.kubernetes.io/managed-by", "tigera-operator"),
					HaveKeyWithValue("app.kubernetes.io/name", "tigera-external-prometheus"),
					HaveKeyWithValue("app.kubernetes.io/part-of", "Calico"),
				))
				Expect(serviceMonitor.Spec.Endpoints[0]).To(Equal(monitoringv1.Endpoint{
					Params: map[string][]string{"match[]": {"{__name__=~\".+\"}"}},
					Port:   "web",
					Path:   "/federate",
					RelabelConfigs: []monitoringv1.RelabelConfig{
						{
							TargetLabel: "__scheme__",
							Replacement: ptr.To("https"),
						},
					},
					HTTPConfigWithProxyAndTLSFiles: monitoringv1.HTTPConfigWithProxyAndTLSFiles{
						HTTPConfigWithTLSFiles: monitoringv1.HTTPConfigWithTLSFiles{
							TLSConfig: &monitoringv1.TLSConfig{
								SafeTLSConfig: monitoringv1.SafeTLSConfig{
									CA: monitoringv1.SecretOrConfigMap{
										ConfigMap: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "tigera-external-prometheus",
											},
											Key: corev1.TLSCertKey,
										},
									},
								},
							},
							HTTPConfigWithoutTLS: monitoringv1.HTTPConfigWithoutTLS{
								BearerTokenSecret: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: monitor.TigeraExternalPrometheus,
									},
									Key: "token",
								},
							},
						},
					},
				}))
			})
		})
	})

	Context("OpenTelemetry Collector ServiceMonitor", func() {
		otelKey := client.ObjectKey{Name: render.OpenTelemetryCollectorName, Namespace: common.TigeraPrometheusNamespace}

		BeforeEach(func() {
			// A licensed, valid export config. The Service is what the collector's
			// own controller creates once it has everything it needs.
			Expect(cli.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default", CreationTimestamp: metav1.Now()},
				Status: v3.LicenseKeyStatus{
					Expiry:   metav1.Time{Time: time.Now().Add(24 * time.Hour)},
					Features: []string{common.OpenTelemetryCollectorFeature},
				},
			})).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Metrics:   &operatorv1.OpenTelemetryMetrics{State: ptr.To(operatorv1.OpenTelemetryMetricsEnabled)},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "https://otlp.example.com:4317"}},
					},
				},
			})).NotTo(HaveOccurred())
		})

		It("should not render the ServiceMonitor before the collector Service exists", func() {
			// The spec is valid and licensed, but the otel controller stops short of
			// rendering when material an exporter names is missing. Scraping then has
			// nothing to select.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, otelKey, &monitoringv1.ServiceMonitor{})).To(HaveOccurred())
		})

		It("should render the ServiceMonitor once the collector Service exists", func() {
			Expect(cli.Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{
				Name:      render.OpenTelemetryCollectorName,
				Namespace: render.OpenTelemetryCollectorNamespace,
			}})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, otelKey, &monitoringv1.ServiceMonitor{})).NotTo(HaveOccurred())
		})

		It("should remove the ServiceMonitor when the collector Service goes away", func() {
			svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
				Name:      render.OpenTelemetryCollectorName,
				Namespace: render.OpenTelemetryCollectorNamespace,
			}}
			Expect(cli.Create(ctx, svc)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, otelKey, &monitoringv1.ServiceMonitor{})).NotTo(HaveOccurred())

			Expect(cli.Delete(ctx, svc)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, otelKey, &monitoringv1.ServiceMonitor{})).To(HaveOccurred())
		})
	})

	Context("Alertmanager Configuration secrets", func() {
		var secretOperator *corev1.Secret
		var secretPrometheus *corev1.Secret

		BeforeEach(func() {
			secretOperator = &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte("Alertmanager secret in tigera-operator namespace"),
				},
			}
			secretPrometheus = &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.TigeraPrometheusNamespace,
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte("Alertmanager secret in tigera-prometheus namespace"),
				},
			}
		})

		AfterEach(func() {
			Expect(cli.Delete(ctx, secretOperator)).To(BeNil())
			Expect(cli.Delete(ctx, secretPrometheus)).To(BeNil())
		})

		It("should create the Alertmanager secret for new install", func() {
			s := &corev1.Secret{}
			// Make sure Alertmanager secrets don't exist in either Operator or Prometheus namespace.
			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).To(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			var ownerRefs []metav1.OwnerReference

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).NotTo(HaveOccurred())
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))
		})

		It("should read Alertmanager secret from the Operator namespace if exists", func() {
			Expect(cli.Create(ctx, secretOperator)).To(BeNil())
			Expect(cli.Create(ctx, secretPrometheus)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			s := &corev1.Secret{}
			var ownerRefs []metav1.OwnerReference

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-operator namespace")))
			Expect(ownerRefs).To(HaveLen(0))

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-operator namespace")))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))
		})

		It("should copy back the Alertmanager secret when upgrading and take ownership if it is unmodified", func() {
			secretPrometheus := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.TigeraPrometheusNamespace,
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte(alertmanagerConfig),
				},
			}
			Expect(cli.Create(ctx, secretPrometheus)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			s := &corev1.Secret{}
			var ownerRefs []metav1.OwnerReference

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))
		})

		It("should copy back the Alertmanager secret when upgrading and won't take ownership if it is modified", func() {
			Expect(cli.Create(ctx, secretPrometheus)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			s := &corev1.Secret{}
			var ownerRefs []metav1.OwnerReference

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-prometheus namespace")))
			Expect(ownerRefs).To(HaveLen(0))

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-prometheus namespace")))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))
		})
	})

	Context("Reconcile for Condition status", func() {
		generation := int64(2)
		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "monitor",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := r.getMonitor(ctx)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(1))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
		})

		It("should reconcile with empty tigerastatus conditions", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "monitor",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := r.getMonitor(ctx)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(0))
		})

		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentProgressing,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.ResourceNotReady),
							Message:            "Progressing Installation.operatorv1.tigera.io",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.ResourceUpdateError),
							Message:            "Error resolving ImageSet for components",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "monitor",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := r.getMonitor(ctx)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.ResourceNotReady)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Progressing Installation.operatorv1.tigera.io"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.ResourceUpdateError)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
		})

		It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentProgressing,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "monitor",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			instance, err := r.getMonitor(ctx)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
		})
	})

	Context("License expiry", func() {
		It("should set degraded status when license is expired", func() {
			// Replace the valid license with an expired one.
			Expect(cli.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default", CreationTimestamp: metav1.Now()},
				Status: v3.LicenseKeyStatus{
					Expiry: metav1.Time{Time: time.Now().Add(-24 * time.Hour)},
				},
			})).NotTo(HaveOccurred())

			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError,
				"License is expired - Contact Tigera support or email licensing@tigera.io", mock.Anything, mock.Anything).Return()

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify that ServiceMonitors are not created when license is expired.
			sm := &monitoringv1.ServiceMonitor{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentBitMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())

			// Grace period warning should be cleared when license is fully expired.
			mockStatus.AssertCalled(GinkgoT(), "ClearWarning", "license-grace-period")

			// Verify that other Prometheus resources are still created.
			am := &monitoringv1.Alertmanager{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).NotTo(HaveOccurred())
			p := &monitoringv1.Prometheus{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).NotTo(HaveOccurred())
		})

		It("should not set degraded status when license is valid", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Grace period warning should be cleared when license is valid.
			mockStatus.AssertCalled(GinkgoT(), "ClearWarning", "license-grace-period")

			// ServiceMonitors should be created with a valid license.
			sm := &monitoringv1.ServiceMonitor{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentBitMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
		})

		It("should requeue when license is in the grace period", func() {
			// Replace the valid license with one that expired 1 day ago but has a 90-day grace period.
			Expect(cli.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default", CreationTimestamp: metav1.Now()},
				Status: v3.LicenseKeyStatus{
					Expiry:      metav1.Time{Time: time.Now().Add(-24 * time.Hour)},
					GracePeriod: "90d",
				},
			})).NotTo(HaveOccurred())

			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Should requeue to re-reconcile when the grace period expires.
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
			Expect(result.RequeueAfter).To(BeNumerically("~", 89*24*time.Hour, 1*time.Hour))

			// Grace period warning should be visible in TigeraStatus.
			mockStatus.AssertCalled(GinkgoT(), "SetWarning", "license-grace-period",
				"License has expired and is within the grace period. Please renew your license to avoid service disruption.")

			// ServiceMonitors should still be created during the grace period.
			sm := &monitoringv1.ServiceMonitor{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentBitMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
		})
	})
})
