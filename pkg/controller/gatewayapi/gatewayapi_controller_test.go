// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gatewayapi

import (
	"context"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/stretchr/testify/mock"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/gatewayapi"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Gateway API controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r *ReconcileGatewayAPI
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var installation *operatorv1.Installation

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(admregv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a CRUD interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		// Seed the operator CA secret in the fake client so that certificatemanager.Create
		// (called by ReconcileGatewayAPI.Reconcile to build the trusted bundle) does not
		// fail with "CA secret does not exist".
		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.CalicoEnterprise,
				Registry: "some.registry.org/",
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
				Computed: &operatorv1.InstallationSpec{
					Registry: "my-reg",
					// The test is provider agnostic.
					KubernetesProvider: operatorv1.ProviderNone,
				},
			},
		}
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("RemoveDeployments", mock.Anything).Return()

		fakeComponentHandlers = nil
		r = &ReconcileGatewayAPI{
			client:              c,
			scheme:              scheme,
			status:              mockStatus,
			variant:             operatorv1.CalicoEnterprise,
			tierWatchReady:      &utils.ReadyFlag{},
			newComponentHandler: FakeComponentHandler,
			watchEnvoyProxy:     func(namespacedName operatorv1.NamespacedName) error { return nil },
			watchEnvoyGateway:   func(namespacedName operatorv1.NamespacedName) error { return nil },
			watchGateways:       func() error { return nil },
		}
	})

	Context("with real component handler", func() {
		BeforeEach(func() {
			// Use the real component handler for the following test because we want to
			// verify if an existing Gateway CRD gets left as is, or overwritten; and
			// that relies on the create-only (or not) behaviour of the real component
			// handler.  Possibly this should actually be in a UT for the component
			// handler, rather than here; but it's easier to leave this as already
			// coded, and it means we're also covering `render.GatewayAPICRDs`.
			r.newComponentHandler = utils.NewComponentHandler
		})

		DescribeTable("CRD management",
			func(gwapiMod func(*operatorv1.GatewayAPI), expectReplace bool) {
				Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

				By("installing a pre-existing Gateway CRD with an improbable version")
				crdName := "gateways.gateway.networking.k8s.io"
				existingCRD := &apiextenv1.CustomResourceDefinition{
					ObjectMeta: metav1.ObjectMeta{Name: crdName},
					Spec: apiextenv1.CustomResourceDefinitionSpec{
						Versions: []apiextenv1.CustomResourceDefinitionVersion{{
							Name: "v0123456789",
						}},
					},
				}
				Expect(c.Create(ctx, existingCRD)).NotTo(HaveOccurred())

				By("applying the GatewayAPI CR to the fake cluster")
				gwapi := &operatorv1.GatewayAPI{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec:       operatorv1.GatewayAPISpec{},
				}
				gwapiMod(gwapi)
				Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

				By("triggering a reconcile")
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				By("examining the Gateway CRD that is now present")
				gatewayCRD := &apiextenv1.CustomResourceDefinition{}
				Expect(c.Get(ctx, client.ObjectKey{Name: crdName}, gatewayCRD)).NotTo(HaveOccurred())
				if expectReplace {
					Expect(gatewayCRD.Spec.Versions).NotTo(ContainElement(MatchFields(IgnoreExtras, Fields{"Name": Equal("v0123456789")})))
				} else {
					Expect(gatewayCRD.Spec.Versions).To(ContainElement(MatchFields(IgnoreExtras, Fields{"Name": Equal("v0123456789")})))
				}

				if gwapi.Spec.CRDManagement == nil {
					By("checking that CRDManagement field has been updated to PreferExisting")
					Expect(c.Get(ctx, utils.DefaultEnterpriseInstanceKey, gwapi)).NotTo(HaveOccurred())
					Expect(gwapi.Spec.CRDManagement).NotTo(BeNil())
					Expect(*gwapi.Spec.CRDManagement).To(Equal(operatorv1.CRDManagementPreferExisting))
				}
			},
			Entry("default", func(_ *operatorv1.GatewayAPI) {}, false),
			Entry("Reconcile", func(gwapi *operatorv1.GatewayAPI) {
				setting := operatorv1.CRDManagementReconcile
				gwapi.Spec.CRDManagement = &setting
			}, true),
			Entry("PreferExisting", func(gwapi *operatorv1.GatewayAPI) {
				setting := operatorv1.CRDManagementPreferExisting
				gwapi.Spec.CRDManagement = &setting
			}, false),
		)
	})

	It("handles a custom EnvoyGateway", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating a custom EnvoyGateway")
		envoyGateway := &envoyapi.EnvoyGateway{
			EnvoyGatewaySpec: envoyapi.EnvoyGatewaySpec{
				Telemetry: &envoyapi.EnvoyGatewayTelemetry{
					Metrics: &envoyapi.EnvoyGatewayMetrics{
						Sinks: []envoyapi.EnvoyGatewayMetricSink{{
							Type: envoyapi.MetricSinkTypeOpenTelemetry,
						}},
					},
				},
				ExtensionAPIs: &envoyapi.ExtensionAPISettings{
					EnableEnvoyPatchPolicy: true,
					EnableBackend:          true,
				},
			},
		}
		envoyGatewayYAML, err := yaml.Marshal(*envoyGateway)
		Expect(err).NotTo(HaveOccurred())
		envoyGatewayConfigMap := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-envoy-gateway",
				Namespace: "default",
			},
			Data: map[string]string{
				"envoy-gateway.yaml": string(envoyGatewayYAML),
			},
		}
		Expect(c.Create(ctx, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operatorv1.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		By("checking the component handlers")
		Expect(fakeComponentHandlers).To(HaveLen(2))
		Expect(fakeComponentHandlers[0].createOnly).To(BeTrue())
		Expect(fakeComponentHandlers[1].createOnly).To(BeFalse())

		By("checking that the custom EnvoyGateway was passed through")
		gatewayAPIImplementationConfig := fakeComponentHandlers[1].lastComponent.(gatewayapi.GatewayAPIImplementationConfigInterface).GetConfig()
		Expect(gatewayAPIImplementationConfig.CustomEnvoyGateway).NotTo(BeNil())
		Expect(*gatewayAPIImplementationConfig.CustomEnvoyGateway).To(Equal(*envoyGateway))
	})

	It("handles when a custom EnvoyGateway is referenced but does not exist yet, then created later", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operatorv1.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Error reading EnvoyGatewayConfigRef",
			"configmaps \"my-envoy-gateway\" not found",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())

		By("now creating the custom EnvoyGateway")
		envoyGateway := &envoyapi.EnvoyGateway{
			EnvoyGatewaySpec: envoyapi.EnvoyGatewaySpec{
				Telemetry: &envoyapi.EnvoyGatewayTelemetry{
					Metrics: &envoyapi.EnvoyGatewayMetrics{
						Sinks: []envoyapi.EnvoyGatewayMetricSink{{
							Type: envoyapi.MetricSinkTypeOpenTelemetry,
						}},
					},
				},
				ExtensionAPIs: &envoyapi.ExtensionAPISettings{
					EnableEnvoyPatchPolicy: true,
					EnableBackend:          true,
				},
			},
		}
		envoyGatewayYAML, err := yaml.Marshal(*envoyGateway)
		Expect(err).NotTo(HaveOccurred())
		envoyGatewayConfigMap := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-envoy-gateway",
				Namespace: "default",
			},
			Data: map[string]string{
				"envoy-gateway.yaml": string(envoyGatewayYAML),
			},
		}
		Expect(c.Create(ctx, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		fakeComponentHandlers = nil
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		By("checking that the custom EnvoyGateway was passed through")
		gatewayAPIImplementationConfig := fakeComponentHandlers[1].lastComponent.(gatewayapi.GatewayAPIImplementationConfigInterface).GetConfig()
		Expect(gatewayAPIImplementationConfig.CustomEnvoyGateway).NotTo(BeNil())
		Expect(*gatewayAPIImplementationConfig.CustomEnvoyGateway).To(Equal(*envoyGateway))
	})

	It("handles when a custom EnvoyGateway is referenced and exists but does not have the right key", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating a custom EnvoyGateway")
		envoyGatewayConfigMap := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-envoy-gateway",
				Namespace: "default",
			},
			Data: map[string]string{
				"wrong-key": "doesn't matter",
			},
		}
		Expect(c.Create(ctx, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operatorv1.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Error reading EnvoyGatewayConfigRef",
			"missing 'envoy-gateway.yaml' key",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
	})

	It("handles when a custom EnvoyGateway is referenced and exists but holds invalid YAML", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating a custom EnvoyGateway")
		envoyGatewayConfigMap := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-envoy-gateway",
				Namespace: "default",
			},
			Data: map[string]string{
				"envoy-gateway.yaml": "invalid YAML",
			},
		}
		Expect(c.Create(ctx, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operatorv1.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Error reading EnvoyGatewayConfigRef",
			"error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type v1alpha1.EnvoyGateway",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
	})

	It("handles custom EnvoyProxies", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating custom EnvoyProxy #1")
		envoyProxy1 := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy-1",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Logging: envoyapi.ProxyLogging{
					Level: map[envoyapi.ProxyLogComponent]envoyapi.LogLevel{
						envoyapi.LogComponentAdmin: envoyapi.LogLevelWarn,
					},
				},
			},
		}
		Expect(c.Create(ctx, envoyProxy1)).NotTo(HaveOccurred())

		By("creating custom EnvoyProxy #2")
		envoyProxy2 := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy-2",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Provider: &envoyapi.EnvoyProxyProvider{
					Type: envoyapi.EnvoyProxyProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDaemonSet: &envoyapi.KubernetesDaemonSetSpec{
							Pod: &envoyapi.KubernetesPodSpec{
								NodeSelector: map[string]string{
									"x": "y",
								},
							},
						},
					},
				},
			},
		}
		Expect(c.Create(ctx, envoyProxy2)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class-1",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-1",
					},
				}, {
					Name: "custom-class-2",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-2",
					},
				}},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		By("checking the component handlers")
		Expect(fakeComponentHandlers).To(HaveLen(2))
		Expect(fakeComponentHandlers[0].createOnly).To(BeTrue())
		Expect(fakeComponentHandlers[1].createOnly).To(BeFalse())

		By("checking that the custom EnvoyProxies were passed through")
		gatewayAPIImplementationConfig := fakeComponentHandlers[1].lastComponent.(gatewayapi.GatewayAPIImplementationConfigInterface).GetConfig()
		Expect(gatewayAPIImplementationConfig.CustomEnvoyProxies).NotTo(BeNil())
		Expect(gatewayAPIImplementationConfig.CustomEnvoyProxies).To(HaveKeyWithValue("custom-class-1", envoyProxy1))
		Expect(gatewayAPIImplementationConfig.CustomEnvoyProxies).To(HaveKeyWithValue("custom-class-2", envoyProxy2))
	})

	It("handles when a custom EnvoyProxy is referenced but does not exist", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating custom EnvoyProxy #1")
		envoyProxy1 := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy-1",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Logging: envoyapi.ProxyLogging{
					Level: map[envoyapi.ProxyLogComponent]envoyapi.LogLevel{
						envoyapi.LogComponentAdmin: envoyapi.LogLevelWarn,
					},
				},
			},
		}
		Expect(c.Create(ctx, envoyProxy1)).NotTo(HaveOccurred())

		By("NOT creating custom EnvoyProxy #2")

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class-1",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-1",
					},
				}, {
					Name: "custom-class-2",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-2",
					},
				}},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Error reading EnvoyProxyRef",
			"envoyproxies.gateway.envoyproxy.io \"my-proxy-2\" not found",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
	})

	It("handles when both GatewayKind and an incompatible EnvoyProxy are specified", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating custom EnvoyProxy")
		three := int32(3)
		envoyProxy1 := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy-1",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Logging: envoyapi.ProxyLogging{
					Level: map[envoyapi.ProxyLogComponent]envoyapi.LogLevel{
						envoyapi.LogComponentAdmin: envoyapi.LogLevelWarn,
					},
				},
				Provider: &envoyapi.EnvoyProxyProvider{
					Type: envoyapi.EnvoyProxyProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDeployment: &envoyapi.KubernetesDeploymentSpec{
							Replicas: &three,
						},
					},
				},
			},
		}
		Expect(c.Create(ctx, envoyProxy1)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		daemonSet := operatorv1.GatewayKindDaemonSet
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class-1",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-1",
					},
					GatewayKind: &daemonSet,
				}},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Conflict between EnvoyProxyRef and GatewayKind",
			"GatewayKind (for class 'custom-class-1') cannot be 'DaemonSet' when EnvoyProxyRef already indicates that gateways will be provisioned as a Deployment",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
	})

	It("writes back defaults to the GatewayAPI CR", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		By("re-reading the GatewayAPI")
		err = c.Get(ctx, utils.DefaultEnterpriseInstanceKey, gwapi)
		Expect(err).NotTo(HaveOccurred())

		By("checking default GatewayClasses")
		Expect(gwapi.Spec.GatewayClasses).To(HaveLen(1))
		Expect(gwapi.Spec.GatewayClasses[0].Name).To(Equal("tigera-gateway-class"))
		Expect(gwapi.Spec.GatewayClasses[0].EnvoyProxyRef).To(BeNil())
		Expect(gwapi.Spec.GatewayClasses[0].GatewayKind).To(BeNil())
		Expect(gwapi.Spec.GatewayClasses[0].GatewayDeployment).To(BeNil())
		Expect(gwapi.Spec.GatewayClasses[0].GatewayDaemonSet).To(BeNil())
		Expect(gwapi.Spec.GatewayClasses[0].GatewayService).To(BeNil())

		By("checking default CRDManagement")
		Expect(gwapi.Spec.CRDManagement).NotTo(BeNil())
		Expect(*gwapi.Spec.CRDManagement).To(Equal(operatorv1.CRDManagementReconcile))
	})

	It("Check felix configuration patching is set if it's not alreadyconfigured", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		felixConfig := &v3.FelixConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       v3.FelixConfigurationSpec{
				// PolicySyncPathPrefix is not set.
			},
		}

		Expect(c.Create(ctx, felixConfig)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		By("checking felix configuration has been patched")
		actualFelixConfig := &v3.FelixConfiguration{}
		err = c.Get(ctx, client.ObjectKey{Name: "default"}, actualFelixConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(actualFelixConfig.Spec.PolicySyncPathPrefix).To(Equal(DefaultPolicySyncPrefix))
	})

	It("Check felix configuration patching is set if it's not set", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		felixConfig := &v3.FelixConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: v3.FelixConfigurationSpec{
				// PolicySyncPathPrefix is not set.
				PolicySyncPathPrefix: "/dev/null",
			},
		}

		Expect(c.Create(ctx, felixConfig)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		By("checking felix configuration has been patched")
		actualFelixConfig := &v3.FelixConfiguration{}
		err = c.Get(ctx, client.ObjectKey{Name: "default"}, actualFelixConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(actualFelixConfig.Spec.PolicySyncPathPrefix).ToNot(Equal(DefaultPolicySyncPrefix))
		Expect(actualFelixConfig.Spec.PolicySyncPathPrefix).To(Equal("/dev/null"))
	})

	// Legacy tigera-gateway teardown (remove with the teardown gate once 3.x upgrades are unsupported).
	It("deletes only GatewayClass/GatewayAPI-owned legacy resources in tigera-gateway, leaving the GatewayClass and unrelated resources", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.GatewayAPI{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &gapi.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: gatewayapi.GatewayClassName}})).NotTo(HaveOccurred())

		By("seeding the legacy controller + a class-owned proxy (Deployment/Service/SA/ConfigMap)")
		Expect(c.Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "tigera-gateway", Name: "envoy-gateway"}})).NotTo(HaveOccurred())
		ownedByClass := []metav1.OwnerReference{{APIVersion: "gateway.networking.k8s.io/v1", Kind: "GatewayClass", Name: gatewayapi.GatewayClassName, UID: "abc"}}
		Expect(c.Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "tigera-gateway", Name: "envoy-gw-ns-gw-abcd1234", OwnerReferences: ownedByClass}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "tigera-gateway", Name: "envoy-gw-ns-gw-abcd1234", OwnerReferences: ownedByClass}})).NotTo(HaveOccurred())

		By("seeding an unrelated, unowned ServiceAccount + ConfigMap a user might have placed there")
		Expect(c.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "tigera-gateway", Name: "user-sa"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "tigera-gateway", Name: "user-config"}})).NotTo(HaveOccurred())

		By("first reconcile: deletes the controller alone (so it can't re-create proxies), keeps the proxy")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(BeNumerically(">", 0))
		Expect(apierrors.IsNotFound(c.Get(ctx, client.ObjectKey{Namespace: "tigera-gateway", Name: "envoy-gateway"}, &appsv1.Deployment{}))).To(BeTrue())
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "tigera-gateway", Name: "envoy-gw-ns-gw-abcd1234"}, &appsv1.Deployment{})).NotTo(HaveOccurred())

		By("second reconcile: controller gone, so the orphaned class-owned proxy resources are deleted")
		result, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(BeNumerically(">", 0))
		Expect(apierrors.IsNotFound(c.Get(ctx, client.ObjectKey{Namespace: "tigera-gateway", Name: "envoy-gw-ns-gw-abcd1234"}, &appsv1.Deployment{}))).To(BeTrue())
		Expect(apierrors.IsNotFound(c.Get(ctx, client.ObjectKey{Namespace: "tigera-gateway", Name: "envoy-gw-ns-gw-abcd1234"}, &corev1.ServiceAccount{}))).To(BeTrue())

		By("leaving unrelated unowned resources and the GatewayClass untouched")
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "tigera-gateway", Name: "user-sa"}, &corev1.ServiceAccount{})).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "tigera-gateway", Name: "user-config"}, &corev1.ConfigMap{})).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: gatewayapi.GatewayClassName}, &gapi.GatewayClass{})).NotTo(HaveOccurred())
	})

	It("writes per-namespace Gateway resources owned by the namespace's Gateways (Enterprise)", func() {
		// These go through the real component handler, which is what merges each Gateway's
		// owner reference in rather than replacing what is already there.
		r.newComponentHandler = utils.NewComponentHandler
		bundle, err := certificatemanagement.CreateTrustedBundleWithSystemRootCertificates(nil)
		Expect(err).NotTo(HaveOccurred())
		pullSecrets := []*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()}}}
		gateways := []gapi.Gateway{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "gw1", UID: "u1"}, Spec: gapi.GatewaySpec{GatewayClassName: gatewayapi.GatewayClassName}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "gw2", UID: "u2"}, Spec: gapi.GatewaySpec{GatewayClassName: gatewayapi.GatewayClassName}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "gw3", UID: "u3"}, Spec: gapi.GatewaySpec{GatewayClassName: "not-ours"}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: common.CalicoNamespace, Name: "gw4", UID: "u4"}, Spec: gapi.GatewaySpec{GatewayClassName: gatewayapi.GatewayClassName}},
		}
		Expect(r.reconcileGatewayNamespaceResources(ctx, bundle, pullSecrets, true, gateways, map[string]bool{gatewayapi.GatewayClassName: true})).NotTo(HaveOccurred())

		By("creating the bundle + WAF SA/RoleBindings/pull-secret in app-ns, owned by both Gateways")
		ownerNames := func(o client.Object) []string {
			var n []string
			for _, ref := range o.GetOwnerReferences() {
				if ref.Kind == "Gateway" {
					n = append(n, ref.Name)
				}
			}
			return n
		}
		cm := &corev1.ConfigMap{}
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "app-ns", Name: certificatemanagement.TrustedCertConfigMapName}, cm)).NotTo(HaveOccurred())
		Expect(ownerNames(cm)).To(ConsistOf("gw1", "gw2"))
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "app-ns", Name: "waf-http-filter"}, &corev1.ServiceAccount{})).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "app-ns", Name: "waf-http-filter-gateway-resources"}, &rbacv1.RoleBinding{})).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "app-ns", Name: "tigera-operator-secrets"}, &rbacv1.RoleBinding{})).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "app-ns", Name: "tigera-pull-secret"}, &corev1.Secret{})).NotTo(HaveOccurred())

		By("skipping namespaces whose Gateway is not ours, and reserved namespaces")
		Expect(apierrors.IsNotFound(c.Get(ctx, client.ObjectKey{Namespace: "other-ns", Name: certificatemanagement.TrustedCertConfigMapName}, &corev1.ConfigMap{}))).To(BeTrue())
		Expect(apierrors.IsNotFound(c.Get(ctx, client.ObjectKey{Namespace: common.CalicoNamespace, Name: "waf-http-filter"}, &corev1.ServiceAccount{}))).To(BeTrue())
	})

	It("keeps owner references another feature put on the shared RoleBinding and pull secret", func() {
		// The waypoint controller renders the same tigera-operator-secrets RoleBinding and the
		// same pull secret copies into the same namespaces, owned by the Istio CR. Dropping
		// those references would have the objects garbage collected along with the last of our
		// Gateways while a waypoint in that namespace still needed them.
		r.newComponentHandler = utils.NewComponentHandler
		istioRef := metav1.OwnerReference{APIVersion: "operator.tigera.io/v1", Kind: "Istio", Name: "default", UID: "istio-uid"}

		By("seeding both objects with an Istio owner reference")
		rb := render.CreateOperatorSecretsRoleBinding("app-ns")
		rb.OwnerReferences = []metav1.OwnerReference{istioRef}
		Expect(c.Create(ctx, rb)).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace:       "app-ns",
			Name:            "tigera-pull-secret",
			OwnerReferences: []metav1.OwnerReference{istioRef},
		}})).NotTo(HaveOccurred())

		pullSecrets := []*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()}}}
		gateways := []gapi.Gateway{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "gw1", UID: "u1"}, Spec: gapi.GatewaySpec{GatewayClassName: gatewayapi.GatewayClassName}},
		}
		Expect(r.reconcileGatewayNamespaceResources(ctx, nil, pullSecrets, true, gateways, map[string]bool{gatewayapi.GatewayClassName: true})).NotTo(HaveOccurred())

		By("keeping the Istio reference and adding our Gateway alongside it")
		ownerKinds := func(o client.Object) []string {
			var k []string
			for _, ref := range o.GetOwnerReferences() {
				k = append(k, ref.Kind+"/"+ref.Name)
			}
			return k
		}
		updatedRB := &rbacv1.RoleBinding{}
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "app-ns", Name: "tigera-operator-secrets"}, updatedRB)).NotTo(HaveOccurred())
		Expect(ownerKinds(updatedRB)).To(ConsistOf("Istio/default", "Gateway/gw1"))

		updatedSecret := &corev1.Secret{}
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "app-ns", Name: "tigera-pull-secret"}, updatedSecret)).NotTo(HaveOccurred())
		Expect(ownerKinds(updatedSecret)).To(ConsistOf("Istio/default", "Gateway/gw1"))

		By("not leaving the multiple-owners label behind on the written objects")
		Expect(updatedRB.Labels).NotTo(HaveKey(common.MultipleOwnersLabel))
	})

	It("retains the reference of a Gateway that has changed to a class we do not own", func() {
		// References are merged, never recomputed, so one stays until the Gateway that owns it is
		// deleted and garbage collection removes it. A Gateway that moved to a class we do not
		// manage therefore keeps its reference and holds the object alive. That is the accepted
		// trade for never dropping a reference some other controller wrote: recomputing our own
		// references on every pass is what dropped the waypoint controller's Istio reference.
		r.newComponentHandler = utils.NewComponentHandler
		flippedRef := metav1.OwnerReference{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Name: "flipped", UID: "u-flipped"}

		rb := render.CreateOperatorSecretsRoleBinding("app-ns")
		rb.OwnerReferences = []metav1.OwnerReference{flippedRef}
		Expect(c.Create(ctx, rb)).NotTo(HaveOccurred())

		gateways := []gapi.Gateway{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "gw1", UID: "u1"}, Spec: gapi.GatewaySpec{GatewayClassName: gatewayapi.GatewayClassName}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "flipped", UID: "u-flipped"}, Spec: gapi.GatewaySpec{GatewayClassName: "not-ours"}},
		}
		Expect(r.reconcileGatewayNamespaceResources(ctx, nil, nil, true, gateways, map[string]bool{gatewayapi.GatewayClassName: true})).NotTo(HaveOccurred())

		updatedRB := &rbacv1.RoleBinding{}
		Expect(c.Get(ctx, client.ObjectKey{Namespace: "app-ns", Name: "tigera-operator-secrets"}, updatedRB)).NotTo(HaveOccurred())
		var owners []string
		for _, ref := range updatedRB.OwnerReferences {
			owners = append(owners, ref.Kind+"/"+ref.Name)
		}
		Expect(owners).To(ConsistOf("Gateway/flipped", "Gateway/gw1"))
	})
})

var fakeComponentHandlers []*fakeComponentHandler

func FakeComponentHandler(log logr.Logger, client client.Client, scheme *runtime.Scheme, cr metav1.Object, opts ...utils.ComponentHandlerOption) utils.ComponentHandler {
	h := &fakeComponentHandler{
		client: client,
		scheme: scheme,
		cr:     cr,
		log:    log,
	}
	fakeComponentHandlers = append(fakeComponentHandlers, h)
	return h
}

type fakeComponentHandler struct {
	client        client.Client
	scheme        *runtime.Scheme
	cr            metav1.Object
	log           logr.Logger
	createOnly    bool
	lastComponent render.Component
}

func (t *fakeComponentHandler) CreateOrUpdateOrDelete(_ context.Context, component render.Component, _ status.StatusManager) error {
	t.lastComponent = component
	return nil
}

func (t *fakeComponentHandler) SetCreateOnly() {
	t.createOnly = true
}
