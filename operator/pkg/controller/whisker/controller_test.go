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

package whisker

import (
	"context"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	rgateway "github.com/projectcalico/calico/operator/pkg/render/gateway"
	"github.com/projectcalico/calico/operator/pkg/render/whisker"
	"github.com/projectcalico/calico/operator/pkg/tls"
)

var _ = Describe("whisker controller tests", func() {
	var (
		cli                   client.Client
		scheme                *runtime.Scheme
		ctx                   context.Context
		mockStatus            *status.MockStatus
		installation          *operatorv1.Installation
		certificateManagement *operatorv1.CertificateManagement
	)

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admregv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(networkingv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		// Gateway and HTTPRoute status is written by the Envoy Gateway
		// controller, not by the operator's spec updates — model that as a
		// status subresource so reconcile updates don't wipe it.
		gwMapper := apimeta.NewDefaultRESTMapper(nil)
		gwMapper.Add(schema.GroupVersionKind{Group: gapi.GroupName, Version: "v1", Kind: "Gateway"}, apimeta.RESTScopeNamespace)
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).
			WithStatusSubresource(&gapi.Gateway{}, &gapi.HTTPRoute{}).
			WithRESTMapper(gwMapper).
			Build()

		// Create a CertificateManagement instance for tests that need it.
		ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		Expect(err).NotTo(HaveOccurred())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		certificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		replicas := int32(2)
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Generation: 2,
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.Calico,
				Registry:             "some.registry.org/",
			},
		}
		installation.Status.Computed = installation.Spec.DeepCopy()
		installation.Spec.Variant = ""

		// Apply prerequisites for the basic reconcile to succeed.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).ToNot(HaveOccurred())

		Expect(cli.Create(ctx, &operatorv1.Goldmane{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).ToNot(HaveOccurred())

		Expect(cli.Create(ctx, &operatorv1.Whisker{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).ToNot(HaveOccurred())

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("AddCertificateSigningRequests", mock.Anything)
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("SetDegraded", operatorv1.ResourceReadError, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	})

	Context("verify reconciliation", func() {
		It("should use builtin images", func() {
			installation.Status.Computed.CertificateManagement = certificateManagement
			Expect(cli.Create(ctx, installation)).To(BeNil())
			reconciler := Reconciler{
				cli:      cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
				ext:      extensions.Extensions{}.Whisker(),
			}
			_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: "calico-system"}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Get(ctx, types.NamespacedName{Name: installation.Name}, installation)).ShouldNot(HaveOccurred())
			_ = installation
		})

		It("should create the whisker TLS key pairs", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())
			reconciler := Reconciler{
				cli:      cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
				ext:      extensions.Extensions{}.Whisker(),
			}
			_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: "calico-system"}})
			Expect(err).ShouldNot(HaveOccurred())

			for _, name := range []string{whisker.WhiskerKeyPairSecret, whisker.WhiskerBackendKeyPairSecret} {
				secret := &corev1.Secret{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: name, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
				Expect(secret.Data).To(HaveKey("tls.crt"))
				Expect(secret.Data).To(HaveKey("tls.key"))
			}
		})
	})

	Context("gateway reconciliation", func() {
		const gatewayName = whisker.GatewayResourcePrefix + "-gateway"

		var reconciler Reconciler

		doReconcile := func() (reconcile.Result, error) {
			return reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: "calico-system"}})
		}

		setIngressGateway := func(gatewayNS *string) {
			w := &operatorv1.Whisker{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, w)).NotTo(HaveOccurred())
			w.Spec.IngressGateway = &operatorv1.IngressGatewaySpec{
				Hostname:         "whisker.test.local",
				GatewayNamespace: gatewayNS,
			}
			Expect(cli.Update(ctx, w)).NotTo(HaveOccurred())
		}

		createGatewayAPI := func() {
			Expect(cli.Create(ctx, &operatorv1.GatewayAPI{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				},
			})).NotTo(HaveOccurred())
		}

		BeforeEach(func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())
			reconciler = Reconciler{
				cli:      cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
				ext:      extensions.Extensions{}.Whisker(),
			}
		})

		It("degrades when spec.ingressGateway is set but the GatewayAPI CR is missing", func() {
			var degradedErr string
			mockStatus.On("SetDegraded", operatorv1.ResourceCreateError, mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { degradedErr = args.String(2) }).Return()
			setIngressGateway(nil)

			_, err := doReconcile()
			Expect(err).To(HaveOccurred())
			Expect(degradedErr).To(ContainSubstring("GatewayAPI CR not found"))

			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: whisker.WhiskerNamespace}, gw)).To(HaveOccurred())
		})

		It("renders the gateway resources when spec.ingressGateway is set", func() {
			createGatewayAPI()
			setIngressGateway(nil)

			_, err := doReconcile()
			Expect(err).NotTo(HaveOccurred())

			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: whisker.WhiskerNamespace}, gw)).NotTo(HaveOccurred())
			Expect(gw.Labels).To(HaveKeyWithValue(rgateway.GatewayLabel, whisker.GatewayResourcePrefix))
			Expect(string(gw.Spec.GatewayClassName)).To(Equal("tigera-gateway-class"))

			route := &gapi.HTTPRoute{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: whisker.GatewayResourcePrefix + "-route", Namespace: whisker.WhiskerNamespace}, route)).NotTo(HaveOccurred())
			Expect(route.Spec.Rules).To(HaveLen(1))
			Expect(route.Spec.Rules[0].Timeouts).NotTo(BeNil(), "SSE flow-log streams need the request timeout disabled")
			Expect(*route.Spec.Rules[0].Timeouts.Request).To(Equal(gapi.Duration("0s")))

			backend := &envoyapi.Backend{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: whisker.GatewayResourcePrefix + "-backend", Namespace: whisker.WhiskerNamespace}, backend)).NotTo(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: whisker.GatewayTLSSecretName, Namespace: whisker.WhiskerNamespace}, secret)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, types.NamespacedName{Name: whisker.GatewayTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).NotTo(HaveOccurred(),
				"the truth-namespace copy must persist so the certificate is not re-minted every reconcile")
		})

		It("creates a user-chosen gateway namespace and renders the Gateway there", func() {
			createGatewayAPI()
			setIngressGateway(ptr.To("ns-a"))

			_, err := doReconcile()
			Expect(err).NotTo(HaveOccurred())

			ns := &corev1.Namespace{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "ns-a"}, ns)).NotTo(HaveOccurred())

			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: "ns-a"}, gw)).NotTo(HaveOccurred())
		})

		It("degrades and requeues while the Gateway is unhealthy", func() {
			createGatewayAPI()
			setIngressGateway(nil)

			gw := &gapi.Gateway{ObjectMeta: metav1.ObjectMeta{
				Name:      gatewayName,
				Namespace: whisker.WhiskerNamespace,
				Labels:    map[string]string{rgateway.GatewayLabel: whisker.GatewayResourcePrefix},
			}}
			Expect(cli.Create(ctx, gw)).NotTo(HaveOccurred())
			gw.Status.Conditions = []metav1.Condition{{
				Type:               string(gapi.GatewayConditionProgrammed),
				Status:             metav1.ConditionFalse,
				Reason:             "AddressNotAssigned",
				Message:            "no addresses assigned",
				LastTransitionTime: metav1.Now(),
			}}
			Expect(cli.Status().Update(ctx, gw)).NotTo(HaveOccurred())

			result, err := doReconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(utils.StandardRetry))
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceNotReady, mock.Anything, mock.Anything, mock.Anything)
		})

		It("degrades and renders no gateway when certificateManagement is enabled", func() {
			// Under certificateManagement the operator cannot mint the listener
			// key pair, and the placeholder it gets back carries no private key.
			// Rendering it would give Envoy a certificate it cannot serve, so the
			// reconcile must stop and report the combination as unsupported.
			var degradedErr string
			mockStatus.On("SetDegraded", operatorv1.ResourceCreateError, mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { degradedErr = args.String(2) }).Return()
			Expect(cli.Get(ctx, types.NamespacedName{Name: installation.Name}, installation)).NotTo(HaveOccurred())
			installation.Status.Computed.CertificateManagement = certificateManagement
			Expect(cli.Status().Update(ctx, installation)).NotTo(HaveOccurred())

			createGatewayAPI()
			setIngressGateway(nil)

			_, err := doReconcile()
			Expect(err).To(HaveOccurred())

			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: whisker.WhiskerNamespace}, gw)).To(HaveOccurred(),
				"no gateway should be rendered without a usable listener certificate")

			secret := &corev1.Secret{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: whisker.GatewayTLSSecretName, Namespace: whisker.WhiskerNamespace}, secret)).To(HaveOccurred(),
				"a keyless TLS secret must not be written")

			Expect(degradedErr).To(ContainSubstring("spec.ingressGateway is not supported"))
			Expect(degradedErr).To(ContainSubstring("certificateManagement"))
		})

		It("renders no gateway and tears down leftovers when the extension unsets spec.ingressGateway", func() {
			reconciler.ext = trimIngressGateway{reconciler.ext}
			createGatewayAPI()
			setIngressGateway(nil)

			stray := &gapi.Gateway{ObjectMeta: metav1.ObjectMeta{
				Name:      gatewayName,
				Namespace: "ns-b",
				Labels:    map[string]string{rgateway.GatewayLabel: whisker.GatewayResourcePrefix},
			}}
			Expect(cli.Create(ctx, stray)).NotTo(HaveOccurred())

			result, err := doReconcile()
			Expect(err).NotTo(HaveOccurred())

			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: whisker.WhiskerNamespace}, gw)).To(HaveOccurred(),
				"a variant that does not serve the gateway must not render one")
			Expect(cli.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: "ns-b"}, gw)).To(HaveOccurred(),
				"gateway resources left from an earlier install should be torn down")

			// The health read-back must be gated the same way as the render. If it
			// is not, the reconcile degrades over a gateway it just tore down and
			// requeues forever, never reaching ReadyToMonitor.
			Expect(result.RequeueAfter).To(BeZero(), "no requeue: there is no gateway to wait for")
			mockStatus.AssertNotCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceNotReady,
				mock.Anything, mock.Anything, mock.Anything)

			w := &operatorv1.Whisker{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, w)).NotTo(HaveOccurred())
			Expect(w.Spec.IngressGateway).NotTo(BeNil(), "the field the variant ignores must survive on the CR the user wrote")
		})

		It("tears down labeled gateway resources when spec.ingressGateway is nil", func() {
			stray := &gapi.Gateway{ObjectMeta: metav1.ObjectMeta{
				Name:      gatewayName,
				Namespace: "ns-b",
				Labels:    map[string]string{rgateway.GatewayLabel: whisker.GatewayResourcePrefix},
			}}
			Expect(cli.Create(ctx, stray)).NotTo(HaveOccurred())

			_, err := doReconcile()
			Expect(err).NotTo(HaveOccurred())

			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: "ns-b"}, gw)).To(HaveOccurred(),
				"the stray labeled Gateway should be torn down")
		})

		It("deletes a gateway namespace it created once the Whisker CR is gone", func() {
			// The gateway objects are garbage-collected with the CR, but a
			// namespace the operator created for them is not, so the CR-not-found
			// path must delete it or it leaks.
			mockStatus.On("OnCRNotFound").Return()

			w := &operatorv1.Whisker{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, w)).NotTo(HaveOccurred())
			Expect(cli.Delete(ctx, w)).NotTo(HaveOccurred())

			Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "ns-gw",
				Labels: map[string]string{rgateway.GatewayNamespaceLabel: "true"},
			}})).NotTo(HaveOccurred())
			stray := &gapi.Gateway{ObjectMeta: metav1.ObjectMeta{
				Name:      gatewayName,
				Namespace: "ns-gw",
				Labels:    map[string]string{rgateway.GatewayLabel: whisker.GatewayResourcePrefix},
			}}
			Expect(cli.Create(ctx, stray)).NotTo(HaveOccurred())

			_, err := doReconcile()
			Expect(err).NotTo(HaveOccurred())

			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: "ns-gw"}, gw)).To(HaveOccurred(),
				"gateway resources must be torn down once the CR is gone")
			ns := &corev1.Namespace{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "ns-gw"}, ns)).To(HaveOccurred(),
				"the operator-created gateway namespace must be deleted, not leaked")
		})
	})
})

// trimIngressGateway stands in for a variant that does not serve whisker's own
// gateway. The Enterprise version of this lives in pkg/enterprise/whisker.
type trimIngressGateway struct {
	extensions.WhiskerExtension
}

func (trimIngressGateway) ValidateAndDefault(cr *operatorv1.Whisker, _ status.StatusManager) error {
	cr.Spec.IngressGateway = nil
	return nil
}
