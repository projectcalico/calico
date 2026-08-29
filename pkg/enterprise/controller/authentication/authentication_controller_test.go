// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package authentication

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"golang.org/x/net/http/httpproxy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	eutils "github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/test"
)

var _ = Describe("authentication controller tests", func() {
	var (
		cli                 client.Client
		scheme              *runtime.Scheme
		ctx                 context.Context
		mockStatus          *status.MockStatus
		readyFlag           *utils.ReadyFlag
		idpSecret           *corev1.Secret
		installation        *operatorv1.Installation
		auth                *operatorv1.Authentication
		objTrackerWithCalls test.ObjectTrackerWithCalls
		replicas            int32
	)

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		objTrackerWithCalls = test.NewObjectTrackerWithCalls(scheme)
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjectTracker(&objTrackerWithCalls).Build()

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
		mockStatus.On("ClearWarning", mock.Anything).Return()
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("SetMetaData", mock.Anything).Return()

		// Apply prerequisites for the basic reconcile to succeed.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.CalicoEnterprise,
				Registry:             "some.registry.org/",
			},
		}
		installation.Status.Computed = &installation.Spec
		Expect(cli.Create(ctx, installation)).To(BeNil())
		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
		})).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-dex"}})).ToNot(HaveOccurred())
		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()

		// Establish base specifications for context-sensitive resources to create.
		idpSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.OIDCSecretName,
				Namespace: common.OperatorNamespace(),
			},
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			Data: map[string][]byte{
				"clientID":     []byte("a.b.com"),
				"clientSecret": []byte("my-secret"),
			},
		}
		auth = &operatorv1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://example.com",
			},
		}

		replicas = 2
	})

	Context("Reconcile for Condition status", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:      "https://example.com",
						UsernameClaim:  "email",
						GroupsClaim:    "group",
						GroupsPrefix:   "g",
						UsernamePrefix: "u",
					},
				},
			})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
		})
		generation := int64(2)
		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "authentication"},
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
			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", operatorv1.CalicoEnterprise, readyFlag, false, []*httpproxy.Config{}, metav1.Now()}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "authentication",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := eutils.GetAuthentication(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(1))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
		})
		It("should reconcile with empty tigerastatus conditions ", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "authentication"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}

			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", operatorv1.CalicoEnterprise, readyFlag, false, []*httpproxy.Config{}, metav1.Now()}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "authentication",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := eutils.GetAuthentication(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(0))
		})
		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "authentication"},
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
			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", operatorv1.CalicoEnterprise, readyFlag, false, []*httpproxy.Config{}, metav1.Now()}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "authentication",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := eutils.GetAuthentication(ctx, r.client)
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
				ObjectMeta: metav1.ObjectMeta{Name: "authentication"},
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
			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", operatorv1.CalicoEnterprise, readyFlag, false, []*httpproxy.Config{}, metav1.Now()}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "authentication",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := eutils.GetAuthentication(ctx, r.client)
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

	Context("OIDC connector config options", func() {
		It("should set oidc defaults ", func() {
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
			auth.Spec.OIDC = &operatorv1.AuthenticationOIDC{
				IssuerURL:      "https://example.com",
				UsernameClaim:  "email",
				GroupsClaim:    "group",
				GroupsPrefix:   "g",
				UsernamePrefix: "u",
			}
			// Apply an authentication spec that triggers all the logic in the updateAuthenticationWithDefaults() func.
			Expect(cli.Create(ctx, auth)).ToNot(HaveOccurred())

			// Reconcile
			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", operatorv1.CalicoEnterprise, readyFlag, false, []*httpproxy.Config{}, metav1.Now()}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			authentication, err := eutils.GetAuthentication(ctx, cli)
			Expect(err).NotTo(HaveOccurred())

			// Verify all the expected defaults.
			Expect(*authentication.Spec.OIDC.EmailVerification).To(Equal(operatorv1.EmailVerificationTypeVerify))
			Expect(authentication.Spec.UsernamePrefix).To(Equal("u"))
			Expect(authentication.Spec.GroupsPrefix).To(Equal("g"))
		})
	})

	Context("multi-tenant OIDC connector config options", func() {
		It("should reject non-Tigera OIDC setup", func() {
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
			auth.Spec.OIDC = &operatorv1.AuthenticationOIDC{
				IssuerURL:      "https://example.com",
				UsernameClaim:  "email",
				GroupsClaim:    "group",
				GroupsPrefix:   "g",
				UsernamePrefix: "u",
			}
			// Apply an authentication spec that triggers all the logic in the updateAuthenticationWithDefaults() func.
			Expect(cli.Create(ctx, auth)).ToNot(HaveOccurred())

			// Reconcile
			r := &ReconcileAuthentication{client: cli, scheme: scheme, provider: operatorv1.ProviderNone, status: mockStatus, variant: operatorv1.CalicoEnterprise, tierWatchReady: readyFlag, multiTenant: true}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
		})
	})

	Context("image reconciliation", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:      "https://example.com",
						UsernameClaim:  "email",
						GroupsClaim:    "group",
						GroupsPrefix:   "g",
						UsernamePrefix: "u",
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should use builtin images", func() {
			r := ReconcileAuthentication{
				client:         cli,
				scheme:         scheme,
				provider:       operatorv1.ProviderNone,
				status:         mockStatus,
				variant:        operatorv1.CalicoEnterprise,
				tierWatchReady: readyFlag,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.DexObjectName,
					Namespace: render.DexNamespace,
				},
			}
			Expect(test.GetResource(cli, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			dexC := test.GetContainer(d.Spec.Template.Spec.Containers, render.DexObjectName)
			Expect(dexC).ToNot(BeNil())
			Expect(dexC.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentDex.Image,
					components.ComponentDex.Version)))
		})
		It("should use images from imageset", func() {
			Expect(cli.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/dex", Digest: "sha256:dexhash"},
						{Image: "tigera/calico", Digest: "sha256:deadbeef0123456789"},
					},
				},
			})).ToNot(HaveOccurred())

			r := ReconcileAuthentication{
				client:         cli,
				scheme:         scheme,
				provider:       operatorv1.ProviderNone,
				status:         mockStatus,
				variant:        operatorv1.CalicoEnterprise,
				tierWatchReady: readyFlag,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.DexObjectName,
					Namespace: render.DexNamespace,
				},
			}
			Expect(test.GetResource(cli, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			apiserver := test.GetContainer(d.Spec.Template.Spec.Containers, render.DexObjectName)
			Expect(apiserver).ToNot(BeNil())
			Expect(apiserver.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentDex.Image,
					"sha256:dexhash")))
		})
	})

	Context("calico-system reconciliation", func() {
		var r *ReconcileAuthentication
		BeforeEach(func() {
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:      "https://example.com",
						UsernameClaim:  "email",
						GroupsClaim:    "group",
						GroupsPrefix:   "g",
						UsernamePrefix: "u",
					},
				},
			})).ToNot(HaveOccurred())

			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
			r = &ReconcileAuthentication{
				client:         cli,
				scheme:         scheme,
				provider:       operatorv1.ProviderNone,
				status:         mockStatus,
				variant:        operatorv1.CalicoEnterprise,
				tierWatchReady: readyFlag,
			}
		})

		It("should wait if calico-system tier is unavailable", func() {
			mockStatus.On("SetMetaData", mock.Anything).Return()
			test.DeleteCalicoSystemTierAndExpectWait(ctx, cli, r, mockStatus)
		})

		It("should wait if tier watch is not ready", func() {
			mockStatus.On("SetMetaData", mock.Anything).Return()
			r.tierWatchReady = &utils.ReadyFlag{}
			test.ExpectWaitForTierWatch(ctx, r, mockStatus)
		})

		Context("Proxy detection", func() {
			cases := []test.ProxyTestCase{
				{
					PodProxies: []*test.ProxyConfig{{
						HTTPProxy: "http://proxy.io",
					}},
				},
				{
					PodProxies: []*test.ProxyConfig{{
						HTTPSProxy: "https://proxy.io",
					}},
				},
				{
					PodProxies: []*test.ProxyConfig{{
						HTTPProxy:  "http://proxy.io",
						HTTPSProxy: "https://proxy.io",
					}},
				},
				{
					PodProxies: []*test.ProxyConfig{{
						HTTPProxy:  "http://proxy.io",
						HTTPSProxy: "https://192.168.0.2:9000",
					}},
				},
				{
					PodProxies: []*test.ProxyConfig{{
						HTTPProxy:  "http://192.168.0.1:9000",
						HTTPSProxy: "https://192.168.0.1:9000",
					}},
					Lowercase: true,
				},
				{
					PodProxies: []*test.ProxyConfig{
						{
							HTTPProxy:  "http://proxy.io:9000",
							HTTPSProxy: "https://proxy.io:9000",
						},
						{
							HTTPProxy:  "http://proxy.io:9000",
							HTTPSProxy: "https://proxy.io:9000",
						},
					},
				},
			}

			for _, testCase := range cases {
				Describe(fmt.Sprintf("Proxy detection when %+v", test.PrettyFormatProxyTestCase(testCase)), func() {
					// Set up the test based on the test case.
					BeforeEach(func() {
						mockStatus.On("ReadyToMonitor")
						mockStatus.On("SetMetaData", mock.Anything).Return()
						mockStatus.On("AddDeployments", mock.Anything)
						mockStatus.On("ClearDegraded", mock.Anything)
						mockStatus.On("IsAvailable").Return(true)

						// Create the pod whichs back the deployment and have the appropriate proxy settings.
						// idp-resolution: If we update the controller to resolve the specific IdP and use that for
						// policy calculation, we'll need to set the IdP on the Authentication CR here.
						for i, proxy := range testCase.PodProxies {
							createPodWithProxy(ctx, cli, proxy, testCase.Lowercase, i)
						}
					})

					It(fmt.Sprintf("detects proxy correctly when %+v", test.PrettyFormatProxyTestCase(testCase)), func() {
						// First reconcile creates the dex deployment without any availability condition.
						_, err := r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())

						// Validate that we made no calls to get Pods at this stage.
						podGVR := schema.GroupVersionResource{
							Version:  "v1",
							Resource: "pods",
						}
						Expect(objTrackerWithCalls.CallCount(podGVR, test.ObjectTrackerCallList)).To(BeZero())

						// Set the deployment to be unavailable. We need to recreate the deployment otherwise the status update is ignored.
						gd := appsv1.Deployment{}
						err = cli.Get(ctx, client.ObjectKey{Name: "tigera-dex", Namespace: "tigera-dex"}, &gd)
						Expect(err).NotTo(HaveOccurred())
						err = cli.Delete(ctx, &gd)
						Expect(err).NotTo(HaveOccurred())
						gd.ResourceVersion = ""
						gd.Status.Conditions = []appsv1.DeploymentCondition{{
							Type:               appsv1.DeploymentAvailable,
							Status:             corev1.ConditionFalse,
							LastTransitionTime: metav1.Time{Time: time.Now()},
						}}
						err = cli.Create(ctx, &gd)
						Expect(err).NotTo(HaveOccurred())

						// Reconcile again. We should see no calls since the deployment has not transitioned to available.
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(objTrackerWithCalls.CallCount(podGVR, test.ObjectTrackerCallList)).To(Equal(0))

						// Set the deployment to available.
						err = cli.Delete(ctx, &gd)
						Expect(err).NotTo(HaveOccurred())
						gd.ResourceVersion = ""
						gd.Status.Conditions = []appsv1.DeploymentCondition{{
							Type:               appsv1.DeploymentAvailable,
							Status:             corev1.ConditionTrue,
							LastTransitionTime: metav1.Time{Time: time.Now().Add(time.Minute)},
						}}
						err = cli.Create(ctx, &gd)
						Expect(err).NotTo(HaveOccurred())

						// Reconcile again. The proxy detection logic should kick in since the dex deployment is ready.
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(objTrackerWithCalls.CallCount(podGVR, test.ObjectTrackerCallList)).To(Equal(1))

						// Resolve the calico-system policy for Dex.
						policies := v3.NetworkPolicyList{}
						Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
						Expect(policies.Items).To(HaveLen(2))
						Expect(policies.Items[1].Name).To(Equal("calico-system.dex"))
						policy := policies.Items[1]

						// Generate the expectation based on the test case, and compare the rendered rules to our expectations.
						expectedEgressRules := getExpectedEgressDestinationRulesFromCase(testCase)
						var renderedEgressRules []v3.EntityRule
						for _, egressRule := range policy.Spec.Egress[2:] {
							renderedEgressRules = append(renderedEgressRules, egressRule.Destination)
						}
						Expect(policy.Spec.Egress).To(HaveLen(2 + len(expectedEgressRules)))
						Expect(renderedEgressRules).To(ContainElements(expectedEgressRules))

						// Reconcile again. Verify that we do not cause any additional query for pods now that we have resolved the proxy.
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(objTrackerWithCalls.CallCount(podGVR, test.ObjectTrackerCallList)).To(Equal(1))
					})
				})
			}
		})
	})

	Context("Proxy setting", func() {
		DescribeTable("sets the proxy", func(http, https, noProxy bool) {
			// Setup valid auth configuration.
			auth.Spec.OIDC = &operatorv1.AuthenticationOIDC{
				IssuerURL:      "https://example.com",
				UsernameClaim:  "email",
				GroupsClaim:    "group",
				GroupsPrefix:   "g",
				UsernamePrefix: "u",
			}
			Expect(cli.Create(ctx, auth)).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())

			// Set up the proxy.
			installationCopy := installation.DeepCopy()
			installationCopy.Spec.Proxy = &operatorv1.Proxy{}
			if http {
				installationCopy.Spec.Proxy.HTTPProxy = "test-http-proxy"
			}
			if https {
				installationCopy.Spec.Proxy.HTTPSProxy = "test-https-proxy"
			}
			if noProxy {
				installationCopy.Spec.Proxy.NoProxy = "test-no-proxy"
			}
			err := cli.Update(ctx, installationCopy)
			Expect(err).NotTo(HaveOccurred())
			installationCopy.Status.Computed = installationCopy.Spec.DeepCopy()
			Expect(cli.Status().Update(ctx, installationCopy)).NotTo(HaveOccurred())

			// Reconcile to create the dex deployment.
			r := ReconcileAuthentication{
				client:         cli,
				scheme:         scheme,
				provider:       operatorv1.ProviderNone,
				status:         mockStatus,
				variant:        operatorv1.CalicoEnterprise,
				tierWatchReady: readyFlag,
			}
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Get the deployment and validate the env vars.
			dd := appsv1.Deployment{}
			err = cli.Get(ctx, client.ObjectKey{Name: "tigera-dex", Namespace: "tigera-dex"}, &dd)
			Expect(err).NotTo(HaveOccurred())

			var expectedEnvVars []corev1.EnvVar
			if http {
				expectedEnvVars = append(expectedEnvVars,
					corev1.EnvVar{
						Name:  "HTTP_PROXY",
						Value: "test-http-proxy",
					},
					corev1.EnvVar{
						Name:  "http_proxy",
						Value: "test-http-proxy",
					},
				)
			}

			if https {
				expectedEnvVars = append(expectedEnvVars,
					corev1.EnvVar{
						Name:  "HTTPS_PROXY",
						Value: "test-https-proxy",
					},
					corev1.EnvVar{
						Name:  "https_proxy",
						Value: "test-https-proxy",
					},
				)
			}

			if noProxy {
				expectedEnvVars = append(expectedEnvVars,
					corev1.EnvVar{
						Name:  "NO_PROXY",
						Value: "test-no-proxy",
					},
					corev1.EnvVar{
						Name:  "no_proxy",
						Value: "test-no-proxy",
					},
				)
			}

			Expect(dd.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(dd.Spec.Template.Spec.Containers[0].Env).To(ContainElements(expectedEnvVars))
		},
			Entry("http/https/noProxy", true, true, true),
			Entry("http", true, false, false),
			Entry("https", false, true, false),
			Entry("http/https", true, true, false),
			Entry("http/noProxy", true, false, true),
			Entry("https/noProxy", false, true, true),
		)
	})

	tls, err := secret.CreateTLSSecret(nil, "a", "a", corev1.TLSPrivateKeyKey, corev1.TLSCertKey, time.Hour, nil, "a")
	Expect(err).NotTo(HaveOccurred())
	validCert := tls.Data[corev1.TLSCertKey]
	const (
		validPW       = "dc=example,dc=com"
		validDN       = "dc=example,dc=com"
		invalidDN     = "dc=example,dc=com,pancake"
		validFilter   = "(objectClass=posixGroup)"
		invalidFilter = "(objectClass=posixGroup)pancake"
		attribute     = "uid"
	)
	DescribeTable("LDAP connector config options should be validated", func(ldap *operatorv1.AuthenticationLDAP, secretDN, secretPW, secretCA []byte, expectReconcilePass bool) {
		nameAttrEmpty := ldap.UserSearch.NameAttribute == ""
		auth.Spec.LDAP = ldap
		idpSecret.Name = render.LDAPSecretName
		idpSecret.Data = map[string][]byte{
			render.BindDNSecretField: secretDN,
			render.BindPWSecretField: secretPW,
			render.RootCASecretField: secretCA,
		}
		Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, auth)).ToNot(HaveOccurred())
		r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", operatorv1.CalicoEnterprise, readyFlag, false, []*httpproxy.Config{}, metav1.Now()}
		_, err := r.Reconcile(ctx, reconcile.Request{})
		if expectReconcilePass {
			Expect(err).ToNot(HaveOccurred())
		} else {
			Expect(err).To(HaveOccurred())
		}

		if nameAttrEmpty {
			err = cli.Get(ctx, client.ObjectKey{Name: auth.GetName()}, auth)
			Expect(err).ToNot(HaveOccurred())
			Expect(auth.Spec.LDAP.UserSearch.NameAttribute).To(Equal(defaultNameAttribute))
		}
	},
		Entry("Proper configuration",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}},
			},
			[]byte(validDN), []byte(validPW), []byte(validCert),
			true),
		Entry("Proper configuration w/o name attribute",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}},
			},
			[]byte(validDN), []byte(validPW), []byte(validCert),
			true),
		Entry("Proper configuration w/o groupSearch",
			&operatorv1.AuthenticationLDAP{
				UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
			},
			[]byte(validDN), []byte(validPW), []byte(validCert),
			true),
		Entry("Wrong DN in secret",
			&operatorv1.AuthenticationLDAP{
				UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
			},
			[]byte(invalidDN), []byte(validPW), []byte(validCert),
			false),
		Entry("Missing PW in secret",
			&operatorv1.AuthenticationLDAP{
				UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
			},
			[]byte(validDN), []byte(""), []byte(validCert),
			false),
		Entry("Missing CA field in secret",
			&operatorv1.AuthenticationLDAP{
				UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
			},
			[]byte(validDN), []byte(validPW), []byte(""),
			false),
		Entry("Wrong DN in LDAP spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}},
			},
			[]byte(invalidDN), []byte(validPW), []byte(validCert),
			false),
		Entry("Wrong filter in LDAP userSearch spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: invalidFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}},
			},
			[]byte(validDN), []byte(validPW), []byte(validCert),
			false),
		Entry("Proper spec, filter omitted in userSearch spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}},
			},
			[]byte(validDN), []byte(validPW), []byte(validCert),
			true),
		Entry("Wrong filter in LDAP groupSearch spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: invalidFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}},
			},
			[]byte(validDN), []byte(validPW), []byte(validCert),
			false),
		Entry("Proper spec, filter omitted in groupSearch spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}},
			},
			[]byte(validDN), []byte(validPW), []byte(validCert),
			true),
	)
	var (
		iss  = "https://issuer.com"
		ocp  = &operatorv1.AuthenticationOpenshift{IssuerURL: iss}
		ldap = &operatorv1.AuthenticationLDAP{UserSearch: &operatorv1.UserSearch{BaseDN: validDN}}
		oidc = &operatorv1.AuthenticationOIDC{IssuerURL: iss, UsernameClaim: "email"}
	)
	DescribeTable("should validate the authentication spec", func(auth *operatorv1.Authentication, multiTenant, expectPass bool) {
		if expectPass {
			Expect(validateAuthentication(auth, multiTenant)).NotTo(HaveOccurred())
		} else {
			Expect(validateAuthentication(auth, multiTenant)).To(HaveOccurred())
		}
	},
		Entry("Expect single Openshift config to pass validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{Openshift: ocp}}, false, true),
		Entry("Expect single LDAP config to pass validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{LDAP: ldap}}, false, true),
		Entry("Expect single OIDC config to pass validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: oidc}}, false, true),
		Entry("Expect DEX OIDC to fail validation for multi-tenant", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: oidc}}, true, false),
		Entry("Expect 0 configs to fail validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{}}, false, false),
		Entry("Expect two configs to fail validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: oidc, LDAP: ldap}}, false, false),
		Entry("Expect three configs to fail validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: oidc, LDAP: ldap, Openshift: ocp}}, false, false),
		Entry("Expect prompt type to be used without other values", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: copyAndAddPromptTypes(oidc, []operatorv1.PromptType{operatorv1.PromptTypeNone})}}, false, true),
		Entry("Expect prompt type to fail when none is combined", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: copyAndAddPromptTypes(oidc, []operatorv1.PromptType{operatorv1.PromptTypeNone, operatorv1.PromptTypeLogin})}}, false, false),
		Entry("Expect prompt type to be able to be combined", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: copyAndAddPromptTypes(oidc, []operatorv1.PromptType{operatorv1.PromptTypeSelectAccount, operatorv1.PromptTypeLogin})}}, false, true),
	)
})

func copyAndAddPromptTypes(auth *operatorv1.AuthenticationOIDC, promptTypes []operatorv1.PromptType) *operatorv1.AuthenticationOIDC {
	copy := auth.DeepCopy()
	copy.PromptTypes = promptTypes
	return copy
}

func createPodWithProxy(ctx context.Context, c client.Client, config *test.ProxyConfig, lowercase bool, replicaNum int) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-dex" + strconv.Itoa(replicaNum),
			Namespace: "tigera-dex",
			Labels: map[string]string{
				"k8s-app":                "tigera-dex",
				"app.kubernetes.io/name": "tigera-dex",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "tigera-dex",
				Env:  []corev1.EnvVar{},
			}},
		},
	}

	if config != nil {
		// Set the env vars.
		httpsProxyVarName := "HTTPS_PROXY"
		httpProxyVarName := "HTTP_PROXY"
		noProxyVarName := "NO_PROXY"
		if lowercase {
			httpsProxyVarName = strings.ToLower(httpsProxyVarName)
			httpProxyVarName = strings.ToLower(httpProxyVarName)
			noProxyVarName = strings.ToLower(noProxyVarName)
		}
		// Environment variables that are empty can be represented as an unset variable or a set variable with an empty string.
		// For our tests, we'll represent them as an unset variable.
		if config.HTTPProxy != "" {
			pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  httpProxyVarName,
				Value: config.HTTPProxy,
			})
		}
		if config.HTTPSProxy != "" {
			pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  httpsProxyVarName,
				Value: config.HTTPSProxy,
			})
		}
		if config.NoProxy != "" {
			pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  noProxyVarName,
				Value: config.NoProxy,
			})
		}
	}

	err := c.Create(ctx, &pod)
	Expect(err).NotTo(HaveOccurred())
}

// getExpectedEgressDestinationRulesFromCase returns the expected rules based on the current test case. It assumes that
// no IdP resolution is occurring, and all potential destinations are allowed.
// idp-resolution: If the controller is updated to resolve the specific IdP destination, this function should be
// updated to return a single egress rule based on the IdP destination and the proxy/no-proxy settings.
func getExpectedEgressDestinationRulesFromCase(c test.ProxyTestCase) []v3.EntityRule {
	var egressRules []v3.EntityRule
	observedDestinations := map[string]bool{}

	// Generate expected proxy rules.
	for _, proxy := range c.PodProxies {
		var proxyURLs []string

		if proxy.HTTPProxy != "" {
			proxyURLs = append(proxyURLs, proxy.HTTPProxy)
		}

		if proxy.HTTPSProxy != "" {
			proxyURLs = append(proxyURLs, proxy.HTTPSProxy)
		}

		for _, proxyURLString := range proxyURLs {
			proxyURL, err := url.ParseRequestURI(proxyURLString)
			Expect(err).NotTo(HaveOccurred())

			// Resolve host and port
			var host string
			var port uint16
			hostSplit := strings.Split(proxyURL.Host, ":")
			switch {
			case len(hostSplit) == 2:
				port64, err := strconv.ParseUint(hostSplit[1], 10, 16)
				Expect(err).NotTo(HaveOccurred())
				host = hostSplit[0]
				port = uint16(port64)
			case proxyURL.Scheme == "https":
				host = proxyURL.Host
				port = 443
			default:
				host = proxyURL.Host
				port = 80
			}
			hostIsIP := net.ParseIP(host) != nil

			hostPortString := fmt.Sprintf("%v:%v", host, port)
			if observedDestinations[hostPortString] {
				continue
			}

			if hostIsIP {
				egressRules = append(egressRules, v3.EntityRule{
					Nets:  []string{fmt.Sprintf("%s/32", host)},
					Ports: networkpolicy.Ports(port),
				})
			} else {
				egressRules = append(egressRules, v3.EntityRule{
					Domains: []string{host},
					Ports:   networkpolicy.Ports(port),
				})
			}

			observedDestinations[hostPortString] = true
		}
	}

	// Add expected target rules.
	egressRules = append(egressRules, v3.EntityRule{
		Nets:  []string{"0.0.0.0/0"},
		Ports: networkpolicy.Ports(443, 6443, 389, 636),
	})
	egressRules = append(egressRules, v3.EntityRule{
		Nets:  []string{"::/0"},
		Ports: networkpolicy.Ports(443, 6443, 389, 636),
	})
	return egressRules
}
