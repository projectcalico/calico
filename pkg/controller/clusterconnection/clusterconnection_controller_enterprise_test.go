// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package clusterconnection_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/clusterconnection"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/test"
)

// These tests cover the Calico Enterprise behavior of the ManagementClusterConnection
// controller: the enterprise images, the license/tier-gated calico-system network
// policy, and impersonation. The shared (variant-agnostic) controller mechanics live
// in clusterconnection_controller_test.go.
var _ = Describe("ManagementClusterConnection controller enterprise tests", func() {
	var c client.Client
	var ctx context.Context
	var cfg *operatorv1.ManagementClusterConnection
	var installation *operatorv1.Installation
	var r reconcile.Reconciler
	var clientScheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var objTrackerWithCalls test.ObjectTrackerWithCalls

	notReady := &utils.ReadyFlag{}
	ready := &utils.ReadyFlag{}
	ready.MarkAsReady()

	BeforeEach(func() {
		// Create a Kubernetes client.
		clientScheme = runtime.NewScheme()
		Expect(apis.AddToScheme(clientScheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(clientScheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(clientScheme)).ShouldNot(HaveOccurred())
		err := operatorv1.SchemeBuilder.AddToScheme(clientScheme)
		Expect(err).NotTo(HaveOccurred())
		objTrackerWithCalls = test.NewObjectTrackerWithCalls(clientScheme)
		c = ctrlrfake.DefaultFakeClientBuilder(clientScheme).WithObjectTracker(&objTrackerWithCalls).Build()
		ctx = context.Background()
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("Run").Return()
		mockStatus.On("AddDaemonsets", mock.Anything)
		mockStatus.On("AddDeployments", mock.Anything)
		mockStatus.On("AddStatefulSets", mock.Anything)
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("ClearDegraded", mock.Anything)
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("OnCRNotFound").Return()

		Expect(c.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}))

		Expect(c.Create(ctx, &v3.ClusterInformation{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())

		r = clusterconnection.NewReconcilerWithShims(c, clientScheme, mockStatus, operatorv1.ProviderNone, ready, ready)

		Expect(c.Create(ctx, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianNamespace}}))
		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		secret, err := certificateManager.GetOrCreateKeyPair(c, render.GuardianSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		pcSecret, err := certificateManager.GetOrCreateKeyPair(c, render.PacketCaptureServerCert, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		promSecret, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		queryServerSecret, err := certificateManager.GetOrCreateKeyPair(c, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		err = c.Create(ctx, secret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, pcSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, promSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, queryServerSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())

		trustedBundle := certificateManager.CreateTrustedBundle()
		Expect(c.Create(ctx, trustedBundle.ConfigMap(render.GuardianNamespace))).NotTo(HaveOccurred())

		By("applying the required prerequisites")
		// Create a ManagementClusterConnection in the k8s client.
		cfg = &operatorv1.ManagementClusterConnection{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure", Generation: 3},
			Spec: operatorv1.ManagementClusterConnectionSpec{
				ManagementClusterAddr: "127.0.0.1:12345",
			},
		}
		err = c.Create(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())

		installation = &operatorv1.Installation{
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.CalicoEnterprise,
				Registry: "some.registry.org/",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
				Computed: &operatorv1.InstallationSpec{
					Registry:           "my-reg",
					KubernetesProvider: operatorv1.ProviderNone,
				},
			},
		}
		err = c.Create(ctx, installation)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("image reconciliation", func() {
		BeforeEach(func() {
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		})

		It("should use builtin images", func() {
			r = clusterconnection.NewReconcilerWithShims(c, clientScheme, mockStatus, operatorv1.ProviderNone, ready, ready)
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.GuardianDeploymentName,
					Namespace: render.GuardianNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			dexC := test.GetContainer(d.Spec.Template.Spec.Containers, render.GuardianContainerName)
			Expect(dexC).ToNot(BeNil())
			Expect(dexC.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					components.ComponentTigeraCalico.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/calico", Digest: "sha256:guardianhash"},
						{Image: "tigera/calico", Digest: "sha256:deadbeef0123456789"},
					},
				},
			})).ToNot(HaveOccurred())

			r = clusterconnection.NewReconcilerWithShims(c, clientScheme, mockStatus, operatorv1.ProviderNone, ready, ready)
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.GuardianDeploymentName,
					Namespace: render.GuardianNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			apiserver := test.GetContainer(d.Spec.Template.Spec.Containers, render.GuardianContainerName)
			Expect(apiserver).ToNot(BeNil())
			Expect(apiserver.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					"sha256:guardianhash")))
		})
	})

	Context("calico-system reconciliation", func() {
		var licenseKey *v3.LicenseKey
		BeforeEach(func() {
			licenseKey = &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status: v3.LicenseKeyStatus{
					Features: []string{
						common.TiersFeature,
						common.EgressAccessControlFeature,
					},
				},
			}
			Expect(c.Create(ctx, licenseKey)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
			r = clusterconnection.NewReconcilerWithShims(c, clientScheme, mockStatus, operatorv1.ProviderNone, ready, ready)
		})

		Context("IP-based management cluster address", func() {
			It("should render calico-system policy when tier and watch are ready", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())

				Expect(policies.Items).To(HaveLen(1))
				Expect(policies.Items[0].Name).To(Equal("calico-system.guardian-access"))
			})

			It("should omit calico-system policy and not degrade when tier is not ready", func() {
				Expect(c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})

			It("should degrade and wait when tier is ready, but tier watch is not ready", func() {
				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("SetMetaData", mock.Anything).Return()

				r = clusterconnection.NewReconcilerWithShims(c, clientScheme, mockStatus, operatorv1.ProviderNone, notReady, ready)
				test.ExpectWaitForTierWatch(ctx, r, mockStatus)

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})
		})

		Context("Domain-based management cluster address", func() {
			BeforeEach(func() {
				cfg.Spec.ManagementClusterAddr = "mydomain.io:443"
				Expect(c.Update(ctx, cfg)).NotTo(HaveOccurred())
			})

			It("should render calico-system policy when license and tier are ready", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())

				Expect(policies.Items).To(HaveLen(1))
				Expect(policies.Items[0].Name).To(Equal("calico-system.guardian-access"))
			})

			It("should render calico-system policy without domain-based egress when tier is ready, but license is not sufficient", func() {
				licenseKey.Status.Features = []string{common.TiersFeature}
				Expect(c.Update(ctx, licenseKey)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(1))
				Expect(policies.Items[0].Name).To(Equal("calico-system.guardian-access"))

				// Verify no domain-based egress rules are present
				for _, rule := range policies.Items[0].Spec.Egress {
					Expect(rule.Destination.Domains).To(BeEmpty(),
						"Domain-based egress rules should not be present when license lacks EgressAccessControl")
				}
			})

			It("should degrade and wait when tier and license are ready, but tier watch is not ready", func() {
				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("SetMetaData", mock.Anything).Return()

				r = clusterconnection.NewReconcilerWithShims(c, clientScheme, mockStatus, operatorv1.ProviderNone, notReady, ready)
				test.ExpectWaitForTierWatch(ctx, r, mockStatus)

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})

			It("should render calico-system policy without domain-based egress when tier is ready but license is not ready", func() {
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(1))
				Expect(policies.Items[0].Name).To(Equal("calico-system.guardian-access"))

				// Verify no domain-based egress rules are present
				for _, rule := range policies.Items[0].Spec.Egress {
					Expect(rule.Destination.Domains).To(BeEmpty(),
						"Domain-based egress rules should not be present when license is not ready")
				}
			})

			It("should omit calico-system policy when license is ready but tier is not ready", func() {
				Expect(c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})
		})

		Context("Proxy detection", func() {
			// Generate test cases based on the combinations of proxy address forms and proxy settings.
			// Here we specify the base targets along with the base proxy IP, domain, and port that will be used for generation.
			coreCases := generateCoreProxyTestCases("voltron.io:9000", "192.168.1.2:9000", "proxy.io", "10.1.2.3", "8080")

			// In case we support multiple guardian replicas in the future, we test specific multi-pod scenarios.
			multiPodCases := multiplePodCases()

			testCases := append(coreCases, multiPodCases...)
			for _, testCase := range testCases {
				Describe(fmt.Sprintf("Proxy detection when %+v", test.PrettyFormatProxyTestCase(testCase)), func() {
					// Set up the test based on the test case.
					BeforeEach(func() {
						for i, proxy := range testCase.PodProxies {
							createPodWithProxy(ctx, c, proxy, testCase.Lowercase, i)
						}

						// Set the target
						cfg.Spec.ManagementClusterAddr = testCase.Target
						err := c.Update(ctx, cfg)
						Expect(err).NotTo(HaveOccurred())
					})

					It(fmt.Sprintf("detects proxy correctly when %+v", test.PrettyFormatProxyTestCase(testCase)), func() {
						// First reconcile creates the guardian deployment without any availability condition.
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
						err = c.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, &gd)
						Expect(err).NotTo(HaveOccurred())
						err = c.Delete(ctx, &gd)
						Expect(err).NotTo(HaveOccurred())
						gd.ResourceVersion = ""
						gd.Status.Conditions = []appsv1.DeploymentCondition{{
							Type:               appsv1.DeploymentAvailable,
							Status:             v1.ConditionFalse,
							LastTransitionTime: metav1.Time{Time: time.Now()},
						}}
						err = c.Create(ctx, &gd)
						Expect(err).NotTo(HaveOccurred())

						// Reconcile again. We should see no calls since the deployment has not transitioned to available.
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(objTrackerWithCalls.CallCount(podGVR, test.ObjectTrackerCallList)).To(Equal(0))

						// Set the deployment to available.
						err = c.Delete(ctx, &gd)
						Expect(err).NotTo(HaveOccurred())
						gd.ResourceVersion = ""
						gd.Status.Conditions = []appsv1.DeploymentCondition{{
							Type:               appsv1.DeploymentAvailable,
							Status:             v1.ConditionTrue,
							LastTransitionTime: metav1.Time{Time: time.Now().Add(time.Minute)},
						}}
						err = c.Create(ctx, &gd)
						Expect(err).NotTo(HaveOccurred())

						// Reconcile again. The proxy detection logic should kick in since the guardian deployment is ready.
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(objTrackerWithCalls.CallCount(podGVR, test.ObjectTrackerCallList)).To(Equal(1))

						// Resolve the rendered rule that governs egress from guardian to voltron.
						policies := v3.NetworkPolicyList{}
						Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
						Expect(policies.Items).To(HaveLen(1))
						Expect(policies.Items[0].Name).To(Equal("calico-system.guardian-access"))
						policy := policies.Items[0]

						// Generate the expectation based on the test case, and compare the rendered rule to our expectation.
						expectedEgressRules := getExpectedEgressRulesFromCase(testCase)
						Expect(policy.Spec.Egress).To(HaveLen(6 + len(expectedEgressRules)))
						for i, egressRule := range expectedEgressRules {
							managementClusterEgressRule := policy.Spec.Egress[5+i]
							if egressRule.hostIsIP {
								Expect(managementClusterEgressRule.Destination.Nets).To(HaveLen(1))
								Expect(managementClusterEgressRule.Destination.Nets[0]).To(Equal(fmt.Sprintf("%s/32", egressRule.host)))
								Expect(managementClusterEgressRule.Destination.Ports).To(Equal(networkpolicy.Ports(egressRule.port)))
							} else {
								Expect(managementClusterEgressRule.Destination.Domains).To(Equal([]string{egressRule.host}))
								Expect(managementClusterEgressRule.Destination.Ports).To(Equal(networkpolicy.Ports(egressRule.port)))
							}
						}

						// Reconcile again. Verify that we do not cause any additional query for pods now that we have resolved the proxy.
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(objTrackerWithCalls.CallCount(podGVR, test.ObjectTrackerCallList)).To(Equal(1))
					})
				})
			}
		})
	})

	val := []string{"some-value"}
	DescribeTable("should render impersonation permissions correctly", func(impersonation *operatorv1.Impersonation, expectedUser, expectedGroup, expectedSA []string) {
		By("ensuring a tigerastatus exists")
		ts := &operatorv1.TigeraStatus{
			ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
			Spec:       operatorv1.TigeraStatusSpec{},
			Status:     operatorv1.TigeraStatusStatus{},
		}
		Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

		By("updating the CR with the impersonation settings, reconciling and fetching the results")
		err := c.Get(ctx, client.ObjectKey{Name: cfg.Name, Namespace: cfg.Namespace}, cfg)
		Expect(err).ShouldNot(HaveOccurred())
		cfg.Spec.Impersonation = impersonation
		Expect(c.Update(ctx, cfg)).NotTo(HaveOccurred())
		_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "management-cluster-connection",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		role := &rbacv1.ClusterRole{}
		err = c.Get(ctx, client.ObjectKey{Name: render.GuardianClusterRoleName}, role)
		Expect(err).NotTo(HaveOccurred())
		By("verifying the resulting RBAC")
		var users, groups, sas []string
		for _, rule := range role.Rules {
			if len(rule.Verbs) == 1 && rule.Verbs[0] == "impersonate" {
				if len(rule.Resources) == 1 {
					switch rule.Resources[0] {
					case "users":
						users = rule.ResourceNames
					case "groups":
						groups = rule.ResourceNames
					case "serviceaccounts":
						sas = rule.ResourceNames
					}
				}
			}
		}
		Expect(users).To(Equal(expectedUser))
		Expect(groups).To(Equal(expectedGroup))
		Expect(sas).To(Equal(expectedSA))
	},
		Entry("no impersonation configured", nil, nil, nil, nil),
		Entry("all set", &operatorv1.Impersonation{Users: val, Groups: val, ServiceAccounts: val}, val, val, val),
		Entry("all set to empty", &operatorv1.Impersonation{Users: []string{}, Groups: []string{}, ServiceAccounts: []string{}}, nil, nil, nil),
		Entry("user set", &operatorv1.Impersonation{Users: val}, val, nil, nil),
		Entry("groups set", &operatorv1.Impersonation{Groups: val}, nil, val, nil),
		Entry("service accounts set", &operatorv1.Impersonation{ServiceAccounts: val}, nil, nil, val),
		Entry("empty impersonation", &operatorv1.Impersonation{}, nil, nil, nil),
	)
})
