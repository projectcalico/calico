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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/extensions/extensionstest"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
)

// The guardian policy fixtures live next to the render package's testutils, so
// reference them relative to this enterprise subpackage.
const (
	clusterDomain         = "cluster.local"
	guardianPolicyJSON    = "../../render/testutils/expected_policies/guardian.json"
	guardianPolicyOCPJSON = "../../render/testutils/expected_policies/guardian_ocp.json"
)

// guardianObjects renders the guardian component and runs the enterprise extension
// over it, the way the clusterconnection controller does.
func guardianObjects(cfg *render.GuardianConfiguration) []client.Object {
	g := render.Guardian(cfg)
	ExpectWithOffset(1, g.ResolveImages(nil)).To(BeNil())
	objs, _ := g.Objects()
	ri := render.Inputs{Installation: cfg.Installation}
	out, _ := ext.ClusterConnection().Modify(extensionstest.GuardianStub{StubComponent: extensionstest.StubComponent{Create: objs, Delete: nil}, Cfg: cfg}, ri).Objects()
	return out
}

var _ = Describe("Guardian enterprise rendering tests", func() {
	var cfg *render.GuardianConfiguration
	var g render.Component
	var resources []client.Object
	var deleteResources []client.Object

	createGuardianConfig := func(i operatorv1.InstallationSpec, addr string, openshift bool) *render.GuardianConfiguration {
		i.Variant = operatorv1.CalicoEnterprise
		secret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.GuardianSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"cert": []byte("foo"),
				"key":  []byte("bar"),
			},
		}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		bundle := certificateManager.CreateTrustedBundle()

		return &render.GuardianConfiguration{
			URL: addr,
			PullSecrets: []*corev1.Secret{{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pull-secret",
					Namespace: common.OperatorNamespace(),
				},
			}},
			Installation:                &i,
			TunnelSecret:                secret,
			TrustedCertBundle:           bundle,
			OpenShift:                   openshift,
			ManagementClusterConnection: &operatorv1.ManagementClusterConnection{},
			IncludeEgressNetworkPolicy:  true,
		}
	}

	Context("Guardian component", func() {
		renderGuardian := func(i operatorv1.InstallationSpec) {
			cfg = createGuardianConfig(i, "127.0.0.1:1234", false)
			g = render.Guardian(cfg)
			Expect(g.ResolveImages(nil)).To(BeNil())
			resources, deleteResources = g.Objects()
			// Run the extension the way the clusterconnection controller does, so these
			// tests exercise the integrated output.
			ri := render.Inputs{Installation: cfg.Installation}
			resources, _ = ext.ClusterConnection().Modify(extensionstest.GuardianStub{StubComponent: extensionstest.StubComponent{Create: resources, Delete: nil}, Cfg: cfg}, ri).Objects()
		}

		BeforeEach(func() {
			renderGuardian(operatorv1.InstallationSpec{Registry: "my-reg/"})
		})

		It("should layer the enterprise CA bundle env onto the guardian container", func() {
			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			c, ok := render.Container(&deployment.Spec.Template.Spec, render.GuardianContainerName)
			Expect(ok).To(BeTrue())
			Expect(c.Env).To(ContainElement(HaveField("Name", "GUARDIAN_PACKET_CAPTURE_CA_BUNDLE_PATH")))
			Expect(c.Env).To(ContainElement(HaveField("Name", "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH")))
			Expect(c.Env).To(ContainElement(HaveField("Name", "GUARDIAN_QUERYSERVER_CA_BUNDLE_PATH")))
		})

		It("should render all resources for a managed cluster", func() {
			expectedResources := []client.Object{
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianServiceAccountName, Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianClusterRoleName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianClusterRoleBindingName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianSecretsRole, Namespace: "tigera-operator"}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianSecretsRoleBindingName, Namespace: "tigera-operator"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianServiceName, Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: ""}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianSecretName, Namespace: render.GuardianNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
				&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			}

			expectedDeleteResources := []client.Object{
				&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"}},
				&rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"}},
				&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-role"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-binding"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "guardian", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"}},
			}

			rtest.ExpectResources(resources, expectedResources)
			rtest.ExpectResources(deleteResources, expectedDeleteResources)

			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(deployment.Spec.Template.Spec.Containers[0].Image).Should(Equal("my-reg/tigera/calico:" + components.ComponentTigeraCalico.Version))

			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(deployment.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))
			Expect(deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
		})

		It("should render controlPlaneTolerations", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}
			renderGuardian(operatorv1.InstallationSpec{
				ControlPlaneTolerations: []corev1.Toleration{t},
			})
			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment.Spec.Template.Spec.Tolerations).Should(ContainElements(append(rmeta.TolerateCriticalAddonsAndControlPlane, t)))
		})

		It("should render toleration on GKE", func() {
			renderGuardian(operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
			})
			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment).NotTo(BeNil())
			Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
				Key:      "kubernetes.io/arch",
				Operator: corev1.TolerationOpEqual,
				Value:    "arm64",
				Effect:   corev1.TaintEffectNoSchedule,
			}))
		})

		It("should render guardian with unlimited impersonation", func() {
			cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{
				Spec: operatorv1.ManagementClusterConnectionSpec{
					Impersonation: &operatorv1.Impersonation{
						Users:           []string{},
						Groups:          []string{},
						ServiceAccounts: []string{},
					},
				},
			}

			resources := guardianObjects(cfg)
			Expect(resources).ToNot(BeNil())

			clusterRole, ok := rtest.GetResource(resources, render.GuardianClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(ok).To(BeTrue())

			foundUserImp, foundGroupImp, foundSaImp := false, false, false
			for _, rule := range clusterRole.Rules {
				if rule.Verbs[0] == "impersonate" {
					if rule.Resources[0] == "users" {
						Expect(rule.ResourceNames).To(Equal([]string{}))
						foundUserImp = true
					}
					if rule.Resources[0] == "groups" {
						Expect(rule.ResourceNames).To(Equal([]string{}))
						foundGroupImp = true
					}
					if rule.Resources[0] == "serviceaccounts" {
						Expect(rule.ResourceNames).To(Equal([]string{}))
						foundSaImp = true
					}
				}
			}

			Expect(foundUserImp).To(BeTrue())
			Expect(foundGroupImp).To(BeTrue())
			Expect(foundSaImp).To(BeTrue())
		})

		It("should render guardian with specific impersonation", func() {
			cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{
				Spec: operatorv1.ManagementClusterConnectionSpec{
					Impersonation: &operatorv1.Impersonation{
						Users:           []string{"foo"},
						Groups:          []string{"bar"},
						ServiceAccounts: []string{"zaz"},
					},
				},
			}

			resources := guardianObjects(cfg)
			Expect(resources).ToNot(BeNil())

			clusterRole, ok := rtest.GetResource(resources, render.GuardianClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(ok).To(BeTrue())

			foundUserImp, foundGroupImp, foundSaImp := false, false, false
			for _, rule := range clusterRole.Rules {
				if rule.Verbs[0] == "impersonate" {
					if rule.Resources[0] == "users" {
						Expect(rule.ResourceNames).To(Equal([]string{"foo"}))
						foundUserImp = true
					}
					if rule.Resources[0] == "groups" {
						Expect(rule.ResourceNames).To(Equal([]string{"bar"}))
						foundGroupImp = true
					}
					if rule.Resources[0] == "serviceaccounts" {
						Expect(rule.ResourceNames).To(Equal([]string{"zaz"}))
						foundSaImp = true
					}
				}
			}

			Expect(foundUserImp).To(BeTrue())
			Expect(foundGroupImp).To(BeTrue())
			Expect(foundSaImp).To(BeTrue())
		})

		It("should render guardian with specific no sa permissions but with user and group", func() {
			cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{
				Spec: operatorv1.ManagementClusterConnectionSpec{
					Impersonation: &operatorv1.Impersonation{
						Users:  []string{},
						Groups: []string{},
					},
				},
			}

			resources := guardianObjects(cfg)
			Expect(resources).ToNot(BeNil())

			clusterRole, ok := rtest.GetResource(resources, render.GuardianClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(ok).To(BeTrue())

			foundUserImp, foundGroupImp, foundSaImp := false, false, false
			for _, rule := range clusterRole.Rules {
				if rule.Verbs[0] == "impersonate" {
					if rule.Resources[0] == "users" {
						foundUserImp = true
					}
					if rule.Resources[0] == "groups" {
						foundGroupImp = true
					}
					if rule.Resources[0] == "serviceaccounts" {
						foundSaImp = true
					}
				}
			}

			Expect(foundUserImp).To(BeTrue())
			Expect(foundGroupImp).To(BeTrue())
			Expect(foundSaImp).To(BeFalse())
		})
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg = createGuardianConfig(operatorv1.InstallationSpec{Registry: "my-reg/"}, "127.0.0.1:1234", false)
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.OpenShift = true
		resources := guardianObjects(cfg)

		role := rtest.GetResource(resources, render.GuardianClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	Context("GuardianPolicy component", func() {
		guardianPolicy := testutils.GetExpectedPolicyFromFile(guardianPolicyJSON)
		guardianPolicyForOCP := testutils.GetExpectedPolicyFromFile(guardianPolicyOCPJSON)

		renderGuardianPolicy := func(addr string, openshift bool, variant operatorv1.ProductVariant, includeEgressNetworkPolicy bool) {
			installation := operatorv1.InstallationSpec{
				Registry: "my-reg/",
			}
			cfg := createGuardianConfig(installation, addr, openshift)
			cfg.Installation.Variant = variant
			cfg.IncludeEgressNetworkPolicy = includeEgressNetworkPolicy
			g, err := render.GuardianPolicy(cfg)
			Expect(err).NotTo(HaveOccurred())
			objs, _ := g.Objects()
			// Run the extension the way the clusterconnection controller does, so the
			// enterprise policy is exercised.
			ri := render.Inputs{Installation: cfg.Installation}
			resources, _ = ext.ClusterConnection().Modify(extensionstest.GuardianPolicyStub{StubComponent: extensionstest.StubComponent{Create: objs, Delete: nil}, Cfg: cfg}, ri).Objects()
		}

		Context("policy rendering based on variant and IncludeEgressNetworkPolicy", func() {
			It("should render Enterprise network policy without domain-based egress when IncludeEgressNetworkPolicy is false", func() {
				// Enterprise variant with IncludeEgressNetworkPolicy=false should render a policy but skip domain-based egress rules
				renderGuardianPolicy("my-management.example.com:1234", false, operatorv1.CalicoEnterprise, false)

				policyName := types.NamespacedName{Name: "calico-system.guardian-access", Namespace: "calico-system"}
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				Expect(policy).NotTo(BeNil(), "Enterprise variant should always render a network policy when tier exists")

				// Verify it's the Enterprise policy (should have both Ingress and Egress types)
				Expect(policy.Spec.Types).To(ConsistOf(v3.PolicyTypeIngress, v3.PolicyTypeEgress))
				Expect(policy.Spec.Egress).NotTo(BeEmpty())

				// Verify no domain-based egress rules are present
				for _, rule := range policy.Spec.Egress {
					Expect(rule.Destination.Domains).To(BeEmpty(),
						"Domain-based egress rules should not be present when IncludeEgressNetworkPolicy is false")
				}
			})

			It("should render Enterprise network policy with domain-based egress when IncludeEgressNetworkPolicy is true", func() {
				// Enterprise variant with IncludeEgressNetworkPolicy=true should render the full policy including domain-based egress
				renderGuardianPolicy("my-management.example.com:1234", false, operatorv1.CalicoEnterprise, true)

				policyName := types.NamespacedName{Name: "calico-system.guardian-access", Namespace: "calico-system"}
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				Expect(policy).NotTo(BeNil(), "Enterprise variant with IncludeEgressNetworkPolicy=true should render a network policy")

				// Verify it's the Enterprise policy (should have both Ingress and Egress types)
				Expect(policy.Spec.Types).To(ConsistOf(v3.PolicyTypeIngress, v3.PolicyTypeEgress))
				Expect(policy.Spec.Egress).NotTo(BeEmpty())

				// Verify domain-based egress rule is present
				hasDomainRule := false
				for _, rule := range policy.Spec.Egress {
					if len(rule.Destination.Domains) > 0 {
						hasDomainRule = true
						break
					}
				}
				Expect(hasDomainRule).To(BeTrue(), "Domain-based egress rule should be present when IncludeEgressNetworkPolicy is true")
			})
		})

		Context("calico-system rendering", func() {
			policyName := types.NamespacedName{Name: "calico-system.guardian-access", Namespace: "calico-system"}

			getExpectedPolicy := func(name types.NamespacedName, scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
				if name.Name == "calico-system.guardian-access" && scenario.ManagedCluster {
					return testutils.SelectPolicyByProvider(scenario, guardianPolicy, guardianPolicyForOCP)
				}

				return nil
			}

			DescribeTable("should render calico-system policy",
				func(scenario testutils.CalicoSystemScenario) {
					renderGuardianPolicy("127.0.0.1:1234", scenario.OpenShift, operatorv1.CalicoEnterprise, true)
					policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
				Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
			)

			// The test matrix above validates against an IP-based management cluster address.
			// Validate policy adaptation for domain-based management cluster address here.
			It("should adapt Guardian policy if ManagementClusterAddr is domain-based", func() {
				renderGuardianPolicy("mydomain.io:8080", false, operatorv1.CalicoEnterprise, true)
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				managementClusterEgressRule := policy.Spec.Egress[5]
				Expect(managementClusterEgressRule.Destination.Domains).To(Equal([]string{"mydomain.io"}))
				Expect(managementClusterEgressRule.Destination.Ports).To(Equal(networkpolicy.Ports(8080)))
			})
		})
	})
})
