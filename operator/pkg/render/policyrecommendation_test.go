// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package render_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Policy recommendation rendering tests", func() {
	var (
		cfg     *render.PolicyRecommendationConfiguration
		bundle  certificatemanagement.TrustedBundle
		keyPair certificatemanagement.KeyPairInterface
		cli     client.Client
	)

	// Fetch expectations from utilities that require Ginkgo context.
	expectedUnmanagedPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/policyrecommendation.json")
	expectedUnmanagedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/policyrecommendation_ocp.json")

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())

		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		bundle = certificateManager.CreateTrustedBundle()
		secretTLS, err := certificatemanagement.CreateSelfSignedSecret(render.PolicyRecommendationTLSSecretName, "", "", nil)
		Expect(err).NotTo(HaveOccurred())

		keyPair = certificatemanagement.NewKeyPair(secretTLS, []string{""}, "")

		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		cfg = &render.PolicyRecommendationConfiguration{
			ClusterDomain:                  dns.DefaultClusterDomain,
			TrustedBundle:                  bundle,
			Installation:                   &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			ManagedCluster:                 notManagedCluster,
			PolicyRecommendationCertSecret: keyPair,
			Namespace:                      render.PolicyRecommendationNamespace,
			BindingNamespaces:              []string{render.PolicyRecommendationNamespace},
		}
	})

	It("should render all resources for a default configuration", func() {
		cfg.OpenShift = false
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()

		expectedCreateResources := []client.Object{
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation", Namespace: render.PolicyRecommendationNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.PolicyRecommendationManagedClustersWatchRoleBindingName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.tigera-policy-recommendation", Namespace: render.PolicyRecommendationNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation", Namespace: render.PolicyRecommendationNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
		}

		rtest.ExpectResources(resources, expectedCreateResources)

		// Should mount ManagerTLSSecret for non-managed clusters
		prc := rtest.GetResource(resources, render.PolicyRecommendationName, render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(prc.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(prc.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			corev1.EnvVar{Name: "LINSEED_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: "/policy-recommendation-tls/tls.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: "/policy-recommendation-tls/tls.key"},
			corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: fmt.Sprintf("https://%s.%s.svc:%d", render.ManagerServiceName, render.ManagerNamespace, render.ManagerPort)},
		))
		Expect(prc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(prc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))

		Expect(prc.Spec.Template.Spec.Volumes[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(prc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))

		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))

		clusterRole := rtest.GetResource(resources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
					"policyrecommendationscopes",
					"policyrecommendationscopes/status",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
				},
				Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
		))

		clusterRoleBinding := rtest.GetResource(resources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef).To(Equal(
			rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     render.PolicyRecommendationName,
			}))
		Expect(clusterRoleBinding.Subjects).To(ConsistOf(
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      render.PolicyRecommendationName,
				Namespace: render.PolicyRecommendationNamespace,
			}))
		roleBinding := rtest.GetResource(resources, render.PolicyRecommendationManagedClustersWatchRoleBindingName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(roleBinding.RoleRef.Name).To(Equal(render.ManagedClustersWatchClusterRoleName))
		Expect(roleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.PolicyRecommendationName,
				Namespace: render.PolicyRecommendationNamespace,
			},
		}))
	})

	It("should render toleration on GKE", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
		component := render.PolicyRecommendation(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploy := rtest.GetResource(resources, render.PolicyRecommendationName, render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deploy).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.OpenShift = true
		component := render.PolicyRecommendation(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "tigera-policy-recommendation", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"hostnetwork-v2"},
		}))
	})

	It("should apply controlPlaneNodeSelector correctly", func() {
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
		}
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
	})

	It("should apply controlPlaneTolerations correctly", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
	})

	It("should render an init container when certificate management is enabled", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		policyRecommendationCertSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.PolicyRecommendationTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg.PolicyRecommendationCertSecret = policyRecommendationCertSecret

		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()

		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := idc.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.PolicyRecommendationTLSSecretName)))
	})

	It("should override container's resource request with the value from policy recommendation CR", func() {
		prResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}

		policyRecommendationcfg := operatorv1.PolicyRecommendation{
			Spec: operatorv1.PolicyRecommendationSpec{
				PolicyRecommendationDeployment: &operatorv1.PolicyRecommendationDeployment{
					Spec: &operatorv1.PolicyRecommendationDeploymentSpec{
						Template: &operatorv1.PolicyRecommendationDeploymentPodTemplateSpec{
							Spec: &operatorv1.PolicyRecommendationDeploymentPodSpec{
								Containers: []operatorv1.PolicyRecommendationDeploymentContainer{{
									Name:      "policy-recommendation-controller",
									Resources: &prResources,
								}},
							},
						},
					},
				},
			},
		}

		cfg.PolicyRecommendation = &policyRecommendationcfg
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()
		d, ok := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("policy-recommendation-controller"))
		Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(prResources))
	})

	It("should override init container's resource request with the value from policy recommendation CR", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		prResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}

		policyRecommendationcfg := operatorv1.PolicyRecommendation{
			Spec: operatorv1.PolicyRecommendationSpec{
				PolicyRecommendationDeployment: &operatorv1.PolicyRecommendationDeployment{
					Spec: &operatorv1.PolicyRecommendationDeploymentSpec{
						Template: &operatorv1.PolicyRecommendationDeploymentPodTemplateSpec{
							Spec: &operatorv1.PolicyRecommendationDeploymentPodSpec{
								InitContainers: []operatorv1.PolicyRecommendationDeploymentInitContainer{{
									Name:      "policy-recommendation-tls-key-cert-provisioner",
									Resources: &prResources,
								}},
							},
						},
					},
				},
			},
		}

		cfg.PolicyRecommendation = &policyRecommendationcfg
		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		policyRecommendationCertSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.PolicyRecommendationTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg.PolicyRecommendationCertSecret = policyRecommendationCertSecret

		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()

		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(idc.Spec.Template.Spec.InitContainers[0].Name).To(Equal("policy-recommendation-tls-key-cert-provisioner"))
		Expect(idc.Spec.Template.Spec.InitContainers[0].Resources).To(Equal(prResources))
	})

	It("should render a depoloyment with the expected cluster connection type for a stadalone cluster", func() {
		// Test for cluster connection type
		cfg.ManagedCluster = false
		cfg.ManagementCluster = false
		component := render.PolicyRecommendation(cfg)

		resources, _ := component.Objects()
		deployment := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deployment.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "CLUSTER_CONNECTION_TYPE", Value: "standalone"}))
	})

	It("should render a depoloyment with the expected cluster connection type for a management cluster", func() {
		// Test for cluster connection type
		cfg.ManagedCluster = false
		cfg.ManagementCluster = true
		component := render.PolicyRecommendation(cfg)

		resources, _ := component.Objects()
		deployment := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deployment.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "CLUSTER_CONNECTION_TYPE", Value: "management"}))
	})

	It("should render a deployment with the MANAGED_CLUSTER_TYPE set to calico for a management cluster for calico tenant", func() {
		// Test for cluster connection type
		cfg.ManagedCluster = false
		cfg.ManagementCluster = true
		cfg.Tenant = &operatorv1.Tenant{
			Spec: operatorv1.TenantSpec{
				ManagedClusterVariant: ptr.To(operatorv1.Calico),
			},
		}
		component := render.PolicyRecommendation(cfg)

		resources, _ := component.Objects()
		deployment := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deployment.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "MANAGED_CLUSTER_TYPE", Value: "calico"}))
	})

	It("should render a deployment without the MANAGED_CLUSTER_TYPE for a management cluster for enterprise tenant", func() {
		// Test for cluster connection type
		cfg.ManagedCluster = false
		cfg.ManagementCluster = true
		cfg.Tenant = &operatorv1.Tenant{
			Spec: operatorv1.TenantSpec{
				ManagedClusterVariant: ptr.To(operatorv1.CalicoEnterprise),
			},
		}
		component := render.PolicyRecommendation(cfg)

		resources, _ := component.Objects()
		deployment := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deployment.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(WithTransform(
			func(envVar corev1.EnvVar) string { return envVar.Name }, Equal("MANAGED_CLUSTER_TYPE"))))
	})

	It("should render a deployment without the MANAGED_CLUSTER_TYPE for a management cluster without tenant info", func() {
		// Test for cluster connection type
		cfg.ManagedCluster = false
		cfg.ManagementCluster = true
		component := render.PolicyRecommendation(cfg)

		resources, _ := component.Objects()
		deployment := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deployment.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(WithTransform(
			func(envVar corev1.EnvVar) string { return envVar.Name }, Equal("MANAGED_CLUSTER_TYPE"))))
	})

	Context("calico-system rendering", func() {
		policyName := types.NamespacedName{Name: "calico-system.tigera-policy-recommendation", Namespace: "calico-system"}

		getExpectedPolicy := func(scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
			return testutils.SelectPolicyByClusterTypeAndProvider(
				scenario,
				map[string]*v3.NetworkPolicy{
					"unmanaged":           expectedUnmanagedPolicy,
					"unmanaged-openshift": expectedUnmanagedPolicyForOpenshift,
				},
			)
		}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				cfg.ManagedCluster = scenario.ManagedCluster
				cfg.OpenShift = scenario.OpenShift
				component := render.PolicyRecommendation(cfg)
				resources, _ := component.Objects()

				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
		)
	})

	Context("multi-tenant rendering", func() {
		tenantANamespace := "tenant-a"
		tenantBNamespace := "tenant-b"
		It("should render expected components inside expected namespace for each policyrecommendation instance", func() {
			cfg.Namespace = tenantANamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.BindingNamespaces = []string{tenantANamespace}
			cfg.ExternalElastic = true
			tenantAPolicyRec := render.PolicyRecommendation(cfg)

			tenantAResources, _ := tenantAPolicyRec.Objects()

			tenantAExpectedResources := []client.Object{
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.PolicyRecommendationManagedClustersWatchRoleBindingName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation-managed-cluster-access", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.tigera-policy-recommendation", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			}

			rtest.ExpectResources(tenantAResources, tenantAExpectedResources)

			d := rtest.GetResource(tenantAResources, "tigera-policy-recommendation", tenantANamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: tenantANamespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "tenant-a-id"}))

			roleBinding := rtest.GetResource(tenantAResources, render.PolicyRecommendationManagedClustersWatchRoleBindingName, tenantANamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
			Expect(roleBinding.RoleRef.Name).To(Equal(render.ManagedClustersWatchClusterRoleName))
			Expect(roleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.PolicyRecommendationName,
					Namespace: tenantANamespace,
				},
				{
					Kind:      "ServiceAccount",
					Name:      "tigera-policy-recommendation",
					Namespace: "tigera-policy-recommendation",
				},
			}))

			cfg.Namespace = tenantBNamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantB",
					Namespace: tenantBNamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-b-id",
				},
			}
			cfg.BindingNamespaces = []string{tenantANamespace, tenantBNamespace}
			tenantBPolicyRec := render.PolicyRecommendation(cfg)

			tenantBResources, _ := tenantBPolicyRec.Objects()

			tenantBExpectedResources := []client.Object{
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.PolicyRecommendationManagedClustersWatchRoleBindingName, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation-managed-cluster-access", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.tigera-policy-recommendation", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			}

			rtest.ExpectResources(tenantBResources, tenantBExpectedResources)

			d = rtest.GetResource(tenantBResources, "tigera-policy-recommendation", tenantBNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs = d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: tenantBNamespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "tenant-b-id"}))
		})

		It("should render environment variables per tenant", func() {
			cfg.Namespace = tenantANamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.ExternalElastic = true
			cfg.BindingNamespaces = []string{tenantANamespace}
			tenantPolicyRec := render.PolicyRecommendation(cfg)

			createdResources, _ := tenantPolicyRec.Objects()

			d := rtest.GetResource(createdResources, "tigera-policy-recommendation", cfg.Tenant.Namespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: cfg.Tenant.Namespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: render.ManagerService(cfg.Tenant)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", cfg.Tenant.Namespace)}))
		})

		It("should render environment variables for a single tenant external elastic", func() {
			cfg.Namespace = render.PolicyRecommendationNamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenantA",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.ExternalElastic = true
			cfg.BindingNamespaces = []string{render.PolicyRecommendationNamespace}
			tenantPolicyRec := render.PolicyRecommendation(cfg)

			createdResources, _ := tenantPolicyRec.Objects()

			d := rtest.GetResource(createdResources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: render.ManagerService(cfg.Tenant)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", render.ElasticsearchNamespace)}))
		})

		It("should render environment variables for a single tenant internal elastic", func() {
			cfg.Namespace = render.PolicyRecommendationNamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenantA",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.ExternalElastic = false
			cfg.BindingNamespaces = []string{render.PolicyRecommendationNamespace}
			tenantPolicyRec := render.PolicyRecommendation(cfg)

			createdResources, _ := tenantPolicyRec.Objects()

			d := rtest.GetResource(createdResources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: render.ManagerService(cfg.Tenant)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", render.ElasticsearchNamespace)}))
		})

		It("should render RBAC per tenant", func() {
			cfg.Namespace = tenantANamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			cfg.BindingNamespaces = []string{tenantANamespace}
			tenantPolicyRec := render.PolicyRecommendation(cfg)

			createdResources, _ := tenantPolicyRec.Objects()

			// Check that the cluster role allows the tenant's service account to impersonate
			clusterRole := rtest.GetResource(createdResources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			clusterRoleBinding := rtest.GetResource(createdResources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(clusterRole.Rules).To(ContainElements(
				rbacv1.PolicyRule{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts"},
					Verbs:         []string{"impersonate"},
					ResourceNames: []string{render.PolicyRecommendationName},
				},
				rbacv1.PolicyRule{
					APIGroups: []string{""},
					Resources: []string{"groups"},
					Verbs:     []string{"impersonate"},
					ResourceNames: []string{
						serviceaccount.AllServiceAccountsGroup,
						"system:authenticated",
						fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, render.PolicyRecommendationNamespace),
					},
				},
			))
			Expect(clusterRoleBinding.RoleRef).To(Equal(
				rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     render.PolicyRecommendationName,
				}))
			Expect(clusterRoleBinding.Subjects).To(ConsistOf(
				rbacv1.Subject{
					Kind:      "ServiceAccount",
					Name:      render.PolicyRecommendationName,
					Namespace: cfg.Tenant.Namespace,
				}))

			roleBindingManagedClusters := rtest.GetResource(createdResources, render.PolicyRecommendationMultiTenantManagedClustersAccessRoleBindingName, tenantANamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
			Expect(roleBindingManagedClusters.RoleRef).To(Equal(
				rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     render.MultiTenantManagedClustersAccessClusterRoleName,
				}))
			Expect(roleBindingManagedClusters.Subjects).To(ConsistOf(
				rbacv1.Subject{
					Kind:      "ServiceAccount",
					Name:      render.PolicyRecommendationName,
					Namespace: render.PolicyRecommendationNamespace,
				}))
		})
		It("should not render any resources in a managed cluster", func() {
			cfg.ManagedCluster = true
			expectedDeleteResources := []client.Object{
				&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}},
				&rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}},
				&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"}},
			}

			component := render.PolicyRecommendation(cfg)
			resources, deleteResources := component.Objects()

			Expect(resources).To(BeEmpty(), "Expected no resources to be rendered in a managed cluster")
			rtest.ExpectResources(deleteResources, expectedDeleteResources)
		})
	})
})
