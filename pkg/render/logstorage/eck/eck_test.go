// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package eck_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/testutils"
)

var _ = Describe("ECK rendering tests", func() {
	Context("zero-tenant rendering", func() {
		var installation *operatorv1.InstallationSpec
		var replicas int32
		var cfg *eck.Configuration
		eckPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/elastic-operator.json")
		eckPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/elastic-operator_ocp.json")

		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: eck.OperatorNamespace}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: eck.OperatorPolicyName, Namespace: eck.OperatorNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: eck.OperatorNamespace}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator", Namespace: eck.OperatorNamespace}},
			&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: eck.OperatorName, Namespace: eck.OperatorNamespace}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: eck.OperatorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		BeforeEach(func() {
			logStorage := &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{
					Nodes: &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: nil,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}

			cfg = &eck.Configuration{
				LogStorage:   logStorage,
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider: operatorv1.ProviderNone,
			}
		})

		It("should render all supporting resources for ECK Operator", func() {
			component := eck.ECK(cfg)
			createResources, _ := component.Objects()
			rtest.ExpectResources(createResources, expectedResources)

			// Check the namespaces.
			namespace := rtest.GetResource(createResources, "tigera-eck-operator", "", "", "v1", "Namespace").(*corev1.Namespace)
			Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("restricted"))
			Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

			resultECK := rtest.GetResource(createResources, eck.OperatorName, eck.OperatorNamespace,
				"apps", "v1", "StatefulSet").(*appsv1.StatefulSet)
			Expect(resultECK.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(resultECK.Spec.Template.Spec.Containers[0].Args).To(ConsistOf([]string{
				"manager",
				"--namespaces=tigera-elasticsearch,tigera-kibana",
				"--log-verbosity=0",
				"--metrics-port=0",
				"--container-registry=testregistry.com/",
				"--max-concurrent-reconciles=3",
				"--ca-cert-validity=8760h",
				"--ca-cert-rotate-before=720h",
				"--cert-rotate-before=720h",
				"--cert-validity=8760h",
				"--enable-webhook=false",
				"--manage-webhook-certs=false",
			}))
			Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(resultECK.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(resultECK.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))

			eckRole := rtest.GetResource(createResources, "elastic-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(eckRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
				{
					APIGroups: []string{"authorization.k8s.io"},
					Resources: []string{"subjectaccessreviews"},
					Verbs:     []string{"create"},
				},
				{
					APIGroups: []string{"coordination.k8s.io"},
					Resources: []string{"leases"},
					Verbs:     []string{"create"},
				},
				{
					APIGroups:     []string{"coordination.k8s.io"},
					Resources:     []string{"leases"},
					ResourceNames: []string{"elastic-operator-leader"},
					Verbs:         []string{"get", "watch", "update"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"endpoints"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"pods", "events", "persistentvolumeclaims", "secrets", "services", "configmaps"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"deployments", "statefulsets", "daemonsets"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{"policy"},
					Resources: []string{"poddisruptionbudgets"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{"elasticsearch.k8s.elastic.co"},
					Resources: []string{"elasticsearches", "elasticsearches/status", "elasticsearches/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"autoscaling.k8s.elastic.co"},
					Resources: []string{"elasticsearchautoscalers", "elasticsearchautoscalers/status", "elasticsearchautoscalers/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"kibana.k8s.elastic.co"},
					Resources: []string{"kibanas", "kibanas/status", "kibanas/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"apm.k8s.elastic.co"},
					Resources: []string{"apmservers", "apmservers/status", "apmservers/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"enterprisesearch.k8s.elastic.co"},
					Resources: []string{"enterprisesearches", "enterprisesearches/status", "enterprisesearches/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"beat.k8s.elastic.co"},
					Resources: []string{"beats", "beats/status", "beats/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"agent.k8s.elastic.co"},
					Resources: []string{"agents", "agents/status", "agents/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"maps.k8s.elastic.co"},
					Resources: []string{"elasticmapsservers", "elasticmapsservers/status", "elasticmapsservers/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"stackconfigpolicy.k8s.elastic.co"},
					Resources: []string{"stackconfigpolicies", "stackconfigpolicies/status", "stackconfigpolicies/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"logstash.k8s.elastic.co"},
					Resources: []string{"logstashes", "logstashes/status", "logstashes/finalizers"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
				},
				{
					APIGroups: []string{"autoops.k8s.elastic.co"},
					Resources: []string{"autoopsagentpolicies", "autoopsagentpolicies/status", "autoopsagentpolicies/finalizers"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"packageregistry.k8s.elastic.co"},
					Resources: []string{"packageregistries", "packageregistries/status", "packageregistries/finalizers"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"storage.k8s.io"},
					Resources: []string{"storageclasses"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"admissionregistration.k8s.io"},
					Resources: []string{"validatingwebhookconfigurations"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"nodes"},
					Verbs:     []string{"get", "list", "watch"},
				},
			}))
		})

		It("should render trial license", func() {
			expectedResources := []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: eck.OperatorNamespace}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: eck.OperatorPolicyName, Namespace: eck.OperatorNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: eck.OperatorNamespace}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator", Namespace: eck.OperatorNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: eck.EnterpriseTrial, Namespace: eck.OperatorNamespace}},
				&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: eck.OperatorName, Namespace: eck.OperatorNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: eck.OperatorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			}

			cfg.ApplyTrial = true
			component := eck.ECK(cfg)
			createResources, _ := component.Objects()
			rtest.ExpectResources(createResources, expectedResources)
		})

		It("should render toleration on GKE", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
			component := eck.ECK(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			statefulSet := rtest.GetResource(resources, eck.OperatorName, eck.OperatorNamespace, "apps", "v1", "StatefulSet").(*appsv1.StatefulSet)
			Expect(statefulSet).NotTo(BeNil())
			Expect(statefulSet.Spec.Template.Spec.Tolerations).To(ContainElement(corev1.Toleration{
				Key:      "kubernetes.io/arch",
				Operator: corev1.TolerationOpEqual,
				Value:    "arm64",
				Effect:   corev1.TaintEffectNoSchedule,
			}))
		})

		It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
			component := eck.ECK(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			role := rtest.GetResource(resources, "elastic-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"nonroot-v2"},
			}))
		})

		Context("calico-system rendering", func() {
			policyNames := []types.NamespacedName{
				{Name: "calico-system.kibana-access", Namespace: "tigera-kibana"},
			}

			getExpectedPolicy := func(name types.NamespacedName, scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
				if name.Name == "calico-system.elastic-operator-access" {
					return testutils.SelectPolicyByProvider(scenario, eckPolicy, eckPolicyForOpenshift)
				}

				return nil
			}

			DescribeTable("should render calico-system policy",
				func(scenario testutils.CalicoSystemScenario) {
					if scenario.OpenShift {
						cfg.Provider = operatorv1.ProviderOpenShift
					} else {
						cfg.Provider = operatorv1.ProviderNone
					}

					component := eck.ECK(cfg)
					resources, _ := component.Objects()

					for _, policyName := range policyNames {
						policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
						expectedPolicy := getExpectedPolicy(policyName, scenario)
						Expect(policy).To(Equal(expectedPolicy))
					}
				},
				Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
				Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			)
		})

		Context("ECKOperator memory requests/limits", func() {
			When("LogStorage Spec contains an entry for ECKOperator in ComponentResources", func() {
				It("should set matching memory requests/limits in the elastic-operator StatefulSet.Spec manager container", func() {
					limits := corev1.ResourceList{}
					requests := corev1.ResourceList{}
					limits[corev1.ResourceMemory] = resource.MustParse("512Mi")
					requests[corev1.ResourceMemory] = resource.MustParse("512Mi")
					cfg.LogStorage.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
						{
							ComponentName: operatorv1.ComponentNameECKOperator,
							ResourceRequirements: &corev1.ResourceRequirements{
								Limits:   limits,
								Requests: requests,
							},
						},
					}

					limits[corev1.ResourceCPU] = resource.MustParse("1")
					requests[corev1.ResourceCPU] = resource.MustParse("100m")
					expectedResourcesRequirements := corev1.ResourceRequirements{
						Limits:   limits,
						Requests: requests,
					}

					component := eck.ECK(cfg)

					createResources, _ := component.Objects()

					statefulSet := rtest.GetResource(createResources, eck.OperatorName, eck.OperatorNamespace, "apps", "v1", "StatefulSet").(*appsv1.StatefulSet)
					Expect(statefulSet).Should(Not(BeNil()))
					Expect(statefulSet.Spec.Template.Spec.Containers).ToNot(BeEmpty())
					for _, container := range statefulSet.Spec.Template.Spec.Containers {
						if container.Name == "manager" {
							Expect(container).NotTo(BeNil())
							Expect(container.Resources).To(Equal(expectedResourcesRequirements))
							break
						}
					}
				})
			})
		})
	})
})
