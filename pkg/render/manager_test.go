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

package render_test

import (
	"fmt"
	"reflect"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var _ = Describe("Tigera Secure Manager rendering tests", func() {
	var replicas int32 = 2
	installation := &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas}
	compliance := &operatorv1.Compliance{}

	expectedManagerPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/manager.json")
	expectedManagerOpenshiftPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/manager_ocp.json")

	It("should render all resources for a default configuration", func() {
		nonclusterhost := &operatorv1.NonClusterHost{
			Spec: operatorv1.NonClusterHostSpec{
				Endpoint: "https://127.0.0.1:9443",
			},
		}
		resourcesToCreate, resourcesToDelete := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			nonClusterHost:          nonclusterhost,
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})

		// Should render the correct resources.
		expectedResourcesToCreate := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.manager-access", Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceAccount, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceName, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerServiceName, Namespace: render.LegacyManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerDeploymentName, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersWatchRoleBindingName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerNamespace}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
		}
		rtest.ExpectResources(resourcesToCreate, expectedResourcesToCreate)

		expectedResourcesToDelete := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerManagedClustersWatchRoleBindingName}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerManagedClustersUpdateRBACName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerManagedClustersUpdateRBACName}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerClusterRole}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerClusterRoleBinding}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerDeploymentName, Namespace: render.LegacyManagerNamespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerServiceAccount, Namespace: render.LegacyManagerNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyVoltronLinseedPublicCert, Namespace: common.OperatorNamespace()}},
		}
		rtest.ExpectResources(resourcesToDelete, expectedResourcesToDelete)

		deployment := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		// deployment
		Expect(deployment.Spec.Template.Spec.Volumes).To(HaveLen(3))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[1].VolumeSource.ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(4))
		uiAPIs := deployment.Spec.Template.Spec.Containers[0]
		voltron := deployment.Spec.Template.Spec.Containers[1]
		dashboard := deployment.Spec.Template.Spec.Containers[2]
		manager := deployment.Spec.Template.Spec.Containers[3]

		Expect(manager.Image).Should(Equal(components.TigeraRegistry + "tigera/manager:" + components.ComponentManager.Version))
		Expect(uiAPIs.Image).Should(Equal(components.CalicoRegistry + "calico/calico:" + components.ComponentCalico.Version))
		Expect(dashboard.Image).Should(Equal(components.CalicoRegistry + "calico/calico:" + components.ComponentCalico.Version))
		Expect(voltron.Image).Should(Equal(components.CalicoRegistry + "calico/calico:" + components.ComponentCalico.Version))

		// manager container
		Expect(*manager.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*manager.SecurityContext.Privileged).To(BeFalse())
		Expect(*manager.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*manager.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*manager.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(manager.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(manager.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		Expect(manager.Env).Should(ContainElements(
			corev1.EnvVar{Name: "CNX_POLICY_RECOMMENDATION_SUPPORT", Value: "true"},
		))

		// ui-apis container
		uiAPIsExpectedEnvVars := []corev1.EnvVar{
			{Name: "ELASTIC_LICENSE_TYPE", Value: "enterprise_trial"},
			{Name: "ELASTIC_KIBANA_ENDPOINT", Value: "https://tigera-secure-es-gateway-http.tigera-elasticsearch.svc:5601"},
			{Name: "LINSEED_CLIENT_CERT", Value: "/internal-manager-tls/tls.crt"},
			{Name: "LINSEED_CLIENT_KEY", Value: "/internal-manager-tls/tls.key"},
			{Name: "ELASTIC_KIBANA_DISABLED", Value: "false"},
			{Name: "VOLTRON_URL", Value: render.ManagerService(nil)},
			{Name: "RBAC_UI_ENABLED", Value: "false"},
		}
		Expect(uiAPIs.Env).To(Equal(uiAPIsExpectedEnvVars))

		Expect(uiAPIs.VolumeMounts).To(HaveLen(2))
		Expect(uiAPIs.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(uiAPIs.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(uiAPIs.VolumeMounts[1].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(uiAPIs.VolumeMounts[1].MountPath).To(Equal("/internal-manager-tls"))

		Expect(*uiAPIs.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*uiAPIs.SecurityContext.Privileged).To(BeFalse())
		Expect(*uiAPIs.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*uiAPIs.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*uiAPIs.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(uiAPIs.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(uiAPIs.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		dashboardExpectedEnv := []corev1.EnvVar{
			{Name: "LISTEN_ADDR", Value: fmt.Sprintf("127.0.0.1:%s", render.DashboardAPIPort)},
			{Name: "LOG_LEVEL", Value: "Info"},
			{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc.%s", render.ElasticsearchNamespace, clusterDomain)},
			{Name: "LINSEED_CLIENT_KEY", Value: fmt.Sprintf("/%s/tls.key", render.ManagerInternalTLSSecretName)},
			{Name: "LINSEED_CLIENT_CERT", Value: fmt.Sprintf("/%s/tls.crt", render.ManagerInternalTLSSecretName)},
			{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: render.ManagerService(nil)},
			{Name: "HEALTH_PORT", Value: render.DashboardAPIHealthPort},
		}
		Expect(dashboard.Env).To(Equal(dashboardExpectedEnv))

		Expect(dashboard.VolumeMounts).To(HaveLen(2))
		Expect(dashboard.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dashboard.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(dashboard.VolumeMounts[1].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(dashboard.VolumeMounts[1].MountPath).To(Equal(fmt.Sprintf("/%s", render.ManagerInternalTLSSecretName)))

		Expect(dashboard.ReadinessProbe).NotTo(BeNil())
		Expect(dashboard.ReadinessProbe.ProbeHandler.Exec.Command).To(Equal([]string{"/usr/bin/calico", "component", "dashboards", "ready"}))
		Expect(dashboard.LivenessProbe).NotTo(BeNil())
		Expect(dashboard.LivenessProbe.ProbeHandler.Exec.Command).To(Equal([]string{"/usr/bin/calico", "component", "dashboards", "ready"}))

		Expect(dashboard.SecurityContext).NotTo(BeNil())
		Expect(*dashboard.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*dashboard.SecurityContext.RunAsNonRoot).To(BeTrue())

		// voltron container
		Expect(voltron.Env).To(ContainElements([]corev1.EnvVar{
			{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: "true"},
			{Name: "VOLTRON_ENABLE_NONCLUSTER_HOST", Value: "true"},
			{Name: "VOLTRON_LOG_COLLECTOR_CA_BUNDLE_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "VOLTRON_QUERYSERVER_ENDPOINT", Value: "https://calico-api.calico-system.svc:8080"},
			{Name: "VOLTRON_QUERYSERVER_BASE_PATH", Value: "/api/v1/namespaces/calico-system/services/https:calico-api:8080/proxy/"},
			{Name: "VOLTRON_QUERYSERVER_CA_BUNDLE_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		}))

		Expect(voltron.VolumeMounts).To(HaveLen(3))
		Expect(voltron.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal("manager-tls"))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/manager-tls"))
		Expect(voltron.VolumeMounts[2].Name).To(Equal("internal-manager-tls"))
		Expect(voltron.VolumeMounts[2].MountPath).To(Equal("/internal-manager-tls"))

		Expect(*voltron.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*voltron.SecurityContext.Privileged).To(BeFalse())
		Expect(*voltron.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*voltron.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*voltron.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(voltron.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(voltron.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
	})

	It("should render toleration on GKE", func() {
		installation.KubernetesProvider = operatorv1.ProviderGKE
		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})
		deployment := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas, KubernetesProvider: operatorv1.ProviderOpenShift},
			compliance:              compliance,
			complianceFeatureActive: true,
		})

		// calico-manager-role clusterRole should have openshift securitycontextconstraints PolicyRule
		managerRole := rtest.GetResource(resourcesToCreate, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(managerRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	DescribeTable("should set container env appropriately when compliance is not fully available",
		func(crPresent bool, licenseFeatureActive bool, complianceEnabled bool) {
			var complianceCR *operatorv1.Compliance
			if crPresent {
				complianceCR = &operatorv1.Compliance{}
			}

			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              complianceCR,
				complianceFeatureActive: licenseFeatureActive,
				ns:                      render.ManagerNamespace,
			})

			deployment := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			voltron := deployment.Spec.Template.Spec.Containers[1]
			Expect(voltron.Env).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: strconv.FormatBool(complianceEnabled)}))
		},
		Entry("Both CR and license feature not present/active", false, false, false),
		Entry("CR not present, license feature active", false, true, true),
		Entry("CR present, license feature not active", true, false, false),
	)

	It("should render the correct ClusterRole", func() {
		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})

		clusterRole := rtest.GetResource(resourcesToCreate, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"networksets",
					"globalnetworksets",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"uisettings",
					"uisettingsgroups",
					"uisettingsgroups/data",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettings", "uisettingsgroups/data"},
				Verbs:     []string{"delete"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
				},
				Verbs: []string{"patch"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"hostendpoints",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"get", "list", "watch", "create", "delete"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"felixconfigurations",
				},
				ResourceNames: []string{
					"default",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"alertexceptions",
				},
				Verbs: []string{"get", "list", "update"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"policy.networking.k8s.io"},
				Resources: []string{
					"clusternetworkpolicies",
					"adminnetworkpolicies",
					"baselineadminnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces", "nodes", "events", "services", "pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:calico-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flows",
					"flowlogs",
					"flowlogs-multi-cluster",
					"bgplogs",
					"auditlogs",
					"dnsflows",
					"dnslogs",
					"dnslogs-multi-cluster",
					"l7flows",
					"l7logs",
					"l7logs-multi-cluster",
					"events",
					"processes",
					"policyactivity",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
			},
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"},
				Verbs:     []string{"get", "list", "watch"},
			},
		}))
		roleBindingWatchManagedClusters := rtest.GetResource(resourcesToCreate, render.ManagerManagedClustersWatchRoleBindingName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(roleBindingWatchManagedClusters.RoleRef.Name).To(Equal(render.ManagedClustersWatchClusterRoleName))
		Expect(roleBindingWatchManagedClusters.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.ManagerServiceName,
				Namespace: render.ManagerNamespace,
			},
		}))
		roleUpdateManagedClusters := rtest.GetResource(resourcesToCreate, render.ManagerManagedClustersUpdateRBACName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(roleUpdateManagedClusters.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters", "managedclusters/status"},
				Verbs:     []string{"update"},
			},
		}))
		roleBindingUpdateManagedClusters := rtest.GetResource(resourcesToCreate, render.ManagerManagedClustersUpdateRBACName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(roleBindingUpdateManagedClusters.RoleRef.Name).To(Equal(render.ManagerManagedClustersUpdateRBACName))
		Expect(roleBindingWatchManagedClusters.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.ManagerServiceName,
				Namespace: render.ManagerNamespace,
			},
		}))
	})

	It("should set OIDC Authority environment when auth-type is OIDC", func() {
		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    true,
			managementCluster:       nil,
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})
		d := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d).NotTo(BeNil())

		oidcEnvVar := corev1.EnvVar{
			Name:      "CNX_WEB_OIDC_AUTHORITY",
			Value:     "https://127.0.0.1/dex",
			ValueFrom: nil,
		}
		Expect(d.Spec.Template.Spec.Containers[3].Env).To(ContainElement(oidcEnvVar))

		// dashboard-api must get its own bare-prefixed OIDC_AUTH_* env vars so it can
		// validate the bearer token voltron forwards on /dashboards/*.
		dashboard := rtest.GetContainer(d.Spec.Template.Spec.Containers, render.DashboardAPIName)
		Expect(dashboard).NotTo(BeNil())
		Expect(dashboard.Env).To(ContainElement(corev1.EnvVar{Name: "OIDC_AUTH_ENABLED", Value: "true"}))
		Expect(dashboard.Env).To(ContainElement(corev1.EnvVar{Name: "OIDC_AUTH_ISSUER", Value: "https://127.0.0.1/dex"}))
	})

	Describe("public ca bundle", func() {
		var cfg *render.ManagerConfiguration
		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

			certificateManager, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			tunnelSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.VoltronTunnelSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			internalTraffic, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			managerTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerTLSSecretName, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())

			voltronLinseedCert, err := certificateManager.GetOrCreateKeyPair(cli, render.VoltronLinseedTLS, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())

			cfg = &render.ManagerConfiguration{
				TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(certificateManager.KeyPair()),
				TLSKeyPair:            managerTLS,
				ManagementCluster:     &operatorv1.ManagementCluster{},
				TunnelServerCert:      tunnelSecret,
				VoltronLinseedKeyPair: voltronLinseedCert,
				InternalTLSKeyPair:    internalTraffic,
				Installation:          installation,
				Namespace:             render.ManagerNamespace,
				TruthNamespace:        common.OperatorNamespace(),
			}
		})

		It("should render when disabled", func() {
			resources, err := render.Manager(cfg)
			Expect(err).ToNot(HaveOccurred())
			rs, _ := resources.Objects()

			managerDeployment := rtest.GetResource(rs, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			voltronContainer := rtest.GetContainer(managerDeployment.Spec.Template.Spec.Containers, render.VoltronName)

			rtest.ExpectEnv(voltronContainer.Env, "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", "false")
		})

		It("should render when enabled", func() {
			cfg.ManagementCluster.Spec.TLS = &operatorv1.TLS{SecretName: render.ManagerTLSSecretName}

			resources, err := render.Manager(cfg)
			Expect(err).ToNot(HaveOccurred())
			rs, _ := resources.Objects()

			managerDeployment := rtest.GetResource(rs, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			voltronContainer := rtest.GetContainer(managerDeployment.Spec.Template.Spec.Containers, render.VoltronName)

			rtest.ExpectEnv(voltronContainer.Env, "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", "true")
		})
	})

	It("should render multicluster settings properly", func() {
		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       &operatorv1.ManagementCluster{},
			installation:            installation,
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})

		// Should render the correct resources.
		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.manager-access", Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceAccount, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersWatchRoleBindingName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceName, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerServiceName, Namespace: render.LegacyManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerDeploymentName, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerNamespace}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.VoltronLinseedPublicCert, Namespace: common.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
		}
		rtest.ExpectResources(resourcesToCreate, expectedResources)

		By("configuring the manager deployment")
		deployment := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		manager := deployment.Spec.Template.Spec.Containers[3]
		Expect(manager.Name).To(Equal(render.ManagerName))
		rtest.ExpectEnv(manager.Env, "ENABLE_MULTI_CLUSTER_MANAGEMENT", "true")

		voltron := deployment.Spec.Template.Spec.Containers[1]
		uiAPIs := deployment.Spec.Template.Spec.Containers[0]
		Expect(voltron.Name).To(Equal(render.VoltronName))
		rtest.ExpectEnv(voltron.Env, "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", "true")

		Expect(uiAPIs.VolumeMounts).To(HaveLen(2))
		Expect(uiAPIs.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(uiAPIs.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(uiAPIs.VolumeMounts[1].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(uiAPIs.VolumeMounts[1].MountPath).To(Equal("/internal-manager-tls"))

		Expect(len(voltron.VolumeMounts)).To(Equal(5))
		Expect(voltron.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/manager-tls"))
		Expect(voltron.VolumeMounts[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(voltron.VolumeMounts[2].MountPath).To(Equal("/internal-manager-tls"))
		Expect(voltron.VolumeMounts[3].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(voltron.VolumeMounts[3].MountPath).To(Equal(fmt.Sprintf("/%s", render.VoltronTunnelSecretName)))
		Expect(voltron.VolumeMounts[4].Name).To(Equal(render.VoltronLinseedTLS))
		Expect(voltron.VolumeMounts[4].MountPath).To(Equal(fmt.Sprintf("/%s", render.VoltronLinseedTLS)))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(5))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[1].VolumeSource.ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Secret.SecretName).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Name).To(Equal(render.VoltronLinseedTLS))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Secret.SecretName).To(Equal(render.VoltronLinseedTLS))

		clusterRole := rtest.GetResource(resourcesToCreate, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"networksets",
					"globalnetworksets",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"uisettings",
					"uisettingsgroups",
					"uisettingsgroups/data",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettings", "uisettingsgroups/data"},
				Verbs:     []string{"delete"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
				},
				Verbs: []string{"patch"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"hostendpoints",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"get", "list", "watch", "create", "delete"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"felixconfigurations",
				},
				ResourceNames: []string{
					"default",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"alertexceptions",
				},
				Verbs: []string{"get", "list", "update"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"policy.networking.k8s.io"},
				Resources: []string{
					"clusternetworkpolicies",
					"adminnetworkpolicies",
					"baselineadminnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces", "nodes", "events", "services", "pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:calico-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flows",
					"flowlogs",
					"flowlogs-multi-cluster",
					"bgplogs",
					"auditlogs",
					"dnsflows",
					"dnslogs",
					"dnslogs-multi-cluster",
					"l7flows",
					"l7logs",
					"l7logs-multi-cluster",
					"events",
					"processes",
					"policyactivity",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
			},
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"},
				Verbs:     []string{"get", "list", "watch"},
			},
		}))
	})

	var kp certificatemanagement.KeyPairInterface
	var internalKp certificatemanagement.KeyPairInterface
	var voltronLinseedKP certificatemanagement.KeyPairInterface
	var bundle certificatemanagement.TrustedBundle

	BeforeEach(func() {
		var err error
		secret, err := certificatemanagement.CreateSelfSignedSecret(render.ManagerTLSSecretName, common.OperatorNamespace(), render.ManagerTLSSecretName, nil)
		Expect(err).NotTo(HaveOccurred())

		kp = certificatemanagement.NewKeyPair(secret, []string{""}, "")
		Expect(err).NotTo(HaveOccurred())

		internalKp = certificatemanagement.NewKeyPair(secret, []string{""}, "")
		Expect(err).NotTo(HaveOccurred())

		voltronLinseedKP = certificatemanagement.NewKeyPair(secret, []string{""}, "")
		Expect(err).NotTo(HaveOccurred())

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		bundle = certificateManager.CreateTrustedBundle()
	})

	// renderManager passes in as few parameters as possible to render.Manager without it
	// panicing. It accepts variations on the installspec for testing purposes.
	renderManager := func(i *operatorv1.InstallationSpec) *appsv1.Deployment {
		cfg := &render.ManagerConfiguration{
			TrustedCertBundle:     bundle,
			TLSKeyPair:            kp,
			VoltronLinseedKeyPair: voltronLinseedKP,
			Installation:          i,
			ESLicenseType:         render.ElasticsearchLicenseTypeUnknown,
			Replicas:              &replicas,
			InternalTLSKeyPair:    internalKp,
			Namespace:             render.ManagerNamespace,
			TruthNamespace:        common.OperatorNamespace(),
		}
		component, err := render.Manager(cfg)
		Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
		resources, _ := component.Objects()
		return rtest.GetResource(resources, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
	}

	It("should apply controlPlaneNodeSelectors", func() {
		deployment := renderManager(&operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{
				"foo": "bar",
			},
			ControlPlaneReplicas: &replicas,
		})
		Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
	})

	It("should apply controlPlaneTolerations", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		deployment := renderManager(&operatorv1.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
			ControlPlaneReplicas:    &replicas,
		})
		Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateCriticalAddonsAndControlPlane, t)))
	})

	It("should render all resources for certificate management", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes()
		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{CertificateManagement: &operatorv1.CertificateManagement{CACert: cert}, ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})

		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.manager-access", Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceAccount, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceName, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerServiceName, Namespace: render.LegacyManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerDeploymentName, Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersWatchRoleBindingName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerNamespace}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettingsGroup{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerUserSettings}, TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsLayerTigera}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
			&v3.UISettings{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterSettingsViewDefault}, TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"}},
		}
		rtest.ExpectResources(resourcesToCreate, expectedResources)

		deployment := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(deployment.Spec.Template.Spec.InitContainers).To(HaveLen(2))
		managerCSRInitContainer := deployment.Spec.Template.Spec.InitContainers[0]
		internalManagerCSRInitContainer := deployment.Spec.Template.Spec.InitContainers[1]
		Expect(managerCSRInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ManagerTLSSecretName)))
		Expect(internalManagerCSRInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ManagerInternalTLSSecretName)))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(3))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret).To(BeNil())
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret).To(BeNil())

		voltronContainer := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, render.VoltronName)
		var caSignerName string
		for _, e := range voltronContainer.Env {
			if e.Name == "VOLTRON_CA_SIGNER_NAME" {
				caSignerName = e.Value
				break
			}
		}
		Expect(caSignerName).NotTo(BeEmpty(), "Expected VOLTRON_CA_SIGNER_NAME to be set")
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		installation.ControlPlaneReplicas = &replicas

		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})
		deploy, ok := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		installation.ControlPlaneReplicas = &replicas

		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
		})
		deploy, ok := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity(render.ManagerName, []string{render.ManagerNamespace})))
	})

	It("should override container's resource request with the value from Manager CR", func() {
		managerResources := corev1.ResourceRequirements{
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

		managercfg := operatorv1.Manager{
			Spec: operatorv1.ManagerSpec{
				ManagerDeployment: &operatorv1.ManagerDeployment{
					Spec: &operatorv1.ManagerDeploymentSpec{
						Template: &operatorv1.ManagerDeploymentPodTemplateSpec{
							Spec: &operatorv1.ManagerDeploymentPodSpec{
								Containers: []operatorv1.ManagerDeploymentContainer{{
									Name:      render.VoltronName,
									Resources: &managerResources,
								}},
							},
						},
					},
				},
			},
		}

		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
			manager:                 &managercfg,
		})

		d, ok := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())

		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(4))

		container := test.GetContainer(d.Spec.Template.Spec.Containers, render.VoltronName)
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(managerResources))
	})

	It("should gracefully override container resource request using deprecated component names", func() {
		managerResources := corev1.ResourceRequirements{
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

		managercfg := operatorv1.Manager{
			Spec: operatorv1.ManagerSpec{
				ManagerDeployment: &operatorv1.ManagerDeployment{
					Spec: &operatorv1.ManagerDeploymentSpec{
						Template: &operatorv1.ManagerDeploymentPodTemplateSpec{
							Spec: &operatorv1.ManagerDeploymentPodSpec{
								Containers: []operatorv1.ManagerDeploymentContainer{
									{
										Name:      "tigera-voltron",
										Resources: &managerResources,
									},
									{
										Name:      "tigera-es-proxy",
										Resources: &managerResources,
									},
								},
							},
						},
					},
				},
			},
		}

		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
			manager:                 &managercfg,
		})

		d, ok := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())

		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(4))

		container := test.GetContainer(d.Spec.Template.Spec.Containers, render.VoltronName)
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(managerResources))

		container = test.GetContainer(d.Spec.Template.Spec.Containers, render.UIAPIsName)
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(managerResources))
	})

	It("should override init container's resource request with the value from Manager CR", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		certificateManagement := &operatorv1.CertificateManagement{CACert: cert}

		managerResources := corev1.ResourceRequirements{
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

		managercfg := operatorv1.Manager{
			Spec: operatorv1.ManagerSpec{
				ManagerDeployment: &operatorv1.ManagerDeployment{
					Spec: &operatorv1.ManagerDeploymentSpec{
						Template: &operatorv1.ManagerDeploymentPodTemplateSpec{
							Spec: &operatorv1.ManagerDeploymentPodSpec{
								InitContainers: []operatorv1.ManagerDeploymentInitContainer{{
									Name:      "manager-tls-key-cert-provisioner",
									Resources: &managerResources,
								}},
							},
						},
					},
				},
			},
		}

		resourcesToCreate, _ := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas, CertificateManagement: certificateManagement},
			compliance:              compliance,
			complianceFeatureActive: true,
			ns:                      render.ManagerNamespace,
			manager:                 &managercfg,
		})

		d, ok := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())

		Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(2))

		initContainer := test.GetContainer(d.Spec.Template.Spec.InitContainers, "manager-tls-key-cert-provisioner")
		Expect(initContainer).NotTo(BeNil())
		Expect(initContainer.Resources).To(Equal(managerResources))
	})

	Context("calico-system rendering", func() {
		policyName := types.NamespacedName{Name: "calico-system.manager-access", Namespace: render.ManagerNamespace}

		getExpectedPolicy := func(scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
			if scenario.ManagedCluster {
				return nil
			}

			return testutils.SelectPolicyByProvider(scenario, expectedManagerPolicy, expectedManagerOpenshiftPolicy)
		}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				// Default configuration.
				resourcesToCreate, _ := renderObjects(renderConfig{
					openshift:               scenario.OpenShift,
					oidc:                    false,
					managementCluster:       nil,
					installation:            installation,
					compliance:              compliance,
					complianceFeatureActive: true,
					ns:                      render.ManagerNamespace,
				})

				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resourcesToCreate)
				expectedPolicy := getExpectedPolicy(scenario)
				if expectedPolicy != nil {
					// Check fields individually before checking the entire struct so that we get
					// more useful failure messages.
					Expect(policy.ObjectMeta).To(Equal(expectedPolicy.ObjectMeta))
					Expect(policy.Spec.Ingress).To(ConsistOf(expectedPolicy.Spec.Ingress))
					Expect(policy.Spec.Egress).To(ConsistOf(expectedPolicy.Spec.Egress))
					Expect(policy.Spec.Selector).To(Equal(expectedPolicy.Spec.Selector))
					Expect(policy.Spec.Order).To(Equal(expectedPolicy.Spec.Order))
					Expect(policy.Spec.Tier).To(Equal(expectedPolicy.Spec.Tier))
					Expect(policy.Spec.Types).To(Equal(expectedPolicy.Spec.Types))
					Expect(policy.Spec.ServiceAccountSelector).To(Equal(expectedPolicy.Spec.ServiceAccountSelector))
				}
				Expect(policy).To(Equal(expectedPolicy))
			},
			// Manager only renders in the presence of a Manager CR, therefore does not have a config option for managed clusters.
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
		)

		It("should render calico-system policy for the non-cluster-host scenario", func() {
			renderCfg := renderConfig{
				openshift:               false,
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      render.ManagerNamespace,
			}
			resourcesWithoutNonClusterHosts, _ := renderObjects(renderCfg)
			renderCfg.nonClusterHost = &operatorv1.NonClusterHost{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.NonClusterHostSpec{
					Endpoint: "https://1.2.3.4:5678",
				},
			}
			resourcesWithNonClusterHosts, _ := renderObjects(renderCfg)
			policyWithNonClusterHosts := testutils.GetCalicoSystemPolicyFromResources(policyName, resourcesWithNonClusterHosts)
			policyWithoutNonClusterHosts := testutils.GetCalicoSystemPolicyFromResources(policyName, resourcesWithoutNonClusterHosts)

			// Validate that we have a single egress rule added for the fluent-bit service.
			Expect(policyWithoutNonClusterHosts.Spec.Ingress).To(Equal(policyWithNonClusterHosts.Spec.Ingress))
			Expect(len(policyWithoutNonClusterHosts.Spec.Egress)).To(Equal(len(policyWithNonClusterHosts.Spec.Egress) - 1))
			Expect(len(policyWithNonClusterHosts.Spec.Egress)).To(Equal(11))
			Expect(policyWithNonClusterHosts.Spec.Egress[8]).To(Equal(v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Services: &v3.ServiceMatch{
						Namespace: render.LogCollectorNamespace,
						Name:      render.FluentBitInputService,
					},
				},
			}))
		})
	})

	Context("multi-tenant rendering", func() {
		tenantANamespace := "tenant-a"
		tenantBNamespace := "tenant-b"

		It("should render expected components inside expected namespace for each manager instance", func() {
			tenantAResourcesToCreate, tenantAResourcesToDelete := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantANamespace,
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenantA",
						Namespace: tenantANamespace,
					},
					Spec: operatorv1.TenantSpec{
						ID: "tenant-a",
					},
				},
			})

			expectedTenantAResources := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.manager-access", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceAccount, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersWatchRoleBindingName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerMultiTenantManagedClustersAccessClusterRoleBindingName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerServiceName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerDeploymentName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			}
			rtest.ExpectResources(tenantAResourcesToCreate, expectedTenantAResources)

			expectedTenantAResourcesToDelete := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-managed-cluster-watch", Namespace: tenantANamespace}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-managed-cluster-write-access", Namespace: tenantANamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-managed-cluster-write-access", Namespace: tenantANamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-managed-cluster-access", Namespace: tenantANamespace}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-role"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-binding"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantANamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantANamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-voltron-linseed-certs-public", Namespace: tenantANamespace}},
			}

			rtest.ExpectResources(tenantAResourcesToDelete, expectedTenantAResourcesToDelete)

			tenantBResourcesToCreate, tenantBResourcesToDelete := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantBNamespace,
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenantB",
						Namespace: tenantBNamespace,
					},
					Spec: operatorv1.TenantSpec{
						ID: "tenant-b",
					},
				},
			})

			expectedTenantBResources := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.manager-access", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceAccount, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRole}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerClusterRoleBinding}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersWatchRoleBindingName, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerManagedClustersUpdateRBACName, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerMultiTenantManagedClustersAccessClusterRoleBindingName, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerServiceName, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerServiceName, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.ManagerDeploymentName, Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			}
			rtest.ExpectResources(tenantBResourcesToCreate, expectedTenantBResources)

			expectedTenantBResourcesToDelete := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: tenantBNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-managed-cluster-watch", Namespace: tenantBNamespace}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-managed-cluster-write-access", Namespace: tenantBNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-managed-cluster-write-access", Namespace: tenantBNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-managed-cluster-access", Namespace: tenantBNamespace}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-role"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-binding"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantBNamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: tenantBNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-voltron-linseed-certs-public", Namespace: tenantBNamespace}},
			}

			rtest.ExpectResources(tenantBResourcesToDelete, expectedTenantBResourcesToDelete)
		})

		It("should render cluster role binding with tenant namespaces as subjects", func() {
			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantBNamespace,
				bindingNamespaces:       []string{tenantANamespace, tenantBNamespace},
			})

			crb := rtest.GetResource(resourcesToCreate, render.ManagerClusterRoleBinding, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(crb.Subjects).To(Equal([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.ManagerServiceAccount,
					Namespace: tenantANamespace,
				},
				{
					Kind:      "ServiceAccount",
					Name:      render.ManagerServiceAccount,
					Namespace: tenantBNamespace,
				},
			}))
		})

		It("should render distinct RBAC for Calico OSS managed cluster tenants", func() {
			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantBNamespace,
				bindingNamespaces:       []string{tenantANamespace, tenantBNamespace},
				ossBindingNamespaces:    []string{tenantBNamespace},
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenantB",
						Namespace: tenantBNamespace,
					},
					Spec: operatorv1.TenantSpec{
						ID:                    "tenant-b",
						ManagedClusterVariant: &operatorv1.Calico,
					},
				},
			})

			// It should only bind to the ossBindingNamespaces.
			crb := rtest.GetResource(resourcesToCreate, render.ManagerManagedCalicoClusterRoleBinding, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(crb.Subjects).To(Equal([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.ManagerServiceAccount,
					Namespace: tenantBNamespace,
				},
			}))
		})

		It("should render cluster role/roles with additional RBAC", func() {
			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantANamespace,
				bindingNamespaces:       []string{tenantANamespace},
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenantA",
						Namespace: tenantANamespace,
					},
					Spec: operatorv1.TenantSpec{
						ID: "tenant-a",
					},
				},
			})

			roleBindingManagedClusters := rtest.GetResource(resourcesToCreate, render.ManagerMultiTenantManagedClustersAccessClusterRoleBindingName, tenantANamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
			Expect(roleBindingManagedClusters.RoleRef).To(Equal(
				rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     render.MultiTenantManagedClustersAccessClusterRoleName,
				}))
			Expect(roleBindingManagedClusters.Subjects).To(ConsistOf(
				rbacv1.Subject{
					Kind:      "ServiceAccount",
					Name:      render.ManagerServiceName,
					Namespace: render.ManagerNamespace,
				}))
		})

		It("should render multi-tenant environment variables", func() {
			tenant := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenant",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a",
				},
			}
			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantANamespace,
				tenant:                  tenant,
				externalElastic:         true,
			})
			d := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, tenantANamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[1].Env
			uiAPIsEnv := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_TENANT_NAMESPACE", Value: tenantANamespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_TENANT_ID", Value: "tenant-a"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_REQUIRE_TENANT_CLAIM", Value: "true"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_TENANT_CLAIM", Value: "tenant-a"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_LINSEED_ENDPOINT", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", tenantANamespace)}))
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_URL", Value: render.ManagerService(tenant)}))
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "tenant-a"}))
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: tenantANamespace}))
		})

		It("should render multi-tenant environment variables for connected Calico clusters", func() {
			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantANamespace,
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenant",
						Namespace: tenantANamespace,
					},
					Spec: operatorv1.TenantSpec{
						ID:                    "tenant-a",
						ManagedClusterVariant: &operatorv1.Calico,
					},
				},
				externalElastic: true,
			})
			d := rtest.GetResource(resourcesToCreate, render.ManagerName, tenantANamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			uiAPIsEnv := d.Spec.Template.Spec.Containers[0].Env
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "L7_LOGS_ENABLED", Value: "false"}))
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "DNS_LOGS_ENABLED", Value: "false"}))
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "EVENTS_ENABLED", Value: "false"}))
		})

		It("should not install UISettings / UISettingsGroups", func() {
			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantBNamespace,
				bindingNamespaces:       []string{tenantANamespace, tenantBNamespace},
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenant",
						Namespace: tenantANamespace,
					},
					Spec: operatorv1.TenantSpec{
						ID: "tenant-a",
					},
				},
			})

			// Expect no UISettings / UISettingsGroups to be installed.
			for _, res := range resourcesToCreate {
				Expect(reflect.TypeOf(res)).NotTo(Equal(reflect.TypeOf(&v3.UISettings{})), "Unexpected UISettings in multi-tenant mode")
				Expect(reflect.TypeOf(res)).NotTo(Equal(reflect.TypeOf(&v3.UISettingsGroup{})), "Unexpected UISettingsGroup in multi-tenant mode")
			}
		})

		It("should not install manager container in manager pod in single-tenant mode", func() {
			tenant := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-tenant",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a",
				},
			}

			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				tenant:                  tenant,
			})

			d := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, "", appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(2))
			for _, c := range d.Spec.Template.Spec.Containers {
				Expect(c.Name).NotTo(Equal(render.ManagerName))
				Expect(c.Image).NotTo(ContainSubstring("manager"))
			}
		})

		It("should not install manager container in manager pod in multi-tenant mode", func() {
			tenant := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-tenant",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a",
				},
			}

			resourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				tenant:                  tenant,
				ns:                      tenantANamespace,
			})

			d := rtest.GetResource(resourcesToCreate, render.ManagerDeploymentName, tenantANamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(2))
			for _, c := range d.Spec.Template.Spec.Containers {
				Expect(c.Name).NotTo(Equal(render.ManagerName))
				Expect(c.Image).NotTo(ContainSubstring("manager"))
			}
		})

		It("should not render dashboard sidecar", func() {
			tenant := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "tenantA", Namespace: tenantANamespace},
				Spec:       operatorv1.TenantSpec{ID: "tenant-a"},
			}
			resources, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      tenantANamespace,
				tenant:                  tenant,
			})

			deployment := rtest.GetResource(resources, render.ManagerDeploymentName, tenantANamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(2))
			Expect(rtest.GetContainer(deployment.Spec.Template.Spec.Containers, render.DashboardAPIName)).To(BeNil())
		})
	})

	Context("single-tenant rendering", func() {
		It("should render single-tenant environment variables with external elastic", func() {
			tenantAResourcesToCreate, tenantAResourcesToDelete := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      render.ManagerNamespace,
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenant",
						Namespace: "",
					},
					Spec: operatorv1.TenantSpec{
						ID: "tenant-a",
					},
				},
				externalElastic: true,
			})

			expectedTenantAResourcesToDelete := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-manager"}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.manager-access", Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: render.ManagerNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerManagedClustersWatchRoleBindingName}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerManagedClustersUpdateRBACName}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerManagedClustersUpdateRBACName}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerClusterRole}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerClusterRoleBinding}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerDeploymentName, Namespace: render.LegacyManagerNamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyManagerServiceName, Namespace: render.LegacyManagerNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.LegacyVoltronLinseedPublicCert, Namespace: common.OperatorNamespace()}},
			}

			rtest.ExpectResources(tenantAResourcesToDelete, expectedTenantAResourcesToDelete)

			d := rtest.GetResource(tenantAResourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[1].Env
			uiAPIsEnv := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_TENANT_ID", Value: "tenant-a"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_REQUIRE_TENANT_CLAIM", Value: "true"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_TENANT_CLAIM", Value: "tenant-a"}))
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_URL", Value: render.ManagerService(nil)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_LINSEED_ENDPOINT", Value: "https://tigera-linseed.tigera-elasticsearch.svc.cluster.local"}))
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "tenant-a"}))

			// Make sure we don't render multi-tenant environment variables
			for _, env := range envs {
				Expect(env.Name).NotTo(Equal("VOLTRON_TENANT_NAMESPACE"))
			}
			for _, env := range uiAPIsEnv {
				Expect(env.Name).NotTo(Equal("TENANT_NAMESPACE"))
			}
		})

		It("should render single-tenant environment variables with internal elastic", func() {
			tenantAResourcesToCreate, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				ns:                      render.ManagerNamespace,
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tenant",
						Namespace: "",
					},
					Spec: operatorv1.TenantSpec{
						ID: "tenant-a",
					},
				},
			})
			d := rtest.GetResource(tenantAResourcesToCreate, render.ManagerDeploymentName, render.ManagerNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[1].Env
			uiAPIsEnv := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_REQUIRE_TENANT_CLAIM", Value: "true"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_TENANT_CLAIM", Value: "tenant-a"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_LINSEED_ENDPOINT", Value: elasticsearch.LinseedEndpoint(rmeta.OSTypeWindows, "cluster.local", render.ElasticsearchNamespace, false, false)}))
			Expect(uiAPIsEnv).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_URL", Value: render.ManagerService(nil)}))

			// Make sure we don't render multi-tenant environment variables
			for _, env := range envs {
				Expect(env.Name).NotTo(Equal("VOLTRON_TENANT_NAMESPACE"))
			}
			for _, env := range uiAPIsEnv {
				Expect(env.Name).NotTo(Equal("TENANT_NAMESPACE"))
			}
		})

		It("should not render dashboard sidecar", func() {
			tenant := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "tenantA"},
				Spec:       operatorv1.TenantSpec{ID: "tenant-a"},
			}
			resources, _ := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              compliance,
				complianceFeatureActive: true,
				tenant:                  tenant,
				ns:                      render.ManagerNamespace,
			})

			deployment := rtest.GetResource(resources, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(2))
			Expect(rtest.GetContainer(deployment.Spec.Template.Spec.Containers, render.DashboardAPIName)).To(BeNil())
		})
	})

	Context("RBAC management UI", func() {
		var installation *operatorv1.InstallationSpec
		BeforeEach(func() {
			replicas := int32(1)
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.CalicoEnterprise,
				Registry:             "testregistry.com/",
			}
		})

		rbacUIEnabledEnv := func(d *appsv1.Deployment) corev1.EnvVar {
			for _, c := range d.Spec.Template.Spec.Containers {
				if c.Name == render.UIAPIsName {
					for _, e := range c.Env {
						if e.Name == "RBAC_UI_ENABLED" {
							return e
						}
					}
				}
			}
			return corev1.EnvVar{}
		}

		// Namespaced Role carries the create rule on ConfigMaps/Secrets — this
		// is the stable presence check for the RBAC management UI gate.
		nsCreateRule := rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"configmaps", "secrets"},
			Verbs:     []string{"create"},
		}

		It("renders RBAC_UI_ENABLED=false and no namespaced RBAC UI role when rbac is unset", func() {
			resources, _ := renderObjects(renderConfig{
				installation: installation,
				ns:           render.ManagerNamespace,
			})
			d := rtest.GetResource(resources, render.ManagerDeploymentName, render.ManagerNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(rbacUIEnabledEnv(d)).To(Equal(corev1.EnvVar{Name: "RBAC_UI_ENABLED", Value: "false"}))

			Expect(rtest.GetResource(resources, render.ManagerClusterRole, render.ManagerNamespace, rbacv1.GroupName, "v1", "Role")).To(BeNil())
		})

		It("renders RBAC_UI_ENABLED=false and no namespaced RBAC UI role when the Manager exists but rbacUI is unset", func() {
			resources, _ := renderObjects(renderConfig{
				installation: installation,
				ns:           render.ManagerNamespace,
				manager:      &operatorv1.Manager{Spec: operatorv1.ManagerSpec{}},
			})
			d := rtest.GetResource(resources, render.ManagerDeploymentName, render.ManagerNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(rbacUIEnabledEnv(d)).To(Equal(corev1.EnvVar{Name: "RBAC_UI_ENABLED", Value: "false"}))

			Expect(rtest.GetResource(resources, render.ManagerClusterRole, render.ManagerNamespace, rbacv1.GroupName, "v1", "Role")).To(BeNil())
		})

		It("renders RBAC_UI_ENABLED=true and the namespaced RBAC UI role when rbacUI.state is Enabled", func() {
			resources, _ := renderObjects(renderConfig{
				installation: installation,
				ns:           render.ManagerNamespace,
				manager: &operatorv1.Manager{
					Spec: operatorv1.ManagerSpec{
						RBACUI: &operatorv1.RBACUI{State: ptr.To(operatorv1.RBACUIEnabled)},
					},
				},
			})
			d := rtest.GetResource(resources, render.ManagerDeploymentName, render.ManagerNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(rbacUIEnabledEnv(d)).To(Equal(corev1.EnvVar{Name: "RBAC_UI_ENABLED", Value: "true"}))

			role := rtest.GetResource(resources, render.ManagerClusterRole, render.ManagerNamespace, rbacv1.GroupName, "v1", "Role").(*rbacv1.Role)
			Expect(role.Rules).To(ContainElement(nsCreateRule))
		})

		It("renders RBAC_UI_ENABLED=false when rbacUI.state is Disabled", func() {
			resources, _ := renderObjects(renderConfig{
				installation: installation,
				ns:           render.ManagerNamespace,
				manager: &operatorv1.Manager{
					Spec: operatorv1.ManagerSpec{
						RBACUI: &operatorv1.RBACUI{State: ptr.To(operatorv1.RBACUIDisabled)},
					},
				},
			})
			d := rtest.GetResource(resources, render.ManagerDeploymentName, render.ManagerNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(rbacUIEnabledEnv(d)).To(Equal(corev1.EnvVar{Name: "RBAC_UI_ENABLED", Value: "false"}))
		})

		It("does not add the manager-side RBAC rules in multi-tenant mode", func() {
			resources, _ := renderObjects(renderConfig{
				installation:      installation,
				ns:                "tenant-a",
				bindingNamespaces: []string{"tenant-a"},
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{Name: "tenantA", Namespace: "tenant-a"},
					Spec: operatorv1.TenantSpec{
						ID:                    "tenant-a",
						ManagedClusterVariant: &operatorv1.Calico,
					},
				},
				manager: &operatorv1.Manager{
					Spec: operatorv1.ManagerSpec{
						RBACUI: &operatorv1.RBACUI{State: ptr.To(operatorv1.RBACUIEnabled)},
					},
				},
			})
			Expect(rtest.GetResource(resources, render.ManagerClusterRole, "tenant-a", rbacv1.GroupName, "v1", "Role")).To(BeNil())
		})

		Context("LDAP egress network policy gate", func() {
			policyName := types.NamespacedName{Name: "calico-system.manager-access", Namespace: render.ManagerNamespace}
			// ldapEgress is the fallback rule shape rendered when LDAP is configured
			// on the Authentication CR but its host is empty: ports open, destination
			// unscoped.
			ldapEgress := v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Ports: networkpolicy.Ports(389, 636),
				},
			}
			rbacUIManager := &operatorv1.Manager{
				Spec: operatorv1.ManagerSpec{RBACUI: &operatorv1.RBACUI{State: ptr.To(operatorv1.RBACUIEnabled)}},
			}

			It("adds an unscoped LDAP egress when RBAC UI and LDAP auth are configured but no host is set", func() {
				resources, _ := renderObjects(renderConfig{
					installation: installation, ns: render.ManagerNamespace,
					manager: rbacUIManager, ldapConfigured: true,
				})
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				Expect(policy.Spec.Egress).To(ContainElement(ldapEgress))
			})

			It("scopes LDAP egress to a Domains match when the LDAP host is a hostname", func() {
				resources, _ := renderObjects(renderConfig{
					installation: installation, ns: render.ManagerNamespace,
					manager: rbacUIManager, ldapConfigured: true,
					ldapHost: "ad.example.com:636",
				})
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				Expect(policy.Spec.Egress).To(ContainElement(v3.Rule{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Domains: []string{"ad.example.com"},
						Ports:   networkpolicy.Ports(389, 636),
					},
				}))
				// The unscoped fallback rule must not also be present.
				Expect(policy.Spec.Egress).NotTo(ContainElement(ldapEgress))
			})

			It("scopes LDAP egress to a /32 Nets match when the LDAP host is an IPv4 address", func() {
				resources, _ := renderObjects(renderConfig{
					installation: installation, ns: render.ManagerNamespace,
					manager: rbacUIManager, ldapConfigured: true,
					ldapHost: "10.20.30.40:389",
				})
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				Expect(policy.Spec.Egress).To(ContainElement(v3.Rule{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Nets:  []string{"10.20.30.40/32"},
						Ports: networkpolicy.Ports(389, 636),
					},
				}))
				// The unscoped fallback rule must not also be present.
				Expect(policy.Spec.Egress).NotTo(ContainElement(ldapEgress))
			})

			It("scopes LDAP egress to a /128 Nets match when the LDAP host is an IPv6 address", func() {
				resources, _ := renderObjects(renderConfig{
					installation: installation, ns: render.ManagerNamespace,
					manager: rbacUIManager, ldapConfigured: true,
					ldapHost: "[2001:db8::1]:636",
				})
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				Expect(policy.Spec.Egress).To(ContainElement(v3.Rule{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Nets:  []string{"2001:db8::1/128"},
						Ports: networkpolicy.Ports(389, 636),
					},
				}))
				// The unscoped fallback rule must not also be present.
				Expect(policy.Spec.Egress).NotTo(ContainElement(ldapEgress))
			})

			It("omits LDAP egress when LDAP auth is not configured, even with RBAC UI enabled", func() {
				resources, _ := renderObjects(renderConfig{
					installation: installation, ns: render.ManagerNamespace,
					manager: rbacUIManager, ldapConfigured: false,
				})
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				Expect(policy.Spec.Egress).NotTo(ContainElement(ldapEgress))
			})

			It("omits LDAP egress when LDAP auth is configured but RBAC UI is disabled", func() {
				resources, _ := renderObjects(renderConfig{
					installation: installation, ns: render.ManagerNamespace,
					ldapConfigured: true,
				})
				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				Expect(policy.Spec.Egress).NotTo(ContainElement(ldapEgress))
			})

			It("omits LDAP egress in multi-tenant mode even with RBAC UI enabled and LDAP auth configured", func() {
				resources, _ := renderObjects(renderConfig{
					installation:      installation,
					ns:                "tenant-a",
					bindingNamespaces: []string{"tenant-a"},
					tenant: &operatorv1.Tenant{
						ObjectMeta: metav1.ObjectMeta{Name: "tenantA", Namespace: "tenant-a"},
						Spec: operatorv1.TenantSpec{
							ID:                    "tenant-a",
							ManagedClusterVariant: &operatorv1.Calico,
						},
					},
					manager:        rbacUIManager,
					ldapConfigured: true,
				})
				policy := testutils.GetCalicoSystemPolicyFromResources(
					types.NamespacedName{Name: "calico-system.manager-access", Namespace: "tenant-a"}, resources)
				Expect(policy.Spec.Egress).NotTo(ContainElement(ldapEgress))
			})
		})
	})
})

type renderConfig struct {
	oidc                    bool
	managementCluster       *operatorv1.ManagementCluster
	nonClusterHost          *operatorv1.NonClusterHost
	installation            *operatorv1.InstallationSpec
	compliance              *operatorv1.Compliance
	complianceFeatureActive bool
	openshift               bool
	ns                      string
	bindingNamespaces       []string
	ossBindingNamespaces    []string
	tenant                  *operatorv1.Tenant
	manager                 *operatorv1.Manager
	externalElastic         bool
	// ldapConfigured, when true, sets Authentication.spec.ldap (gating the RBAC-UI
	// LDAP egress rule); ldapHost sets Authentication.spec.ldap.host (scoping it).
	ldapConfigured        bool
	ldapHost              string
	cloud                 bool
	voltronMetricsEnabled bool
	cloudResources        render.ManagerCloudResources
}

func renderObjects(roc renderConfig) ([]client.Object, []client.Object) {
	var dexCfg authentication.KeyValidatorConfig
	if roc.oidc {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"},
			},
		}

		dexCfg = render.NewDexKeyValidatorConfig(authentication, dns.DefaultClusterDomain)
	}

	var tunnelSecret certificatemanagement.KeyPairInterface
	var internalTraffic certificatemanagement.KeyPairInterface
	var voltronLinseedKP certificatemanagement.KeyPairInterface

	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, roc.installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	bundle := certificatemanagement.CreateTrustedBundle(certificateManager.KeyPair())

	if roc.managementCluster != nil {
		tunnelSecret, err = certificateManager.GetOrCreateKeyPair(cli, render.VoltronTunnelSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		voltronLinseedKP, err = certificateManager.GetOrCreateKeyPair(cli, render.VoltronLinseedTLS, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())

	}
	managerTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerTLSSecretName, common.OperatorNamespace(), []string{""})
	Expect(err).NotTo(HaveOccurred())
	internalTraffic, err = certificateManager.GetOrCreateKeyPair(cli, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
	Expect(err).NotTo(HaveOccurred())

	if len(roc.bindingNamespaces) == 0 {
		roc.bindingNamespaces = []string{roc.ns}
	}

	if roc.voltronMetricsEnabled {
		roc.cloudResources.VoltronMetricsEnabled = true
		roc.cloudResources.VoltronInternalHttpsPort = 9444
	}

	cfg := &render.ManagerConfiguration{
		KeyValidatorConfig:      dexCfg,
		TrustedCertBundle:       bundle,
		TLSKeyPair:              managerTLS,
		Installation:            roc.installation,
		ManagementCluster:       roc.managementCluster,
		NonClusterHost:          roc.nonClusterHost,
		TunnelServerCert:        tunnelSecret,
		VoltronLinseedKeyPair:   voltronLinseedKP,
		InternalTLSKeyPair:      internalTraffic,
		ClusterDomain:           dns.DefaultClusterDomain,
		ESLicenseType:           render.ElasticsearchLicenseTypeEnterpriseTrial,
		Replicas:                roc.installation.ControlPlaneReplicas,
		Compliance:              roc.compliance,
		ComplianceLicenseActive: roc.complianceFeatureActive,
		OpenShift:               roc.openshift,
		Namespace:               roc.ns,
		BindingNamespaces:       roc.bindingNamespaces,
		OSSTenantNamespaces:     roc.ossBindingNamespaces,
		Tenant:                  roc.tenant,
		Manager:                 roc.manager,
		ExternalElastic:         roc.externalElastic,
		CACertCommonName:        certificateManager.CACertCommonName(),
		Cloud:                   roc.cloud,
		CloudResources:          roc.cloudResources,
	}

	if roc.ldapConfigured {
		cfg.Authentication = &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{LDAP: &operatorv1.AuthenticationLDAP{Host: roc.ldapHost}},
		}
	}

	if roc.tenant.MultiTenant() {
		cfg.TruthNamespace = roc.ns
	} else {
		cfg.TruthNamespace = common.OperatorNamespace()
	}

	component, err := render.Manager(cfg)
	Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
	Expect(component.ResolveImages(nil)).To(BeNil())
	resourcesToCreate, resourcesToDelete := component.Objects()
	return resourcesToCreate, resourcesToDelete
}
