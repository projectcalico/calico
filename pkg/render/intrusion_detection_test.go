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
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var (
	managedCluster    = true
	notManagedCluster = false
)

type expectedEnvVar struct {
	name       string
	val        string
	secretName string
	secretKey  string
}

var _ = Describe("Intrusion Detection rendering tests", func() {
	var (
		cfg     *render.IntrusionDetectionConfiguration
		bundle  certificatemanagement.TrustedBundle
		keyPair certificatemanagement.KeyPairInterface
		cli     client.Client
	)

	expectedIDPolicyForStandalone := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_standalone.json")
	expectedIDPolicyForManaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_managed.json")
	expectedIDPolicyForStandaloneOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_standalone_ocp.json")
	expectedIDPolicyForManagedOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_managed_ocp.json")
	expectedIDPolicyForManagement := testutils.GetExpectedPolicyFromFileWithReplacements("testutils/expected_policies/intrusion-detection-controller_management.json", map[string]string{
		"MANAGER_NAMESPACE": render.ManagerNamespace,
		"MANAGER_NAME":      render.ManagerName,
	})
	expectedIDPolicyForManagementOCP := testutils.GetExpectedPolicyFromFileWithReplacements("testutils/expected_policies/intrusion-detection-controller_management_ocp.json", map[string]string{
		"MANAGER_NAMESPACE": render.ManagerNamespace,
		"MANAGER_NAME":      render.ManagerName,
	})

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		secretTLS, err := certificatemanagement.CreateSelfSignedSecret(render.IntrusionDetectionTLSSecretName, "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		keyPair = certificatemanagement.NewKeyPair(secretTLS, []string{""}, "")

		bundle = certificateManager.CreateTrustedBundle()

		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		cfg = &render.IntrusionDetectionConfiguration{
			TrustedCertBundle:            bundle,
			IntrusionDetectionCertSecret: keyPair,
			Installation:                 &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			ClusterDomain:                dns.DefaultClusterDomain,
			ESLicenseType:                render.ElasticsearchLicenseTypeUnknown,
			ManagedCluster:               notManagedCluster,
			Namespace:                    render.IntrusionDetectionNamespace,
			BindNamespaces:               []string{"tigera-intrusion-detection"},
			Tenant:                       nil,
		}
	})

	It("should render all resources for a default configuration", func() {
		cfg.OpenShift = false
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		expected := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.pod"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkpolicy"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkset"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.serviceaccount"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.cloudapi"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.ssh"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.access"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.originate"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.servfail"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.dos"}},
		}
		rtest.ExpectResources(resources, expected)

		// Check that GlobalAlertTemplates are populated
		for i, res := range resources {
			switch res.(type) {
			case *v3.GlobalAlertTemplate:
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		// Should mount ManagerTLSSecret for non-managed clusters
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Containers).To(HaveLen(2))
		idcExpectedEnvVars := []corev1.EnvVar{
			{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			{Name: "LINSEED_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "LINSEED_CLIENT_CERT", Value: "/intrusion-detection-tls/tls.crt"},
			{Name: "LINSEED_CLIENT_KEY", Value: "/intrusion-detection-tls/tls.key"},
			{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
			{Name: "MANAGEMENT_CLUSTER", Value: "false"},
		}
		Expect(idc.Spec.Template.Spec.Containers[0].Env).To(Equal(idcExpectedEnvVars))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(2))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("intrusion-detection-tls"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/intrusion-detection-tls"))

		Expect(idc.Spec.Template.Spec.Volumes).To(HaveLen(2))
		Expect(idc.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.IntrusionDetectionTLSSecretName))
		Expect(idc.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.IntrusionDetectionTLSSecretName))

		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(idc.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(idc.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.Privileged).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(idc.Spec.Template.Spec.Containers[1].SecurityContext.Capabilities).To(Equal(&corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}))
		Expect(idc.Spec.Template.Spec.Containers[1].SecurityContext.SeccompProfile).To(Equal(&corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}))

		clusterRole := rtest.GetResource(resources, "intrusion-detection-controller", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs", "jobs"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets", "configmaps"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"securityeventwebhooks", "securityeventwebhooks/status"},
				Verbs:     []string{"get", "list", "watch", "update"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"alertexceptions"},
				Verbs:     []string{"get", "list"},
			},
		))

		role := rtest.GetResource(resources, render.IntrusionDetectionName, render.IntrusionDetectionNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(role.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get"},
			},
			rbacv1.PolicyRule{
				// Intrusion detection forwarder snapshots its state to a specific ConfigMap.
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "create", "update"},
			},
		))

		roleBinding := rtest.GetResource(resources, render.IntrusionDetectionName, render.IntrusionDetectionNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(roleBinding.RoleRef.Name).To(Equal(render.IntrusionDetectionName))
		Expect(roleBinding.RoleRef.Kind).To(Equal("Role"))
		Expect(roleBinding.RoleRef.APIGroup).To(Equal("rbac.authorization.k8s.io"))
		Expect(roleBinding.Subjects).To(ContainElements(
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      render.IntrusionDetectionName,
				Namespace: render.IntrusionDetectionNamespace,
			},
		))

		// The managed-clusters watch binding should not be rendered on standalone clusters.
		Expect(rtest.GetResource(resources, render.IntrusionDetectionManagedClustersWatchRoleBindingName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).To(BeNil())
	})

	It("should render the managed-clusters watch ClusterRoleBinding on a management cluster", func() {
		cfg.ManagementCluster = true
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		crb := rtest.GetResource(resources, render.IntrusionDetectionManagedClustersWatchRoleBindingName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Name).To(Equal(render.ManagedClustersWatchClusterRoleName))
		Expect(crb.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.IntrusionDetectionName,
				Namespace: render.IntrusionDetectionNamespace,
			},
		}))

		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "MANAGEMENT_CLUSTER", Value: "true"}))
	})

	It("should render finalizers rbac resources in the IDS ClusterRole for an Openshift management/standalone cluster", func() {
		cfg.OpenShift = true
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.ManagedCluster = false
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		idsControllerRole := rtest.GetResource(resources, render.IntrusionDetectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)

		Expect(idsControllerRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments/finalizers"},
			Verbs:     []string{"update"},
		}))
	})

	It("should render all resources for a configuration that includes event forwarding turned on (Syslog)", func() {
		// Initialize a default LogCollector instance to use.
		cfg.LogCollector = &operatorv1.LogCollector{}
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		cfg.OpenShift = false

		cfg.SyslogForwardingIsEnabled = true
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		expected := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.pod"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkpolicy"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkset"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.serviceaccount"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.cloudapi"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.ssh"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.access"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.originate"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.servfail"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.dos"}},
		}
		rtest.ExpectResources(resources, expected)

		// Check that GlobalAlertTemplates are populated
		for i, res := range resources {
			switch res.(type) {
			case *v3.GlobalAlertTemplate:
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		dp := rtest.GetResource(resources, "intrusion-detection-controller", "tigera-intrusion-detection", "apps", "v1", "Deployment").(*appsv1.Deployment)
		envs := dp.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []expectedEnvVar{
			{"MULTI_CLUSTER_FORWARDING_CA", cfg.TrustedCertBundle.MountPath(), "", ""},
			{"IDS_ENABLE_EVENT_FORWARDING", "true", "", ""},
		}

		assertEnvVarlistMatch(envs, expectedEnvs)

		// Validate that even with syslog configured we still have the CA configmap Volume
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Volumes).To(HaveLen(3))
		Expect(idc.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.IntrusionDetectionTLSSecretName))
		Expect(idc.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.IntrusionDetectionTLSSecretName))
		Expect(idc.Spec.Template.Spec.Volumes[2].Name).To(Equal("var-log-calico"))
		Expect(idc.Spec.Template.Spec.Volumes[2].VolumeSource.HostPath.Path).To(Equal("/var/log/calico"))

		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(idc.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(idc.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
	})

	It("should disable GlobalAlert controller when cluster is managed", func() {
		cfg.OpenShift = false
		cfg.ManagedCluster = managedCluster

		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		expected := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.pod"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkpolicy"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkset"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.serviceaccount"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.cloudapi"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.ssh"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.access"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.originate"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.servfail"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.dos"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: "tigera-intrusion-detection"}},
		}
		rtest.ExpectResources(resources, expected)

		// Check that GlobalAlertTemplates are populated
		for i, res := range resources {
			switch res.(type) {
			case *v3.GlobalAlertTemplate:
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Containers[0].Env).To(ContainElements(
			corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: cfg.TrustedCertBundle.MountPath()},
			corev1.EnvVar{Name: "DISABLE_ALERTS", Value: "yes"},
		))

		clusterRole := rtest.GetResource(resources, "intrusion-detection-controller", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).NotTo(ContainElements([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs", "jobs"},
				Verbs: []string{
					"get", "list", "watch", "create", "update", "patch", "delete",
				},
			},
		}))
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.OpenShift = true
		component := render.IntrusionDetection(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "intrusion-detection-controller", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	It("should apply controlPlaneNodeSelector correctly", func() {
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
		}
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
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
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
	})

	It("should render toleration on GKE", func() {
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderGKE,
		}
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc).NotTo(BeNil())
		Expect(idc.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
	})

	Context("calico-system rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "calico-system.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"},
			{Name: "calico-system.intrusion-detection-elastic", Namespace: "tigera-intrusion-detection"},
		}

		getExpectedPolicy := func(policyName types.NamespacedName, scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
			if policyName.Name == "calico-system.intrusion-detection-controller" {
				return testutils.SelectPolicyByClusterTypeAndProvider(scenario,
					map[string]*v3.NetworkPolicy{
						"standalone":           expectedIDPolicyForStandalone,
						"standalone-openshift": expectedIDPolicyForStandaloneOCP,
						"managed":              expectedIDPolicyForManaged,
						"managed-openshift":    expectedIDPolicyForManagedOCP,
						"management":           expectedIDPolicyForManagement,
						"management-openshift": expectedIDPolicyForManagementOCP,
					},
				)
			}

			return nil
		}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				cfg.OpenShift = scenario.OpenShift
				cfg.ManagedCluster = scenario.ManagedCluster
				cfg.ManagementCluster = scenario.ManagementCluster
				component := render.IntrusionDetection(cfg)
				resources, _ := component.Objects()

				for _, policyName := range policyNames {
					policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},
			Entry("for standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false, ManagementCluster: false}),
			Entry("for standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true, ManagementCluster: false}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false, ManagementCluster: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true, ManagementCluster: false}),
			Entry("for management, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false, ManagementCluster: true}),
			Entry("for management, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true, ManagementCluster: true}),
		)
	})

	It("should render an init container for pods when certificate management is enabled", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		intrusionDetectionCertSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.IntrusionDetectionTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg.IntrusionDetectionCertSecret = intrusionDetectionCertSecret

		component := render.IntrusionDetection(cfg)
		toCreate, _ := component.Objects()

		intrusionDetectionDeploy := rtest.GetResource(toCreate, "intrusion-detection-controller", "tigera-intrusion-detection", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(intrusionDetectionDeploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := intrusionDetectionDeploy.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.IntrusionDetectionTLSSecretName)))
	})

	It("should render container and init container with resource requests/limits when configured", func() {
		intrusionDetectionResources := corev1.ResourceRequirements{
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

		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		intrusionDetectionCertSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.IntrusionDetectionTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg.IntrusionDetectionCertSecret = intrusionDetectionCertSecret
		cfg.IntrusionDetection = &operatorv1.IntrusionDetection{
			Spec: operatorv1.IntrusionDetectionSpec{
				IntrusionDetectionControllerDeployment: &operatorv1.IntrusionDetectionControllerDeployment{
					Spec: &operatorv1.IntrusionDetectionControllerDeploymentSpec{
						Template: &operatorv1.IntrusionDetectionControllerDeploymentPodTemplateSpec{
							Spec: &operatorv1.IntrusionDetectionControllerDeploymentPodSpec{
								Containers: []operatorv1.IntrusionDetectionControllerDeploymentContainer{{
									Name:      "controller",
									Resources: &intrusionDetectionResources,
								}},
								InitContainers: []operatorv1.IntrusionDetectionControllerDeploymentInitContainer{{
									Name:      "tigera-dex-tls-key-cert-provisioner",
									Resources: &intrusionDetectionResources,
								}},
							},
						},
					},
				},
			},
		}

		component := render.IntrusionDetection(cfg)
		toCreate, _ := component.Objects()

		intrusionDetectionDeploy := rtest.GetResource(toCreate, "intrusion-detection-controller", "tigera-intrusion-detection", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(intrusionDetectionDeploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := intrusionDetectionDeploy.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.IntrusionDetectionTLSSecretName)))

		// Should set requests/limits for controller container
		Expect(intrusionDetectionDeploy.Spec.Template.Spec.Containers).To(HaveLen(2))
		container := test.GetContainer(intrusionDetectionDeploy.Spec.Template.Spec.Containers, "controller")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(intrusionDetectionResources))

		// Should not update for container webhooks-processor
		container = test.GetContainer(intrusionDetectionDeploy.Spec.Template.Spec.Containers, "webhooks-processor")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(corev1.ResourceRequirements{}))
	})

	It("should render configuration with default Init container resource requests and limits", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		intrusionDetectionCertSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.IntrusionDetectionTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg.IntrusionDetectionCertSecret = intrusionDetectionCertSecret

		component := render.IntrusionDetection(cfg)
		toCreate, _ := component.Objects()
		intrusionDetectionDeploy, ok := rtest.GetResource(toCreate, "intrusion-detection-controller", "tigera-intrusion-detection", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(intrusionDetectionDeploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))

		initContainer := test.GetContainer(intrusionDetectionDeploy.Spec.Template.Spec.InitContainers, "intrusion-detection-tls-key-cert-provisioner")
		Expect(initContainer).NotTo(BeNil())
		Expect(initContainer.Resources).To(Equal(corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    resource.MustParse("10m"),
				"memory": resource.MustParse("50Mi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    resource.MustParse("10m"),
				"memory": resource.MustParse("50Mi"),
			},
		}))
	})

	It("should NOT render impersonation permissions as part of intrusion detection ClusterRole", func() {
		component := render.IntrusionDetection(cfg)
		Expect(component).NotTo(BeNil())
		resources, _ := component.Objects()
		cr := rtest.GetResource(resources, render.IntrusionDetectionControllerName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
		expectedRules := []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{render.IntrusionDetectionControllerName},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
				ResourceNames: []string{
					serviceaccount.AllServiceAccountsGroup,
					"system:authenticated",
					fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, render.IntrusionDetectionNamespace),
				},
			},
		}
		Expect(cr.Rules).NotTo(ContainElements(expectedRules))
	})

	Context("multi-tenant rendering", func() {
		tenantANamespace := "tenant-a-ns"
		tenantBNamespace := "tenant-b-ns"
		var tenantA *operatorv1.Tenant

		BeforeEach(func() {
			// Configure a tenant.
			tenantA = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: tenantANamespace},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a",
				},
			}
			cfg.Namespace = tenantANamespace
			cfg.BindNamespaces = []string{tenantANamespace, tenantBNamespace}
			cfg.Tenant = tenantA
			cfg.ExternalElastic = true
			cfg.ManagementCluster = true
		})

		It("should render multi-tenant resources", func() {
			component := render.IntrusionDetection(cfg)
			toCreate, _ := component.Objects()

			expected := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.intrusion-detection-controller", Namespace: tenantANamespace}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: tenantANamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: tenantANamespace}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: tenantANamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: tenantANamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-intrusion-detection-managed-cluster-access", Namespace: tenantANamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: tenantANamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.IntrusionDetectionManagedClustersWatchRoleBindingName, Namespace: tenantANamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			}
			rtest.ExpectResources(toCreate, expected)

			netpol, err := rtest.GetResourceOfType[*v3.NetworkPolicy](toCreate, render.IntrusionDetectionControllerPolicyName, tenantANamespace)
			Expect(err).NotTo(HaveOccurred())

			Expect(netpol.Spec.Ingress).To(ConsistOf(v3.Rule{Action: v3.Deny}))

			expectedEgressRules := []v3.Rule{
				{
					Action:   v3.Deny,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Nets: []string{"169.254.0.0/16"},
					},
				},
				{
					Action:   v3.Deny,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Nets: []string{"fe80::/10"},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.UDPProtocol,
					Destination: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'kube-system'",
						Selector:          "k8s-app in { 'kube-dns', 'coredns' }",
						Ports:             networkpolicy.Ports(53),
					},
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Destination: networkpolicy.CreateEntityRule(tenantANamespace, "tigera-linseed", 8444),
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", tenantANamespace),
						Selector:          "k8s-app == 'calico-manager'",
						Ports:             networkpolicy.Ports(9443),
					},
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Destination: networkpolicy.KubeAPIServerEntityRule,
				},
				{
					Action: v3.Pass,
				},
			}
			Expect(netpol.Spec.Egress).To(ConsistOf(expectedEgressRules))
		})

		It("should render multi-tenant environment variables", func() {
			component := render.IntrusionDetection(cfg)
			toCreate, _ := component.Objects()

			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](toCreate, render.IntrusionDetectionName, tenantANamespace)
			Expect(err).NotTo(HaveOccurred())

			envs := deployment.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: tenantANamespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "tenant-a"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", tenantANamespace)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: render.ManagerService(tenantA)}))
		})

		It("should render impersonation permissions as part of tigera-intrusion-detection ClusterRole", func() {
			component := render.IntrusionDetection(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			cr := rtest.GetResource(resources, render.IntrusionDetectionControllerName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts"},
					Verbs:         []string{"impersonate"},
					ResourceNames: []string{render.IntrusionDetectionControllerName},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"groups"},
					Verbs:     []string{"impersonate"},
					ResourceNames: []string{
						serviceaccount.AllServiceAccountsGroup,
						"system:authenticated",
						fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, render.IntrusionDetectionNamespace),
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
		})

		It("should render managed cluster permissions as part of tigera-intrusion-detection-managed-clusters-access ClusterRole", func() {
			component := render.IntrusionDetection(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			rb := rtest.GetResource(resources, render.MultiTenantManagedClustersAccessClusterRoleBindingName, tenantA.Namespace, rbacv1.GroupName, "v1", "RoleBinding").(*rbacv1.RoleBinding)
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(render.MultiTenantManagedClustersAccessClusterRoleName))
			Expect(rb.Subjects).To(ContainElements([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.IntrusionDetectionControllerName,
					Namespace: render.IntrusionDetectionNamespace,
				},
			}))
		})

		It("should render managed cluster permissions as part of tigera-intrusion-detection-managed-clusters-watch ClusterRole", func() {
			component := render.IntrusionDetection(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			rb := rtest.GetResource(resources, render.IntrusionDetectionManagedClustersWatchRoleBindingName, tenantA.Namespace, rbacv1.GroupName, "v1", "RoleBinding").(*rbacv1.RoleBinding)
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(render.ManagedClustersWatchClusterRoleName))
			Expect(rb.Subjects).To(ContainElements([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.IntrusionDetectionControllerName,
					Namespace: tenantA.Namespace,
				},
			}))
		})

		It("should render NOT render web hooks inside the management cluster", func() {
			component := render.IntrusionDetection(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			deployment := rtest.GetResource(resources, render.IntrusionDetectionControllerName, tenantA.Namespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(deployment.Spec.Template.Spec.Containers[0].Name).To(Equal("controller"))
		})
	})
})

func assertEnvVarlistMatch(envVars []corev1.EnvVar, expectedEnvVars []expectedEnvVar) {
	for _, expected := range expectedEnvVars {
		if expected.val != "" {
			ExpectWithOffset(1, envVars).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
		} else {
			ExpectWithOffset(1, envVars).To(ContainElement(corev1.EnvVar{
				Name: expected.name,
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
						Key:                  expected.secretKey,
					},
				},
			}))
		}
	}
}
