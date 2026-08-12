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

package kubecontrollers

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	rkc "github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("es-kube-controllers rendering tests", func() {
	var (
		instance     *operatorv1.InstallationSpec
		k8sServiceEp k8sapi.ServiceEndpoint
		cfg          rkc.KubeControllersConfiguration
		cli          client.Client
	)

	esEnvs := []corev1.EnvVar{
		{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
		{Name: "ELASTIC_PORT", Value: "9200", ValueFrom: nil},
		{
			Name: "ELASTIC_USERNAME", Value: "",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "username",
				},
			},
		},
		{
			Name: "ELASTIC_PASSWORD", Value: "",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ee-kube-controllers-elasticsearch-access",
					},
					Key: "password",
				},
			},
		},
		{Name: "ELASTIC_CA", Value: certificatemanagement.TrustedCertBundleMountPath},
	}

	// The es-kube-controllers policy fixtures live next to the render package's
	// testutils, so reference them relative to this enterprise subpackage.
	expectedESPolicy := testutils.GetExpectedPolicyFromFile("../../render/testutils/expected_policies/es-kubecontrollers.json")
	expectedESPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../render/testutils/expected_policies/es-kubecontrollers_ocp.json")

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.

		miMode := operatorv1.MultiInterfaceModeNone
		instance = &operatorv1.InstallationSpec{
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{
				IPPools:            []operatorv1.IPPool{{CIDR: "192.168.1.0/16"}},
				MultiInterfaceMode: &miMode,
			},
			Registry: "test-reg/",
		}
		k8sServiceEp = k8sapi.ServiceEndpoint{}

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		cfg = rkc.KubeControllersConfiguration{
			K8sServiceEp:      k8sServiceEp,
			Installation:      instance,
			ClusterDomain:     dns.DefaultClusterDomain,
			MetricsPort:       9094,
			TrustedBundle:     certificateManager.CreateTrustedBundle(),
			Namespace:         common.CalicoNamespace,
			BindingNamespaces: []string{common.CalicoNamespace},
		}
	})

	It("should render all es-calico-kube-controllers resources for a default configuration (standalone) using CalicoEnterprise when logstorage and secrets exist", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: EsKubeControllerNetworkPolicyName, ns: common.CalicoNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "calico-kube-controllers", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: EsKubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: ElasticsearchKubeControllersUserSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: EsKubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operatorv1.CalicoEnterprise
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.MetricsPort = 9094

		component := NewElasticsearchKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := rtest.GetResource(resources, EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/calico:" + components.ComponentTigeraCalico.Version))
		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "authorization,elasticsearchconfiguration",
		}))
		Expect(envs).To(ContainElements(esEnvs))

		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))

		Expect(dp.Spec.Template.Spec.Volumes).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dp.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal("tigera-ca-bundle"))

		clusterRole := rtest.GetResource(resources, EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(HaveLen(26), "cluster role should have 26 rules")
		Expect(clusterRole.Rules).To(ContainElement(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"watch", "list", "get", "update", "create", "delete"},
			}))
		Expect(clusterRole.Rules).To(ContainElement(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"watch", "list", "get"},
			}))
	})

	It("should render all es-calico-kube-controllers resources for a default configuration using CalicoEnterprise and ClusterType is Management", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: EsKubeControllerNetworkPolicyName, ns: common.CalicoNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "calico-kube-controllers", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: rkc.ManagedClustersWatchRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: EsKubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: ElasticsearchKubeControllersUserSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: EsKubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.MetricsPort = 9094

		component := NewElasticsearchKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The Deployment should have the correct configuration.
		dp := rtest.GetResource(resources, EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name:  "ENABLED_CONTROLLERS",
			Value: "authorization,elasticsearchconfiguration,managedcluster",
		}))

		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))

		Expect(dp.Spec.Template.Spec.Volumes).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(dp.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal("tigera-ca-bundle"))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/calico:" + components.ComponentTigeraCalico.Version))

		clusterRole := rtest.GetResource(resources, EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(HaveLen(26), "cluster role should have 26 rules")
		Expect(clusterRole.Rules).To(ContainElement(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"watch", "list", "get", "update", "create", "delete"},
			}))
		Expect(clusterRole.Rules).To(ContainElement(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"watch", "list", "get"},
			}))
		roleBindingWatch := rtest.GetResource(resources, rkc.ManagedClustersWatchRoleBindingName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(roleBindingWatch.RoleRef.Name).To(Equal(render.ManagedClustersWatchClusterRoleName))
		Expect(roleBindingWatch.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      rkc.KubeControllerServiceAccount,
				Namespace: common.CalicoNamespace,
			},
		}))
	})

	It("should add the OIDC prefix env variables", func() {
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.MetricsPort = 9094
		cfg.Authentication = &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{
			UsernamePrefix: "uOIDC:",
			GroupsPrefix:   "gOIDC:",
			Openshift:      &operatorv1.AuthenticationOpenshift{IssuerURL: "https://api.example.com"},
		}}

		component := NewElasticsearchKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)

		var usernamePrefix, groupPrefix string
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == EsKubeController {
				for _, env := range container.Env {
					switch env.Name {
					case "OIDC_AUTH_USERNAME_PREFIX":
						usernamePrefix = env.Value
					case "OIDC_AUTH_GROUP_PREFIX":
						groupPrefix = env.Value
					}
				}
			}
		}

		Expect(usernamePrefix).To(Equal("uOIDC:"))
		Expect(groupPrefix).To(Equal("gOIDC:"))
	})

	When("enableESOIDCWorkaround is true", func() {
		It("should set the ENABLE_ELASTICSEARCH_OIDC_WORKAROUND env variable to true", func() {
			instance.Variant = operatorv1.CalicoEnterprise
			cfg.ManagementCluster = &operatorv1.ManagementCluster{}
			cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
			cfg.MetricsPort = 9094
			component := NewElasticsearchKubeControllers(&cfg)
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			deployment := depResource.(*appsv1.Deployment)

			var esLicenseType string
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == EsKubeController {
					for _, env := range container.Env {
						if env.Name == "ENABLE_ELASTICSEARCH_OIDC_WORKAROUND" {
							esLicenseType = env.Value
						}
					}
				}
			}

			Expect(esLicenseType).To(Equal("true"))
		})
	})

	Context("es-kube-controllers calico-system rendering", func() {
		policyName := types.NamespacedName{Name: "calico-system.es-kube-controller-access", Namespace: common.CalicoNamespace}

		getExpectedPolicy := func(scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
			if scenario.ManagedCluster {
				return nil
			}

			return testutils.SelectPolicyByProvider(scenario, expectedESPolicy, expectedESPolicyForOpenshift)
		}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				if scenario.OpenShift {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
				} else {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
				}
				if scenario.ManagedCluster {
					cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
				} else {
					cfg.ManagementClusterConnection = nil
				}
				instance.Variant = operatorv1.CalicoEnterprise
				cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret

				component := NewElasticsearchKubeControllers(&cfg)
				resources, _ := component.Objects()

				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
		)
	})
})
