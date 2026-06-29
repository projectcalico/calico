// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package esgateway

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var _ = Describe("ES Gateway rendering tests", func() {
	Context("ES Gateway deployment", func() {
		var installation *operatorv1.InstallationSpec
		var replicas int32
		var cfg *Config
		var cli client.Client
		clusterDomain := "cluster.local"
		expectedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/es-gateway.json")
		expectedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/es-gateway_ocp.json")

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
				Variant:              operatorv1.CalicoEnterprise,
			}
			replicas = 2
			kp, bundle := getTLS(cli, installation)

			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				ESGatewayKeyPair: kp,
				TrustedBundle:    bundle,
				KubeControllersUserSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersUserSecret, Namespace: common.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, Namespace: render.ElasticsearchNamespace}},
				},
				ClusterDomain:   clusterDomain,
				EsAdminUserName: "elastic",
				Namespace:       render.ElasticsearchNamespace,
				TruthNamespace:  common.OperatorNamespace(),
			}
		})

		It("should render an ES Gateway deployment and all supporting resources", func() {
			expectedResources := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: PolicyName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersUserSecret, Namespace: common.OperatorNamespace()}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: ServiceAccountName, Namespace: render.ElasticsearchNamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: DeploymentName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: common.OperatorNamespace()}},
			}
			createResources, _ := EsGateway(cfg).Objects()
			rtest.ExpectResources(createResources, expectedResources)

			deploy, ok := rtest.GetResource(createResources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))

			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))
		})

		It("should render Calico Cloud resources and deployment tweaks when Cloud is enabled", func() {
			cfg.Cloud = CloudConfig{
				Enabled:              true,
				EsAdminUserSecret:    &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchAdminUserSecret, Namespace: common.OperatorNamespace()}},
				ExternalCertsSecret:  &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: logstorage.ExternalCertsSecret, Namespace: common.OperatorNamespace()}},
				TenantId:             "tenantId",
				EnableMTLS:           true,
				ExternalElastic:      true,
				ExternalESDomain:     "externalEs.com",
				ExternalKibanaDomain: "externalKb.com",
			}

			expectedResources := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: PolicyName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersUserSecret, Namespace: common.OperatorNamespace()}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: ServiceAccountName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: logstorage.ExternalCertsSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchAdminUserSecret, Namespace: render.ElasticsearchNamespace}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: CloudPolicyName, Namespace: render.ElasticsearchNamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: DeploymentName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: common.OperatorNamespace()}},
			}
			createResources, _ := EsGateway(cfg).Objects()
			rtest.ExpectResources(createResources, expectedResources)

			deploy, ok := rtest.GetResource(createResources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			env := deploy.Spec.Template.Spec.Containers[0].Env
			Expect(env).To(ContainElement(corev1.EnvVar{Name: "ES_GATEWAY_METRICS_ENABLED", Value: "true"}))
			Expect(env).To(ContainElement(corev1.EnvVar{Name: "ES_GATEWAY_ELASTIC_ENDPOINT", Value: "https://externalEs.com:443"}))
			Expect(env).To(ContainElement(corev1.EnvVar{Name: "ES_GATEWAY_KIBANA_ENDPOINT", Value: "https://externalKb.com:443"}))
			Expect(env).To(ContainElement(corev1.EnvVar{Name: "ES_GATEWAY_TENANT_ID", Value: "tenantId"}))
			Expect(env).To(ContainElement(corev1.EnvVar{Name: "ES_GATEWAY_ENABLE_ELASTIC_MUTUAL_TLS", Value: "true"}))
		})

		It("should not render Calico Cloud resources when Cloud is disabled", func() {
			createResources, _ := EsGateway(cfg).Objects()
			Expect(rtest.GetResource(createResources, CloudPolicyName, render.ElasticsearchNamespace, "projectcalico.org", "v3", "NetworkPolicy")).To(BeNil())
			deploy := rtest.GetResource(createResources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(deploy.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(corev1.EnvVar{Name: "ES_GATEWAY_METRICS_ENABLED", Value: "true"}))
		})

		It("should render an ES Gateway deployment and all supporting resources when CertificateManagement is enabled", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("", "", "", nil)
			Expect(err).NotTo(HaveOccurred())
			installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: secret.Data[corev1.TLSCertKey]}
			expectedResources := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: PolicyName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersUserSecret, Namespace: common.OperatorNamespace()}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, Namespace: render.ElasticsearchNamespace}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RoleName, Namespace: render.ElasticsearchNamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: ServiceAccountName, Namespace: render.ElasticsearchNamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: DeploymentName, Namespace: render.ElasticsearchNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: common.OperatorNamespace()}},
			}
			createResources, _ := EsGateway(cfg).Objects()
			rtest.ExpectResources(createResources, expectedResources)
		})

		It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
			component := EsGateway(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			role := rtest.GetResource(resources, "tigera-secure-es-gateway", "tigera-elasticsearch", "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
			Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"nonroot-v2"},
			}))
		})

		It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
			var replicas int32 = 1
			installation.ControlPlaneReplicas = &replicas

			component := EsGateway(cfg)

			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
		})

		It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
			var replicas int32 = 2
			installation.ControlPlaneReplicas = &replicas

			component := EsGateway(cfg)

			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
			Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity(DeploymentName, []string{render.ElasticsearchNamespace})))
		})

		It("should apply controlPlaneNodeSelector correctly", func() {
			installation.ControlPlaneNodeSelector = map[string]string{"foo": "bar"}

			component := EsGateway(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
		})

		It("should apply controlPlaneTolerations correctly", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			installation.ControlPlaneTolerations = []corev1.Toleration{t}
			component := EsGateway(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
		})

		It("should render deployment with resource requests and limits", func() {
			ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			esGatewayTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.ESGatewayKeyPair = esGatewayTLS

			esGatewayResources := corev1.ResourceRequirements{
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
			cfg.LogStorage = &operatorv1.LogStorage{
				Spec: operatorv1.LogStorageSpec{
					ESGatewayDeployment: &operatorv1.ESGatewayDeployment{
						Spec: &operatorv1.ESGatewayDeploymentSpec{
							Template: &operatorv1.ESGatewayDeploymentPodTemplateSpec{
								Spec: &operatorv1.ESGatewayDeploymentPodSpec{
									InitContainers: []operatorv1.ESGatewayDeploymentInitContainer{{
										Name:      "tigera-secure-elasticsearch-cert-key-cert-provisioner",
										Resources: &esGatewayResources,
									}},
									Containers: []operatorv1.ESGatewayDeploymentContainer{{
										Name:      "tigera-secure-es-gateway",
										Resources: &esGatewayResources,
									}},
								},
							},
						},
					},
				},
			}

			component := EsGateway(cfg)
			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue(), "Deployment not found")

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))

			container := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-secure-es-gateway")
			Expect(container).NotTo(BeNil())
			Expect(container.Resources).To(Equal(esGatewayResources))

			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			initContainer := test.GetContainer(d.Spec.Template.Spec.InitContainers, "tigera-secure-elasticsearch-cert-key-cert-provisioner")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Resources).To(Equal(esGatewayResources))
		})

		Context("calico-system rendering", func() {
			policyName := types.NamespacedName{Name: "calico-system.es-gateway-access", Namespace: "tigera-elasticsearch"}

			getExpectedPolicy := func(scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
				if scenario.ManagedCluster {
					return nil
				}

				return testutils.SelectPolicyByProvider(scenario, expectedPolicy, expectedPolicyForOpenshift)
			}

			DescribeTable("should render calico-system policy",
				func(scenario testutils.CalicoSystemScenario) {
					if scenario.OpenShift {
						cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
					} else {
						cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
					}
					component := EsGateway(cfg)
					resources, _ := component.Objects()

					policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				// ES Gateway only renders in the presence of an LogStorage CR and absence of a ManagementClusterConnection CR, therefore
				// does not have a config option for managed clusters.
				Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
				Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			)
		})
	})
})

func getTLS(cli client.Client, installation *operatorv1.InstallationSpec) (certificatemanagement.KeyPairInterface, certificatemanagement.TrustedBundle) {
	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	esDNSNames := dns.GetServiceDNSNames(render.TigeraElasticsearchGatewaySecret, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	gwKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchGatewaySecret, render.ElasticsearchNamespace, esDNSNames)
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle(gwKeyPair)
	Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

	return gwKeyPair, trustedBundle
}
