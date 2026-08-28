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

package render_test

import (
	"context"
	"fmt"

	v1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/common/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"

	batchv1 "k8s.io/api/batch/v1"
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
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

type resourceTestObj struct {
	name string
	ns   string
	typ  runtime.Object
	f    func(resource runtime.Object)
}

var _ = Describe("Elasticsearch rendering tests", func() {
	// Setup shared policies utilities that require Ginkgo context.
	var (
		expectedESPolicy             = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elasticsearch.json")
		expectedESPolicyForOpenshift = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elasticsearch_ocp.json")
		expectedESInternalPolicy     = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elasticsearch-internal.json")
	)
	getExpectedPolicy := func(policyName types.NamespacedName, scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
		if scenario.ManagedCluster {
			return nil
		}

		switch policyName.Name {
		case "calico-system.elasticsearch-access":
			return testutils.SelectPolicyByProvider(scenario, expectedESPolicy, expectedESPolicyForOpenshift)

		case "calico-system.elasticsearch-internal":
			return expectedESInternalPolicy

		default:
			return nil
		}
	}

	Context("Standalone cluster type", func() {
		var cfg *render.ElasticsearchConfiguration
		replicas := int32(1)
		retention := int32(1)

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
					Indices: &operatorv1.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
						DNSLogs:           &retention,
						BGPLogs:           &retention,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderOpenShift,
				Registry:             "testregistry.com/",
			}

			esConfig := relasticsearch.NewClusterConfig("cluster", 1, 1, 1)

			elasticsearchKeyPair, trustedBundle := getTLS(installation)
			cfg = &render.ElasticsearchConfiguration{
				LogStorage:           logStorage,
				Installation:         installation,
				ClusterConfig:        esConfig,
				ElasticsearchKeyPair: elasticsearchKeyPair,
				PullSecrets: []*corev1.Secret{
					{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           installation.KubernetesProvider,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
				TrustedBundle:      trustedBundle,
			}
		})

		It("should not panic if an empty spec is provided", func() {
			// Override with an instance that has no spec.
			cfg.LogStorage = &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{},
			}

			component := render.LogStorage(cfg)

			// Render the objects and make sure we don't panic!
			_, _ = component.Objects()
		})

		Context("Initial creation", func() {
			It("should render an elasticsearchComponent", func() {
				expectedCreateResources := []client.Object{
					// ES resources
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchInternalPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.ElasticsearchNamespace}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: render.ElasticsearchNamespace}},
					&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch", Namespace: render.ElasticsearchNamespace}},
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}},
					&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRole, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRoleBinding, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: render.ElasticsearchNamespace}},
				}

				component := render.LogStorage(cfg)
				createResources, deleteResources := component.Objects()
				rtest.ExpectResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{
					{"allow-tigera.elasticsearch-access", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"allow-tigera.elasticsearch-internal", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"allow-tigera.default-deny", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				})

				namespace := rtest.GetResource(createResources, "tigera-elasticsearch", "", "", "v1", "Namespace").(*corev1.Namespace)
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("privileged"))
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

				resultES := rtest.GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)

				// There are no node selectors in the LogStorage CR, so we expect no node selectors in the Elasticsearch CR.
				Expect(resultES.Spec.NodeSets).To(HaveLen(1))
				nodeSet := resultES.Spec.NodeSets[0]
				Expect(nodeSet.PodTemplate.Spec.NodeSelector).To(BeEmpty())

				// Verify that an initContainer is added
				initContainers := resultES.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
				Expect(initContainers).To(HaveLen(3))
				Expect(initContainers[0].Name).To(Equal("elastic-internal-init-os-settings"))
				Expect(*initContainers[0].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
				Expect(*initContainers[0].SecurityContext.Privileged).To(BeTrue())
				Expect(*initContainers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*initContainers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
				Expect(*initContainers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
				Expect(initContainers[0].SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(initContainers[0].SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				// Verify that the default container limits/requests are set.
				Expect(resultES.Spec.NodeSets[0].PodTemplate.Spec.Containers).To(HaveLen(1))
				esContainer := resultES.Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
				Expect(*esContainer.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
				Expect(*esContainer.SecurityContext.Privileged).To(BeFalse())
				Expect(*esContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
				Expect(*esContainer.SecurityContext.RunAsNonRoot).To(BeTrue())
				Expect(*esContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
				Expect(esContainer.SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(esContainer.SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				limits := esContainer.Resources.Limits
				resources := esContainer.Resources.Requests

				Expect(limits.Cpu().String()).To(Equal("1"))
				Expect(limits.Memory().String()).To(Equal("4Gi"))
				Expect(resources.Cpu().String()).To(Equal("250m"))
				Expect(resources.Memory().String()).To(Equal("4Gi"))
				Expect(esContainer.Env[0].Value).To(Equal("-Xms2G -Xmx2G"))

				// Check that the expected config made it's way to the Elastic CR
				Expect(nodeSet.Config.Data).Should(Equal(map[string]interface{}{
					"node.roles":                              []string{"data", "ingest", "master", "remote_cluster_client"},
					"cluster.max_shards_per_node":             10000,
					"ingest.geoip.downloader.enabled":         false,
					"xpack.eql.default_allow_partial_results": false,
					"indices.lifecycle.poll_interval":         "60m",
				}))
			})

			It("should render an elasticsearch Component and delete the Elasticsearch ExternalService as well as Curator components", func() {
				expectedCreateResources := []client.Object{
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchInternalPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.ElasticsearchNamespace}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: render.ElasticsearchNamespace}},
					&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch", Namespace: render.ElasticsearchNamespace}},
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}},
					&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRole, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRoleBinding, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.ElasticsearchNamespace}},
				}

				expectedDeleteResources := []resourceTestObj{
					{"allow-tigera.elasticsearch-access", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"allow-tigera.elasticsearch-internal", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"allow-tigera.default-deny", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ElasticsearchServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
				}

				cfg.ESService = &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName},
				}
				cfg.ElasticLicenseType = render.ElasticsearchLicenseTypeBasic

				component := render.LogStorage(cfg)

				createResources, deleteResources := component.Objects()
				rtest.ExpectResources(createResources, expectedCreateResources)
				// compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, expectedDeleteResources)
			})

			It("should render an elasticsearchComponent with certificate management enabled", func() {
				cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{
					CACert:             cfg.ElasticsearchKeyPair.GetCertificatePEM(),
					SignerName:         "my signer name",
					SignatureAlgorithm: "ECDSAWithSHA256",
					KeyAlgorithm:       "ECDSAWithCurve521",
				}

				cfg.ElasticsearchKeyPair, cfg.TrustedBundle = getTLS(cfg.Installation)

				expectedCreateResources := []client.Object{
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchInternalPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.ElasticsearchNamespace}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: render.ElasticsearchNamespace}},
					&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch", Namespace: render.ElasticsearchNamespace}},
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}},
					&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRole, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRoleBinding, Namespace: render.ElasticsearchNamespace}},
					// Certificate management comes with two additional cluster role bindings:
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.UnusedCertSecret, Namespace: common.OperatorNamespace()}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchInternalCertSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.ElasticsearchNamespace}},
				}

				cfg.UnusedTLSSecret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.UnusedCertSecret, Namespace: common.OperatorNamespace()},
				}
				component := render.LogStorage(cfg)

				createResources, deleteResources := component.Objects()
				rtest.ExpectResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{
					{"allow-tigera.elasticsearch-access", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"allow-tigera.elasticsearch-internal", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"allow-tigera.default-deny", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				})

				resultES := rtest.GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)

				initContainers := resultES.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
				Expect(initContainers).To(HaveLen(5))
				compareInitContainer := func(ic corev1.Container, expectedName string, expectedVolumes []corev1.VolumeMount, privileged bool) {
					Expect(ic.Name).To(Equal(expectedName))
					Expect(ic.VolumeMounts).To(HaveLen(len(expectedVolumes)))
					Expect(ic.SecurityContext.Privileged).To(Equal(&privileged))
					for i, vm := range ic.VolumeMounts {
						Expect(vm.Name).To(Equal(expectedVolumes[i].Name))
						Expect(vm.MountPath).To(Equal(expectedVolumes[i].MountPath))
					}
				}
				compareInitContainer(initContainers[0], "elastic-internal-init-os-settings", []corev1.VolumeMount{}, true)
				compareInitContainer(initContainers[1], "elastic-internal-init-filesystem", []corev1.VolumeMount{
					{Name: "elastic-internal-transport-certificates", MountPath: "/csr"},
				}, true)
				compareInitContainer(initContainers[2], "elastic-internal-suspend", nil, true)
				compareInitContainer(initContainers[3], "key-cert-elastic", []corev1.VolumeMount{
					{Name: "elastic-internal-http-certificates", MountPath: certificatemanagement.CSRCMountPath},
				}, false)
				compareInitContainer(initContainers[4], "key-cert-elastic-transport", []corev1.VolumeMount{
					{Name: "elastic-internal-transport-certificates", MountPath: certificatemanagement.CSRCMountPath},
				}, false)
				Expect(resultES.Spec.NodeSets[0].Config).To(Equal(&v1.Config{Data: map[string]interface{}{
					"node.roles": []string{
						"data",
						"ingest",
						"master",
						"remote_cluster_client",
					},
					"cluster.max_shards_per_node":                     10000,
					"ingest.geoip.downloader.enabled":                 false,
					"xpack.eql.default_allow_partial_results":         false,
					"indices.lifecycle.poll_interval":                 "60m",
					"xpack.security.http.ssl.certificate_authorities": []string{"/usr/share/elasticsearch/config/http-certs/ca.crt"},
					"xpack.security.transport.ssl.key":                "/usr/share/elasticsearch/config/transport-certs/transport.tls.key",
					"xpack.security.transport.ssl.certificate":        "/usr/share/elasticsearch/config/transport-certs/transport.tls.crt",
				}}))
			})

			It("should render toleration on GKE", func() {
				cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

				component := render.LogStorage(cfg)
				createResources, _ := component.Objects()

				resultES := rtest.GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)
				Expect(resultES).NotTo(BeNil())
				Expect(resultES.Spec.NodeSets[0].PodTemplate.Spec.Tolerations).To(ContainElements(corev1.Toleration{
					Key:      "kubernetes.io/arch",
					Operator: corev1.TolerationOpEqual,
					Value:    "arm64",
					Effect:   corev1.TaintEffectNoSchedule,
				}))
			})
		})

		Context("Elasticsearch with a default cluster domain", func() {
			BeforeEach(func() {
				cfg.ClusterDomain = dns.DefaultClusterDomain
			})

			It("should render correctly", func() {
				expectedCreateResources := []client.Object{
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchInternalPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.ElasticsearchNamespace}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: render.ElasticsearchNamespace}},
					&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch", Namespace: render.ElasticsearchNamespace}},
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}},
					&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRole, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRoleBinding, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.ElasticsearchNamespace}},
				}

				cfg.Provider = operatorv1.ProviderNone
				component := render.LogStorage(cfg)
				createResources, deleteResources := component.Objects()
				rtest.ExpectResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{
					{"allow-tigera.elasticsearch-access", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"allow-tigera.elasticsearch-internal", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"allow-tigera.default-deny", render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				})
			})

			Context("calico-system rendering", func() {
				policyNames := []types.NamespacedName{
					{Name: "calico-system.elasticsearch-access", Namespace: "tigera-elasticsearch"},
					{Name: "calico-system.elasticsearch-internal", Namespace: "tigera-elasticsearch"},
				}

				DescribeTable("should render calico-system policy",
					func(scenario testutils.CalicoSystemScenario) {
						if scenario.OpenShift {
							cfg.Provider = operatorv1.ProviderOpenShift
						} else {
							cfg.Provider = operatorv1.ProviderNone
						}

						component := render.LogStorage(cfg)
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
		})

		Context("Deleting LogStorage", deleteLogStorageTests(nil, nil))

		Context("Updating LogStorage resource", func() {
			It("should create new NodeSet", func() {
				cfg.LogStorage = &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: 1,
							ResourceRequirements: &corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									"cpu":    resource.MustParse("1"),
									"memory": resource.MustParse("150Mi"),
								},
								Requests: corev1.ResourceList{
									"cpu":     resource.MustParse("1"),
									"memory":  resource.MustParse("150Mi"),
									"storage": resource.MustParse("10Gi"),
								},
							},
						},
					},
				}
				cfg.Elasticsearch = &esv1.Elasticsearch{
					Spec: esv1.ElasticsearchSpec{
						NodeSets: []esv1.NodeSet{
							{
								Name: "default",
								VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
									{
										Spec: corev1.PersistentVolumeClaimSpec{
											StorageClassName: ptr.To("tigera-elasticsearch"),
										},
									},
								},
							},
						},
					},
				}

				component := render.LogStorage(cfg)

				createResources, _ := component.Objects()

				oldNodeSetName := rtest.GetResource(createResources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch).Spec.NodeSets[0].Name

				// update resource requirements
				cfg.LogStorage.Spec.Nodes.ResourceRequirements = &corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("150Mi"),
					},
					Requests: corev1.ResourceList{
						"cpu":     resource.MustParse("1"),
						"memory":  resource.MustParse("2Gi"),
						"storage": resource.MustParse("5Gi"),
					},
				}

				updatedComponent := render.LogStorage(cfg)

				updatedResources, _ := updatedComponent.Objects()

				newNodeName := rtest.GetResource(updatedResources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch).Spec.NodeSets[0].Name
				Expect(newNodeName).NotTo(Equal(oldNodeSetName))
			})

			// A non-canonical Quantity (e.g. "1024Gi") set in the resource requirements in the LogStorage CR
			// is parsed by the operator and written into the Elasticsearch CR in its canonical form (e.g.
			// "1Ti"). This is because when a Quantity is parsed, the requested string representation is
			// ignored if it is non-canonical, leaving the default encoding logic of the Quantity to decide on
			// the string representation. We must ensure that if the user specifies a non-canonical Quantity in
			// the LogStorage, we do not view it as unequal to the canonical quantity we write to the
			// Elasticsearch CR. Otherwise, we would wrongly conclude that the storage configuration changed
			// and rename the NodeSet, which causes ECK to recreate the StatefulSet and its PVCs.
			It("should retain the NodeSet name when the current storage quantity is equal but formatted differently", func() {
				cfg.LogStorage = &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: 1,
							ResourceRequirements: &corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									"storage": resource.MustParse("1024Gi"),
								},
							},
						},
						StorageClassName: "tigera-elasticsearch",
					},
				}
				cfg.Elasticsearch = &esv1.Elasticsearch{
					Spec: esv1.ElasticsearchSpec{
						NodeSets: []esv1.NodeSet{
							{
								Name: "t5kdhpw24vq7",
								VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
									{
										Spec: corev1.PersistentVolumeClaimSpec{
											StorageClassName: ptr.To("tigera-elasticsearch"),
											Resources: corev1.VolumeResourceRequirements{
												Requests: corev1.ResourceList{
													"storage": resource.MustParse("1Ti"),
												},
											},
										},
									},
								},
							},
						},
					},
				}

				component := render.LogStorage(cfg)
				createResources, _ := component.Objects()
				es := rtest.GetResource(createResources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)
				Expect(es.Spec.NodeSets[0].Name).To(Equal("t5kdhpw24vq7"))

				// A genuine storage change must still force a rename.
				cfg.Elasticsearch.Spec.NodeSets[0].VolumeClaimTemplates[0].Spec.Resources.Requests["storage"] = resource.MustParse("2Ti")
				component = render.LogStorage(cfg)
				createResources, _ = component.Objects()
				es = rtest.GetResource(createResources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)
				Expect(es.Spec.NodeSets[0].Name).NotTo(Equal("t5kdhpw24vq7"))
			})
		})

		It("should render DataNodeSelectors defined in the LogStorage CR", func() {
			cfg.LogStorage.Spec.DataNodeSelector = map[string]string{
				"k1": "v1",
				"k2": "v2",
			}
			component := render.LogStorage(cfg)

			// Verify that the node selectors are passed into the Elasticsearch pod spec.
			createResources, _ := component.Objects()
			nodeSelectors := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.NodeSelector
			Expect(nodeSelectors["k1"]).To(Equal("v1"))
			Expect(nodeSelectors["k2"]).To(Equal("v2"))
		})

		It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
			component := render.LogStorage(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			role := rtest.GetResource(resources, "tigera-elasticsearch", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"privileged"},
			}))
		})
	})

	Context("Managed cluster", func() {
		var cfg *render.ManagedClusterLogStorageConfiguration
		var managementClusterConnection *operatorv1.ManagementClusterConnection

		BeforeEach(func() {
			replicas := int32(1)
			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			managementClusterConnection = &operatorv1.ManagementClusterConnection{}
			cfg = &render.ManagedClusterLogStorageConfiguration{
				Installation:  installation,
				ClusterDomain: "cluster.local",
			}
		})

		Context("Initial creation", func() {
			It("creates Managed cluster logstorage components", func() {
				expectedCreateResources := []client.Object{
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed-secrets"}},
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: "tigera-operator"},
						RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "tigera-linseed-secrets"},
						Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "guardian", Namespace: "calico-system"}},
					},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoKubeControllerSecret, Namespace: common.OperatorNamespace()}},
				}

				expectedDeleteResources := []client.Object{
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed-namespaces"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed"}},
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed-configmap"}},
					&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: "tigera-elasticsearch"}},
					&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure-es-gateway-http", Namespace: "tigera-elasticsearch"}},
					&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
				}

				component := render.NewManagedClusterLogStorage(cfg)
				createResources, deleteResources := component.Objects()
				rtest.ExpectResources(createResources, expectedCreateResources)
				rtest.ExpectResources(deleteResources, expectedDeleteResources)
			})
		})

		Context("Deleting LogStorage", deleteLogStorageTests(nil, managementClusterConnection))

		Context("calico-system rendering", func() {
			policyNames := []types.NamespacedName{
				{Name: "calico-system.elasticsearch-access", Namespace: "tigera-elasticsearch"},
				{Name: "calico-system.kibana-access", Namespace: "tigera-kibana"},
				{Name: "calico-system.elastic-operator-access", Namespace: "tigera-eck-operator"},
				{Name: "calico-system.elasticsearch-internal", Namespace: "tigera-elasticsearch"},
			}

			DescribeTable("should render calico-system policy",
				func(scenario testutils.CalicoSystemScenario) {
					if scenario.OpenShift {
						cfg.Provider = operatorv1.ProviderOpenShift
					} else {
						cfg.Provider = operatorv1.ProviderNone
					}

					component := render.NewManagedClusterLogStorage(cfg)
					resources, _ := component.Objects()

					for _, policyName := range policyNames {
						policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
						expectedPolicy := getExpectedPolicy(policyName, scenario)
						Expect(policy).To(Equal(expectedPolicy))
					}
				},
				Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
				Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
			)
		})
	})

	Context("NodeSet configuration", func() {
		var cfg *render.ElasticsearchConfiguration
		replicas, retention := int32(1), int32(1)

		BeforeEach(func() {
			logStorage := &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{
					Indices: &operatorv1.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
						DNSLogs:           &retention,
						BGPLogs:           &retention,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			esConfig := relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
			elasticsearchKeyPair, trustedBundle := getTLS(installation)
			cfg = &render.ElasticsearchConfiguration{
				LogStorage:           logStorage,
				Installation:         installation,
				ClusterConfig:        esConfig,
				ElasticsearchKeyPair: elasticsearchKeyPair,
				TrustedBundle:        trustedBundle,
				PullSecrets: []*corev1.Secret{
					{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
			}
		})

		Context("Node distribution", func() {
			When("the number of Nodes and NodeSets is 3", func() {
				It("creates 3 1 Node NodeSet", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 3,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(1)))
					}
				})
			})

			When("the number of Nodes is 2 and the number of NodeSets is 3", func() {
				It("creates 2 1 Node NodeSets", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 2,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(1)))
					}
				})
			})

			When("the number of Nodes is 6 and the number of NodeSets is 3", func() {
				It("creates 3 2 Node NodeSets", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 6,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(2)))
					}
				})
			})

			When("the number of Nodes is 5 and the number of NodeSets is 6", func() {
				It("creates 2 2 Node NodeSets and 1 1 Node NodeSet", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 5,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))

					Expect(nodeSets[0].Count).Should(Equal(int32(2)))
					Expect(nodeSets[1].Count).Should(Equal(int32(2)))
					Expect(nodeSets[2].Count).Should(Equal(int32(1)))
				})
			})
		})

		Context("Node Resource", func() {
			When("the ResourceRequirements is set", func() {
				defaultLimitCpu := "1"
				defaultLimitMemory := "4Gi"
				defaultRequestsCpu := "250m"
				defaultRequestsMemory := "4Gi"
				It("sets memory and cpu requirements in pod template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse("5"),
							"memory": resource.MustParse("2Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("500m"),
							"memory": resource.MustParse("2Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pod := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
					Expect(pod.Resources).Should(Equal(res))
					Expect(pod.Env[0].Value).To(Equal("-Xms1G -Xmx1G"))
				})

				It("sets default memory and cpu requirements in pod template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"memory": resource.MustParse("10Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu": resource.MustParse(defaultRequestsCpu),
						},
					}
					expectedRes := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultLimitCpu),
							"memory": resource.MustParse("10Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultRequestsCpu),
							"memory": resource.MustParse(defaultRequestsMemory),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pod := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
					Expect(pod.Resources).Should(Equal(expectedRes))
					Expect(pod.Env[0].Value).To(Equal("-Xms2G -Xmx2G"))
				})

				It("sets value of Limits to user's Requests when user's Limits is not set and default Limits is lesser than Requests", func() {
					res := corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse("1Gi"),
						},
					}
					expectedRes := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse(defaultLimitMemory),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse("1Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pod := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
					Expect(pod.Resources).Should(Equal(expectedRes))
					Expect(pod.Env[0].Value).To(Equal("-Xms512M -Xmx512M"))
				})

				It("sets value of Requests to user's Limits when user's Requests is not set and default Requests is greater than Limits", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"memory": resource.MustParse("2Gi"),
						},
					}
					expectedRes := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultLimitCpu),
							"memory": resource.MustParse("2Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultRequestsCpu),
							"memory": resource.MustParse("2Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					podResource := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0].Resources
					Expect(podResource).Should(Equal(expectedRes))
				})

				It("sets storage requirements in pvc template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"storage": resource.MustParse("16Gi"),
						},
						Requests: corev1.ResourceList{
							"storage": resource.MustParse("8Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pvcResource := getElasticsearch(createResources).Spec.NodeSets[0].VolumeClaimTemplates[0].Spec.Resources
					Expect(pvcResource.Limits).Should(Equal(res.Limits))
					Expect(pvcResource.Requests).Should(Equal(res.Requests))
				})

				It("sets storage value of Requests to user's Limits when user's Requests is not set and default Requests is greater than Limits in pvc template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"storage": resource.MustParse("8Gi"),
						},
					}
					expected := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"storage": resource.MustParse("8Gi"),
						},
						Requests: corev1.ResourceList{
							"storage": resource.MustParse("8Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pvcResource := getElasticsearch(createResources).Spec.NodeSets[0].VolumeClaimTemplates[0].Spec.Resources
					Expect(pvcResource.Limits).Should(Equal(expected.Limits))
					Expect(pvcResource.Requests).Should(Equal(expected.Requests))
				})
			})
		})
		Context("Node selection", func() {
			When("NodeSets is set but empty", func() {
				It("returns the default NodeSet", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:    2,
						NodeSets: []operatorv1.NodeSet{},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(1))
				})
			})

			When("there is a single selection attribute for a NodeSet", func() {
				It("sets the Node Affinity Elasticsearch cluster awareness attributes with the single selection attribute", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 2,
						NodeSets: []operatorv1.NodeSet{
							{
								SelectionAttributes: []operatorv1.NodeSetSelectionAttribute{{
									Name:      "zone",
									NodeLabel: "failure-domain.beta.kubernetes.io/zone",
									Value:     "us-west-2a",
								}},
							},
							{
								SelectionAttributes: []operatorv1.NodeSetSelectionAttribute{{
									Name:      "zone",
									NodeLabel: "failure-domain.beta.kubernetes.io/zone",
									Value:     "us-west-2b",
								}},
							},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					Expect(nodeSets[0].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{{
									Key:      "failure-domain.beta.kubernetes.io/zone",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"us-west-2a"},
								}},
							}},
						},
					}))
					Expect(nodeSets[0].Config.Data).Should(Equal(map[string]interface{}{
						"node.roles":                                      []string{"data", "ingest", "master", "remote_cluster_client"},
						"cluster.max_shards_per_node":                     10000,
						"ingest.geoip.downloader.enabled":                 false,
						"xpack.eql.default_allow_partial_results":         false,
						"indices.lifecycle.poll_interval":                 "60m",
						"node.attr.zone":                                  "us-west-2a",
						"cluster.routing.allocation.awareness.attributes": "zone",
					}))

					Expect(nodeSets[1].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{{
									Key:      "failure-domain.beta.kubernetes.io/zone",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"us-west-2b"},
								}},
							}},
						},
					}))
					Expect(nodeSets[1].Config.Data).Should(Equal(map[string]interface{}{
						"node.roles":                                      []string{"data", "ingest", "master", "remote_cluster_client"},
						"cluster.max_shards_per_node":                     10000,
						"ingest.geoip.downloader.enabled":                 false,
						"xpack.eql.default_allow_partial_results":         false,
						"indices.lifecycle.poll_interval":                 "60m",
						"node.attr.zone":                                  "us-west-2b",
						"cluster.routing.allocation.awareness.attributes": "zone",
					}))
				})
			})

			When("there are multiple selection attributes for a NodeSet", func() {
				It("combines to attributes for the Node Affinity and Elasticsearch cluster awareness attributes", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 2,
						NodeSets: []operatorv1.NodeSet{
							{
								SelectionAttributes: []operatorv1.NodeSetSelectionAttribute{
									{
										Name:      "zone",
										NodeLabel: "failure-domain.beta.kubernetes.io/zone",
										Value:     "us-west-2a",
									},
									{
										Name:      "rack",
										NodeLabel: "some-rack-label.kubernetes.io/rack",
										Value:     "rack1",
									},
								},
							},
							{
								SelectionAttributes: []operatorv1.NodeSetSelectionAttribute{
									{
										Name:      "zone",
										NodeLabel: "failure-domain.beta.kubernetes.io/zone",
										Value:     "us-west-2b",
									},
									{
										Name:      "rack",
										NodeLabel: "some-rack-label.kubernetes.io/rack",
										Value:     "rack1",
									},
								},
							},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					Expect(nodeSets[0].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "failure-domain.beta.kubernetes.io/zone",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"us-west-2a"},
									},
									{
										Key:      "some-rack-label.kubernetes.io/rack",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"rack1"},
									},
								},
							}},
						},
					}))
					Expect(nodeSets[0].Config.Data).Should(Equal(map[string]interface{}{
						"node.roles":                                      []string{"data", "ingest", "master", "remote_cluster_client"},
						"cluster.max_shards_per_node":                     10000,
						"ingest.geoip.downloader.enabled":                 false,
						"xpack.eql.default_allow_partial_results":         false,
						"indices.lifecycle.poll_interval":                 "60m",
						"node.attr.zone":                                  "us-west-2a",
						"node.attr.rack":                                  "rack1",
						"cluster.routing.allocation.awareness.attributes": "zone,rack",
					}))

					Expect(nodeSets[1].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{
								{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{
											Key:      "failure-domain.beta.kubernetes.io/zone",
											Operator: corev1.NodeSelectorOpIn,
											Values:   []string{"us-west-2b"},
										},
										{
											Key:      "some-rack-label.kubernetes.io/rack",
											Operator: corev1.NodeSelectorOpIn,
											Values:   []string{"rack1"},
										},
									},
								},
							},
						},
					}))
					Expect(nodeSets[1].Config.Data).Should(Equal(map[string]interface{}{
						"node.roles":                                      []string{"data", "ingest", "master", "remote_cluster_client"},
						"cluster.max_shards_per_node":                     10000,
						"ingest.geoip.downloader.enabled":                 false,
						"xpack.eql.default_allow_partial_results":         false,
						"indices.lifecycle.poll_interval":                 "60m",
						"node.attr.zone":                                  "us-west-2b",
						"node.attr.rack":                                  "rack1",
						"cluster.routing.allocation.awareness.attributes": "zone,rack",
					}))
				})
			})
		})
	})
})

func getTLS(installation *operatorv1.InstallationSpec) (certificatemanagement.KeyPairInterface, certificatemanagement.TrustedBundle) {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	esDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	elasticsearchKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchInternalCertSecret, render.ElasticsearchNamespace, esDNSNames)
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle(elasticsearchKeyPair)
	Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
	return elasticsearchKeyPair, trustedBundle
}

var deleteLogStorageTests = func(managementCluster *operatorv1.ManagementCluster, managementClusterConnection *operatorv1.ManagementClusterConnection) func() {
	return func() {
		var cfg *render.ElasticsearchConfiguration
		replicas := int32(1)
		retention := int32(1)

		BeforeEach(func() {
			t := metav1.Now()

			logStorage := &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "tigera-secure",
					DeletionTimestamp: &t,
				},
				Spec: operatorv1.LogStorageSpec{
					Nodes: &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: nil,
					},
					Indices: &operatorv1.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
						DNSLogs:           &retention,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			esConfig := relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
			elasticsearchKeyPair, trustedBundle := getTLS(installation)

			cfg = &render.ElasticsearchConfiguration{
				LogStorage:           logStorage,
				Installation:         installation,
				ManagementCluster:    managementCluster,
				Elasticsearch:        &esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
				ClusterConfig:        esConfig,
				ElasticsearchKeyPair: elasticsearchKeyPair,
				TrustedBundle:        trustedBundle,
				PullSecrets: []*corev1.Secret{
					{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
			}
		})
		It("returns Elasticsearch CR's to delete and keeps the finalizers on the LogStorage CR", func() {
			expectedCreateResources := []resourceTestObj{}

			expectedDeleteResources := []resourceTestObj{
				{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
			}

			component := render.LogStorage(cfg)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, expectedDeleteResources)
		})
		It("doesn't return anything to delete when Elasticsearch have their deletion times stamps set and the LogStorage finalizers are still set", func() {
			expectedCreateResources := []resourceTestObj{}

			t := metav1.Now()
			cfg.Elasticsearch.DeletionTimestamp = &t
			component := render.LogStorage(cfg)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, []resourceTestObj{})
		})
	}
}

func compareResources(resources []client.Object, expectedResources []resourceTestObj) {
	ExpectWithOffset(1, len(resources)).To(Equal(len(expectedResources)))
	for i, expectedResource := range expectedResources {
		resource := resources[i]
		actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
		actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()

		Expect(actualName).To(Equal(expectedResource.name), fmt.Sprintf("Rendered resource has wrong name (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(actualNS).To(Equal(expectedResource.ns), fmt.Sprintf("Rendered resource has wrong namespace (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(resource).Should(BeAssignableToTypeOf(expectedResource.typ))
		if expectedResource.f != nil {
			expectedResource.f(resource)
		}
	}
}

func getElasticsearch(resources []client.Object) *esv1.Elasticsearch {
	resource := rtest.GetResource(resources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch")
	Expect(resource).ShouldNot(BeNil())

	return resource.(*esv1.Elasticsearch)
}
