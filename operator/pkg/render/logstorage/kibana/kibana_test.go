// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package kibana_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var _ = Describe("Kibana rendering tests", func() {
	Context("zero-tenant rendering", func() {
		var installation *operatorv1.InstallationSpec
		var replicas int32
		var cfg *kibana.Configuration
		kibanaPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/kibana.json")
		kibanaPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/kibana_ocp.json")

		expectedResources := []client.Object{
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-kibana"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-kibana"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kibana.Namespace}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: kibana.PolicyName, Namespace: kibana.Namespace}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: kibana.Namespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-kibana", Namespace: kibana.Namespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: kibana.Namespace}},
			&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: kibana.CRName, Namespace: kibana.Namespace}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: kibana.Namespace}},
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
				KubernetesProvider:   operatorv1.ProviderOpenShift,
				Registry:             "testregistry.com/",
			}

			replicas = 2
			kibanaKeyPair, bundle := getX509Certs(installation)

			cfg = &kibana.Configuration{
				LogStorage:    logStorage,
				Installation:  installation,
				KibanaKeyPair: kibanaKeyPair,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:      installation.KubernetesProvider,
				ClusterDomain: dns.DefaultClusterDomain,
				TrustedBundle: bundle,
				Enabled:       true,
			}
		})

		It("should render all supporting resources for Kibana", func() {
			component := kibana.Kibana(cfg)
			createResources, _ := component.Objects()
			rtest.ExpectResources(createResources, expectedResources)

			namespace := rtest.GetResource(createResources, "tigera-kibana", "", "", "v1", "Namespace").(*corev1.Namespace)
			Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("baseline"))
			Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

			kb := rtest.GetResource(createResources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana")
			Expect(kb).NotTo(BeNil())
			kibanaCR := kb.(*kbv1.Kibana)
			Expect(kibanaCR.Spec.PodTemplate.Spec.Containers).To(HaveLen(1))

			Expect(*kibanaCR.Spec.PodTemplate.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*kibanaCR.Spec.PodTemplate.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*kibanaCR.Spec.PodTemplate.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*kibanaCR.Spec.PodTemplate.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*kibanaCR.Spec.PodTemplate.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(kibanaCR.Spec.PodTemplate.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(kibanaCR.Spec.PodTemplate.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
				Name:      "kibana-plugins",
				MountPath: "/mnt/dummy-location/",
			}))

			Expect(kibanaCR.Spec.PodTemplate.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))
			resultKB := rtest.GetResource(createResources, kibana.CRName, kibana.Namespace, "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
			Expect(resultKB.Spec.Config.Data["xpack.security.session.lifespan"]).To(Equal("8h"))
			Expect(resultKB.Spec.Config.Data["xpack.security.session.idleTimeout"]).To(Equal("30m"))
			Expect(resultKB.Spec.Config.Data["xpack.fleet.enabled"]).To(BeFalse())
			Expect(resultKB.Spec.Config.Data["xpack.fleet.agents.enabled"]).To(BeFalse())
			Expect(resultKB.Spec.Config.Data["xpack.fleet.isAirGapped"]).To(BeTrue())
			Expect(resultKB.Spec.Config.Data["xpack.fleet.packages"]).To(Equal([]string{}))
			Expect(resultKB.Spec.Config.Data["xpack.fleet.registryUrl"]).To(Equal("http://localhost:5601"))
			Expect(resultKB.Spec.Config.Data["migrations.discardUnknownObjects"]).To(Equal(components.ComponentEckKibana.Version))
			Expect(resultKB.Spec.Config.Data["newsfeed.enabled"]).To(BeFalse())
			Expect(resultKB.Spec.Config.Data["xpack.productDocBase.artifactRepositoryUrl"]).To(Equal("http://localhost:5601"))
		})

		It("should render toleration on GKE", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
			component := kibana.Kibana(cfg)
			createResources, _ := component.Objects()
			kb := rtest.GetResource(createResources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana")
			Expect(kb).NotTo(BeNil())
			kibanaCR := kb.(*kbv1.Kibana)
			Expect(kibanaCR.Spec.PodTemplate.Spec.Tolerations).To(ContainElements(corev1.Toleration{
				Key:      "kubernetes.io/arch",
				Operator: corev1.TolerationOpEqual,
				Value:    "arm64",
				Effect:   corev1.TaintEffectNoSchedule,
			}))
		})

		It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
			component := kibana.Kibana(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			role := rtest.GetResource(resources, "tigera-kibana", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"nonroot-v2"},
			}))
		})

		It("should configures Kibana publicBaseUrl when BaseURL is specified", func() {
			// cfg.ElasticLicenseType = render.ElasticsearchLicenseTypeBasic
			cfg.BaseURL = "https://test.domain.com"

			component := kibana.Kibana(cfg)

			createResources, _ := component.Objects()
			kb := rtest.GetResource(createResources, kibana.CRName, kibana.Namespace, "kibana.k8s.elastic.co", "v1", "Kibana")
			Expect(kb).ShouldNot(BeNil())
			kibana := kb.(*kbv1.Kibana)
			x := kibana.Spec.Config.Data["server"].(map[string]interface{})
			Expect(x["publicBaseUrl"]).To(Equal("https://test.domain.com/tigera-kibana"))
		})

		It("should configure X-Frame-Options as DENY in customResponseHeaders", func() {
			component := kibana.Kibana(cfg)

			createResources, _ := component.Objects()
			kb := rtest.GetResource(createResources, kibana.CRName, kibana.Namespace, "kibana.k8s.elastic.co", "v1", "Kibana")
			kibana := kb.(*kbv1.Kibana)
			server := kibana.Spec.Config.Data["server"].(map[string]interface{})
			customResponseHeaders := server["customResponseHeaders"].(map[string]interface{})
			Expect(customResponseHeaders["X-Frame-Options"]).To(Equal("DENY"))
		})

		It("should delete Kibana ExternalService", func() {
			cfg.KbService = &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: kibana.ServiceName, Namespace: kibana.Namespace},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName},
			}

			expectedDeletedResources := []client.Object{
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: kibana.ServiceName, Namespace: kibana.Namespace}},

				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.kibana-access", Namespace: kibana.Namespace}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: kibana.Namespace}},
			}

			component := kibana.Kibana(cfg)
			createResources, deleteResources := component.Objects()
			rtest.ExpectResources(createResources, expectedResources)
			rtest.ExpectResources(deleteResources, expectedDeletedResources)
		})

		It("should render kibana with certificate management enabled", func() {
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{
				CACert:             cfg.KibanaKeyPair.GetCertificatePEM(),
				SignerName:         "my signer name",
				SignatureAlgorithm: "ECDSAWithSHA256",
				KeyAlgorithm:       "ECDSAWithCurve521",
			}
			kibanaKeyPair, trustedBundle := getX509Certs(cfg.Installation)
			cfg.KibanaKeyPair = kibanaKeyPair
			cfg.TrustedBundle = trustedBundle
			cfg.UnusedTLSSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.UnusedCertSecret, Namespace: common.OperatorNamespace()},
			}

			resources := append(expectedResources, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kibana.TigeraKibanaCertSecret, Namespace: kibana.Namespace}})
			component := kibana.Kibana(cfg)

			createdResources, _ := component.Objects()
			rtest.ExpectResources(createdResources, resources)
		})

		Context("calico-system rendering", func() {
			policyNames := []types.NamespacedName{
				{Name: "calico-system.kibana-access", Namespace: "tigera-kibana"},
			}

			getExpectedPolicy := func(name types.NamespacedName, scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
				if name.Name == "calico-system.kibana-access" {
					return testutils.SelectPolicyByProvider(scenario, kibanaPolicy, kibanaPolicyForOpenshift)
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

					component := kibana.Kibana(cfg)
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

		It("Should not install Kibana when instructed so", func() {
			cfg.Enabled = false
			component := kibana.Kibana(cfg)

			createdResources, deletedResources := component.Objects()
			expectedDeletedResources := []client.Object{
				&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: kibana.CRName, Namespace: kibana.Namespace}},
			}
			rtest.ExpectResources(deletedResources, expectedDeletedResources)
			Expect(createdResources).To(BeEmpty())
		})

		Context("Deleting LogStorage", func() {
			expectedDeletedResources := []client.Object{
				&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: kibana.CRName, Namespace: kibana.Namespace}},
			}

			BeforeEach(func() {
				cfg.Kibana = &kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: kibana.CRName, Namespace: kibana.Namespace}}
				t := metav1.Now()
				cfg.LogStorage = &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "tigera-secure",
						DeletionTimestamp: &t,
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
			})

			It("returns Kibana CR's to delete and keeps the finalizers on the LogStorage CR", func() {
				component := kibana.Kibana(cfg)

				createdResources, deletedResources := component.Objects()
				rtest.ExpectResources(deletedResources, expectedDeletedResources)
				Expect(createdResources).To(BeEmpty())
			})

			It("doesn't return anything to delete when Kibana have their deletion times stamps set and the LogStorage finalizers are still set", func() {
				t := metav1.Now()
				cfg.Kibana.DeletionTimestamp = &t
				component := kibana.Kibana(cfg)

				createResources, deleteResources := component.Objects()

				Expect(createResources).To(BeEmpty())
				Expect(deleteResources).To(BeEmpty())
			})
		})

		Context("Kibana high availability", func() {
			var cfg *kibana.Configuration
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
					KubernetesProvider:   operatorv1.ProviderNone,
					Registry:             "testregistry.com/",
				}

				kibanaKeyPair, bundle := getX509Certs(installation)

				cfg = &kibana.Configuration{
					LogStorage:    logStorage,
					Installation:  installation,
					KibanaKeyPair: kibanaKeyPair,
					PullSecrets: []*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					},
					Provider:      operatorv1.ProviderNone,
					ClusterDomain: dns.DefaultClusterDomain,
					TrustedBundle: bundle,
					Enabled:       true,
				}
			})

			It("should set count to 1 when ControlPlaneReplicas is nil", func() {
				cfg.Installation.ControlPlaneReplicas = nil
				component := kibana.Kibana(cfg)
				resources, _ := component.Objects()

				kibana, ok := rtest.GetResource(resources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
				Expect(ok).To(BeTrue())
				Expect(kibana.Spec.Count).To(Equal(int32(1)))
				Expect(kibana.Spec.PodTemplate.Spec.Affinity).To(BeNil())
			})

			It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
				var replicas int32 = 1
				cfg.Installation.ControlPlaneReplicas = &replicas

				component := kibana.Kibana(cfg)
				resources, _ := component.Objects()

				kibana, ok := rtest.GetResource(resources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
				Expect(ok).To(BeTrue())
				Expect(kibana.Spec.PodTemplate.Spec.Affinity).To(BeNil())
			})

			It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
				var replicas int32 = 2
				cfg.Installation.ControlPlaneReplicas = &replicas
				cfg.LogStorage.Spec.Kibana = &operatorv1.Kibana{
					Spec: &operatorv1.KibanaSpec{
						Replicas: &replicas,
					},
				}

				component := kibana.Kibana(cfg)
				resources, _ := component.Objects()

				kibana, ok := rtest.GetResource(resources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
				Expect(ok).To(BeTrue())
				Expect(kibana.Spec.PodTemplate.Spec.Affinity).NotTo(BeNil())
				Expect(kibana.Spec.PodTemplate.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-secure", []string{"tigera-kibana"})))
			})

			It("should render the kibana pod template with resource requests and limits when set", func() {
				cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{
					CACert:             cfg.KibanaKeyPair.GetCertificatePEM(),
					SignerName:         "my signer name",
					SignatureAlgorithm: "ECDSAWithSHA256",
					KeyAlgorithm:       "ECDSAWithCurve521",
				}

				cfg.KibanaKeyPair, cfg.TrustedBundle = getX509Certs(cfg.Installation)
				cfg.UnusedTLSSecret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.UnusedCertSecret, Namespace: common.OperatorNamespace()},
				}
				expectedResourcesRequirements := corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("500Mi"),
					},
					Requests: corev1.ResourceList{
						"cpu":    resource.MustParse("101m"),
						"memory": resource.MustParse("100Mi"),
					},
				}

				cfg.LogStorage.Spec.Kibana = &operatorv1.Kibana{
					Spec: &operatorv1.KibanaSpec{
						Template: &operatorv1.KibanaPodTemplateSpec{
							Spec: &operatorv1.KibanaPodSpec{
								Containers: []operatorv1.KibanaContainer{
									{
										Name:      "kibana",
										Resources: &expectedResourcesRequirements,
									},
								},
								InitContainers: []operatorv1.KibanaInitContainer{
									{
										Name:      "key-cert-provisioner",
										Resources: &expectedResourcesRequirements,
									},
								},
							},
						},
					},
				}

				component := kibana.Kibana(cfg)
				resources, _ := component.Objects()

				kibana, ok := rtest.GetResource(resources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
				Expect(ok).To(BeTrue())
				Expect(kibana.Spec.Count).To(Equal(int32(1)))
				container := test.GetContainer(kibana.Spec.PodTemplate.Spec.Containers, "kibana")
				Expect(container).NotTo(BeNil())
				Expect(container.Resources).To(Equal(expectedResourcesRequirements))

				initcontainer := test.GetContainer(kibana.Spec.PodTemplate.Spec.InitContainers, "key-cert-provisioner")
				Expect(initcontainer).NotTo(BeNil())
				Expect(initcontainer.Resources).To(Equal(expectedResourcesRequirements))
			})
		})
	})
})

func getX509Certs(installation *operatorv1.InstallationSpec) (certificatemanagement.KeyPairInterface, certificatemanagement.TrustedBundle) {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	kbDNSNames := dns.GetServiceDNSNames(kibana.ServiceName, kibana.Namespace, dns.DefaultClusterDomain)
	kibanaKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, kibana.TigeraKibanaCertSecret, common.OperatorNamespace(), kbDNSNames)
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle(kibanaKeyPair)
	Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

	return kibanaKeyPair, trustedBundle
}
