// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package istio_test

import (
	"encoding/json"
	"strings"

	netattachv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/components"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
)

// getCalicoTestImageSet returns a standard imageSet for testing with Calico variant
func getCalicoTestImageSet() *operatorv1.ImageSet {
	return &operatorv1.ImageSet{
		Spec: operatorv1.ImageSetSpec{
			Images: []operatorv1.Image{
				{Image: "calico/istio-pilot", Digest: "sha256:test-pilot-digest"},
				{Image: "calico/istio-install-cni", Digest: "sha256:test-cni-digest"},
				{Image: "calico/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
				{Image: "calico/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
			},
		},
	}
}

// getCommonExpectedResources returns the list of resources expected for standard platforms
func getCommonExpectedResources() []client.Object {
	return []client.Object{
		// NetworkPolicies
		&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: istio.IstioIstiodPolicyName, Namespace: istio.IstioNamespace}},
		&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: istio.IstioCNIPolicyName, Namespace: istio.IstioNamespace}},
		&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: istio.IstioZTunnelPolicyName, Namespace: istio.IstioNamespace}},
		// Workloads
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: istio.IstioIstiodDeploymentName, Namespace: istio.IstioNamespace}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: istio.IstioCNIDaemonSetName, Namespace: istio.IstioNamespace}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: istio.IstioZTunnelDaemonSetName, Namespace: istio.IstioNamespace}},
		// ServiceAccounts
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "istio-reader-service-account", Namespace: istio.IstioNamespace}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "istiod", Namespace: istio.IstioNamespace}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni", Namespace: istio.IstioNamespace}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "ztunnel", Namespace: istio.IstioNamespace}},
		// ClusterRoles
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "istiod-clusterrole-calico-system"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "istiod-gateway-controller-calico-system"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "istio-reader-clusterrole-calico-system"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni-repair-role"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni-ambient"}},
		// ClusterRoleBindings
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "istiod-clusterrole-calico-system"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "istiod-gateway-controller-calico-system"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "istio-reader-clusterrole-calico-system"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni-repair-rolebinding"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni-ambient"}},
		// ConfigMaps
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "values", Namespace: istio.IstioNamespace}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "istio", Namespace: istio.IstioNamespace}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "istio-sidecar-injector", Namespace: istio.IstioNamespace}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni-config", Namespace: istio.IstioNamespace}},
		// Service
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "istiod", Namespace: istio.IstioNamespace}},
		// Role & RoleBinding
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "istiod", Namespace: istio.IstioNamespace}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "istiod", Namespace: istio.IstioNamespace}},
		// ValidatingWebhookConfigurations
		&admregv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "istiod-default-validator"}},
		&admregv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "istio-validator-calico-system"}},
		// HorizontalPodAutoscaler
		&autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "istiod", Namespace: istio.IstioNamespace}},
	}
}

// getCommonExpectedResources returns the list of resources to delete expected for standard platforms
func getCommonExpectedDeleteResources() []client.Object {
	return []client.Object{
		&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.istiod", Namespace: istio.IstioNamespace}},
		&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.istio-cni-node", Namespace: istio.IstioNamespace}},
		&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.ztunnel", Namespace: istio.IstioNamespace}},
	}
}

var _ = Describe("Istio Component Rendering", func() {
	var (
		testScheme *runtime.Scheme
		cfg        *istio.Configuration
	)

	BeforeEach(func() {
		testScheme = runtime.NewScheme()
		Expect(scheme.AddToScheme(testScheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.AddToScheme(testScheme)).ShouldNot(HaveOccurred())
		Expect(v3.AddToScheme(testScheme)).ShouldNot(HaveOccurred())
		Expect(apiextv1.AddToScheme(testScheme)).ShouldNot(HaveOccurred())
		Expect(netattachv1.AddToScheme(testScheme)).ShouldNot(HaveOccurred())

		cfg = &istio.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "test-registry",
				ImagePath:          "test-path",
				ImagePrefix:        "test-prefix",
			},
			Istio: &operatorv1.Istio{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: operatorv1.IstioSpec{
					DSCPMark: func() *numorstring.DSCP { d := numorstring.DSCPFromInt(11); return &d }(),
				},
			},
			IstioNamespace: istio.IstioNamespace,
			Scheme:         testScheme,
		}
	})

	Describe("ResolveImages", func() {
		It("should fail when required images are missing", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{},
				},
			}

			err = component.ResolveImages(imageSet)
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("Objects", func() {
		It("should return CRDs", func() {
			crds, _, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, objsToDelete := crds.Objects()
			Expect(objsToDelete).To(BeEmpty())

			// Verify we have exactly 14 Istio CRDs
			Expect(objsToCreate).To(HaveLen(14))

			// Check that all returned objects are actually CRDs
			for _, obj := range objsToCreate {
				_, ok := obj.(*apiextv1.CustomResourceDefinition)
				Expect(ok).To(BeTrue(), "Expected all objects to be CRDs")
			}

			// Verify all key Istio CRDs are present
			crdNames := make([]string, 0, len(objsToCreate))
			for _, obj := range objsToCreate {
				if crd, ok := obj.(*apiextv1.CustomResourceDefinition); ok {
					crdNames = append(crdNames, crd.Name)
				}
			}

			// Verify all expected Istio CRDs
			Expect(crdNames).To(ConsistOf(
				"wasmplugins.extensions.istio.io",
				"destinationrules.networking.istio.io",
				"envoyfilters.networking.istio.io",
				"gateways.networking.istio.io",
				"proxyconfigs.networking.istio.io",
				"serviceentries.networking.istio.io",
				"sidecars.networking.istio.io",
				"virtualservices.networking.istio.io",
				"workloadentries.networking.istio.io",
				"workloadgroups.networking.istio.io",
				"authorizationpolicies.security.istio.io",
				"peerauthentications.security.istio.io",
				"requestauthentications.security.istio.io",
				"telemetries.telemetry.istio.io",
			))
		})

		It("should return objects to create", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, objsToDelete := component.Objects()

			Expect(objsToCreate).To(HaveLen(32))
			Expect(objsToDelete).To(HaveLen(3))

			expectedResources := getCommonExpectedResources()
			expectedDeleteResources := getCommonExpectedDeleteResources()

			rtest.ExpectResources(objsToCreate, expectedResources)
			rtest.ExpectResources(objsToDelete, expectedDeleteResources)
		})

		It("should render network policies with correct tier, selector, and ingress/egress rules", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// Verify istiod policy
			istiodPolicy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioIstiodPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(istiodPolicy.Spec.Tier).To(Equal(networkpolicy.CalicoTierName))
			Expect(istiodPolicy.Spec.Selector).To(Equal(networkpolicy.KubernetesAppSelector(istio.IstioIstiodDeploymentName)))
			Expect(istiodPolicy.Spec.Ingress).To(HaveLen(1))
			Expect(istiodPolicy.Spec.Ingress[0].Destination.Ports).To(ContainElements(
				numorstring.SinglePort(15012),
				numorstring.SinglePort(15017),
			))
			Expect(istiodPolicy.Spec.Egress).To(HaveLen(1))
			Expect(istiodPolicy.Spec.Egress[0].Action).To(Equal(v3.Allow))

			// Verify istio-cni policy
			cniPolicy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioCNIPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cniPolicy.Spec.Tier).To(Equal(networkpolicy.CalicoTierName))
			Expect(cniPolicy.Spec.Selector).To(Equal(networkpolicy.KubernetesAppSelector(istio.IstioCNIDaemonSetName)))
			Expect(cniPolicy.Spec.Egress).To(HaveLen(1))
			Expect(cniPolicy.Spec.Egress[0].Action).To(Equal(v3.Allow))

			// Verify ztunnel policy
			ztunnelPolicy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioZTunnelPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(ztunnelPolicy.Spec.Tier).To(Equal(networkpolicy.CalicoTierName))
			Expect(ztunnelPolicy.Spec.Selector).To(Equal(networkpolicy.KubernetesAppSelector(istio.IstioZTunnelDaemonSetName)))
			Expect(ztunnelPolicy.Spec.Egress).NotTo(BeEmpty())
			foundIstiodRule := false
			for _, rule := range ztunnelPolicy.Spec.Egress {
				if rule.Destination.Selector != "" {
					foundIstiodRule = true
					break
				}
			}
			Expect(foundIstiodRule).To(BeTrue(), "Expected egress rule for istiod service")
		})

		It("should set TRANSPARENT_NETWORK_POLICIES env var on ztunnel", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(daemonset.Spec.Template.Spec.Containers[0].Env).To(ContainElements(corev1.EnvVar{
				Name:  "TRANSPARENT_NETWORK_POLICIES",
				Value: "true",
			}))
		})

		It("should set MAGIC_DSCP_MARK env var on CNI", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(daemonset.Spec.Template.Spec.Containers[0].Env).To(ContainElements(corev1.EnvVar{
				Name:  "MAGIC_DSCP_MARK",
				Value: "11",
			}))
		})
	})

	Describe("Pull Secrets", func() {
		It("should append pull secrets to all workloads", func() {
			pullSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pull-secret",
					Namespace: istio.IstioNamespace,
				},
			}
			cfg.PullSecrets = []*corev1.Secret{pullSecret}

			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// Check istiod deployment
			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(deployment.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "test-pull-secret"}))

			// Check CNI daemonset
			cniDS, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cniDS.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "test-pull-secret"}))

			// Check ztunnel daemonset
			ztunnelDS, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(ztunnelDS.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "test-pull-secret"}))
		})

		It("should include imagePullSecrets in istiod Helm values", func() {
			pullSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-pull-secret",
					Namespace: istio.IstioNamespace,
				},
			}
			cfg.PullSecrets = []*corev1.Secret{pullSecret}

			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// The "values" ConfigMap contains the serialized Helm values for istiod.
			// Verify that imagePullSecrets appears in its data.
			valuesConfigMap, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "values", istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// The values ConfigMap should contain the imagePullSecrets key with the secret name
			found := false
			for _, v := range valuesConfigMap.Data {
				if strings.Contains(v, "imagePullSecrets") && strings.Contains(v, "my-pull-secret") {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Expected imagePullSecrets with 'my-pull-secret' in istiod values ConfigMap")
		})

		It("should not include secret names in imagePullSecrets Helm values when no pull secrets configured", func() {
			cfg.PullSecrets = nil

			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			valuesConfigMap, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "values", istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// When no pull secrets are configured, imagePullSecrets should be
			// an empty array (the Helm chart default), not populated with names.
			for _, v := range valuesConfigMap.Data {
				Expect(v).NotTo(ContainSubstring("my-pull-secret"), "Expected no secret names in imagePullSecrets when none configured")
			}
		})

		It("should set gateways.seccompProfile so waypoints run in PSA-restricted namespaces", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			injectorConfigMap, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, istio.IstioSidecarInjectorConfigMapName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			var values struct {
				Gateways struct {
					SeccompProfile corev1.SeccompProfile `json:"seccompProfile"`
				} `json:"gateways"`
			}
			Expect(json.Unmarshal([]byte(injectorConfigMap.Data["values"]), &values)).To(Succeed())
			Expect(values.Gateways.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault),
				"waypoint istio-proxy containers only get a seccompProfile when gateways.seccompProfile is set in the istiod values")
		})
	})

	Describe("Deployment Overrides", func() {
		DescribeTable("Istiod Deployment Overrides", func(overrides *operatorv1.IstiodDeployment, verify func(*appsv1.Deployment)) {
			cfg.Istio.Spec.IstiodDeployment = overrides
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()
			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			verify(deployment)
		},
			Entry("should apply affinity override",
				&operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								Affinity: &corev1.Affinity{
									NodeAffinity: &corev1.NodeAffinity{
										RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
											NodeSelectorTerms: []corev1.NodeSelectorTerm{
												{
													MatchExpressions: []corev1.NodeSelectorRequirement{
														{
															Key:      "custom-affinity-key",
															Operator: corev1.NodeSelectorOpExists,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				func(deployment *appsv1.Deployment) {
					Expect(deployment.Spec.Template.Spec.Affinity).NotTo(BeNil())
					Expect(deployment.Spec.Template.Spec.Affinity.NodeAffinity).NotTo(BeNil())
					Expect(deployment.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0].Key).To(Equal("custom-affinity-key"))
				},
			),
			Entry("should apply node selector override",
				&operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								NodeSelector: map[string]string{
									"custom-node-selector": "test-value",
								},
							},
						},
					},
				},
				func(deployment *appsv1.Deployment) {
					Expect(deployment.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "test-value"))
				},
			),
			Entry("should apply tolerations override",
				&operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								Tolerations: []corev1.Toleration{
									{
										Key:      "custom-toleration",
										Operator: corev1.TolerationOpEqual,
										Value:    "test-value",
									},
								},
							},
						},
					},
				},
				func(deployment *appsv1.Deployment) {
					Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElement(corev1.Toleration{
						Key:      "custom-toleration",
						Operator: corev1.TolerationOpEqual,
						Value:    "test-value",
					}))
				},
			),
			Entry("should apply resources override",
				&operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								Resources: &corev1.ResourceRequirements{
									Limits: corev1.ResourceList{
										"memory": resource.MustParse("2Gi"),
									},
									Requests: corev1.ResourceList{
										"memory": resource.MustParse("1Gi"),
									},
								},
							},
						},
					},
				},
				func(deployment *appsv1.Deployment) {
					// Resources are applied to the deployment
					// The override system applies resources to the pod spec, not individual containers
					// So we just verify that the deployment has at least one container with resources set
					hasResourcesSet := false
					for _, container := range deployment.Spec.Template.Spec.Containers {
						if container.Resources.Limits != nil || container.Resources.Requests != nil {
							hasResourcesSet = true
							break
						}
					}
					Expect(hasResourcesSet).To(BeTrue(), "Expected at least one container to have resources set")
				},
			),
		)
	})

	Describe("DaemonSet Overrides", func() {
		DescribeTable("CNI DaemonSet Overrides", func(overrides *operatorv1.IstioCNIDaemonset, verify func(*appsv1.DaemonSet)) {
			cfg.Istio.Spec.IstioCNIDaemonset = overrides
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()
			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			verify(daemonset)
		},
			Entry("should apply node selector override",
				&operatorv1.IstioCNIDaemonset{
					Spec: &operatorv1.IstioCNIDaemonsetSpec{
						Template: &operatorv1.IstioCNIDaemonsetSpecTemplate{
							Spec: &operatorv1.IstioCNIDaemonsetPodSpec{
								NodeSelector: map[string]string{
									"cni-node-selector": "test-value",
								},
							},
						},
					},
				},
				func(daemonset *appsv1.DaemonSet) {
					Expect(daemonset.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("cni-node-selector", "test-value"))
				},
			),
			Entry("should apply tolerations override",
				&operatorv1.IstioCNIDaemonset{
					Spec: &operatorv1.IstioCNIDaemonsetSpec{
						Template: &operatorv1.IstioCNIDaemonsetSpecTemplate{
							Spec: &operatorv1.IstioCNIDaemonsetPodSpec{
								Tolerations: []corev1.Toleration{
									{
										Key:      "cni-toleration",
										Operator: corev1.TolerationOpEqual,
										Value:    "cni-value",
									},
								},
							},
						},
					},
				},
				func(daemonset *appsv1.DaemonSet) {
					Expect(daemonset.Spec.Template.Spec.Tolerations).To(ContainElement(corev1.Toleration{
						Key:      "cni-toleration",
						Operator: corev1.TolerationOpEqual,
						Value:    "cni-value",
					}))
				},
			),
		)

		DescribeTable("ZTunnel DaemonSet Overrides", func(overrides *operatorv1.ZTunnelDaemonset, verify func(*appsv1.DaemonSet)) {
			cfg.Istio.Spec.ZTunnelDaemonset = overrides
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()
			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			verify(daemonset)
		},
			Entry("should apply node selector override",
				&operatorv1.ZTunnelDaemonset{
					Spec: &operatorv1.ZTunnelDaemonsetSpec{
						Template: &operatorv1.ZTunnelDaemonsetSpecTemplate{
							Spec: &operatorv1.ZTunnelDaemonsetPodSpec{
								NodeSelector: map[string]string{
									"ztunnel-node-selector": "test-value",
								},
							},
						},
					},
				},
				func(daemonset *appsv1.DaemonSet) {
					Expect(daemonset.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("ztunnel-node-selector", "test-value"))
				},
			),
			Entry("should apply affinity override",
				&operatorv1.ZTunnelDaemonset{
					Spec: &operatorv1.ZTunnelDaemonsetSpec{
						Template: &operatorv1.ZTunnelDaemonsetSpecTemplate{
							Spec: &operatorv1.ZTunnelDaemonsetPodSpec{
								Affinity: &corev1.Affinity{
									NodeAffinity: &corev1.NodeAffinity{
										RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
											NodeSelectorTerms: []corev1.NodeSelectorTerm{
												{
													MatchExpressions: []corev1.NodeSelectorRequirement{
														{
															Key:      "ztunnel-affinity-key",
															Operator: corev1.NodeSelectorOpExists,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				func(daemonset *appsv1.DaemonSet) {
					Expect(daemonset.Spec.Template.Spec.Affinity).NotTo(BeNil())
					Expect(daemonset.Spec.Template.Spec.Affinity.NodeAffinity).NotTo(BeNil())
					Expect(daemonset.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0].Key).To(Equal("ztunnel-affinity-key"))
				},
			),
		)
	})

	Describe("DSCP Mark Configuration", func() {
		It("should set DSCP mark value correctly", func() {
			dscpMark := numorstring.DSCPFromInt(10)
			cfg.Istio.Spec.DSCPMark = &dscpMark

			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundEnvVar := false
			for _, container := range daemonset.Spec.Template.Spec.Containers {
				if container.Name == "install-cni" {
					for _, env := range container.Env {
						if env.Name == "MAGIC_DSCP_MARK" {
							Expect(env.Value).To(Equal("10"))
							foundEnvVar = true
							break
						}
					}
				}
			}
			Expect(foundEnvVar).To(BeTrue(), "MAGIC_DSCP_MARK env var not found")
		})
	})

	Describe("Component Metadata", func() {
		It("should return Ready as true", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(component.Ready()).To(BeTrue())
		})

		It("should return Linux as supported OS type", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(component.SupportedOSType()).To(Equal(rmeta.OSTypeLinux))
		})
	})

	Describe("CRDs Component", func() {
		It("should return Ready as true", func() {
			crds, _, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(crds.Ready()).To(BeTrue())
		})

		It("should return Linux as supported OS type", func() {
			crds, _, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(crds.SupportedOSType()).To(Equal(rmeta.OSTypeLinux))
		})

		It("should not require image resolution", func() {
			crds, _, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{},
				},
			}

			err = crds.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Describe("Image Patching", func() {
		It("should patch all required images", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := getCalicoTestImageSet()
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// Verify istiod deployment image
			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundDiscoveryContainer := false
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == "discovery" {
					foundDiscoveryContainer = true
					expectedImage, _ := components.GetReference(components.ComponentCalicoIstioPilot, cfg.Installation.Registry, cfg.Installation.ImagePath, cfg.Installation.ImagePrefix, imageSet)
					Expect(container.Image).To(Equal(expectedImage))
					break
				}
			}
			Expect(foundDiscoveryContainer).To(BeTrue(), "discovery container not found in istiod deployment")

			// Verify CNI daemonset image
			cniDS, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundInstallCNIContainer := false
			for _, container := range cniDS.Spec.Template.Spec.Containers {
				if container.Name == "install-cni" {
					foundInstallCNIContainer = true
					expectedImage, _ := components.GetReference(components.ComponentCalicoIstioInstallCNI, cfg.Installation.Registry, cfg.Installation.ImagePath, cfg.Installation.ImagePrefix, imageSet)
					Expect(container.Image).To(Equal(expectedImage))
					break
				}
			}
			Expect(foundInstallCNIContainer).To(BeTrue(), "install-cni container not found in CNI daemonset")

			// Verify ztunnel daemonset image
			ztunnelDS, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundIstioProxyContainer := false
			for _, container := range ztunnelDS.Spec.Template.Spec.Containers {
				if container.Name == "istio-proxy" {
					foundIstioProxyContainer = true
					expectedImage, _ := components.GetReference(components.ComponentCalicoIstioZTunnel, cfg.Installation.Registry, cfg.Installation.ImagePath, cfg.Installation.ImagePrefix, imageSet)
					Expect(container.Image).To(Equal(expectedImage))
					break
				}
			}
			Expect(foundIstioProxyContainer).To(BeTrue(), "istio-proxy container not found in ztunnel daemonset")
		})

		It("should patch ConfigMap with proxyv2 image", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			err = component.ResolveImages(getCalicoTestImageSet())
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// Find the istio-sidecar-injector ConfigMap
			configMap, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "istio-sidecar-injector", istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// Verify that the fake image has been replaced
			for _, data := range configMap.Data {
				Expect(data).NotTo(ContainSubstring("fake.io/fakeimg/proxyv2:faketag"))
			}
		})

	})

	Describe("GKE Platform Configuration", func() {
		var component *istio.IstioComponent

		BeforeEach(func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

			_, comp, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			component = comp
		})

		It("should render all workloads successfully on GKE", func() {
			objsToCreate, objsToDelete := component.Objects()

			// GKE adds: istio-cni ResourceQuota + ztunnel ResourceQuota
			Expect(objsToCreate).To(HaveLen(34))
			Expect(objsToDelete).To(HaveLen(3))

			// Start with common resources and append GKE-specific ones
			expectedResources := getCommonExpectedResources()
			expectedResources = append(expectedResources,
				// ResourceQuotas (GKE specific)
				&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "istio-cni-resource-quota", Namespace: istio.IstioNamespace}},
				&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "ztunnel", Namespace: istio.IstioNamespace}},
			)
			expectedDeleteResources := getCommonExpectedDeleteResources()

			rtest.ExpectResources(objsToCreate, expectedResources)
			rtest.ExpectResources(objsToDelete, expectedDeleteResources)
		})

		It("should set PLATFORM env var on istiod", func() {
			objsToCreate, _ := component.Objects()
			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundPlatformEnv := false
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == "discovery" {
					for _, env := range container.Env {
						if env.Name == "PLATFORM" {
							Expect(env.Value).To(Equal("gke"))
							foundPlatformEnv = true
						}
					}
				}
			}
			Expect(foundPlatformEnv).To(BeTrue(), "Expected PLATFORM=gke env var on istiod")
		})
	})

	Describe("OpenShift Platform Configuration", func() {
		var component *istio.IstioComponent

		BeforeEach(func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift

			_, comp, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			component = comp
		})

		It("should render all workloads successfully on OpenShift", func() {
			objsToCreate, objsToDelete := component.Objects()

			// OpenShift adds: NetworkAttachmentDefinition (CNI/Multus) +
			// ztunnel ClusterRole + ztunnel ClusterRoleBinding (SCC)
			Expect(objsToCreate).To(HaveLen(35))
			Expect(objsToDelete).To(HaveLen(3))
		})

		It("should include SCC use rule in istio-cni ClusterRole", func() {
			objsToCreate, _ := component.Objects()

			clusterRole, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, "istio-cni", "")
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the OpenShift SCC rule is present
			foundSCCRule := false
			for _, rule := range clusterRole.Rules {
				for _, apiGroup := range rule.APIGroups {
					if apiGroup == "security.openshift.io" {
						Expect(rule.Resources).To(ContainElement("securitycontextconstraints"))
						Expect(rule.Verbs).To(ContainElement("use"))
						Expect(rule.ResourceNames).To(ContainElement("privileged"))
						foundSCCRule = true
					}
				}
			}
			Expect(foundSCCRule).To(BeTrue(), "Expected SCC 'use' rule in istio-cni ClusterRole for OpenShift")
		})

		It("should include SCC use rule in ztunnel ClusterRole", func() {
			objsToCreate, _ := component.Objects()

			clusterRole, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, "ztunnel", "")
			Expect(err).ShouldNot(HaveOccurred())

			foundSCCRule := false
			for _, rule := range clusterRole.Rules {
				for _, apiGroup := range rule.APIGroups {
					if apiGroup == "security.openshift.io" {
						Expect(rule.Resources).To(ContainElement("securitycontextconstraints"))
						Expect(rule.Verbs).To(ContainElement("use"))
						Expect(rule.ResourceNames).To(ContainElement("privileged"))
						foundSCCRule = true
					}
				}
			}
			Expect(foundSCCRule).To(BeTrue(), "Expected SCC 'use' rule in ztunnel ClusterRole for OpenShift")
		})

		It("should use OpenShift CNI bin directory", func() {
			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the hostPath volume uses /var/lib/cni/bin (OpenShift path)
			foundCNIBinVolume := false
			for _, vol := range daemonset.Spec.Template.Spec.Volumes {
				if vol.Name == "cni-bin-dir" && vol.HostPath != nil {
					Expect(vol.HostPath.Path).To(Equal("/var/lib/cni/bin"))
					foundCNIBinVolume = true
				}
			}
			Expect(foundCNIBinVolume).To(BeTrue(), "Expected cni-bin-dir volume with OpenShift path /var/lib/cni/bin")
		})

		It("should use Multus CNI config directory", func() {
			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the hostPath volume uses /etc/cni/multus/net.d (Multus config dir)
			foundCNINetVolume := false
			for _, vol := range daemonset.Spec.Template.Spec.Volumes {
				if vol.Name == "cni-net-dir" && vol.HostPath != nil {
					Expect(vol.HostPath.Path).To(Equal("/etc/cni/multus/net.d"))
					foundCNINetVolume = true
				}
			}
			Expect(foundCNINetVolume).To(BeTrue(), "Expected cni-net-dir volume with Multus path /etc/cni/multus/net.d")
		})

		It("should set PLATFORM env var on istiod", func() {
			objsToCreate, _ := component.Objects()

			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundPlatformEnv := false
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == "discovery" {
					for _, env := range container.Env {
						if env.Name == "PLATFORM" {
							Expect(env.Value).To(Equal("openshift"))
							foundPlatformEnv = true
						}
					}
				}
			}
			Expect(foundPlatformEnv).To(BeTrue(), "Expected PLATFORM=openshift env var on istiod")
		})

		It("should set trusted ztunnel namespace to calico-system on istiod", func() {
			objsToCreate, _ := component.Objects()

			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundTrustedAccounts := false
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == "discovery" {
					for _, env := range container.Env {
						if env.Name == "CA_TRUSTED_NODE_ACCOUNTS" {
							Expect(env.Value).To(Equal("calico-system/ztunnel"))
							foundTrustedAccounts = true
						}
					}
				}
			}
			Expect(foundTrustedAccounts).To(BeTrue(), "Expected CA_TRUSTED_NODE_ACCOUNTS=calico-system/ztunnel on istiod")
		})

		It("should set SELinux context on ztunnel", func() {
			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundSELinux := false
			for _, container := range daemonset.Spec.Template.Spec.Containers {
				if container.Name == "istio-proxy" {
					Expect(container.SecurityContext).NotTo(BeNil())
					Expect(container.SecurityContext.SELinuxOptions).NotTo(BeNil())
					Expect(container.SecurityContext.SELinuxOptions.Type).To(Equal("spc_t"))
					foundSELinux = true
				}
			}
			Expect(foundSELinux).To(BeTrue(), "Expected SELinux type spc_t on ztunnel container")
		})
	})
})
