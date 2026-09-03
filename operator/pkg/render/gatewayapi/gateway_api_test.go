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

package gatewayapi

import (
	"fmt"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

type matchObject struct {
	name string
}

func (m *matchObject) Match(actual any) (success bool, err error) {
	return actual.(client.Object).GetName() == m.name, nil
}

func (m *matchObject) FailureMessage(actual any) (message string) {
	return "" // not used within ContainElement
}

func (m *matchObject) NegatedFailureMessage(actual any) (message string) {
	return "" // not used within ContainElement
}

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	Expect(scheme.AddToScheme(s)).ShouldNot(HaveOccurred())
	Expect(apiextenv1.AddToScheme(s)).ShouldNot(HaveOccurred())
	Expect(admissionregv1.AddToScheme(s)).ShouldNot(HaveOccurred())
	return s
}

// expectLegacyCleanup asserts the legacy tigera-gateway upgrade-cleanup is
// queued in objsToDelete and the Namespace itself is *not* deleted. hasPullSecret
// accounts for the tigera-pull-secret previously copied into the legacy namespace.
func expectLegacyCleanup(objsToDelete []client.Object, hasPullSecret bool) {
	expected := 12 + 4 + 1 + 3 // helm-rendered in-namespace + certgen Secrets + tigera-operator-secrets RB + cluster-scoped (MWC, CR, CRB).
	if hasPullSecret {
		expected += 1
	}
	Expect(objsToDelete).To(HaveLen(expected))
	for _, o := range objsToDelete {
		if ns, ok := o.(*corev1.Namespace); ok {
			Expect(ns.Name).NotTo(Equal("tigera-gateway"),
				"tigera-gateway Namespace must not be deleted — users may have placed their own resources there")
		}
	}
	rtest.ExpectResourceInList(objsToDelete, "envoy-gateway-topology-injector.tigera-gateway", "", "admissionregistration.k8s.io", "v1", "MutatingWebhookConfiguration")
	rtest.ExpectResourceInList(objsToDelete, "envoy-gateway", "tigera-gateway", "apps", "v1", "Deployment")
	rtest.ExpectResourceInList(objsToDelete, "envoy", "tigera-gateway", "", "v1", "Secret")
	rtest.ExpectResourceInList(objsToDelete, "tigera-operator-secrets", "tigera-gateway", "rbac.authorization.k8s.io", "v1", "RoleBinding")
}

var _ = Describe("Gateway API rendering tests", func() {

	// Helm-rendered resources for the envoy-gateway controller in calico-system,
	// plus the auto-provisioned default GatewayClass.
	controllerExpected := []client.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "calico-system"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-config", Namespace: "calico-system"}},
		&admissionregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-topology-injector.calico-system"}},
		&admissionregv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: "safe-upgrades.gateway.networking.k8s.io"}},
		&admissionregv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: "safe-upgrades.gateway.networking.k8s.io"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-role"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-cluster-infra-manager"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:calico-system"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-rolebinding"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-cluster-infra-manager"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:calico-system"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "calico-system"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-role", Namespace: "calico-system"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "calico-system"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-rolebinding", Namespace: "calico-system"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "calico-system"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "calico-system"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "calico-system"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "calico-system"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "calico-system"}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "calico-system"}},
		&envoyapi.EnvoyProxy{ObjectMeta: metav1.ObjectMeta{Name: GatewayClassName, Namespace: "calico-system"}},
		&gapi.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: GatewayClassName}},
	}

	// V3 NetworkPolicy allowing the controller under the calico-system default-deny tier.
	bootstrapExpected := []client.Object{
		&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: ControllerPolicyName, Namespace: common.CalicoNamespace}},
	}

	It("should render Gateway API resources from helm chart", func() {
		s := testScheme()
		resources, err := renderChart(s)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(resources.controllerDeployment).NotTo(BeNil())
		Expect(resources.controllerDeployment.Namespace).To(Equal(common.CalicoNamespace))
	})

	It("should report UDPRoute as required when platform is not OpenShift", func() {
		s := testScheme()
		essentialCRDs, optionalCRDs, err := GatewayAPICRDs(operatorv1.ProviderAKS, s)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(essentialCRDs).To(ContainElement(&matchObject{name: "udproutes.gateway.networking.k8s.io"}))
		Expect(optionalCRDs).NotTo(ContainElement(&matchObject{name: "udproutes.gateway.networking.k8s.io"}))
	})

	It("should report UDPRoute as optional when platform is OpenShift", func() {
		s := testScheme()
		essentialCRDs, optionalCRDs, err := GatewayAPICRDs(operatorv1.ProviderOpenShift, s)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(essentialCRDs).NotTo(ContainElement(&matchObject{name: "udproutes.gateway.networking.k8s.io"}))
		Expect(optionalCRDs).To(ContainElement(&matchObject{name: "udproutes.gateway.networking.k8s.io"}))
	})

	It("should apply overrides from GatewayAPI CR", func() {
		installation := &operatorv1.InstallationSpec{}
		five := int32(5)
		affinity := &corev1.Affinity{}
		resourceRequirements := &corev1.ResourceRequirements{
			Claims: []corev1.ResourceClaim{{
				Name: "whatnot",
			}},
		}
		tolerations := []corev1.Toleration{}
		rollingUpdate := &appsv1.RollingUpdateDeployment{}
		topologySpreadConstraints := []corev1.TopologySpreadConstraint{}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayControllerDeployment: &operatorv1.GatewayControllerDeployment{
					Metadata: &operatorv1.Metadata{
						Labels: map[string]string{
							"x":     "y",
							"white": "black",
						},
						Annotations: map[string]string{
							"up":    "down",
							"round": "flat",
						},
					},
					Spec: &operatorv1.GatewayControllerDeploymentSpec{
						MinReadySeconds: &five,
						Template: &operatorv1.GatewayControllerDeploymentPodTemplate{
							Metadata: &operatorv1.Metadata{
								Labels: map[string]string{
									"rural": "urban",
								},
								Annotations: map[string]string{
									"haste": "speed",
								},
							},
							Spec: &operatorv1.GatewayControllerDeploymentPodSpec{
								Affinity: affinity,
								Containers: []operatorv1.GatewayControllerDeploymentContainer{{
									Name:      "envoy-gateway",
									Resources: resourceRequirements,
								}},
								NodeSelector: map[string]string{
									"fast": "slow",
								},
								Tolerations: tolerations,
							},
						},
					},
				},
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "tigera-gateway-class",
					GatewayDeployment: &operatorv1.GatewayDeployment{
						Spec: &operatorv1.GatewayDeploymentSpec{
							Template: &operatorv1.GatewayDeploymentPodTemplate{
								Metadata: &operatorv1.Metadata{
									Labels: map[string]string{
										"g-rural": "urban",
									},
									Annotations: map[string]string{
										"g-haste": "speed",
									},
								},
								Spec: &operatorv1.GatewayDeploymentPodSpec{
									Affinity: affinity,
									Containers: []operatorv1.GatewayDeploymentContainer{{
										Name:      "envoy",
										Resources: resourceRequirements,
									}},
									NodeSelector: map[string]string{
										"g-fast": "slow",
									},
									Tolerations:               tolerations,
									TopologySpreadConstraints: topologySpreadConstraints,
								},
							},
							Strategy: &operatorv1.GatewayDeploymentStrategy{
								RollingUpdate: rollingUpdate,
							},
						},
					},
				}},
				GatewayCertgenJob: &operatorv1.GatewayCertgenJob{
					Metadata: &operatorv1.Metadata{
						Labels: map[string]string{
							"job-x":     "y",
							"job-white": "black",
						},
						Annotations: map[string]string{
							"job-up":    "down",
							"job-round": "flat",
						},
					},
					Spec: &operatorv1.GatewayCertgenJobSpec{
						Template: &operatorv1.GatewayCertgenJobPodTemplate{
							Metadata: &operatorv1.Metadata{
								Labels: map[string]string{
									"job-rural": "urban",
								},
								Annotations: map[string]string{
									"job-haste": "speed",
								},
							},
							Spec: &operatorv1.GatewayCertgenJobPodSpec{
								Affinity: affinity,
								Containers: []operatorv1.GatewayCertgenJobContainer{{
									Name:      "envoy-gateway-certgen",
									Resources: resourceRequirements,
								}},
								NodeSelector: map[string]string{
									"job-fast": "slow",
								},
								Tolerations: tolerations,
							},
						},
					},
				},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:                 testScheme(),
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())
		By("resolving images")
		objsToCreate, objsToDelete := gatewayComp.Objects()
		// Legacy tigera-gateway install cleanup (operator-owned only; the
		// Namespace itself is intentionally not deleted).
		expectLegacyCleanup(objsToDelete, false)
		Expect(objsToCreate).NotTo(BeEmpty())

		expected := append([]client.Object{}, bootstrapExpected...)
		expected = append(expected, controllerExpected...)
		rtest.ExpectResources(objsToCreate, expected)

		deploy, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(deploy.Labels).To(HaveKeyWithValue("x", "y"))
		Expect(deploy.Labels).To(HaveKeyWithValue("white", "black"))
		Expect(deploy.Annotations).To(HaveKeyWithValue("up", "down"))
		Expect(deploy.Annotations).To(HaveKeyWithValue("round", "flat"))
		Expect(deploy.Spec.MinReadySeconds).To(BeNumerically("==", 5))
		Expect(deploy.Spec.Template.Labels).To(HaveKeyWithValue("rural", "urban"))
		Expect(deploy.Spec.Template.Annotations).To(HaveKeyWithValue("haste", "speed"))
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(affinity))
		Expect(deploy.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway"),
			HaveField("Resources", *resourceRequirements),
		)))
		Expect(deploy.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("fast", "slow"))
		Expect(deploy.Spec.Template.Spec.Tolerations).To(Equal(tolerations))

		job, err := rtest.GetResourceOfType[*batchv1.Job](objsToCreate, "tigera-gateway-api-gateway-helm-certgen", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(job.Labels).To(HaveKeyWithValue("job-x", "y"))
		Expect(job.Labels).To(HaveKeyWithValue("job-white", "black"))
		Expect(job.Annotations).To(HaveKeyWithValue("job-up", "down"))
		Expect(job.Annotations).To(HaveKeyWithValue("job-round", "flat"))
		Expect(job.Spec.Template.Labels).To(HaveKeyWithValue("job-rural", "urban"))
		Expect(job.Spec.Template.Annotations).To(HaveKeyWithValue("job-haste", "speed"))
		Expect(job.Spec.Template.Spec.Affinity).To(Equal(affinity))
		Expect(job.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway-certgen"),
			HaveField("Resources", *resourceRequirements),
		)))
		Expect(job.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("job-fast", "slow"))
		Expect(job.Spec.Template.Spec.Tolerations).To(Equal(tolerations))

		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, GatewayClassName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Labels).To(HaveKeyWithValue("g-rural", "urban"))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Annotations).To(HaveKeyWithValue("g-haste", "speed"))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Affinity).To(Equal(affinity))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.NodeSelector).To(HaveKeyWithValue("g-fast", "slow"))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Tolerations).To(Equal(tolerations))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.TopologySpreadConstraints).To(Equal(topologySpreadConstraints))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Resources).To(Equal(resourceRequirements))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Strategy.RollingUpdate).To(Equal(rollingUpdate))
	})

	It("should honour private registry (OSS)", func() {
		pullSecretRefs := []corev1.LocalObjectReference{{
			Name: "secret1",
		}}
		pullSecrets := []*corev1.Secret{}
		for _, ref := range pullSecretRefs {
			pullSecrets = append(pullSecrets, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: common.OperatorNamespace()},
			})
		}
		installation := &operatorv1.InstallationSpec{
			Registry:         "myregistry.io/",
			ImagePullSecrets: pullSecretRefs,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:                 testScheme(),
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			PullSecrets:            pullSecrets,
			IncludeV3NetworkPolicy: true,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/calico/envoy-gateway:" + components.ComponentCalicoEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/calico/envoy-ratelimit:" + components.ComponentCalicoEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/calico/envoy-proxy:" + components.ComponentCalicoEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		// Legacy tigera-gateway install cleanup, including the pull secret
		// previously copied into tigera-gateway by the legacy install.
		expectLegacyCleanup(objsToDelete, true)

		// calico-system is core-owned, so pull secrets are not copied here — the
		// controller Deployment still references them via ImagePullSecrets.
		expected := append([]client.Object{}, bootstrapExpected...)
		expected = append(expected, controllerExpected...)
		rtest.ExpectResources(objsToCreate, expected)

		deploy, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(deploy.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway"),
			HaveField("Image", "myregistry.io/calico/envoy-gateway:"+components.ComponentCalicoEnvoyGateway.Version),
		)))
		Expect(deploy.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		job, err := rtest.GetResourceOfType[*batchv1.Job](objsToCreate, "tigera-gateway-api-gateway-helm-certgen", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(job.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway-certgen"),
			HaveField("Image", "myregistry.io/calico/envoy-gateway:"+components.ComponentCalicoEnvoyGateway.Version),
		)))
		Expect(job.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, GatewayClassName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(*proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Image).To(Equal("myregistry.io/calico/envoy-proxy:" + components.ComponentCalicoEnvoyProxy.Version))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		gatewayCM, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "envoy-gateway-config", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig := &envoyapi.EnvoyGateway{}
		Expect(yaml.Unmarshal([]byte(gatewayCM.Data[EnvoyGatewayConfigKey]), gatewayConfig)).NotTo(HaveOccurred())
		Expect(gatewayConfig.APIVersion).NotTo(Equal(""), fmt.Sprintf("gatewayConfig = %#v", *gatewayConfig))
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment).NotTo(BeNil())
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container).NotTo(BeNil())
		Expect(*gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container.Image).To(Equal("myregistry.io/calico/envoy-ratelimit:" + components.ComponentCalicoEnvoyRatelimit.Version))
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))
		Expect(*gatewayConfig.Provider.Kubernetes.ShutdownManager.Image).To(Equal("myregistry.io/calico/envoy-gateway:" + components.ComponentCalicoEnvoyGateway.Version))
		Expect(gatewayConfig.ExtensionAPIs).NotTo(BeNil())
		Expect(gatewayConfig.ExtensionAPIs.EnableBackend).To(BeTrue())
	})

	It("honours gateway controller customizations", func() {
		DeferCleanup(components.UseImages(components.EnterpriseImages))

		installation := &operatorv1.InstallationSpec{
			Registry: "myregistry.io/",
			Variant:  operatorv1.CalicoEnterprise,
		}
		threeReplicas := int32(3)
		topologySpreadConstraints := []corev1.TopologySpreadConstraint{{
			MaxSkew:     2,
			TopologyKey: "balanced",
		}}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				GatewayControllerDeployment: &operatorv1.GatewayControllerDeployment{
					Spec: &operatorv1.GatewayControllerDeploymentSpec{
						Replicas: &threeReplicas,
						Template: &operatorv1.GatewayControllerDeploymentPodTemplate{
							Metadata: &operatorv1.Metadata{},
							Spec: &operatorv1.GatewayControllerDeploymentPodSpec{
								TopologySpreadConstraints: topologySpreadConstraints,
							},
						},
					},
				},
			},
		}
		customName := "my-gateway-controller"
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyGateway: &envoyapi.EnvoyGateway{
				EnvoyGatewaySpec: envoyapi.EnvoyGatewaySpec{
					Provider: &envoyapi.EnvoyGatewayProvider{
						Type: envoyapi.ProviderTypeKubernetes,
						Kubernetes: &envoyapi.EnvoyGatewayKubernetesProvider{
							RateLimitDeployment: &envoyapi.KubernetesDeploymentSpec{
								Name: &customName,
							},
						},
					},
					ExtensionAPIs: &envoyapi.ExtensionAPISettings{
						EnableEnvoyPatchPolicy: true,
					},
				},
			},
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		expectLegacyCleanup(objsToDelete, false)

		deploy, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(deploy.Spec.Replicas).NotTo(BeNil())
		Expect(*deploy.Spec.Replicas).To(BeNumerically("==", threeReplicas))
		Expect(deploy.Spec.Template.Spec.TopologySpreadConstraints).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologySpreadConstraints))

		gatewayCM, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "envoy-gateway-config", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig := &envoyapi.EnvoyGateway{}
		Expect(yaml.Unmarshal([]byte(gatewayCM.Data[EnvoyGatewayConfigKey]), gatewayConfig)).NotTo(HaveOccurred())
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment).NotTo(BeNil())
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Name).NotTo(BeNil())
		Expect(*gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Name).To(Equal(customName))
		Expect(*gatewayConfig.Provider.Kubernetes.ShutdownManager.Image).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayConfig.ExtensionAPIs).NotTo(BeNil())
		Expect(gatewayConfig.ExtensionAPIs.EnableBackend).To(BeTrue())
		Expect(gatewayConfig.ExtensionAPIs.EnableEnvoyPatchPolicy).To(BeTrue())
	})

	It("honours GatewayClass and EnvoyProxy customizations", func() {
		DeferCleanup(components.UseImages(components.EnterpriseImages))

		installation := &operatorv1.InstallationSpec{
			Registry: "myregistry.io/",
			Variant:  operatorv1.CalicoEnterprise,
		}
		twoReplicas := int32(2)
		topologySpreadConstraints := []corev1.TopologySpreadConstraint{{
			MaxSkew:     2,
			TopologyKey: "balanced",
		}}
		lbClass := "upper"
		lbIP := "10.4.10.4"
		resourceRequirements := &corev1.ResourceRequirements{
			Claims: []corev1.ResourceClaim{{
				Name: "whatnot",
			}},
		}
		daemonSet := operatorv1.GatewayKindDaemonSet
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class-1",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-1",
					},
					GatewayService: &operatorv1.GatewayService{
						Metadata: &operatorv1.Metadata{
							Annotations: map[string]string{
								"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
								"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "instance",
								"service.beta.kubernetes.io/aws-load-balancer-scheme":          "internet-facing",
							},
						},
					},
				}, {
					Name: "custom-class-2",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-2", // Daemonset instead of Deployment
					},
					GatewayDaemonSet: &operatorv1.GatewayDaemonSet{
						Spec: &operatorv1.GatewayDaemonSetSpec{
							Template: &operatorv1.GatewayDaemonSetPodTemplate{
								Spec: &operatorv1.GatewayDaemonSetPodSpec{
									TopologySpreadConstraints: topologySpreadConstraints,
								},
							},
						},
					},
				}, {
					Name: "custom-class-3",
					// No custom EnvoyProxy for this class.
					GatewayDeployment: &operatorv1.GatewayDeployment{
						Spec: &operatorv1.GatewayDeploymentSpec{
							Replicas: &twoReplicas,
							Template: &operatorv1.GatewayDeploymentPodTemplate{
								Metadata: &operatorv1.Metadata{
									Labels: map[string]string{
										"envoy-proxy": "standard",
									},
								},
								Spec: &operatorv1.GatewayDeploymentPodSpec{
									Containers: []operatorv1.GatewayDeploymentContainer{{
										Name:      "envoy",
										Resources: resourceRequirements,
									}},
									NodeSelector: map[string]string{
										"east": "west",
									},
								},
							},
						},
					},
					GatewayService: &operatorv1.GatewayService{
						Spec: &operatorv1.GatewayServiceSpec{
							LoadBalancerClass: &lbClass,
							LoadBalancerSourceRanges: []string{
								"182.98.44.55/24",
							},
							LoadBalancerIP: &lbIP,
						},
					},
				}, {
					Name: "custom-class-4",
					// Same as custom-class-3 but with DaemonSet.
					GatewayKind: &daemonSet,
					GatewayDaemonSet: &operatorv1.GatewayDaemonSet{
						Spec: &operatorv1.GatewayDaemonSetSpec{
							Template: &operatorv1.GatewayDaemonSetPodTemplate{
								Metadata: &operatorv1.Metadata{
									Labels: map[string]string{
										"envoy-proxy": "standard",
									},
								},
								Spec: &operatorv1.GatewayDaemonSetPodSpec{
									Containers: []operatorv1.GatewayDaemonSetContainer{{
										Name:      "envoy",
										Resources: resourceRequirements,
									}},
									NodeSelector: map[string]string{
										"east": "west",
									},
								},
							},
						},
					},
					GatewayService: &operatorv1.GatewayService{
						Spec: &operatorv1.GatewayServiceSpec{
							LoadBalancerClass: &lbClass,
							LoadBalancerSourceRanges: []string{
								"182.98.44.55/24",
							},
							LoadBalancerIP: &lbIP,
						},
					},
				}},
			},
		}

		envoyProxy1 := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy-1",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Logging: envoyapi.ProxyLogging{
					Level: map[envoyapi.ProxyLogComponent]envoyapi.LogLevel{
						envoyapi.LogComponentAdmin: envoyapi.LogLevelWarn,
					},
				},
			},
		}
		envoyProxy2 := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy-2",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Provider: &envoyapi.EnvoyProxyProvider{
					Type: envoyapi.EnvoyProxyProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDaemonSet: &envoyapi.KubernetesDaemonSetSpec{
							Pod: &envoyapi.KubernetesPodSpec{
								NodeSelector: map[string]string{
									"x": "y",
								},
							},
						},
					},
				},
			},
		}

		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyProxies: map[string]*envoyapi.EnvoyProxy{
				"custom-class-1": envoyProxy1,
				"custom-class-2": envoyProxy2,
			},
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		expectLegacyCleanup(objsToDelete, false)

		// The user-declared GatewayClasses fully replace the default — the controller
		// only patches in tigera-gateway-class when Spec.GatewayClasses is nil.
		_, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, GatewayClassName, "")
		Expect(err).To(HaveOccurred())

		// GatewayClass is cluster-scoped, so namespace is empty.
		gc1, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class-1", "")
		Expect(err).NotTo(HaveOccurred())
		gc2, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class-2", "")
		Expect(err).NotTo(HaveOccurred())
		gc3, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class-3", "")
		Expect(err).NotTo(HaveOccurred())
		gc4, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class-4", "")
		Expect(err).NotTo(HaveOccurred())

		// Get their four EnvoyProxies.
		Expect(gc1.Spec.ParametersRef).NotTo(BeNil())
		ep1, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc1.Spec.ParametersRef.Name, string(*gc1.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())
		ep2, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc2.Spec.ParametersRef.Name, string(*gc2.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())
		ep3, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc3.Spec.ParametersRef.Name, string(*gc3.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())
		ep4, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc4.Spec.ParametersRef.Name, string(*gc4.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())

		// Check customizations from custom EnvoyProxies.
		Expect(ep1.Spec.Logging.Level).To(Equal(envoyProxy1.Spec.Logging.Level))

		Expect(ep2.Spec.Provider.Kubernetes.EnvoyDaemonSet).NotTo(BeNil())
		Expect(ep2.Spec.Provider.Kubernetes.EnvoyDeployment).To(BeNil())
		Expect(ep2.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.NodeSelector).To(Equal(envoyProxy2.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.NodeSelector))
		Expect(ep2.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.TopologySpreadConstraints).To(Equal(topologySpreadConstraints))

		// Check customizations from class-specific customization structs.
		Expect(ep1.Spec.Provider.Kubernetes.EnvoyService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
		Expect(ep1.Spec.Provider.Kubernetes.EnvoyService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
		Expect(ep1.Spec.Provider.Kubernetes.EnvoyService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))

		Expect(ep3.Spec.Provider.Kubernetes.EnvoyDeployment).NotTo(BeNil())
		Expect(*ep3.Spec.Provider.Kubernetes.EnvoyDeployment.Replicas).To(Equal(*gatewayAPI.Spec.GatewayClasses[2].GatewayDeployment.Spec.Replicas))
		Expect(ep3.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Labels).To(HaveKeyWithValue("envoy-proxy", "standard"))
		Expect(ep3.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Resources).To(Equal(resourceRequirements))
		Expect(ep3.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.NodeSelector).To(HaveKeyWithValue("east", "west"))
		Expect(*ep3.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerClass).To(Equal(lbClass))
		Expect(ep3.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerSourceRanges).To(ConsistOf("182.98.44.55/24"))
		Expect(*ep3.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerIP).To(Equal(lbIP))

		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDeployment).To(BeNil())
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDaemonSet).NotTo(BeNil())
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.Labels).To(HaveKeyWithValue("envoy-proxy", "standard"))
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container.Resources).To(Equal(resourceRequirements))
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.NodeSelector).To(HaveKeyWithValue("east", "west"))
		Expect(*ep4.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerClass).To(Equal(lbClass))
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerSourceRanges).To(ConsistOf("182.98.44.55/24"))
		Expect(*ep4.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerIP).To(Equal(lbIP))
	})

	It("passes GatewayService.Spec.Patch through to the EnvoyProxy's KubernetesServiceSpec", func() {
		patchYAML := `
type: JSONMerge
value:
  spec:
    ports:
    - name: http-80
      nodePort: 30008
      port: 80
      protocol: TCP
      targetPort: 10080
    - name: https-443
      nodePort: 30004
      port: 443
      protocol: TCP
      targetPort: 10443
`
		patch := &envoyapi.KubernetesPatchSpec{}
		Expect(yaml.Unmarshal([]byte(patchYAML), patch)).NotTo(HaveOccurred())

		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "tigera-gateway-class",
					GatewayService: &operatorv1.GatewayService{
						Spec: &operatorv1.GatewayServiceSpec{
							Patch: patch,
						},
					},
				}},
			},
		}
		gatewayComp, err := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico},
			GatewayAPI:   gatewayAPI,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()
		ep, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(ep.Spec.Provider).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes.EnvoyService).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes.EnvoyService.Patch).To(Equal(patch))
	})

	// https://github.com/projectcalico/calico/operator/issues/4717
	It("supports setting ipFamilyPolicy on the gateway Service via GatewayService.Spec.Patch", func() {
		patchYAML := `
type: StrategicMerge
value:
  spec:
    ipFamilyPolicy: RequireDualStack
`
		patch := &envoyapi.KubernetesPatchSpec{}
		Expect(yaml.Unmarshal([]byte(patchYAML), patch)).NotTo(HaveOccurred())

		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "tigera-gateway-class",
					GatewayService: &operatorv1.GatewayService{
						Spec: &operatorv1.GatewayServiceSpec{
							Patch: patch,
						},
					},
				}},
			},
		}
		gatewayComp, err := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico},
			GatewayAPI:   gatewayAPI,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()
		ep, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(ep.Spec.Provider).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes.EnvoyService).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes.EnvoyService.Patch).To(Equal(patch))
	})

	// https://github.com/projectcalico/calico/operator/issues/4718
	It("supports setting healthCheckNodePort on the gateway Service via GatewayService.Spec.Patch", func() {
		patchYAML := `
type: StrategicMerge
value:
  spec:
    healthCheckNodePort: 12345
`
		patch := &envoyapi.KubernetesPatchSpec{}
		Expect(yaml.Unmarshal([]byte(patchYAML), patch)).NotTo(HaveOccurred())

		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "tigera-gateway-class",
					GatewayService: &operatorv1.GatewayService{
						Spec: &operatorv1.GatewayServiceSpec{
							Patch: patch,
						},
					},
				}},
			},
		}
		gatewayComp, err := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico},
			GatewayAPI:   gatewayAPI,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()
		ep, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(ep.Spec.Provider).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes.EnvoyService).NotTo(BeNil())
		Expect(ep.Spec.Provider.Kubernetes.EnvoyService.Patch).To(Equal(patch))
	})

	It("mounts the trust bundle on envoy-gateway and envoy-proxy when provided", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.Calico,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		bundle, err := certificatemanagement.CreateTrustedBundleWithSystemRootCertificates(nil)
		Expect(err).NotTo(HaveOccurred())
		gatewayComp, err := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:        testScheme(),
			Installation:  installation,
			GatewayAPI:    gatewayAPI,
			TrustedBundle: bundle,
		})
		Expect(err).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		// The bundle ConfigMap is materialised in the gateway namespace.
		bundleCM, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, certificatemanagement.TrustedCertConfigMapName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundleCM.Data).To(HaveKey(certificatemanagement.TrustedCertConfigMapKeyName))

		// The envoy-gateway controller mounts the bundle.
		controller, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		volNames := []string{}
		for _, v := range controller.Spec.Template.Spec.Volumes {
			volNames = append(volNames, v.Name)
		}
		Expect(volNames).To(ContainElement(certificatemanagement.TrustedCertConfigMapName))
		mountPaths := []string{}
		for _, m := range controller.Spec.Template.Spec.Containers[0].VolumeMounts {
			mountPaths = append(mountPaths, m.MountPath)
		}
		Expect(mountPaths).To(ContainElement("/etc/pki/tls/certs"))

		// The envoy-proxy data plane (patched via EnvoyProxy) mounts the bundle.
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		dep := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(dep).NotTo(BeNil())
		proxyVolNames := []string{}
		for _, v := range dep.Pod.Volumes {
			proxyVolNames = append(proxyVolNames, v.Name)
		}
		Expect(proxyVolNames).To(ContainElement(certificatemanagement.TrustedCertConfigMapName))
		proxyMountPaths := []string{}
		for _, m := range dep.Container.VolumeMounts {
			proxyMountPaths = append(proxyMountPaths, m.MountPath)
		}
		Expect(proxyMountPaths).To(ContainElement("/etc/pki/tls/certs"))
	})

	It("should not deploy waf-http-filter or l7-log-collector for open-source", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.Calico,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:                 testScheme(),
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, GatewayClassName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())
		Expect(envoyDeployment.InitContainers).To(BeNil())
		Expect(envoyDeployment.Container).ToNot(BeNil())
		Expect(envoyDeployment.Container.VolumeMounts).To(BeNil())
	})

	It("should not legacy-delete operator resources that the per-NS loop is re-creating in tigera-gateway", func() {
		// User Gateway in tigera-gateway: per-NS create must win over legacy delete.
		pullSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: "tigera-operator"},
			Data:       map[string][]byte{".dockerconfigjson": []byte("{}")},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:            testScheme(),
			Installation:      &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			GatewayAPI:        &operatorv1.GatewayAPI{Spec: operatorv1.GatewayAPISpec{GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}}}},
			PullSecrets:       []*corev1.Secret{pullSecret},
			GatewayNamespaces: []string{"tigera-gateway"},
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		_, objsToDelete := gatewayComp.Objects()
		for _, o := range objsToDelete {
			if o.GetNamespace() != "tigera-gateway" {
				continue
			}
			switch obj := o.(type) {
			case *corev1.ServiceAccount:
				Expect(obj.Name).NotTo(Equal("waf-http-filter"), "must not queue waf-http-filter SA for delete in tigera-gateway")
			case *corev1.Secret:
				Expect(obj.Name).NotTo(Equal("tigera-pull-secret"), "must not queue tigera-pull-secret for delete in tigera-gateway")
			case *rbacv1.RoleBinding:
				Expect(obj.Name).NotTo(Equal("tigera-operator-secrets"), "must not queue tigera-operator-secrets RB for delete in tigera-gateway")
			}
		}
	})

	It("should deploy a single envoy-gateway controller in calico-system", func() {
		installation := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:                 testScheme(),
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, objsToDelete := gatewayComp.Objects()

		// Single controller in calico-system with its auto-provisioned GatewayClass.
		_, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.Service](objsToCreate, "envoy-gateway", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "envoy-gateway", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, GatewayClassName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		gc, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, GatewayClassName, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(gc.Spec.ControllerName)).To(Equal(ControllerName))

		// No controller resources should be rendered in the legacy tigera-gateway namespace.
		for _, obj := range objsToCreate {
			Expect(obj.GetNamespace()).NotTo(Equal("tigera-gateway"),
				"unexpected resource in legacy namespace: %T %s", obj, obj.GetName())
		}

		// calico-system is owned by the core Installation; don't bootstrap shared resources there.
		_, err = rtest.GetResourceOfType[*corev1.Namespace](objsToCreate, common.CalicoNamespace, "")
		Expect(err).To(HaveOccurred())
		_, err = rtest.GetResourceOfType[*rbacv1.RoleBinding](objsToCreate, "tigera-operator-secrets", common.CalicoNamespace)
		Expect(err).To(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.Secret](objsToCreate, "tigera-pull-secret", common.CalicoNamespace)
		Expect(err).To(HaveOccurred())

		// Upgrade cleanup: the legacy controller Deployment and topology webhook
		// must be queued for delete so an in-place upgrade tears down the old
		// install. The tigera-gateway Namespace itself is intentionally left in
		// place — users may have placed their own resources there.
		for _, obj := range objsToDelete {
			if ns, ok := obj.(*corev1.Namespace); ok {
				Expect(ns.Name).NotTo(Equal("tigera-gateway"),
					"tigera-gateway Namespace must not be deleted")
			}
		}
		rtest.ExpectResourceInList(objsToDelete, "envoy-gateway", "tigera-gateway", "apps", "v1", "Deployment")
		rtest.ExpectResourceInList(objsToDelete, "envoy-gateway-topology-injector.tigera-gateway", "", "admissionregistration.k8s.io", "v1", "MutatingWebhookConfiguration")

		// calico-system has a default-deny policy from the core Installation; the
		// controller there + certgen need an allow policy to reach the kube API.
		policy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, ControllerPolicyName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(policy.Spec.Tier).To(Equal("calico-system"))
		Expect(policy.Spec.Selector).To(Equal(EnvoyGatewayPolicySelector))
		_, err = rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, "calico-system.default-deny", common.CalicoNamespace)
		Expect(err).To(HaveOccurred(), "must not render default-deny in calico-system")
	})

	It("should not render any v3 NetworkPolicy when IncludeV3NetworkPolicy is false", func() {
		gatewayComp, err := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			GatewayAPI: &operatorv1.GatewayAPI{
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				},
			},
		})
		Expect(err).NotTo(HaveOccurred())
		objsToCreate, _ := gatewayComp.Objects()
		for _, obj := range objsToCreate {
			_, isPolicy := obj.(*v3.NetworkPolicy)
			Expect(isPolicy).To(BeFalse(),
				"unexpected v3 NetworkPolicy %s/%s with IncludeV3NetworkPolicy=false", obj.GetNamespace(), obj.GetName())
		}
	})

	It("should queue the legacy tigera-gateway install for cleanup on every reconcile", func() {
		installation := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:                 testScheme(),
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, objsToDelete := gatewayComp.Objects()

		// No render should target the legacy tigera-gateway namespace; everything
		// runs in calico-system now.
		for _, obj := range objsToCreate {
			Expect(obj.GetNamespace()).NotTo(Equal("tigera-gateway"),
				"unexpected resource in legacy namespace: %T %s", obj, obj.GetName())
		}

		// Cleanup queue: every operator-owned object from the legacy install,
		// but NOT the tigera-gateway Namespace itself (users may have placed
		// their own resources there).
		for _, obj := range objsToDelete {
			if ns, ok := obj.(*corev1.Namespace); ok {
				Expect(ns.Name).NotTo(Equal("tigera-gateway"),
					"tigera-gateway Namespace must not be deleted")
			}
		}
		// Helm-rendered controller resources in tigera-gateway.
		rtest.ExpectResourceInList(objsToDelete, "envoy-gateway", "tigera-gateway", "", "v1", "ServiceAccount")
		rtest.ExpectResourceInList(objsToDelete, "envoy-gateway-config", "tigera-gateway", "", "v1", "ConfigMap")
		rtest.ExpectResourceInList(objsToDelete, "envoy-gateway", "tigera-gateway", "", "v1", "Service")
		rtest.ExpectResourceInList(objsToDelete, "envoy-gateway", "tigera-gateway", "apps", "v1", "Deployment")
		rtest.ExpectResourceInList(objsToDelete, "tigera-gateway-api-gateway-helm-certgen", "tigera-gateway", "batch", "v1", "Job")
		rtest.ExpectResourceInList(objsToDelete, "tigera-gateway-api-gateway-helm-infra-manager", "tigera-gateway", "rbac.authorization.k8s.io", "v1", "Role")
		rtest.ExpectResourceInList(objsToDelete, "tigera-gateway-api-gateway-helm-infra-manager", "tigera-gateway", "rbac.authorization.k8s.io", "v1", "RoleBinding")
		rtest.ExpectResourceInList(objsToDelete, "tigera-gateway-api-gateway-helm-leader-election-role", "tigera-gateway", "rbac.authorization.k8s.io", "v1", "Role")
		rtest.ExpectResourceInList(objsToDelete, "tigera-gateway-api-gateway-helm-leader-election-rolebinding", "tigera-gateway", "rbac.authorization.k8s.io", "v1", "RoleBinding")
		// Operator-secrets RoleBinding + cluster-scoped legacy bits.
		rtest.ExpectResourceInList(objsToDelete, "tigera-operator-secrets", "tigera-gateway", "rbac.authorization.k8s.io", "v1", "RoleBinding")
		rtest.ExpectResourceInList(objsToDelete, "envoy-gateway-topology-injector.tigera-gateway", "", "admissionregistration.k8s.io", "v1", "MutatingWebhookConfiguration")
		rtest.ExpectResourceInList(objsToDelete, "waf-http-filter", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		rtest.ExpectResourceInList(objsToDelete, "waf-http-filter", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")

		// Pull secrets in tigera-gateway must come before the
		// tigera-operator-secrets RoleBinding that grants delete perms.
		secretIdx, rbIdx := -1, -1
		for i, obj := range objsToDelete {
			if obj.GetNamespace() != "tigera-gateway" {
				continue
			}
			switch o := obj.(type) {
			case *corev1.Secret:
				secretIdx = i
				_ = o
			case *rbacv1.RoleBinding:
				if obj.GetName() == "tigera-operator-secrets" {
					rbIdx = i
				}
			}
		}
		// secretIdx may be -1 when no pull secrets are configured; in that
		// case ordering is moot.
		if secretIdx >= 0 {
			Expect(rbIdx).NotTo(Equal(-1))
			Expect(secretIdx).To(BeNumerically("<", rbIdx),
				"pull secrets must be deleted before tigera-operator-secrets RoleBinding")
		}
	})
})
