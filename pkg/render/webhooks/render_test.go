// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package webhooks_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/webhooks"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Webhooks rendering tests", func() {
	var (
		installation       *operatorv1.InstallationSpec
		apiServerSpec      *operatorv1.APIServerSpec
		cfg                *webhooks.Configuration
		certificateManager certificatemanager.CertificateManager
		cli                client.Client
		clusterDomain      = "cluster.local"
	)

	BeforeEach(func() {
		installation = &operatorv1.InstallationSpec{
			Registry: "test-registry.com/",
			Variant:  operatorv1.Calico,
		}
		apiServerSpec = &operatorv1.APIServerSpec{}

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		dnsNames := dns.GetServiceDNSNames(webhooks.WebhooksName, common.CalicoNamespace, clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, webhooks.WebhooksTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())

		cfg = &webhooks.Configuration{
			Installation: installation,
			APIServer:    apiServerSpec,
			KeyPair:      kp,
		}
	})

	It("should render all resources for Calico", func() {
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksPolicyName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "api.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "ValidatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		rtest.ExpectResources(resources, expectedResources)

		// Verify the Calico (non-enterprise) variant uses the combined calico/calico image with Command set.
		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(dep.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("test-registry.com/%s%s:%s",
				components.CalicoImagePath,
				components.ComponentCalico.Image,
				components.ComponentCalico.Version)))
		Expect(dep.Spec.Template.Spec.Containers[0].Command).To(Equal([]string{"/usr/bin/calico", "component", "webhooks"}))

		// Verify the ClusterRole includes expected rules.
		cr := rtest.GetResource(resources, webhooks.WebhooksName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(cr.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"tiers"},
				Verbs:     []string{"get"},
			},
		))
		Expect(cr.Rules).NotTo(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"managedclusters"},
			Verbs:     []string{"list", "watch", "update"},
		}))

		// The audit-logging webhook targets the Enterprise-only /audit endpoint, so it must not
		// be registered on Calico OSS.
		vwc, err := rtest.GetResourceOfType[*admissionregistrationv1.ValidatingWebhookConfiguration](resources, "api.projectcalico.org", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(vwc.Webhooks).To(ConsistOf(
			HaveField("Name", "tiered-rbac.api.projectcalico.org"),
			HaveField("Name", "cluster-info.api.projectcalico.org"),
		))
	})

	It("should render all resources for Enterprise with the correct image", func() {
		installation.Variant = operatorv1.CalicoEnterprise
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksPolicyName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "api.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "ValidatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"}},
			&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "api.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "MutatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		// Verify the MutatingWebhookConfiguration has the expected webhooks.
		mwc, err := rtest.GetResourceOfType[*admissionregistrationv1.MutatingWebhookConfiguration](resources, "api.projectcalico.org", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(mwc.Webhooks).To(HaveLen(1))
		Expect(mwc.Webhooks[0].Name).To(Equal("uisettings.api.projectcalico.org"))
		Expect(*mwc.Webhooks[0].ClientConfig.Service.Path).To(Equal("/uisettings"))
		Expect(*mwc.Webhooks[0].FailurePolicy).To(Equal(admissionregistrationv1.Fail))
		Expect(*mwc.Webhooks[0].TimeoutSeconds).To(Equal(int32(10)))
		Expect(mwc.Webhooks[0].Rules).To(HaveLen(1))
		Expect(mwc.Webhooks[0].Rules[0].Operations).To(ConsistOf(
			admissionregistrationv1.Create,
			admissionregistrationv1.Update,
			admissionregistrationv1.Delete,
		))
		Expect(mwc.Webhooks[0].Rules[0].Rule.Resources).To(Equal([]string{"uisettings"}))

		// The audit-logging webhook is Enterprise-only.
		vwc, err := rtest.GetResourceOfType[*admissionregistrationv1.ValidatingWebhookConfiguration](resources, "api.projectcalico.org", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(vwc.Webhooks).To(ContainElement(HaveField("Name", "audit-logging.api.projectcalico.org")))

		// Verify the ClusterRole includes the enterprise-only rules.
		cr := rtest.GetResource(resources, webhooks.WebhooksName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(cr.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "watch", "update"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettingsgroups"},
				Verbs:     []string{"get"},
			},
		))

		// Verify Enterprise uses the Tigera webhooks image.
		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(dep.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("test-registry.com/%s%s:%s",
				components.TigeraImagePath,
				components.ComponentTigeraCalico.Image,
				components.ComponentTigeraCalico.Version)))
	})

	It("should only register the UISettings mutating webhook", func() {
		installation.Variant = operatorv1.CalicoEnterprise
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		mwc, err := rtest.GetResourceOfType[*admissionregistrationv1.MutatingWebhookConfiguration](resources, "api.projectcalico.org", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(mwc.Webhooks).To(HaveLen(1))
		Expect(mwc.Webhooks[0].Name).To(Equal("uisettings.api.projectcalico.org"))
	})

	It("should not include UISettingsGroup rule for Calico", func() {
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		cr := rtest.GetResource(resources, webhooks.WebhooksName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(cr.Rules).NotTo(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettingsgroups"},
			Verbs:     []string{"get"},
		}))
	})

	It("should set control plane tolerations by default", func() {
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Tolerations).To(ConsistOf(
			corev1.Toleration{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
			corev1.Toleration{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule},
		))
	})

	It("should use ControlPlaneReplicas from the installation", func() {
		var replicas int32 = 3
		installation.ControlPlaneReplicas = &replicas
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(*dep.Spec.Replicas).To(Equal(int32(3)))
		Expect(dep.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(dep.Spec.Template.Spec.Affinity.PodAntiAffinity).NotTo(BeNil())
	})

	It("should apply deployment overrides", func() {
		apiServerSpec.CalicoWebhooksDeployment = &operatorv1.CalicoWebhooksDeployment{
			Spec: &operatorv1.CalicoWebhooksDeploymentSpec{
				Template: &operatorv1.CalicoWebhooksDeploymentPodTemplateSpec{
					Spec: &operatorv1.CalicoWebhooksDeploymentPodSpec{
						NodeSelector: map[string]string{"foo": "bar"},
					},
				},
			},
		}
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
	})

	It("should render a readiness probe on the webhook container", func() {
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		probe := dep.Spec.Template.Spec.Containers[0].ReadinessProbe
		Expect(probe).NotTo(BeNil())
		Expect(probe.HTTPGet).NotTo(BeNil())
		Expect(probe.HTTPGet.Path).To(Equal("/readyz"))
		Expect(probe.HTTPGet.Port.IntValue()).To(Equal(6443))
		Expect(probe.HTTPGet.Scheme).To(Equal(corev1.URISchemeHTTPS))
		Expect(probe.PeriodSeconds).To(Equal(int32(10)))
		Expect(probe.TimeoutSeconds).To(Equal(int32(5)))

		Expect(dep.Spec.Template.Spec.Containers[0].LivenessProbe).To(BeNil())
	})

	It("should use default container port (6443) when no override is set", func() {
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		// Verify the container port defaults to 6443.
		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort).To(Equal(int32(6443)))

		// Verify the service target port defaults to 6443.
		svc, err := rtest.GetResourceOfType[*corev1.Service](resources, webhooks.WebhooksName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(svc.Spec.Ports[0].TargetPort.IntValue()).To(Equal(6443))

		// Verify the network policy.
		np := rtest.GetResource(resources, webhooks.WebhooksPolicyName, common.CalicoNamespace, "projectcalico.org", "v3", "NetworkPolicy").(*v3.NetworkPolicy)
		Expect(np.Spec.Ingress).To(HaveLen(4))

		// Rule 1: Allow from kube-apiserver.
		Expect(np.Spec.Ingress[0].Action).To(Equal(v3.Allow))
		Expect(np.Spec.Ingress[0].Source.Services).To(Equal(&v3.ServiceMatch{
			Namespace: "default",
			Name:      "kubernetes",
		}))
		Expect(np.Spec.Ingress[0].Destination.Ports[0].MinPort).To(Equal(uint16(6443)))

		// Rule 2: Allow from the konnectivity agents that proxy apiserver traffic on AKS and GKE.
		Expect(np.Spec.Ingress[1].Action).To(Equal(v3.Allow))
		Expect(np.Spec.Ingress[1].Source.NamespaceSelector).To(Equal("kubernetes.io/metadata.name == 'kube-system'"))
		Expect(np.Spec.Ingress[1].Source.Selector).To(Equal("app == 'konnectivity-agent' || k8s-app == 'konnectivity-agent'"))
		Expect(np.Spec.Ingress[1].Destination.Ports[0].MinPort).To(Equal(uint16(6443)))

		// Rule 3: Deny from any workload endpoint. The orchestrator selector excludes NetworkSets.
		Expect(np.Spec.Ingress[2].Action).To(Equal(v3.Deny))
		Expect(np.Spec.Ingress[2].Source.NamespaceSelector).To(Equal("all()"))
		Expect(np.Spec.Ingress[2].Source.Selector).To(Equal("has(projectcalico.org/orchestrator)"))

		// Rule 4: Fallback allow for non-pod sources (including tunnel-SNAT'd hostnet apiserver traffic).
		Expect(np.Spec.Ingress[3].Action).To(Equal(v3.Allow))
		Expect(np.Spec.Ingress[3].Destination.Ports[0].MinPort).To(Equal(uint16(6443)))
	})

	It("should use custom container port", func() {
		var customPort int32 = 8443
		apiServerSpec.CalicoWebhooksDeployment = &operatorv1.CalicoWebhooksDeployment{
			Spec: &operatorv1.CalicoWebhooksDeploymentSpec{
				Template: &operatorv1.CalicoWebhooksDeploymentPodTemplateSpec{
					Spec: &operatorv1.CalicoWebhooksDeploymentPodSpec{
						Containers: []operatorv1.CalicoWebhooksDeploymentContainer{
							{
								Name: "calico-webhooks",
								Ports: []operatorv1.CalicoWebhooksDeploymentContainerPort{
									{Name: "calico-webhooks", ContainerPort: customPort},
								},
							},
						},
					},
				},
			},
		}
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		// Verify the container port is set to the custom value.
		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort).To(Equal(customPort))
		Expect(dep.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Port.IntValue()).To(Equal(int(customPort)))
		Expect(dep.Spec.Template.Spec.Containers[0].Args).To(ContainElement(fmt.Sprintf("--port=%d", customPort)))

		// Verify the service target port uses the custom value.
		svc, err := rtest.GetResourceOfType[*corev1.Service](resources, webhooks.WebhooksName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(svc.Spec.Ports[0].TargetPort.IntValue()).To(Equal(int(customPort)))

		// Verify the network policy uses the custom port.
		np := rtest.GetResource(resources, webhooks.WebhooksPolicyName, common.CalicoNamespace, "projectcalico.org", "v3", "NetworkPolicy").(*v3.NetworkPolicy)
		Expect(np.Spec.Ingress).To(HaveLen(4))
		Expect(np.Spec.Ingress[0].Destination.Ports[0].MinPort).To(Equal(uint16(customPort)))
		Expect(np.Spec.Ingress[1].Destination.Ports[0].MinPort).To(Equal(uint16(customPort)))
		Expect(np.Spec.Ingress[2].Action).To(Equal(v3.Deny))
		Expect(np.Spec.Ingress[2].Source.NamespaceSelector).To(Equal("all()"))
		Expect(np.Spec.Ingress[2].Source.Selector).To(Equal("has(projectcalico.org/orchestrator)"))
		Expect(np.Spec.Ingress[3].Destination.Ports[0].MinPort).To(Equal(uint16(customPort)))
	})

	It("should not use host network by default on non-EKS", func() {
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.HostNetwork).To(BeFalse())
		Expect(dep.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSPolicy("")))
	})

	It("should use host network when configured", func() {
		hostNetwork := true
		apiServerSpec.CalicoWebhooksDeployment = &operatorv1.CalicoWebhooksDeployment{
			Spec: &operatorv1.CalicoWebhooksDeploymentSpec{
				Template: &operatorv1.CalicoWebhooksDeploymentPodTemplateSpec{
					Spec: &operatorv1.CalicoWebhooksDeploymentPodSpec{
						HostNetwork: &hostNetwork,
					},
				},
			},
		}
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.HostNetwork).To(BeTrue())
		Expect(dep.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirstWithHostNet))

		// Network policy should not be installed for host-networked pods.
		Expect(rtest.GetResource(resources, webhooks.WebhooksPolicyName, common.CalicoNamespace, "projectcalico.org", "v3", "NetworkPolicy")).To(BeNil())
	})

	It("should auto-detect host network on EKS with Calico CNI", func() {
		installation.KubernetesProvider = operatorv1.ProviderEKS
		installation.CNI = &operatorv1.CNISpec{Type: operatorv1.PluginCalico}

		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.HostNetwork).To(BeTrue())
		Expect(dep.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirstWithHostNet))

		// Network policy should not be installed for host-networked pods.
		Expect(rtest.GetResource(resources, webhooks.WebhooksPolicyName, common.CalicoNamespace, "projectcalico.org", "v3", "NetworkPolicy")).To(BeNil())
	})

	It("should allow HostNetwork=false to override auto-detection on EKS", func() {
		installation.KubernetesProvider = operatorv1.ProviderEKS
		installation.CNI = &operatorv1.CNISpec{Type: operatorv1.PluginCalico}

		hostNetwork := false
		apiServerSpec.CalicoWebhooksDeployment = &operatorv1.CalicoWebhooksDeployment{
			Spec: &operatorv1.CalicoWebhooksDeploymentSpec{
				Template: &operatorv1.CalicoWebhooksDeploymentPodTemplateSpec{
					Spec: &operatorv1.CalicoWebhooksDeploymentPodSpec{
						HostNetwork: &hostNetwork,
					},
				},
			},
		}
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.HostNetwork).To(BeFalse())
		Expect(dep.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSPolicy("")))
	})

	It("should apply both custom container port and host network together", func() {
		var customPort int32 = 9443
		hostNetwork := true
		apiServerSpec.CalicoWebhooksDeployment = &operatorv1.CalicoWebhooksDeployment{
			Spec: &operatorv1.CalicoWebhooksDeploymentSpec{
				Template: &operatorv1.CalicoWebhooksDeploymentPodTemplateSpec{
					Spec: &operatorv1.CalicoWebhooksDeploymentPodSpec{
						Containers: []operatorv1.CalicoWebhooksDeploymentContainer{
							{
								Name: "calico-webhooks",
								Ports: []operatorv1.CalicoWebhooksDeploymentContainerPort{
									{Name: "calico-webhooks", ContainerPort: customPort},
								},
							},
						},
						HostNetwork: &hostNetwork,
					},
				},
			},
		}
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		// Verify the container port uses the custom value.
		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort).To(Equal(customPort))
		Expect(dep.Spec.Template.Spec.HostNetwork).To(BeTrue())
		Expect(dep.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirstWithHostNet))

		// Verify the service target port uses the custom value.
		svc, err := rtest.GetResourceOfType[*corev1.Service](resources, webhooks.WebhooksName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(svc.Spec.Ports[0].TargetPort.IntValue()).To(Equal(int(customPort)))

		// Network policy should not be installed for host-networked pods.
		Expect(rtest.GetResource(resources, webhooks.WebhooksPolicyName, common.CalicoNamespace, "projectcalico.org", "v3", "NetworkPolicy")).To(BeNil())
	})
})
