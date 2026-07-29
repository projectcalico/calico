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

package kubecontrollers_test

import (
	"fmt"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var (
		instance     *operatorv1.InstallationSpec
		k8sServiceEp k8sapi.ServiceEndpoint
		cfg          kubecontrollers.KubeControllersConfiguration
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

	expectedPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers.json")
	expectedPolicyForUnmanagedOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_ocp.json")
	expectedPolicyForManaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_managed.json")
	expectedPolicyForManagedOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/kubecontrollers_managed_ocp.json")
	expectedESPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/es-kubecontrollers.json")
	expectedESPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/es-kubecontrollers_ocp.json")

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

		cfg = kubecontrollers.KubeControllersConfiguration{
			K8sServiceEp:      k8sServiceEp,
			Installation:      instance,
			ClusterDomain:     dns.DefaultClusterDomain,
			MetricsPort:       9094,
			TrustedBundle:     certificateManager.CreateTrustedBundle(),
			Namespace:         common.CalicoNamespace,
			BindingNamespaces: []string{common.CalicoNamespace},
		}
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	It("should use the tesla calico image for kube-controllers when Cloud is enabled (TSLA-11580)", func() {
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.Cloud = true
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/calico:" + components.CalicoCloudImage().Version))
	})

	It("should include kubevirt.io RBAC rules in calico-kube-controllers ClusterRole", func() {
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"kubevirt.io"},
			Resources: []string{"virtualmachineinstances", "virtualmachines"},
			Verbs:     []string{"get", "list", "watch"},
		}))
	})

	It("should render all resources for a custom configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
		}

		cfg = kubecontrollers.KubeControllersConfiguration{
			K8sServiceEp:      k8sServiceEp,
			Installation:      instance,
			ClusterDomain:     dns.DefaultClusterDomain,
			Namespace:         common.CalicoNamespace,
			BindingNamespaces: []string{common.CalicoNamespace},
		}
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The tier controller patches tiers to add and remove its finalizer, so
		// the role must grant patch in addition to update.
		clusterRole := rtest.GetResource(resources, kubecontrollers.KubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create", "update", "patch", "get", "list", "watch"},
		}))

		// The Deployment should have the correct configuration.
		ds := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))

		// Image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("test-reg/%s%s:%s", components.CalicoImagePath, components.ComponentCalico.Image, components.ComponentCalico.Version),
		))

		// Verify command and probes use the combined image entrypoint with generic health check.
		Expect(ds.Spec.Template.Spec.Containers[0].Command).To(Equal([]string{"/usr/bin/calico", "component", "kube-controllers", "--health-port=9440"}))
		Expect(ds.Spec.Template.Spec.Containers[0].ReadinessProbe.Exec.Command).To(Equal([]string{"/usr/bin/calico", "health", "--port=9440", "--type=readiness"}))
		Expect(ds.Spec.Template.Spec.Containers[0].LivenessProbe.Exec.Command).To(Equal([]string{"/usr/bin/calico", "health", "--port=9440", "--type=liveness"}))

		// Verify env
		expectedEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer"},
			{Name: "KUBE_CONTROLLERS_CONFIG_NAME", Value: "default"},
			{Name: "DISABLE_KUBE_CONTROLLERS_CONFIG_API", Value: "false"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// SecurityContext
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(999))
		Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateCriticalAddonsAndControlPlane))
	})

	It("should render all calico kube-controllers resources for a default configuration (standalone) using CalicoEnterprise", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: kubecontrollers.WASMPullSecretName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.WASMCACertName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: applicationlayer.WAFWebhookServiceName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-waf.applicationlayer.projectcalico.org", ns: "", group: "admissionregistration.k8s.io", version: "v1", kind: "ValidatingWebhookConfiguration"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operatorv1.CalicoEnterprise
		instance.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "tigera-pull-secret"}}
		cfg.MetricsPort = 9094
		// Opt in to the WAF Gateway API add-on so the WAF env vars + RBAC are rendered.
		cfg.WAFGatewayExtensionEnabled = true
		cfg.GatewayAPIPresent = true
		cfg.WAFWebhookCABundle = []byte("fake-ca-bundle")
		// core_controller provisions a dedicated WAF wasm pull secret (a renamed
		// copy of the install pull secret) so the reconciler can replicate it into
		// WAFPolicy namespaces without clashing with the operator-managed
		// tigera-pull-secret; surface it here so it renders and WASM_PULL_SECRET is set.
		cfg.WASMPullSecret = &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.WASMPullSecretName, Namespace: common.CalicoNamespace}}
		// Likewise core_controller provisions the dedicated WAF wasm CA-bundle
		// ConfigMap (a renamed copy of the trusted bundle); surface it here so it
		// renders and WASM_CA_CERT is set.
		cfg.WASMCACert = &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.WASMCACertName, Namespace: common.CalicoNamespace}}

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/calico:" + components.ComponentTigeraCalico.Version))
		Expect(dp.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "tigera-pull-secret"}))
		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage,applicationlayer",
		}))
		// Application-layer reconcilers consume these env vars to program WAF
		// EnvoyExtensionPolicy attachments.
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "WASM_IMAGE", Value: "test-reg/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version,
		}))
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "WASM_PULL_SECRET", Value: kubecontrollers.WASMPullSecretName,
		}))
		// WASM_CA_CERT names the dedicated WAF trusted-bundle ConfigMap that the
		// reconciler replicates into WAFPolicy namespaces (kept separate from the
		// operator-managed tigera-ca-bundle the GatewayAPI render also copies there).
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "WASM_CA_CERT", Value: kubecontrollers.WASMCACertName,
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))

		clusterRole := rtest.GetResource(resources, kubecontrollers.KubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(HaveLen(38), "cluster role should have 38 rules")

		// Application-layer reconciler RBAC: WAF CRDs (resources, /status, /finalizers).
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies", "globalwafpolicies",
				"wafplugins", "globalwafplugins",
				"wafvalidationpolicies", "globalwafvalidationpolicies",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		}))
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies/status", "globalwafpolicies/status",
				"wafplugins/status", "globalwafplugins/status",
				"wafvalidationpolicies/status", "globalwafvalidationpolicies/status",
			},
			Verbs: []string{"get", "update", "patch"},
		}))
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies/finalizers", "globalwafpolicies/finalizers",
				"wafplugins/finalizers", "globalwafplugins/finalizers",
				"wafvalidationpolicies/finalizers", "globalwafvalidationpolicies/finalizers",
			},
			Verbs: []string{"update"},
		}))
		// Gateway API targetRef validation + status patching.
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes", "tcproutes", "tlsroutes", "grpcroutes"},
			Verbs:     []string{"get", "list", "watch", "update", "patch"},
		}))
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways/status", "httproutes/status", "tcproutes/status", "tlsroutes/status", "grpcroutes/status"},
			Verbs:     []string{"get", "update", "patch"},
		}))
		// Recorder.Eventf emits to both core/events and events.k8s.io/events.
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		}))
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"events.k8s.io"},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		}))
		// Cluster-wide secrets+configmaps CRUD: reconciler replicates pull
		// secrets and CA bundles from the controller namespace into target
		// WAFPolicy namespaces.
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"secrets", "configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		}))
		// EnvoyExtensionPolicy CRUD: reconciler renders one EEP per WAF targetRef.
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"gateway.envoyproxy.io"},
			Resources: []string{"envoyextensionpolicies"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		}))

		ms := rtest.GetResource(resources, kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless")

		// The webhook surface is rendered with the operator CA stamped into the
		// ValidatingWebhookConfiguration caBundle.
		vwc := rtest.GetResource(resources, "tigera-waf.applicationlayer.projectcalico.org", "", "admissionregistration.k8s.io", "v1", "ValidatingWebhookConfiguration").(*admissionregistrationv1.ValidatingWebhookConfiguration)
		Expect(vwc.Webhooks).To(HaveLen(1))
		Expect(vwc.Webhooks[0].ClientConfig.CABundle).To(Equal([]byte("fake-ca-bundle")))
	})

	It("should delete the WAF admission webhook surface when the WAF Gateway API add-on is disabled", func() {
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.WAFGatewayExtensionEnabled = false

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		toCreate, toDelete := component.Objects()

		// Neither webhook object is created...
		Expect(rtest.GetResource(toCreate, applicationlayer.WAFWebhookServiceName, common.CalicoNamespace, "", "v1", "Service")).To(BeNil())
		Expect(rtest.GetResource(toCreate, "tigera-waf.applicationlayer.projectcalico.org", "", "admissionregistration.k8s.io", "v1", "ValidatingWebhookConfiguration")).To(BeNil())
		// ...and both are queued for deletion, so disabling the feature (or
		// removing the GatewayAPI CR) cleans up an earlier enabled render.
		Expect(rtest.GetResource(toDelete, applicationlayer.WAFWebhookServiceName, common.CalicoNamespace, "", "v1", "Service")).NotTo(BeNil())
		Expect(rtest.GetResource(toDelete, "tigera-waf.applicationlayer.projectcalico.org", "", "admissionregistration.k8s.io", "v1", "ValidatingWebhookConfiguration")).NotTo(BeNil())
	})

	It("should render all calico kube-controllers resources using CalicoEnterprise on Openshift", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// We expect an extra cluster role binding.
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: "calico-kube-controllers-endpoint-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}
		instance.Variant = operatorv1.CalicoEnterprise
		instance.KubernetesProvider = operatorv1.ProviderOpenShift
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))
		// Should render the correct resources.
		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	Context("RBAC management UI gate", func() {
		BeforeEach(func() {
			instance.Variant = operatorv1.CalicoEnterprise
		})

		It("does not enable rbacsync when RBACManagementEnabled is false", func() {
			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			envs := dp.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{
				Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage",
			}))

			Expect(rtest.GetResource(resources, "calico-kube-controllers-rbac-sync", common.CalicoNamespace, "rbac.authorization.k8s.io", "v1", "Role")).To(BeNil())
		})

		It("enables rbacsync and adds the controller's RBAC when RBACManagementEnabled is true", func() {
			cfg.RBACManagementEnabled = true
			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			envs := dp.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{
				Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage,rbacsync",
			}))

			nsRole := rtest.GetResource(resources, "calico-kube-controllers-rbac-sync", common.CalicoNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
			Expect(nsRole.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{"tigera-idp-groups"},
				Verbs:         []string{"get", "list", "watch"},
			}), "expected read-only access to tigera-idp-groups in calico-system")
		})
	})

	It("should render all es-calico-kube-controllers resources for a default configuration (standalone) using CalicoEnterprise when logstorage and secrets exist", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.EsKubeControllerNetworkPolicyName, ns: common.CalicoNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "calico-kube-controllers", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.EsKubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: kubecontrollers.ElasticsearchKubeControllersUserSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.EsKubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		instance.Variant = operatorv1.CalicoEnterprise
		cfg.LogStorageExists = true
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.MetricsPort = 9094
		// Opt in to the WAF Gateway API add-on so the WAF env vars + RBAC are rendered.
		cfg.WAFGatewayExtensionEnabled = true
		cfg.GatewayAPIPresent = true

		component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

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

		clusterRole := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(HaveLen(36), "cluster role should have 36 rules")
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

	It("should render all calico-kube-controllers resources for a default configuration using CalicoEnterprise and ClusterType is Management", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.ManagedClustersWatchRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: applicationlayer.WAFWebhookServiceName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-waf.applicationlayer.projectcalico.org", ns: "", group: "admissionregistration.k8s.io", version: "v1", kind: "ValidatingWebhookConfiguration"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.MetricsPort = 9094
		// Opt in to the WAF Gateway API add-on so the WAF env vars + RBAC are rendered.
		cfg.WAFGatewayExtensionEnabled = true
		cfg.GatewayAPIPresent = true

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name:  "ENABLED_CONTROLLERS",
			Value: "node,loadbalancer,service,federatedservices,usage,applicationlayer",
		}))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(1))
		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/calico:" + components.ComponentTigeraCalico.Version))
	})
	It("should render all calico-kube-controllers resources for a default configuration using CalicoEnterprise", func() {
		var defaultMode int32 = 420
		var kubeControllerTLS certificatemanagement.KeyPairInterface
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: kubecontrollers.KubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		expectedEnv := []corev1.EnvVar{
			{Name: "TLS_KEY_PATH", Value: "/calico-kube-controllers-metrics-tls/tls.key"},
			{Name: "TLS_CRT_PATH", Value: "/calico-kube-controllers-metrics-tls/tls.crt"},
			{Name: "CLIENT_COMMON_NAME", Value: "calico-node-prometheus-client-tls"},
			{Name: "CA_CRT_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		}
		expectedVolumeMounts := []corev1.VolumeMount{
			{Name: "tigera-ca-bundle", MountPath: "/etc/pki/tls/certs", ReadOnly: true},
			{Name: "calico-kube-controllers-metrics-tls", MountPath: "/calico-kube-controllers-metrics-tls", ReadOnly: true},
		}
		expectedVolume := []corev1.Volume{
			{
				Name: "tigera-ca-bundle",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-ca-bundle"},
					},
				},
			},
			{
				Name: "calico-kube-controllers-metrics-tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  "calico-kube-controllers-metrics-tls",
						DefaultMode: &defaultMode,
					},
				},
			},
		}

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		kubeControllerTLS, err = certificateManager.GetOrCreateKeyPair(cli,
			kubecontrollers.KubeControllerPrometheusTLSSecret,
			common.OperatorNamespace(),
			dns.GetServiceDNSNames(kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, dns.DefaultClusterDomain))
		Expect(err).NotTo(HaveOccurred())

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.MetricsPort = 9094
		cfg.MetricsServerTLS = kubeControllerTLS

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		envs := dp.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElements(expectedEnv))

		Expect(len(dp.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElements(expectedVolumeMounts))

		Expect(len(dp.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(dp.Spec.Template.Spec.Volumes).To(ContainElements(expectedVolume))

		Expect(dp.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/calico:" + components.ComponentTigeraCalico.Version))
	})

	It("should mount the WAF admission webhook serving cert and expose its port when WAF is enabled", func() {
		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		wafTLS, err := certificateManager.GetOrCreateKeyPair(cli,
			applicationlayer.WAFWebhookServerTLSSecretName,
			common.OperatorNamespace(),
			dns.GetServiceDNSNames(applicationlayer.WAFWebhookServiceName, common.CalicoNamespace, dns.DefaultClusterDomain))
		Expect(err).NotTo(HaveOccurred())

		instance.Variant = operatorv1.CalicoEnterprise
		cfg.WAFGatewayExtensionEnabled = true
		cfg.GatewayAPIPresent = true
		cfg.WAFWebhookServerTLS = wafTLS

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		c := dp.Spec.Template.Spec.Containers[0]

		// Serving cert is mounted and advertised to the in-process webhook server.
		Expect(dp.Spec.Template.Spec.Volumes).To(ContainElement(wafTLS.Volume()))
		Expect(c.VolumeMounts).To(ContainElement(wafTLS.VolumeMount(rmeta.OSTypeLinux)))
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name:  "WAF_WEBHOOK_CERT_DIR",
			Value: filepath.Dir(wafTLS.VolumeMountCertificateFilePath()),
		}))

		// In-process webhook port exposed for the tigera-waf-webhook Service.
		Expect(c.Ports).To(ContainElement(corev1.ContainerPort{
			Name:          "waf-webhook",
			ContainerPort: int32(9443),
			Protocol:      corev1.ProtocolTCP,
		}))

		// namespaces patch/update RBAC for the waf-id-range annotation.
		clusterRole := rtest.GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "patch", "update"},
		}))
	})

	It("should keep the WAF controller wired for teardown but render no active WAF surface when WAF is disabled (EV-6751)", func() {
		instance.Variant = operatorv1.CalicoEnterprise
		// GatewayAPI present but WAF turned off: the applicationlayer controller
		// must stay wired (with its EnvoyExtensionPolicy delete RBAC) so it can
		// tear down the EEPs it generated, and be told it is disabled via the env.
		cfg.GatewayAPIPresent = true
		cfg.WAFGatewayExtensionEnabled = false

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		c := dp.Spec.Template.Spec.Containers[0]

		// Controller stays wired.
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage,applicationlayer",
		}))
		// Told it is disabled → the reconciler de-programs rather than attaches.
		Expect(c.Env).To(ContainElement(corev1.EnvVar{Name: "WAF_GATEWAY_EXTENSION_ENABLED", Value: "false"}))
		// No active WAF surface: no WASM image env, no webhook cert dir.
		for _, e := range c.Env {
			Expect(e.Name).NotTo(Equal("WASM_IMAGE"))
			Expect(e.Name).NotTo(Equal("WAF_WEBHOOK_CERT_DIR"))
		}
		// But it keeps the EnvoyExtensionPolicy delete RBAC to run the teardown.
		clusterRole := rtest.GetResource(resources, "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"gateway.envoyproxy.io"},
			Resources: []string{"envoyextensionpolicies"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
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
			{name: kubecontrollers.EsKubeControllerNetworkPolicyName, ns: common.CalicoNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "calico-kube-controllers", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.EsKubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.EsKubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.ManagedClustersWatchRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.EsKubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: kubecontrollers.ElasticsearchKubeControllersUserSecret, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Secret"},
			{name: kubecontrollers.EsKubeControllerMetrics, ns: common.CalicoNamespace, group: "", version: "v1", kind: "Service"},
		}

		// Override configuration to match expected Enterprise config.
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.LogStorageExists = true
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.MetricsPort = 9094
		// Opt in to the WAF Gateway API add-on so the WAF env vars + RBAC are rendered.
		cfg.WAFGatewayExtensionEnabled = true
		cfg.GatewayAPIPresent = true

		component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
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
		dp := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

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

		clusterRole := rtest.GetResource(resources, kubecontrollers.EsKubeControllerRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(HaveLen(36), "cluster role should have 36 rules")
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
		roleBindingWatch := rtest.GetResource(resources, kubecontrollers.ManagedClustersWatchRoleBindingName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(roleBindingWatch.RoleRef.Name).To(Equal(render.ManagedClustersWatchClusterRoleName))
		Expect(roleBindingWatch.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      kubecontrollers.KubeControllerServiceAccount,
				Namespace: common.CalicoNamespace,
			},
		}))
	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: kubecontrollers.KubeControllerServiceAccount, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: kubecontrollers.KubeControllerRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: kubecontrollers.KubeControllerRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: kubecontrollers.KubeController, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "Deployment"},
		}

		// Set node selector.
		instance.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

		// Simulate enterprise config.
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.MetricsPort = 0

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		d := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		instance.ControlPlaneTolerations = []corev1.Toleration{t}
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, t)))
	})

	It("should not duplicate default tolerations when they are specified as ControlPlaneTolerations", func() {
		instance.ControlPlaneTolerations = []corev1.Toleration{rmeta.TolerateCriticalAddonsOnly}
		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateCriticalAddonsAndControlPlane))
	})

	It("should render resourcerequirements", func() {
		rr := &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		instance.ComponentResources = []operatorv1.ComponentResource{
			{
				ComponentName:        operatorv1.ComponentNameKubeControllers,
				ResourceRequirements: rr,
			},
		}

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)

		passed := false
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == kubecontrollers.KubeController {
				Expect(container.Resources).To(Equal(*rr))
				passed = true
			}
		}
		Expect(passed).To(Equal(true))
	})

	It("should add the OIDC prefix env variables", func() {
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.LogStorageExists = true
		cfg.ManagementCluster = &operatorv1.ManagementCluster{}
		cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
		cfg.MetricsPort = 9094
		cfg.Authentication = &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{
			UsernamePrefix: "uOIDC:",
			GroupsPrefix:   "gOIDC:",
			Openshift:      &operatorv1.AuthenticationOpenshift{IssuerURL: "https://api.example.com"},
		}}

		component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)

		var usernamePrefix, groupPrefix string
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == kubecontrollers.EsKubeController {
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

	Context("With calico-kube-controllers overrides", func() {
		rr1 := corev1.ResourceRequirements{
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
		rr2 := corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		It("should handle calicoKubeControllersDeployment overrides", func() {
			var minReadySeconds int32 = 20

			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			instance.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
							Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{
								{
									Name:      "calico-kube-controllers",
									Resources: &rr1,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							Affinity:    affinity,
							Tolerations: []corev1.Toleration{toleration},
						},
					},
				},
			}

			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			d := depResource.(*appsv1.Deployment)

			Expect(d.Labels).To(HaveLen(1))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(2))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))
			// The render package records the applied resource override in an annotation.
			Expect(d.Annotations["operator.tigera.io/custom-overrides"]).To(Equal("resources"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-kube-controllers". But the calico-kube-controllers deployment object
			// produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(1))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 3 template-level annotations
			// - 1 added by the operator by default because TrustedBundle was set on kubecontrollerconfiguration.
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(2))
			Expect(d.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-kube-controllers"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
		})

		It("should override ComponentResources", func() {
			instance.ComponentResources = []operatorv1.ComponentResource{
				{
					ComponentName:        operatorv1.ComponentNameKubeControllers,
					ResourceRequirements: &rr1,
				},
			}

			instance.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
				Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
					Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
						Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
							Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{
								{
									Name:      "calico-kube-controllers",
									Resources: &rr2,
								},
							},
						},
					},
				},
			}

			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			d := depResource.(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-kube-controllers"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr2))
		})

		It("should override ControlPlaneNodeSelector when specified", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

			instance.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
				Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
					Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
						Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
						},
					},
				},
			}
			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			d := depResource.(*appsv1.Deployment)

			// nodeSelectors are merged
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))
		})

		It("should override ControlPlaneTolerations when specified", func() {
			cfg.Installation.ControlPlaneTolerations = rmeta.TolerateControlPlane

			tol := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}

			instance.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
				Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
					Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
						Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
							Tolerations: []corev1.Toleration{tol},
						},
					},
				},
			}
			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			d := depResource.(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(tol))
		})

		It("should render toleration on GKE", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).NotTo(BeNil())
			d := depResource.(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
				Key:      "kubernetes.io/arch",
				Operator: corev1.TolerationOpEqual,
				Value:    "arm64",
				Effect:   corev1.TaintEffectNoSchedule,
			}))
		})
	})

	When("enableESOIDCWorkaround is true", func() {
		It("should set the ENABLE_ELASTICSEARCH_OIDC_WORKAROUND env variable to true", func() {
			instance.Variant = operatorv1.CalicoEnterprise
			cfg.LogStorageExists = true
			cfg.ManagementCluster = &operatorv1.ManagementCluster{}
			cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret
			cfg.MetricsPort = 9094
			component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
			resources, _ := component.Objects()

			depResource := rtest.GetResource(resources, kubecontrollers.EsKubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
			Expect(depResource).ToNot(BeNil())
			deployment := depResource.(*appsv1.Deployment)

			var esLicenseType string
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == kubecontrollers.EsKubeController {
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

	It("should add the KUBERNETES_SERVICE_... variables", func() {
		cfg.K8sServiceEpPodNetwork = k8sapi.ServiceEndpoint{
			Host: "k8shost",
			Port: "1234",
		}

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not add the KUBERNETES_SERVICE_... variables when pod network endpoint is not set", func() {
		cfg.K8sServiceEpPodNetwork = k8sapi.ServiceEndpoint{}

		component := kubecontrollers.NewCalicoKubeControllers(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})

	It("should add prometheus annotations to metrics service", func() {
		for _, variant := range []operatorv1.ProductVariant{operatorv1.Calico, operatorv1.CalicoEnterprise} {
			cfg.Installation.Variant = variant
			component := kubecontrollers.NewCalicoKubeControllers(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			obj := rtest.GetResource(resources, kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, "", "v1", "Service")
			Expect(obj).ToNot(BeNil())
			svc := obj.(*corev1.Service)
			Expect(svc.Annotations["prometheus.io/scrape"]).To(Equal("true"))
			Expect(svc.Annotations["prometheus.io/port"]).To(Equal(fmt.Sprintf("%d", cfg.MetricsPort)))
		}
	})

	Context("kube-controllers calico-system rendering", func() {
		policyName := types.NamespacedName{Name: "calico-system.kube-controller-access", Namespace: common.CalicoNamespace}

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
				defaultDenyPolicy := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-deny",
						Namespace: common.CalicoNamespace,
					},
				}

				component := kubecontrollers.NewCalicoKubeControllersPolicy(&cfg, defaultDenyPolicy)
				resources, _ := component.Objects()
				Expect(resources).To(HaveLen(2))
				Expect(resources).Should(ContainElement(defaultDenyPolicy))

				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				expectedPolicy := testutils.SelectPolicyByClusterTypeAndProvider(
					scenario,
					map[string]*v3.NetworkPolicy{
						"unmanaged":           expectedPolicyForUnmanaged,
						"unmanaged-openshift": expectedPolicyForUnmanagedOCP,
						"managed":             expectedPolicyForManaged,
						"managed-openshift":   expectedPolicyForManagedOCP,
					},
				)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
		)

		It("policy should omit prometheus ingress rule when metrics port is 0", func() {
			// Baseline
			cfg.MetricsPort = 9094
			component := kubecontrollers.NewCalicoKubeControllersPolicy(&cfg, nil)
			resources, _ := component.Objects()
			Expect(resources).To(HaveLen(1))
			baselinePolicy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)

			// Zeroed policy
			cfg.MetricsPort = 0
			component = kubecontrollers.NewCalicoKubeControllersPolicy(&cfg, nil)
			resources, _ = component.Objects()
			zeroedPolicy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)

			Expect(len(zeroedPolicy.Spec.Ingress)).To(Equal(len(baselinePolicy.Spec.Ingress) - 1))
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
				cfg.LogStorageExists = true
				cfg.KubeControllersGatewaySecret = &testutils.KubeControllersUserSecret

				component := kubecontrollers.NewElasticsearchKubeControllers(&cfg)
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

	It("should render init containers when certificate management is enabled", func() {
		instance.Variant = operatorv1.CalicoEnterprise
		cfg.MetricsPort = 9094
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		tls, err := certificateManager.GetOrCreateKeyPair(cli, kubecontrollers.KubeControllerPrometheusTLSSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		cfg.MetricsServerTLS = tls

		resources, _ := kubecontrollers.NewCalicoKubeControllers(&cfg).Objects()

		dp := rtest.GetResource(resources, kubecontrollers.KubeController, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dp.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := dp.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", kubecontrollers.KubeControllerPrometheusTLSSecret)))
	})

	It("should add egress policy with Enterprise variant and K8SServiceEndpoint defined", func() {
		cfg.K8sServiceEp.Host = "k8shost"
		cfg.K8sServiceEp.Port = "1234"
		objects, _ := kubecontrollers.NewCalicoKubeControllersPolicy(&cfg, nil).Objects()
		Expect(objects).To(HaveLen(1))
		policy, ok := objects[0].(*v3.NetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(policy).ToNot(BeNil())
		Expect(policy.Spec).ToNot(BeNil())
		Expect(policy.Spec.Egress).ToNot(BeNil())
		Expect(policy.Spec.Egress).To(ContainElement(v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports:   networkpolicy.Ports(1234),
				Domains: []string{"k8shost"},
			},
		}))
	})
})
