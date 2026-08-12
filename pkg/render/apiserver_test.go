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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// apiServerObjects renders the base (OSS) API server component. The enterprise
// modifier and the Calico-variant cleanup are exercised in pkg/enterprise/apiserver;
// these tests cover the OSS render path, which the base render handles on its own
// (including the deletes it queues for itself).
func apiServerObjects(c render.Component) ([]client.Object, []client.Object) {
	return c.Objects()
}

func verifyAPIService(service *apiregv1.APIService, enterprise bool, clusterDomain string) {
	Expect(service.Name).To(Equal("v3.projectcalico.org"))
	Expect(service.Spec.Group).To(Equal("projectcalico.org"))
	Expect(service.Spec.Version).To(Equal("v3"))
	Expect(service.Spec.GroupPriorityMinimum).To(BeEquivalentTo(1500))
	Expect(service.Spec.VersionPriority).To(BeEquivalentTo(200))
	Expect(service.Spec.InsecureSkipTLSVerify).To(BeFalse())

	ca := service.Spec.CABundle

	expectedDNSNames := []string{
		"calico-api",
		"calico-api.calico-system",
		"calico-api.calico-system.svc",
		"calico-api.calico-system.svc." + clusterDomain,
	}

	test.VerifyCertSANs(ca, expectedDNSNames...)
}

var _ = Describe("API server rendering tests (Calico)", func() {
	var instance *operatorv1.InstallationSpec
	var apiserver *operatorv1.APIServerSpec
	var cfg *render.APIServerConfiguration
	var certificateManager certificatemanager.CertificateManager
	var cli client.Client

	BeforeEach(func() {
		instance = &operatorv1.InstallationSpec{
			ControlPlaneReplicas: ptr.To(int32(2)),
			Registry:             "testregistry.com/",
			Variant:              operatorv1.Calico,
		}
		apiserver = &operatorv1.APIServerSpec{}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())

		cfg = &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              instance,
			APIServer:                 apiserver,
			OpenShift:                 true,
			TLSKeyPair:                kp,
		}
	})

	DescribeTable("should render an API server with default configuration", func(clusterDomain string) {
		expectedResources := []client.Object{
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		cfg.TLSKeyPair = kp
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, deleteResources := apiServerObjects(component)

		rtest.ExpectResources(resources, expectedResources)
		rtest.ExpectResourceInList(deleteResources, "allow-apiserver", "calico-system", "networking.k8s.io", "v1", "NetworkPolicy")

		apiService, ok := rtest.GetResource(resources, "v3.projectcalico.org", "", "apiregistration.k8s.io", "v1", "APIService").(*apiregv1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1.APIService")
		verifyAPIService(apiService, false, clusterDomain)

		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Name).To(Equal("calico-apiserver"))
		Expect(len(d.Labels)).To(Equal(1))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(*d.Spec.Replicas).To(BeEquivalentTo(2))
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RollingUpdateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Spec.Template.Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("calico-system"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(1))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateControlPlane))
		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(1))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s%s:%s", components.CalicoImagePath, components.ComponentCalico.Image, components.ComponentCalico.Version),
		))
		Expect(d.Spec.Template.Spec.Containers[0].Command).To(Equal([]string{"/usr/bin/calico", "component", "apiserver"}))

		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/calico-apiserver-certs/tls.key",
			"--tls-cert-file=/calico-apiserver-certs/tls.crt",
		}
		Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
		Expect(len(d.Spec.Template.Spec.Containers[0].Env)).To(Equal(2))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].Name).To(Equal("LOG_LEVEL"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].Value).To(Equal("info"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].ValueFrom).To(BeNil())

		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))

		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Path).To(Equal("/readyz"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("5443"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(1))

		clusterRole := rtest.GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		Expect(clusterRole).To(BeNil())

		clusterRole = rtest.GetResource(resources, "tigera-ui-user", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		Expect(clusterRole).To(BeNil())

		clusterRoleBinding := rtest.GetResource(resources, "calico-extension-apiserver-auth-access", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef.Name).To(Equal("calico-extension-apiserver-auth-access"))

		cr := rtest.GetResource(resources, "calico-tiered-policy-passthrough", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		var tieredPolicyRules []string
		for _, rule := range cr.Rules {
			tieredPolicyRules = append(tieredPolicyRules, rule.Resources...)
		}
		Expect(tieredPolicyRules).To(ContainElements("networkpolicies", "globalnetworkpolicies"))
		Expect(tieredPolicyRules).ToNot(ContainElements("stagednetworkpolicies", "stagedglobalnetworkpolicies"))
	},
		Entry("default cluster domain", dns.DefaultClusterDomain),
		Entry("custom cluster domain", "custom-domain.internal"),
	)

	It("should not render deployment for OSS without aggregation server", func() {
		cfg.RequiresAggregationServer = false

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, deleteResources := apiServerObjects(component)

		// Should not include deployment, service, SA, or PDB.
		Expect(rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")).To(BeNil())
		Expect(rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service")).To(BeNil())
		Expect(rtest.GetResource(resources, "calico-apiserver", "calico-system", "", "v1", "ServiceAccount")).To(BeNil())
		Expect(rtest.GetResource(resources, "calico-apiserver", "calico-system", "policy", "v1", "PodDisruptionBudget")).To(BeNil())

		// Should still include RBAC.
		Expect(rtest.GetResource(resources, "calico-crds", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-webhook-reader", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())

		// Deployment and related objects should be in the delete list.
		rtest.ExpectResourceInList(deleteResources, "calico-apiserver", "calico-system", "", "v1", "ServiceAccount")
		rtest.ExpectResourceInList(deleteResources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		rtest.ExpectResourceInList(deleteResources, "calico-api", "calico-system", "", "v1", "Service")
		rtest.ExpectResourceInList(deleteResources, "calico-apiserver", "calico-system", "policy", "v1", "PodDisruptionBudget")
	})

	It("should not register the aggregation APIService when not requiring the aggregation server", func() {
		cfg.RequiresAggregationServer = false

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// The v3.projectcalico.org APIService registration must be absent in v3 CRD mode.
		for _, r := range resources {
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("APIService"),
				"unexpected APIService registered in v3 CRD mode: %s", r.GetName())
		}
	})

	It("should render an API server with custom configuration", func() {
		expectedResources := []client.Object{
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{APIVersion: "apiregistration.k8s.io/v1", Kind: "APIService"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "policy/v1", Kind: "PodDisruptionBudget"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, deleteResources := apiServerObjects(component)

		// Should render the correct resources.
		By("Checking each expected resource is actually rendered")
		for _, e := range expectedResources {
			gvk := e.GetObjectKind().GroupVersionKind()
			rtest.ExpectResourceInList(resources, e.GetName(), e.GetNamespace(), gvk.Group, gvk.Version, gvk.Kind)
		}

		By("Checking each rendered resource is actually expected")
		for _, r := range resources {
			gvk := r.GetObjectKind().GroupVersionKind()
			rtest.ExpectResourceInList(expectedResources, r.GetName(), r.GetNamespace(), gvk.Group, gvk.Version, gvk.Kind)
		}

		rtest.ExpectResourceInList(deleteResources, "allow-apiserver", "calico-system", "networking.k8s.io", "v1", "NetworkPolicy")

		// Expect same number as above
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		rtest.ExpectResourceTypeAndObjectMetadata(dep, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		d := dep.(*appsv1.Deployment)
		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(1))

		svc := rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service").(*corev1.Service)
		Expect(len(svc.Spec.Ports)).To(Equal(1))
		Expect(svc.Spec.Ports[0].Name).To(Equal(render.APIServerPortName))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(443)))
		Expect(svc.Spec.Ports[0].TargetPort.IntValue()).To(Equal(5443))
	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := apiServerObjects(component)
		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		tol := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
			Effect:   corev1.TaintEffectNoExecute,
		}
		cfg.Installation.ControlPlaneTolerations = []corev1.Toleration{tol}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := apiServerObjects(component)
		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, tol)))
	})

	It("should set KUBERNETES_SERVICE_... variables if host networked", func() {
		cfg.K8SServiceEndpoint.Host = "k8shost"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE
		cfg.ForceHostNetwork = true

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := apiServerObjects(component)

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should set RecreateDeploymentStrategyType if host networked", func() {
		cfg.ForceHostNetwork = true
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := apiServerObjects(component)
		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))
	})

	It("should not set KUBERNETES_SERVICE_... variables if Docker EE using proxy.local", func() {
		cfg.K8SServiceEndpoint.Host = "proxy.local"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := apiServerObjects(component)

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})

	It("should set KUBERNETES_SERVICE_... variables if Docker EE using non-proxy address", func() {
		cfg.K8SServiceEndpointPodNetwork.Host = "k8shost"
		cfg.K8SServiceEndpointPodNetwork.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := apiServerObjects(component)

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		cfg.Installation.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := apiServerObjects(component)

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		cfg.Installation.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := apiServerObjects(component)

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("calico-apiserver", []string{"calico-system", "tigera-system", "calico-apiserver"})))
	})

	It("should render with EKS provider without CNI.Type", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderEKS

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		_, _ = apiServerObjects(component)
	})

	It("should render host networked with TKG provider", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderTKG
		cfg.Installation.CNI = &operatorv1.CNISpec{
			Type: operatorv1.PluginCalico,
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := apiServerObjects(component)

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.HostNetwork).To(BeTrue())
	})

	Context("With APIServer Deployment overrides", func() {
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

		It("should handle APIServerDeployment overrides", func() {
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

			apiServerPort := operatorv1.APIServerDeploymentContainerPort{
				Name:          render.APIServerPortName,
				ContainerPort: 1111,
			}

			priorityclassname := "priority"

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.APIServerDeploymentSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Containers: []operatorv1.APIServerDeploymentContainer{
								{
									Name:      "calico-apiserver",
									Resources: &rr1,
									Ports:     []operatorv1.APIServerDeploymentContainerPort{apiServerPort},
								},
							},
							InitContainers: []operatorv1.APIServerDeploymentInitContainer{
								{
									Name:      "calico-apiserver-certs-key-cert-provisioner",
									Resources: &rr2,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							Affinity:          affinity,
							Tolerations:       []corev1.Toleration{toleration},
							PriorityClassName: priorityclassname,
						},
					},
				},
			}
			// Enable certificate management.
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cfg.TLSKeyPair.GetCertificatePEM()}
			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			// Create and add the TLS keypair so the initContainer is rendered.
			dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
			kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			cfg.TLSKeyPair = kp

			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			resources, _ := apiServerObjects(component)

			d, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())

			// API server has apiserver: true label
			Expect(d.Labels).To(HaveLen(2))
			Expect(d.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(2))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))
			// The render package records the applied resource override in an annotation.
			Expect(d.Annotations["operator.tigera.io/custom-overrides"]).To(Equal("resources"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-apiserver". But the APIServer
			// deployment object produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(2))
			Expect(d.Spec.Template.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 2 template-level annotations
			// - 1 added by the operator by default
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(2))
			Expect(d.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/calico-apiserver-certs"))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))
			Expect(d.Spec.Template.Spec.Containers[0].Ports[0].Name).To(Equal(apiServerPort.Name))
			Expect(d.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort).To(Equal(apiServerPort.ContainerPort))
			Expect(d.Spec.Template.Spec.Containers[0].Args[0]).To(ContainSubstring(fmt.Sprintf("--secure-port=%d", apiServerPort.ContainerPort)))

			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.InitContainers[0].Name).To(Equal("calico-apiserver-certs-key-cert-provisioner"))
			Expect(d.Spec.Template.Spec.InitContainers[0].Resources).To(Equal(rr2))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
			Expect(d.Spec.Template.Spec.PriorityClassName).To(Equal(priorityclassname))

			svc := rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service").(*corev1.Service)
			Expect(svc).NotTo(BeNil())
			Expect(svc.Spec.Ports).To(HaveLen(1))
			Expect(svc.Spec.Ports[0].Name).To(Equal(render.APIServerPortName))
			Expect(svc.Spec.Ports[0].Port).To(Equal(int32(443)))
			Expect(svc.Spec.Ports[0].TargetPort.IntVal).To(Equal(apiServerPort.ContainerPort))

			Expect(ok).To(BeTrue())
		})

		It("should override a ControlPlaneNodeSelector when specified", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := apiServerObjects(component)
			d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
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

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Tolerations: []corev1.Toleration{tol},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := apiServerObjects(component)
			d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(tol))
		})

		It("should render toleration on GKE", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			resources, _ := apiServerObjects(component)
			d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d).NotTo(BeNil())
			Expect(d.Spec.Template.Spec.Tolerations).To(ContainElement(corev1.Toleration{
				Key:      "kubernetes.io/arch",
				Operator: corev1.TolerationOpEqual,
				Value:    "arm64",
				Effect:   corev1.TaintEffectNoSchedule,
			}))
		})
	})
})
