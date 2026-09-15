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

package test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/internal/controller"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/dns"
)

var _ = Describe("GatewayAPI tests", func() {
	var c client.Client
	var clientset *kubernetes.Clientset
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	var operatorDone chan struct{}
	BeforeEach(func() {
		c, clientset, mgr = setupManagerNoControllers()

		// Start the GatewayAPI controller.
		shutdownContext, cancel = context.WithCancel(context.TODO())
		err := (&controller.GatewayAPIReconciler{
			Client: c,
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options.ControllerOptions{
			DetectedProvider: operator.ProviderNone,
			Variant:          testVariant,
			Extensions:       testExtensions,
			ManageCRDs:       ManageCRDsDisable,
			ShutdownContext:  shutdownContext,
			K8sClientset:     clientset,
		})
		Expect(err).NotTo(HaveOccurred())

		By("Cleaning up resources before the test")
		// Kick off calico-system deletion up-front so cleanupResources'
		// waitForProductTeardown doesn't time out on leftover state from a prior run.
		_ = c.Delete(context.Background(), &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
		})
		cleanupGatewayResources(c)
		cleanupResources(c)

		By("Verifying CRDs are installed")
		verifyCRDsExist(c, operator.Calico)

		By("Creating the tigera-operator namespace, if it doesn't exist")
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
			Spec:       corev1.NamespaceSpec{},
		}
		err = c.Create(context.Background(), ns)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		By("Creating the calico-system namespace, if it doesn't exist")
		calicoSystemNs := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
			Spec:       corev1.NamespaceSpec{},
		}
		err = c.Create(context.Background(), calicoSystemNs)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		By("Seeding the operator CA secret (normally created by the core controller, which is not running in this FV suite)")
		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		By("Checking no Installation is left over from previous tests")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err = c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance)
		Expect(kerror.IsNotFound(err)).To(BeTrue(), fmt.Sprintf("Expected Installation not to exist, but got: %s", err))

		operatorDone = RunOperator(mgr, shutdownContext)
	})

	AfterEach(func() {
		defer func() {
			cancel()
			Eventually(func() error {
				select {
				case <-operatorDone:
					return nil
				default:
					return fmt.Errorf("operator did not shutdown")
				}
			}, 60*time.Second).ShouldNot(HaveOccurred())
		}()

		By("Cleaning up resources after the test")
		// Delete the GatewayAPI CR first so the operator stops reconciling new
		// resources into calico-system while we're tearing it down.
		cleanupGatewayResources(c)
		_ = c.Delete(context.Background(), &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
		})
		cleanupResources(c)

		// Clean up Calico data that might be left behind.
		Eventually(func() error {
			cs := kubernetes.NewForConfigOrDie(mgr.GetConfig())
			nodes, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				return err
			}
			if len(nodes.Items) == 0 {
				return fmt.Errorf("No nodes found")
			}
			for _, n := range nodes.Items {
				for k := range n.ObjectMeta.Annotations {
					if strings.Contains(k, "projectcalico") {
						delete(n.ObjectMeta.Annotations, k)
					}
				}
				_, err = cs.CoreV1().Nodes().Update(context.Background(), &n, metav1.UpdateOptions{})
				if err != nil {
					return err
				}
			}
			return nil
		}, 30*time.Second).Should(BeNil())

		mgr = nil
	})

	It("deploys the calico-system envoy-gateway controller", func() {
		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operator.InstallationSpec{Variant: testVariant},
		}
		Expect(c.Create(shutdownContext, instance)).NotTo(HaveOccurred())
		Expect(c.Get(shutdownContext, utils.DefaultInstanceKey, instance)).NotTo(HaveOccurred())
		instance.Status.Variant = testVariant
		instance.Status.Computed = instance.Spec.DeepCopy()
		Expect(c.Status().Update(shutdownContext, instance)).NotTo(HaveOccurred())

		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())

		By("Checking envoy-gateway Deployment lands in calico-system")
		Eventually(func() error {
			var d appsv1.Deployment
			return c.Get(shutdownContext, types.NamespacedName{Namespace: "calico-system", Name: "envoy-gateway"}, &d)
		}, "30s").ShouldNot(HaveOccurred())

		By("Checking envoy-gateway Deployment is NOT in tigera-gateway")
		var d appsv1.Deployment
		err := c.Get(shutdownContext, types.NamespacedName{Namespace: "tigera-gateway", Name: "envoy-gateway"}, &d)
		Expect(kerror.IsNotFound(err)).To(BeTrue(), fmt.Sprintf("unexpected envoy-gateway in tigera-gateway: %v", err))
	})

	It("provisions and cleans up per-namespace resources for namespaced-class Gateways", func() {
		if !testVariant.IsEnterprise() {
			Skip("the per-gateway WAF and L7 log objects come from the Enterprise gateway extension")
		}

		const testNs = "gw-fv-test-ns"

		By("Creating the user Gateway namespace")
		userNs := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: testNs},
		}
		if err := c.Create(shutdownContext, userNs); err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		defer func() {
			_ = c.Delete(context.Background(), userNs)
		}()

		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operator.InstallationSpec{Variant: testVariant},
		}
		Expect(c.Create(shutdownContext, instance)).NotTo(HaveOccurred())
		Expect(c.Get(shutdownContext, utils.DefaultInstanceKey, instance)).NotTo(HaveOccurred())
		instance.Status.Variant = testVariant
		instance.Status.Computed = instance.Spec.DeepCopy()
		Expect(c.Status().Update(shutdownContext, instance)).NotTo(HaveOccurred())

		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())

		By("Waiting for the default tigera-gateway-class GatewayClass")
		Eventually(func() error {
			var gc gapi.GatewayClass
			return c.Get(shutdownContext, types.NamespacedName{Name: "tigera-gateway-class"}, &gc)
		}, "30s").ShouldNot(HaveOccurred())

		By("Creating a Gateway in the user namespace")
		gw := &gapi.Gateway{
			TypeMeta:   metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "fv-gw", Namespace: testNs},
			Spec: gapi.GatewaySpec{
				GatewayClassName: "tigera-gateway-class",
				Listeners: []gapi.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: gapi.HTTPProtocolType,
				}},
			},
		}
		Expect(c.Create(shutdownContext, gw)).NotTo(HaveOccurred())

		By("Checking per-namespace resources get provisioned for the user namespace")
		Eventually(func() error {
			var sa corev1.ServiceAccount
			if err := c.Get(shutdownContext, types.NamespacedName{Namespace: testNs, Name: "waf-http-filter"}, &sa); err != nil {
				return fmt.Errorf("waf-http-filter SA: %w", err)
			}
			var rb rbacv1.RoleBinding
			if err := c.Get(shutdownContext, types.NamespacedName{Namespace: testNs, Name: "waf-http-filter-gateway-resources"}, &rb); err != nil {
				return fmt.Errorf("waf-http-filter-gateway-resources RB: %w", err)
			}
			if err := c.Get(shutdownContext, types.NamespacedName{Namespace: testNs, Name: "tigera-operator-secrets"}, &rb); err != nil {
				return fmt.Errorf("tigera-operator-secrets RB: %w", err)
			}
			return nil
		}, "30s").ShouldNot(HaveOccurred())

		By("Checking the shared ClusterRoleBinding carries a subject for the user namespace")
		Eventually(func() error {
			var crb rbacv1.ClusterRoleBinding
			if err := c.Get(shutdownContext, types.NamespacedName{Name: "waf-http-filter-gateway-namespaces"}, &crb); err != nil {
				return err
			}
			for _, s := range crb.Subjects {
				if s.Kind == "ServiceAccount" && s.Name == "waf-http-filter" && s.Namespace == testNs {
					return nil
				}
			}
			return fmt.Errorf("no subject for %s in shared CRB (subjects=%+v)", testNs, crb.Subjects)
		}, "30s").ShouldNot(HaveOccurred())

		By("Deleting the Gateway")
		Expect(c.Delete(shutdownContext, gw)).NotTo(HaveOccurred())

		By("Checking per-namespace resources are cleaned up")
		Eventually(func() error {
			var sa corev1.ServiceAccount
			if err := c.Get(shutdownContext, types.NamespacedName{Namespace: testNs, Name: "waf-http-filter"}, &sa); !kerror.IsNotFound(err) {
				return fmt.Errorf("waf-http-filter SA still present: %v", err)
			}
			var rb rbacv1.RoleBinding
			if err := c.Get(shutdownContext, types.NamespacedName{Namespace: testNs, Name: "waf-http-filter-gateway-resources"}, &rb); !kerror.IsNotFound(err) {
				return fmt.Errorf("waf-http-filter-gateway-resources RB still present: %v", err)
			}
			if err := c.Get(shutdownContext, types.NamespacedName{Namespace: testNs, Name: "tigera-operator-secrets"}, &rb); !kerror.IsNotFound(err) {
				return fmt.Errorf("tigera-operator-secrets RB still present: %v", err)
			}
			return nil
		}, "30s").ShouldNot(HaveOccurred())

		By("Checking the shared ClusterRoleBinding is deleted when no Gateway namespaces remain")
		Eventually(func() error {
			var crb rbacv1.ClusterRoleBinding
			err := c.Get(shutdownContext, types.NamespacedName{Name: "waf-http-filter-gateway-namespaces"}, &crb)
			if kerror.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("shared CRB still exists with subjects=%+v", crb.Subjects)
		}, "30s").ShouldNot(HaveOccurred())
	})

	It("cleans up GatewayClass and EnvoyProxy resources when no longer wanted", func() {
		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operator.InstallationSpec{Registry: "myregistry.io/", Variant: testVariant},
		}
		Expect(c.Create(shutdownContext, instance)).NotTo(HaveOccurred())
		Expect(c.Get(shutdownContext, utils.DefaultInstanceKey, instance)).NotTo(HaveOccurred())
		instance.Status.Variant = testVariant
		instance.Status.Computed = instance.Spec.DeepCopy()
		Expect(c.Status().Update(shutdownContext, instance)).NotTo(HaveOccurred())

		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())

		getGatewayClassNames := func() (gcepNames []string) {
			var gcList gapi.GatewayClassList
			if err := c.List(shutdownContext, &gcList); err != nil {
				return []string{err.Error()}
			}
			for i := range gcList.Items {
				gcepNames = append(gcepNames, gcList.Items[i].Name+":"+gcList.Items[i].Spec.ParametersRef.Name)
			}
			return
		}

		By("Checking for the default tigera-gateway-class and its EnvoyProxy")
		Eventually(getGatewayClassNames, "10s").Should(ConsistOf("tigera-gateway-class:tigera-gateway-class"))

		By("Switching to two custom classes")
		Expect(c.Get(shutdownContext, utils.DefaultEnterpriseInstanceKey, gatewayAPI)).NotTo(HaveOccurred())
		gatewayAPI.Spec.GatewayClasses = []operator.GatewayClassSpec{{Name: "custom-class-1"}, {Name: "custom-class-2"}}
		Expect(c.Update(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())
		Eventually(getGatewayClassNames, "10s").Should(ConsistOf("custom-class-1:custom-class-1", "custom-class-2:custom-class-2"))

		By("Removing one custom class")
		Expect(c.Get(shutdownContext, utils.DefaultEnterpriseInstanceKey, gatewayAPI)).NotTo(HaveOccurred())
		gatewayAPI.Spec.GatewayClasses = []operator.GatewayClassSpec{{Name: "custom-class-1"}}
		Expect(c.Update(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())
		Eventually(getGatewayClassNames, "10s").Should(ConsistOf("custom-class-1:custom-class-1"))

		By("Reverting to the default GatewayAPI")
		Expect(c.Get(shutdownContext, utils.DefaultEnterpriseInstanceKey, gatewayAPI)).NotTo(HaveOccurred())
		gatewayAPI.Spec.GatewayClasses = nil
		Expect(c.Update(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())
		Eventually(getGatewayClassNames, "10s").Should(ConsistOf("tigera-gateway-class:tigera-gateway-class"))
	})

	It("watches custom EnvoyProxy resources", func() {
		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operator.InstallationSpec{Registry: "myregistry.io/", Variant: testVariant},
		}
		Expect(c.Create(shutdownContext, instance)).NotTo(HaveOccurred())
		Expect(c.Get(shutdownContext, utils.DefaultInstanceKey, instance)).NotTo(HaveOccurred())
		instance.Status.Variant = testVariant
		instance.Status.Computed = instance.Spec.DeepCopy()
		Expect(c.Status().Update(shutdownContext, instance)).NotTo(HaveOccurred())

		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())

		By("Creating a custom EnvoyProxy in default/")
		envoyProxy := &envoyapi.EnvoyProxy{
			TypeMeta:   metav1.TypeMeta{Kind: "EnvoyProxy", APIVersion: "gateway.envoyproxy.io/v1alpha1"},
			ObjectMeta: metav1.ObjectMeta{Name: "custom-ep", Namespace: "default"},
			Spec: envoyapi.EnvoyProxySpec{
				Logging: envoyapi.ProxyLogging{
					Level: map[envoyapi.ProxyLogComponent]envoyapi.LogLevel{envoyapi.LogComponentAdmin: envoyapi.LogLevelInfo},
				},
			},
		}
		Eventually(func() error { return c.Create(shutdownContext, envoyProxy) }, "10s").ShouldNot(HaveOccurred())

		By("Pointing the default GatewayClass at the custom EnvoyProxy")
		Expect(c.Get(shutdownContext, utils.DefaultEnterpriseInstanceKey, gatewayAPI)).NotTo(HaveOccurred())
		gatewayAPI.Spec.GatewayClasses = []operator.GatewayClassSpec{{
			Name:          "custom-gc",
			EnvoyProxyRef: &operator.NamespacedName{Namespace: "default", Name: "custom-ep"},
		}}
		Expect(c.Update(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())

		getEPLoggingLevels := func() (map[envoyapi.ProxyLogComponent]envoyapi.LogLevel, error) {
			var ep envoyapi.EnvoyProxy
			if err := c.Get(shutdownContext, types.NamespacedName{Namespace: "calico-system", Name: "custom-gc"}, &ep); err != nil {
				return nil, err
			}
			return ep.Spec.Logging.Level, nil
		}

		By("Checking for the rendered EnvoyProxy in calico-system")
		Eventually(getEPLoggingLevels, "10s").Should(HaveKeyWithValue(envoyapi.LogComponentAdmin, envoyapi.LogLevelInfo))

		By("Mutating the source EnvoyProxy and expecting the rendered copy to follow")
		Expect(c.Get(shutdownContext, types.NamespacedName{Namespace: "default", Name: "custom-ep"}, envoyProxy)).NotTo(HaveOccurred())
		envoyProxy.Spec.Logging.Level[envoyapi.LogComponentConnection] = envoyapi.LogLevelDebug
		Expect(c.Update(shutdownContext, envoyProxy)).NotTo(HaveOccurred())
		Eventually(getEPLoggingLevels, "10s").Should(HaveKeyWithValue(envoyapi.LogComponentConnection, envoyapi.LogLevelDebug))
		Consistently(getEPLoggingLevels, "60s", "10s").Should(HaveKeyWithValue(envoyapi.LogComponentConnection, envoyapi.LogLevelDebug))
	})

	It("creates EnvoyProxy with owning gateway env vars in l7-log-collector", func() {
		if !testVariant.IsEnterprise() {
			Skip("the per-gateway WAF and L7 log objects come from the Enterprise gateway extension")
		}

		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operator.InstallationSpec{Registry: "myregistry.io/", Variant: testVariant},
		}
		Expect(c.Create(shutdownContext, instance)).NotTo(HaveOccurred())
		Expect(c.Get(shutdownContext, utils.DefaultInstanceKey, instance)).NotTo(HaveOccurred())
		instance.Status.Variant = testVariant
		instance.Status.Computed = instance.Spec.DeepCopy()
		Expect(c.Status().Update(shutdownContext, instance)).NotTo(HaveOccurred())

		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())

		By("Verifying the rendered EnvoyProxy in calico-system has the expected l7-log-collector env vars")
		Eventually(func() error {
			var ep envoyapi.EnvoyProxy
			if err := c.Get(shutdownContext, types.NamespacedName{Namespace: "calico-system", Name: "tigera-gateway-class"}, &ep); err != nil {
				return err
			}
			if ep.Spec.Provider == nil || ep.Spec.Provider.Kubernetes == nil || ep.Spec.Provider.Kubernetes.EnvoyDeployment == nil {
				return errors.New("EnvoyProxy does not have EnvoyDeployment configured")
			}
			var l7 *corev1.Container
			for i := range ep.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers {
				if ep.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].Name == "l7-log-collector" {
					l7 = &ep.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i]
					break
				}
			}
			if l7 == nil {
				return errors.New("l7-log-collector init container not found")
			}
			want := map[string]string{
				"OWNING_GATEWAY_NAME":      "metadata.labels['gateway.envoyproxy.io/owning-gateway-name']",
				"OWNING_GATEWAY_NAMESPACE": "metadata.labels['gateway.envoyproxy.io/owning-gateway-namespace']",
			}
			for _, env := range l7.Env {
				expected, ok := want[env.Name]
				if !ok {
					continue
				}
				if env.ValueFrom == nil || env.ValueFrom.FieldRef == nil || env.ValueFrom.FieldRef.FieldPath != expected {
					return fmt.Errorf("%s has wrong fieldRef", env.Name)
				}
				delete(want, env.Name)
			}
			if len(want) > 0 {
				return fmt.Errorf("missing env vars: %v", want)
			}
			return nil
		}, "30s").ShouldNot(HaveOccurred())
	})

	It("watches the custom EnvoyGateway ConfigMap", func() {
		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operator.InstallationSpec{Registry: "myregistry.io/", Variant: testVariant},
		}
		Expect(c.Create(shutdownContext, instance)).NotTo(HaveOccurred())
		Expect(c.Get(shutdownContext, utils.DefaultInstanceKey, instance)).NotTo(HaveOccurred())
		instance.Status.Variant = testVariant
		instance.Status.Computed = instance.Spec.DeepCopy()
		Expect(c.Status().Update(shutdownContext, instance)).NotTo(HaveOccurred())

		By("Creating GatewayAPI with an EnvoyGatewayConfigRef that doesn't exist yet")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operator.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operator.NamespacedName{Namespace: "default", Name: "my-envoy-gateway"},
			},
		}
		Expect(c.Create(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())

		By("Verifying the gatewayapi status is degraded")
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "gatewayapi")
			if err != nil {
				return err
			}
			return assertDegraded(ts)
		}, 10*time.Second).Should(BeNil())

		By("Creating the custom EnvoyGateway ConfigMap")
		customEG := &envoyapi.EnvoyGateway{
			EnvoyGatewaySpec: envoyapi.EnvoyGatewaySpec{
				Telemetry: &envoyapi.EnvoyGatewayTelemetry{
					Metrics: &envoyapi.EnvoyGatewayMetrics{
						Sinks: []envoyapi.EnvoyGatewayMetricSink{{Type: envoyapi.MetricSinkTypeOpenTelemetry}},
					},
				},
				ExtensionAPIs: &envoyapi.ExtensionAPISettings{EnableEnvoyPatchPolicy: true, EnableBackend: true},
			},
		}
		egYAML, err := yaml.Marshal(*customEG)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(shutdownContext, &corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "my-envoy-gateway", Namespace: "default"},
			Data:       map[string]string{"envoy-gateway.yaml": string(egYAML)},
		})).NotTo(HaveOccurred())

		By("Verifying the gatewayapi status is no longer degraded")
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "gatewayapi")
			if err != nil {
				return err
			}
			if _, degraded, _ := readStatus(ts); degraded {
				return errors.New("still degraded")
			}
			return nil
		}, 10*time.Second).Should(BeNil())

		By("Verifying the expected envoy-gateway-config in calico-system")
		Eventually(func() error {
			var eg corev1.ConfigMap
			if err := c.Get(shutdownContext, types.NamespacedName{Name: "envoy-gateway-config", Namespace: "calico-system"}, &eg); err != nil {
				return err
			}
			if !strings.Contains(eg.Data["envoy-gateway.yaml"], "type: OpenTelemetry") {
				return errors.New("envoy-gateway-config does not contain expected text")
			}
			return nil
		}, 10*time.Second).ShouldNot(HaveOccurred())
	})
})

func cleanupGatewayResources(c client.Client) {
	By("Cleaning up custom EnvoyGateway")
	Eventually(func() error {
		var eg corev1.ConfigMap
		err := c.Get(context.Background(), types.NamespacedName{Name: "my-envoy-gateway", Namespace: "default"}, &eg)
		if err == nil {
			By(fmt.Sprintf("Deleting EnvoyGateway %s", eg.Name))
			err = c.Delete(context.Background(), &eg)
			if err != nil {
				return err
			}
		}
		return nil
	}, 30*time.Second).ShouldNot(HaveOccurred())

	By("Cleaning up GatewayAPIs")
	Eventually(func() error {
		objs := &operator.GatewayAPIList{}
		err := c.List(context.Background(), objs)
		if err != nil {
			return err
		}

		for _, p := range objs.Items {
			By(fmt.Sprintf("Deleting GatewayAPI %s", p.Name))
			err = c.Delete(context.Background(), &p)
			if err != nil {
				return err
			}
		}
		return nil
	}, 30*time.Second).ShouldNot(HaveOccurred())

	By("Cleaning up EnvoyProxies")
	Eventually(func() error {
		objs := &envoyapi.EnvoyProxyList{}
		err := c.List(context.Background(), objs)
		if err != nil {
			if strings.Contains(err.Error(), "no matches for kind \"EnvoyProxy\"") {
				// CRD has not been created yet.
				return nil
			}
			return err
		}

		for _, p := range objs.Items {
			By(fmt.Sprintf("Deleting EnvoyProxy %s", p.Name))
			err = c.Delete(context.Background(), &p)
			if err != nil {
				return err
			}
		}
		return nil
	}, 30*time.Second).ShouldNot(HaveOccurred())

	By("Expecting the legacy envoy-gateway Deployment in tigera-gateway to disappear")
	Eventually(func() error {
		var d appsv1.Deployment
		err := c.Get(context.Background(), types.NamespacedName{Namespace: "tigera-gateway", Name: "envoy-gateway"}, &d)
		if err == nil {
			return fmt.Errorf("legacy envoy-gateway Deployment still exists in tigera-gateway")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		return nil
	}, "60s").ShouldNot(HaveOccurred())
}
