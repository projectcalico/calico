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

package clusterconnection_test

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/clusterconnection"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/test"
)

var _ = Describe("ManagementClusterConnection controller tests", func() {
	var c client.Client
	var ctx context.Context
	var cfg *operatorv1.ManagementClusterConnection
	var installation *operatorv1.Installation
	var r reconcile.Reconciler
	var clientScheme *runtime.Scheme
	var dpl *appsv1.Deployment
	var mockStatus *status.MockStatus
	var objTrackerWithCalls test.ObjectTrackerWithCalls

	ready := &utils.ReadyFlag{}
	ready.MarkAsReady()

	BeforeEach(func() {
		// Create a Kubernetes client.
		clientScheme = runtime.NewScheme()
		Expect(apis.AddToScheme(clientScheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(clientScheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(clientScheme)).ShouldNot(HaveOccurred())
		err := operatorv1.SchemeBuilder.AddToScheme(clientScheme)
		Expect(err).NotTo(HaveOccurred())
		objTrackerWithCalls = test.NewObjectTrackerWithCalls(clientScheme)
		c = ctrlrfake.DefaultFakeClientBuilder(clientScheme).WithObjectTracker(&objTrackerWithCalls).Build()
		ctx = context.Background()
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("Run").Return()
		mockStatus.On("AddDaemonsets", mock.Anything)
		mockStatus.On("AddDeployments", mock.Anything)
		mockStatus.On("AddStatefulSets", mock.Anything)
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("ClearDegraded", mock.Anything)
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("OnCRNotFound").Return()

		Expect(c.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}))

		Expect(c.Create(ctx, &v3.ClusterInformation{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())

		r = clusterconnection.NewReconcilerWithShims(c, clientScheme, mockStatus, operatorv1.ProviderNone, ready, ready)
		dpl = &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.GuardianDeploymentName,
				Namespace: render.GuardianNamespace,
			},
		}

		Expect(c.Create(ctx, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianNamespace}}))
		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		secret, err := certificateManager.GetOrCreateKeyPair(c, render.GuardianSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		pcSecret, err := certificateManager.GetOrCreateKeyPair(c, render.PacketCaptureServerCert, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		promSecret, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		queryServerSecret, err := certificateManager.GetOrCreateKeyPair(c, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		err = c.Create(ctx, secret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, pcSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, promSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, queryServerSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())

		trustedBundle := certificateManager.CreateTrustedBundle()
		Expect(c.Create(ctx, trustedBundle.ConfigMap(render.GuardianNamespace))).NotTo(HaveOccurred())

		By("applying the required prerequisites")
		// Create a ManagementClusterConnection in the k8s client.
		cfg = &operatorv1.ManagementClusterConnection{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure", Generation: 3},
			Spec: operatorv1.ManagementClusterConnectionSpec{
				ManagementClusterAddr: "127.0.0.1:12345",
			},
		}
		err = c.Create(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())

		installation = &operatorv1.Installation{
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.CalicoEnterprise,
				Registry: "some.registry.org/",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
				Computed: &operatorv1.InstallationSpec{
					Registry:           "my-reg",
					KubernetesProvider: operatorv1.ProviderNone,
				},
			},
		}
		err = c.Create(ctx, installation)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("default config", func() {
		BeforeEach(func() {
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		})

		It("should create a default ManagementClusterConnection", func() {
			By("reconciling with the required prerequisites")
			err := c.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, dpl)
			Expect(err).To(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ToNot(HaveOccurred())
			err = c.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, dpl)
			// Verifying that there is a deployment is enough for the purpose of this test. More detailed testing will be done
			// in the render package.
			Expect(err).NotTo(HaveOccurred())
			Expect(dpl.Labels["k8s-app"]).To(Equal(render.GuardianName))
		})
	})

	Context("guardian finalizer", func() {
		BeforeEach(func() {
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		})

		It("should be added and removed from the Installation CR", func() {
			By("reconciling with the required prerequisites")
			err := c.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, dpl)
			Expect(err).To(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ToNot(HaveOccurred())
			err = c.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, dpl)
			// Verifying that there is a deployment is enough for the purpose of this test. More detailed testing will be done
			// in the render package.
			Expect(err).NotTo(HaveOccurred())
			Expect(dpl.Labels["k8s-app"]).To(Equal(render.GuardianName))

			By("verifying that the installation cr has a guardian finalizer")
			install := &operatorv1.Installation{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
			Expect(test.GetResource(c, install)).To(BeNil())
			Expect(install.ObjectMeta.Finalizers).To(ContainElement(render.GuardianFinalizer))

			By("not removing the guardian finalizer when the management cluster connection is deleted and the guardian deployment is still present.")
			Expect(c.Delete(ctx, cfg)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ToNot(HaveOccurred())
			Expect(test.GetResource(c, install)).To(BeNil())
			Expect(install.ObjectMeta.Finalizers).To(ContainElement(render.GuardianFinalizer))

			By("removing the guardian finalizer when the management cluster connection is deleted and the guardian deployment is deleted.")
			Expect(c.Delete(ctx, dpl)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ToNot(HaveOccurred())
			Expect(test.GetResource(c, install)).To(BeNil())
			Expect(install.ObjectMeta.Finalizers).To(Not(ContainElement(render.GuardianFinalizer)))
		})
	})

	Context("Proxy setting", func() {
		DescribeTable("sets the proxy", func(http, https, noProxy bool) {
			installationCopy := installation.DeepCopy()
			installationCopy.Spec.Proxy = &operatorv1.Proxy{}

			if http {
				installationCopy.Spec.Proxy.HTTPProxy = "test-http-proxy"
			}
			if https {
				installationCopy.Spec.Proxy.HTTPSProxy = "test-https-proxy"
			}
			if noProxy {
				installationCopy.Spec.Proxy.NoProxy = "test-no-proxy"
			}

			err := c.Update(ctx, installationCopy)
			Expect(err).NotTo(HaveOccurred())

			// Reconcile creates the guardian deployment.
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Get the deployment and validate the env vars.
			gd := appsv1.Deployment{}
			err = c.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, &gd)
			Expect(err).NotTo(HaveOccurred())

			var expectedEnvVars []v1.EnvVar
			if http {
				expectedEnvVars = append(expectedEnvVars,
					v1.EnvVar{
						Name:  "HTTP_PROXY",
						Value: "test-http-proxy",
					},
					v1.EnvVar{
						Name:  "http_proxy",
						Value: "test-http-proxy",
					},
				)
			}

			if https {
				expectedEnvVars = append(expectedEnvVars,
					v1.EnvVar{
						Name:  "HTTPS_PROXY",
						Value: "test-https-proxy",
					},
					v1.EnvVar{
						Name:  "https_proxy",
						Value: "test-https-proxy",
					},
				)
			}

			if noProxy {
				expectedEnvVars = append(expectedEnvVars,
					v1.EnvVar{
						Name:  "NO_PROXY",
						Value: "test-no-proxy",
					},
					v1.EnvVar{
						Name:  "no_proxy",
						Value: "test-no-proxy",
					},
				)
			}

			Expect(gd.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(gd.Spec.Template.Spec.Containers[0].Env).To(ContainElements(expectedEnvVars))
		},
			Entry("http/https/noProxy", true, true, true),
			Entry("http", true, false, false),
			Entry("https", false, true, false),
			Entry("http/https", true, true, false),
			Entry("http/noProxy", true, false, true),
			Entry("https/noProxy", false, true, true),
		)
	})

	Context("Reconcile for Condition status", func() {
		generation := int64(2)
		It("should reconcile with empty tigerastatus conditions ", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "management-cluster-connection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetManagementClusterConnection(ctx, c)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(0))
			Expect(c.Delete(ctx, ts)).NotTo(HaveOccurred())
		})
		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "management-cluster-connection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetManagementClusterConnection(ctx, c)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(1))

			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
			Expect(c.Delete(ctx, ts)).NotTo(HaveOccurred())
		})
		It("should reconcile with creating new status condition with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentProgressing,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.ResourceNotReady),
							Message:            "Progressing Installation.operatorv1.tigera.io",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.ResourceUpdateError),
							Message:            "Error resolving ImageSet for components",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "management-cluster-connection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetManagementClusterConnection(ctx, c)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.ResourceNotReady)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Progressing Installation.operatorv1.tigera.io"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.ResourceUpdateError)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
			Expect(c.Delete(ctx, ts)).NotTo(HaveOccurred())
		})
		It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentProgressing,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "management-cluster-connection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetManagementClusterConnection(ctx, c)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
			Expect(c.Delete(ctx, ts)).NotTo(HaveOccurred())
		})
	})

})

func createPodWithProxy(ctx context.Context, c client.Client, config *test.ProxyConfig, lowercase bool, replicaNum int) {
	pod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.GuardianDeploymentName + strconv.Itoa(replicaNum),
			Namespace: render.GuardianNamespace,
			Labels: map[string]string{
				"k8s-app":                render.GuardianDeploymentName,
				"app.kubernetes.io/name": render.GuardianDeploymentName,
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name: render.GuardianContainerName,
				Env:  []v1.EnvVar{},
			}},
		},
	}

	if config != nil {
		// Set the env vars.
		httpsProxyVarName := "HTTPS_PROXY"
		httpProxyVarName := "HTTP_PROXY"
		noProxyVarName := "NO_PROXY"
		if lowercase {
			httpsProxyVarName = strings.ToLower(httpsProxyVarName)
			httpProxyVarName = strings.ToLower(httpProxyVarName)
			noProxyVarName = strings.ToLower(noProxyVarName)
		}
		// Environment variables that are empty can be represented as an unset variable or a set variable with an empty string.
		// For our tests, we'll represent them as an unset variable.
		if config.HTTPSProxy != "" {
			pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, v1.EnvVar{
				Name:  httpsProxyVarName,
				Value: config.HTTPSProxy,
			})
			// Add a static HTTP_PROXY variable to catch any scenarios where the controller picks the wrong env var (Guardian uses HTTPS).
			pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, v1.EnvVar{
				Name:  httpProxyVarName,
				Value: "http://wrong-proxy-url.com/",
			})
		}
		if config.NoProxy != "" {
			pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, v1.EnvVar{
				Name:  noProxyVarName,
				Value: config.NoProxy,
			})
		}
	}

	err := c.Create(ctx, &pod)
	Expect(err).NotTo(HaveOccurred())
}

type expectedEgressRule struct {
	host      string
	port      uint16
	hostIsIP  bool
	isProxied bool
}

func generateCoreProxyTestCases(targetDomain, targetIP, proxyDomain, proxyIP, proxyPort string) []test.ProxyTestCase {
	var cases []test.ProxyTestCase
	// We will collect the cases by target type. Targets are in the form of ip:port or domain:port.
	for _, target := range []string{targetDomain, targetIP} {
		var casesByTargetType []test.ProxyTestCase
		// Generate the proxy strings. They can be http or https, use a domain or IP host, and can optionally specify a port.
		var proxyStrings []string
		for _, scheme := range []string{"http", "https"} {
			for _, host := range []string{proxyDomain, proxyIP} {
				for _, port := range []string{"", proxyPort} {
					proxyString := fmt.Sprintf("%s://%s", scheme, host)
					if port != "" {
						proxyString = fmt.Sprintf("%s:%s", proxyString, port)
					}
					proxyStrings = append(proxyStrings, proxyString)
				}
			}
		}
		// Add base case: proxy is empty (empty and unset env vars are handled the same).
		proxyStrings = append(proxyStrings, "")

		// Generate the "no proxy" strings. They can either match or not match the target, can list one or many exemptions,
		// and can optionally specify a port.
		var noProxyStrings []string
		for _, matchesTarget := range []bool{true, false} {
			noProxyContainsPort := []bool{false}
			if matchesTarget {
				noProxyContainsPort = append(noProxyContainsPort, true)
			}
			for _, containsPort := range noProxyContainsPort {
				for _, multipleExemptions := range []bool{true, false} {
					host, port, err := net.SplitHostPort(target)
					Expect(err).NotTo(HaveOccurred())
					matchString := host
					if containsPort {
						matchString = fmt.Sprintf("%s:%s", matchString, port)
					}

					var noProxyString string
					if matchesTarget {
						noProxyString = matchString
					} else {
						noProxyString = "nomatch.com"
					}

					if multipleExemptions {
						noProxyString = fmt.Sprintf("1.1.1.1,%s,nobueno.com", noProxyString)
					}

					noProxyStrings = append(noProxyStrings, noProxyString)
				}
			}
		}
		// Add base case: no-proxy is empty (empty and unset env vars are handled the same).
		noProxyStrings = append(noProxyStrings, "")

		// Create the cases based on the generated combinations of proxy strings.
		// The env vars can be set as either lowercase or uppercase on the container, we express that possibility here.
		for _, lowercase := range []bool{true, false} {
			for _, proxyString := range proxyStrings {
				for _, noProxyString := range noProxyStrings {
					testCase := test.ProxyTestCase{
						Lowercase: lowercase,
						Target:    target,
					}
					var podProxyConfig *test.ProxyConfig
					if proxyString != "" || noProxyString != "" {
						podProxyConfig = &test.ProxyConfig{
							HTTPSProxy: proxyString,
							NoProxy:    noProxyString,
						}
					}
					testCase.PodProxies = []*test.ProxyConfig{podProxyConfig}
					casesByTargetType = append(casesByTargetType, testCase)
				}
			}
		}
		cases = append(cases, casesByTargetType...)
	}
	return cases
}

func getExpectedEgressRulesFromCase(c test.ProxyTestCase) []expectedEgressRule {
	var expectedEgressRules []expectedEgressRule
	expectedEgressRulesAdded := map[expectedEgressRule]bool{}

	for _, proxy := range c.PodProxies {
		var isProxied bool
		if proxy != nil && proxy.HTTPSProxy != "" {
			if proxy.NoProxy == "" {
				isProxied = true
			} else {
				var proxyIsExempt bool
				for _, noProxySubstring := range strings.Split(proxy.NoProxy, ",") {
					if strings.Contains(c.Target, noProxySubstring) {
						proxyIsExempt = true
						break
					}
				}
				if !proxyIsExempt {
					isProxied = true
				}
			}
		}

		var host string
		var port uint16
		if isProxied {
			proxyURL, err := url.ParseRequestURI(proxy.HTTPSProxy)
			Expect(err).NotTo(HaveOccurred())

			// Resolve port
			hostSplit := strings.Split(proxyURL.Host, ":")
			switch {
			case len(hostSplit) == 2:
				port64, err := strconv.ParseUint(hostSplit[1], 10, 16)
				Expect(err).NotTo(HaveOccurred())
				host = hostSplit[0]
				port = uint16(port64)
			case proxyURL.Scheme == "https":
				host = proxyURL.Host
				port = 443
			default:
				host = proxyURL.Host
				port = 80
			}

			Expect(err).NotTo(HaveOccurred())
		} else {
			var portString string
			var err error
			host, portString, err = net.SplitHostPort(c.Target)
			Expect(err).NotTo(HaveOccurred())
			port64, err := strconv.ParseUint(portString, 10, 16)
			Expect(err).NotTo(HaveOccurred())
			port = uint16(port64)
		}

		proxyPolicy := expectedEgressRule{
			host:      host,
			port:      port,
			isProxied: isProxied,
			hostIsIP:  net.ParseIP(host) != nil,
		}

		if !expectedEgressRulesAdded[proxyPolicy] {
			expectedEgressRules = append(expectedEgressRules, proxyPolicy)
			expectedEgressRulesAdded[proxyPolicy] = true
		}
	}

	return expectedEgressRules
}

func multiplePodCases() []test.ProxyTestCase {
	return []test.ProxyTestCase{
		// Mainline case with multiple pods: both have the same proxy.
		{
			Target: "voltron:9000",
			PodProxies: []*test.ProxyConfig{
				{
					HTTPSProxy: "http://proxy.io/",
					NoProxy:    "nomatch",
				},
				{
					HTTPSProxy: "http://proxy.io/",
					NoProxy:    "nomatch",
				},
			},
		},
		// Mainline case with multiple pods: neither have a proxy.
		{
			Target:     "voltron:9000",
			PodProxies: []*test.ProxyConfig{nil, nil},
		},
		// One pod has a proxy, one pod does not.
		{
			Target:     "voltron:9000",
			PodProxies: []*test.ProxyConfig{{HTTPSProxy: "http://proxy.io/", NoProxy: "nomatch"}, nil},
		},
		// Pods have different proxies.
		{
			Target: "voltron:9000",
			PodProxies: []*test.ProxyConfig{
				{
					HTTPSProxy: "http://proxy.io/",
					NoProxy:    "nomatch",
				},
				{
					HTTPSProxy: "http://proxy-number-two.io/",
					NoProxy:    "nomatch",
				},
			},
		},
		// Pods have different proxies, but one of them is exempt from the proxy.
		{
			Target: "voltron:9000",
			PodProxies: []*test.ProxyConfig{
				{
					HTTPSProxy: "http://proxy.io/",
					NoProxy:    "nomatch",
				},
				{
					HTTPSProxy: "http://proxy-number-two.io/",
					NoProxy:    "voltron",
				},
			},
		},
		// Pods have different proxies, but both of them are exempt from the proxy.
		{
			Target: "voltron:9000",
			PodProxies: []*test.ProxyConfig{
				{
					HTTPSProxy: "http://proxy.io/",
					NoProxy:    "voltron",
				},
				{
					HTTPSProxy: "http://proxy-number-two.io/",
					NoProxy:    "voltron",
				},
			},
		},
	}
}
