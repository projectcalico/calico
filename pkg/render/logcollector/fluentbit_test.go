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

package logcollector_test

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/resourcequota"

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
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/logcollector"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var _ = Describe("Tigera Secure Fluent Bit rendering tests", func() {
	var cfg *logcollector.FluentBitConfiguration
	var cli client.Client

	expectedFluentBitPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/fluentbit_unmanaged.json")
	expectedFluentBitPolicyForUnmanagedOpenshift := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/fluentbit_unmanaged_ocp.json")
	expectedFluentBitPolicyForManaged := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/fluentbit_managed.json")

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		metricsSecret, err := certificateManager.GetOrCreateKeyPair(cli, logcollector.FluentBitTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		eksSecret, err := certificateManager.GetOrCreateKeyPair(cli, logcollector.EKSLogForwarderTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg = &logcollector.FluentBitConfiguration{
			LogCollector:  &operatorv1.LogCollector{},
			ClusterDomain: dns.DefaultClusterDomain,
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
			},
			FluentBitKeyPair:       metricsSecret,
			EKSLogForwarderKeyPair: eksSecret,
			TrustedBundle:          certificatemanagement.CreateNamedTrustedBundle(render.FluentBitNodeName, certificateManager.KeyPair(), true),
		}
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// calico-fluent-bit clusterRole should have openshift securitycontextconstraints PolicyRule
		fluentBitRole := rtest.GetResource(resources, "calico-fluent-bit", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(fluentBitRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"privileged"},
		}))

		// Both the fluent-bit container and the pos-migrator init container
		// write to the /var/log/calico host path volume, so both must be
		// privileged on OpenShift.
		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		container := ds.Spec.Template.Spec.Containers[0]
		Expect(*container.SecurityContext.Privileged).To(BeTrue())
		initContainers := ds.Spec.Template.Spec.InitContainers
		Expect(initContainers).NotTo(BeEmpty())
		Expect(initContainers[0].Name).To(Equal("pos-migrator"))
		Expect(*initContainers[0].SecurityContext.Privileged).To(BeTrue())
	})

	It("preserves the cloud/enterprise log feature split on the Linseed outputs", func() {
		// linseedTags renders the Linux fluent-bit config and returns the tags of
		// the built-in Linseed (http) outputs — the fluent-bit equivalent of the
		// log types fluentd shipped to Elasticsearch.
		linseedTags := func() []string {
			resources, _ := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux).Objects()
			cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
			var conf struct {
				Pipeline struct {
					Outputs []map[string]interface{} `json:"outputs"`
				} `json:"pipeline"`
			}
			Expect(json.Unmarshal([]byte(cm.Data["fluent-bit.yaml"]), &conf)).NotTo(HaveOccurred())
			var tags []string
			for _, out := range conf.Pipeline.Outputs {
				if out["name"] == "http" {
					tags = append(tags, out["match"].(string))
				}
			}
			return tags
		}

		By("shipping every log type to Linseed for enterprise (Cloud false)")
		Expect(linseedTags()).To(ConsistOf(
			"flows", "dns", "l7", "waf", "runtime", "audit.tsee", "audit.kube", "bird", "bird6", "policy_activity"))

		By("omitting DNS, EE/kube audit, BGP and flow logs for a non-multi-tenant cloud install")
		cfg.Cloud = true
		Expect(linseedTags()).To(ConsistOf("l7", "waf", "runtime", "policy_activity"))

		By("keeping flow logs (but still dropping DNS/audit/BGP) for a multi-tenant cloud management cluster")
		cfg.Tenant = &operatorv1.Tenant{ObjectMeta: metav1.ObjectMeta{Namespace: "tigera-tenant"}}
		Expect(linseedTags()).To(ConsistOf("flows", "l7", "waf", "runtime", "policy_activity"))
	})

	It("should render with a default configuration", func() {
		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsService, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
		}

		// Should render the correct resources.
		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)
		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Volumes[0].VolumeSource.HostPath.Path).To(Equal("/var/log/calico"))
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))

		// The pos-migrator init container pre-creates the tailed log dirs so
		// glob inputs (compliance) don't error while a feature's dir is absent.
		initContainers := ds.Spec.Template.Spec.InitContainers
		Expect(initContainers).NotTo(BeEmpty())
		Expect(initContainers[0].Name).To(Equal("pos-migrator"))
		var logDirs string
		for _, env := range initContainers[0].Env {
			if env.Name == "LOG_DIRS" {
				logDirs = env.Value
			}
		}
		Expect(logDirs).To(ContainSubstring("/var/log/calico/compliance"))
		Expect(logDirs).To(ContainSubstring("/var/log/calico/waf"))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		Expect(envs).Should(ContainElement(
			corev1.EnvVar{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
		))

		// Linseed/TLS config is now in the ConfigMap, not env vars.
		Expect(envs).ShouldNot(ContainElements(
			corev1.EnvVar{Name: "LINSEED_ENABLED", Value: "true"},
			corev1.EnvVar{Name: "LINSEED_ENDPOINT", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			corev1.EnvVar{Name: "TLS_KEY_PATH", Value: "/calico-fluent-bit-tls/tls.key"},
			corev1.EnvVar{Name: "TLS_CRT_PATH", Value: "/calico-fluent-bit-tls/tls.crt"},
		))

		// Verify the ConfigMap contains the expected config.
		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		Expect(cm.Data).To(HaveKey("fluent-bit.yaml"))
		fluentBitConf := cm.Data["fluent-bit.yaml"]
		// Linseed shipping uses the built-in http output (no Go proxy
		// plugins): one block per tag, NDJSON body, mTLS plus a bearer token
		// re-read from file on every request.
		Expect(fluentBitConf).To(ContainSubstring(`"name": "http"`))
		Expect(fluentBitConf).To(ContainSubstring(`"host": "tigera-linseed.tigera-elasticsearch.svc"`))
		Expect(fluentBitConf).To(ContainSubstring(`"uri": "/api/v1/flows/logs/bulk"`))
		Expect(fluentBitConf).To(ContainSubstring(`"uri": "/api/v1/dns/logs/bulk"`))
		Expect(fluentBitConf).To(ContainSubstring(`"uri": "/api/v1/audit/logs/ee/bulk"`))
		Expect(fluentBitConf).To(ContainSubstring(`"uri": "/api/v1/audit/logs/kube/bulk"`))
		Expect(fluentBitConf).To(ContainSubstring(`"uri": "/api/v1/bgp/logs/bulk"`))
		Expect(fluentBitConf).To(ContainSubstring(`"format": "json_lines"`))
		Expect(fluentBitConf).To(ContainSubstring(`"json_date_key": false`))
		Expect(fluentBitConf).To(ContainSubstring(`"bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"`))
		// Per-tag filesystem retry caps: flows is the dominant volume and
		// keeps the budget the single shared output used to have.
		Expect(fluentBitConf).To(ContainSubstring(`"storage.total_limit_size": "500M"`))
		Expect(fluentBitConf).To(ContainSubstring(`"storage.total_limit_size": "100M"`))
		// Long-line safety on the tail inputs: at the 32K default
		// buffer_max_size, one over-long line (routine for kube-audit) makes
		// in_tail abandon the whole file.
		Expect(fluentBitConf).To(ContainSubstring(`"buffer_chunk_size": "256K"`))
		Expect(fluentBitConf).To(ContainSubstring(`"buffer_max_size": "10M"`))
		Expect(fluentBitConf).To(ContainSubstring(`"skip_long_lines": true`))
		// No Go proxy plugins are loaded.
		Expect(fluentBitConf).NotTo(ContainSubstring("plugins_file"))
		Expect(fluentBitConf).NotTo(ContainSubstring(`"name": "linseed"`))

		container := ds.Spec.Template.Spec.Containers[0]

		Expect(container.Command).To(Equal([]string{"/usr/bin/fluent-bit"}))
		Expect(container.Args).To(Equal([]string{"-c", "/etc/fluent-bit/fluent-bit.yaml"}))

		Expect(container.ReadinessProbe.HTTPGet).NotTo(BeNil())
		Expect(container.ReadinessProbe.HTTPGet.Path).To(Equal("/api/v1/health"))
		Expect(container.ReadinessProbe.HTTPGet.Port).To(Equal(intstr.FromInt(logcollector.FluentBitMetricsPort)))
		Expect(container.ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.LivenessProbe.HTTPGet).NotTo(BeNil())
		Expect(container.LivenessProbe.HTTPGet.Path).To(Equal("/api/v1/uptime"))
		Expect(container.LivenessProbe.HTTPGet.Port).To(Equal(intstr.FromInt(logcollector.FluentBitMetricsPort)))
		Expect(container.LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.LivenessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.StartupProbe.HTTPGet).NotTo(BeNil())
		Expect(container.StartupProbe.HTTPGet.Path).To(Equal("/api/v1/uptime"))
		Expect(container.StartupProbe.HTTPGet.Port).To(Equal(intstr.FromInt(logcollector.FluentBitMetricsPort)))
		Expect(container.StartupProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.StartupProbe.PeriodSeconds).To(BeEquivalentTo(60))
		Expect(container.StartupProbe.FailureThreshold).To(BeEquivalentTo(10))

		Expect(*container.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*container.SecurityContext.Privileged).To(BeFalse())
		Expect(*container.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*container.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*container.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(container.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(container.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// The metrics service should have the correct configuration.
		ms := rtest.GetResource(resources, logcollector.FluentBitMetricsService, render.LogCollectorNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless to prevent kube-proxy from rendering too many iptables rules")
	})

	It("should render fluent-bit DaemonSet with resources requests/limits", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		metricsSecret, err := certificateManager.GetOrCreateKeyPair(cli, logcollector.FluentBitTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		cfg.FluentBitKeyPair = metricsSecret

		fluentBitResources := corev1.ResourceRequirements{
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

		logCollectorcfg := operatorv1.LogCollector{
			Spec: operatorv1.LogCollectorSpec{
				CalicoFluentBitDaemonSet: &operatorv1.FluentBitDaemonSet{
					Spec: &operatorv1.FluentBitDaemonSetSpec{
						Template: &operatorv1.FluentBitDaemonSetPodTemplateSpec{
							Spec: &operatorv1.FluentBitDaemonSetPodSpec{
								InitContainers: []operatorv1.FluentBitDaemonSetInitContainer{{
									Name:      "calico-fluent-bit-tls-key-cert-provisioner",
									Resources: &fluentBitResources,
								}},
								Containers: []operatorv1.FluentBitDaemonSetContainer{{
									Name:      "calico-fluent-bit",
									Resources: &fluentBitResources,
								}},
							},
						},
					},
				},
			},
		}

		cfg.LogCollector = &logCollectorcfg
		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		resources, _ := component.Objects()

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))

		container := test.GetContainer(ds.Spec.Template.Spec.Containers, "calico-fluent-bit")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(fluentBitResources))

		Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(2))
		initContainer := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "calico-fluent-bit-tls-key-cert-provisioner")
		Expect(initContainer).NotTo(BeNil())
		Expect(initContainer.Resources).To(Equal(fluentBitResources))
	})

	It("should honor the deprecated fluentdDaemonSet override alias, including legacy container names", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		metricsSecret, err := certificateManager.GetOrCreateKeyPair(cli, logcollector.FluentBitTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		cfg.FluentBitKeyPair = metricsSecret

		legacyResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    resource.MustParse("2"),
				"memory": resource.MustParse("300Mi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    resource.MustParse("1"),
				"memory": resource.MustParse("150Mi"),
			},
		}

		// A pre-migration LogCollector: overrides stored under the deprecated
		// fluentdDaemonSet field, using the fluentd-era container names.
		cfg.LogCollector = &operatorv1.LogCollector{
			Spec: operatorv1.LogCollectorSpec{
				FluentdDaemonSet: &operatorv1.FluentBitDaemonSet{
					Spec: &operatorv1.FluentBitDaemonSetSpec{
						Template: &operatorv1.FluentBitDaemonSetPodTemplateSpec{
							Spec: &operatorv1.FluentBitDaemonSetPodSpec{
								InitContainers: []operatorv1.FluentBitDaemonSetInitContainer{{
									Name:      "tigera-fluentd-prometheus-tls-key-cert-provisioner",
									Resources: &legacyResources,
								}},
								Containers: []operatorv1.FluentBitDaemonSetContainer{{
									Name:      "fluentd",
									Resources: &legacyResources,
								}},
							},
						},
					},
				},
			},
		}
		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		resources, _ := component.Objects()

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		container := test.GetContainer(ds.Spec.Template.Spec.Containers, "calico-fluent-bit")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(legacyResources))

		initContainer := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "calico-fluent-bit-tls-key-cert-provisioner")
		Expect(initContainer).NotTo(BeNil())
		Expect(initContainer.Resources).To(Equal(legacyResources))

		// When both the deprecated alias and the new field are set, the new
		// field takes precedence.
		newResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    resource.MustParse("4"),
				"memory": resource.MustParse("600Mi"),
			},
		}
		cfg.LogCollector.Spec.CalicoFluentBitDaemonSet = &operatorv1.FluentBitDaemonSet{
			Spec: &operatorv1.FluentBitDaemonSetSpec{
				Template: &operatorv1.FluentBitDaemonSetPodTemplateSpec{
					Spec: &operatorv1.FluentBitDaemonSetPodSpec{
						Containers: []operatorv1.FluentBitDaemonSetContainer{{
							Name:      "calico-fluent-bit",
							Resources: &newResources,
						}},
					},
				},
			},
		}
		resources, _ = logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux).Objects()
		ds = rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		container = test.GetContainer(ds.Spec.Template.Spec.Containers, "calico-fluent-bit")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(newResources))
	})

	It("should render with a configuration for a managed cluster", func() {
		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsService, Namespace: render.LogCollectorNamespace}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.FluentBitNodeName, Namespace: render.LogCollectorNamespace}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: render.FluentBitNodeName, Namespace: render.LogCollectorNamespace}},
			&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}},
		}

		expectedDeleteResources := append([]client.Object{
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.FluentBitInputService, Namespace: render.LogCollectorNamespace}},
		}, legacyFluentdDeleteResources()...)

		// Should render the correct resources.
		managedCfg := &logcollector.FluentBitConfiguration{
			LogCollector:     cfg.LogCollector,
			ClusterDomain:    cfg.ClusterDomain,
			Installation:     cfg.Installation,
			FluentBitKeyPair: cfg.FluentBitKeyPair,
			TrustedBundle:    cfg.TrustedBundle,
			ManagedCluster:   true,
		}
		createResources, deleteResources := renderAll(managedCfg, rmeta.OSTypeLinux)
		rtest.ExpectResources(createResources, expectedResources)
		rtest.ExpectResources(deleteResources, expectedDeleteResources)

		ds := rtest.GetResource(createResources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Volumes[0].VolumeSource.HostPath.Path).To(Equal("/var/log/calico"))
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		Expect(envs).Should(ContainElement(
			corev1.EnvVar{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
		))

		// Verify the ConfigMap contains the linseed config for the managed cluster.
		cm := rtest.GetResource(createResources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		Expect(cm.Data).To(HaveKey("fluent-bit.yaml"))
		fluentBitConf := cm.Data["fluent-bit.yaml"]
		Expect(fluentBitConf).To(ContainSubstring(`"name": "http"`))
		// Managed clusters post to the external tigera-linseed service (which
		// redirects to Guardian) with the operator-provisioned token, not the
		// pod's ServiceAccount token.
		Expect(fluentBitConf).To(ContainSubstring(`"host": "tigera-linseed"`))
		Expect(fluentBitConf).To(ContainSubstring(`"bearer_token_file": "/var/run/secrets/tigera.io/linseed/token"`))

		container := ds.Spec.Template.Spec.Containers[0]

		Expect(container.ReadinessProbe.HTTPGet).NotTo(BeNil())
		Expect(container.ReadinessProbe.HTTPGet.Path).To(Equal("/api/v1/health"))
		Expect(container.ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.LivenessProbe.HTTPGet).NotTo(BeNil())
		Expect(container.LivenessProbe.HTTPGet.Path).To(Equal("/api/v1/uptime"))
		Expect(container.LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.LivenessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.StartupProbe.HTTPGet).NotTo(BeNil())
		Expect(container.StartupProbe.HTTPGet.Path).To(Equal("/api/v1/uptime"))
		Expect(container.StartupProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.StartupProbe.PeriodSeconds).To(BeEquivalentTo(60))
		Expect(container.StartupProbe.FailureThreshold).To(BeEquivalentTo(10))

		Expect(*container.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*container.SecurityContext.Privileged).To(BeFalse())
		Expect(*container.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*container.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*container.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(container.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(container.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		linseedRoleBinding := rtest.GetResource(createResources, "tigera-linseed", render.LogCollectorNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(linseedRoleBinding.RoleRef.Name).To(Equal("tigera-linseed-secrets"))
		Expect(linseedRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.GuardianServiceAccountName,
				Namespace: render.GuardianNamespace,
			},
		}))

		// The metrics service should have the correct configuration.
		ms := rtest.GetResource(createResources, logcollector.FluentBitMetricsService, render.LogCollectorNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless to prevent kube-proxy from rendering too many iptables rules")
	})

	It("should render with a resource quota for provider GKE", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

		// Should render the correct resources.
		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)

		// Should render resource quota
		Expect(rtest.GetResource(resources, "tigera-critical-pods", "calico-system", "", "v1", "ResourceQuota")).ToNot(BeNil())
	})

	It("should render for Windows nodes", func() {
		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsServiceWindows, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName + "-windows", Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit-windows"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit-windows"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit-windows", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit-windows", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
		}

		// Should render the correct resources.
		resources, _ := renderAll(cfg, rmeta.OSTypeWindows)
		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, "calico-fluent-bit-windows", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Volumes[0].VolumeSource.HostPath.Path).To(Equal("c:/TigeraCalico"))

		envs := ds.Spec.Template.Spec.Containers[0].Env

		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "NODENAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		}))

		// Verify the ConfigMap contains expected config for Windows paths. The
		// Windows component renders its own OS-suffixed ConfigMap so it cannot
		// fight the Linux one on mixed clusters.
		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName+"-windows", render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		Expect(cm.Data).To(HaveKey("fluent-bit.yaml"))
		fluentBitConf := cm.Data["fluent-bit.yaml"]
		// Windows ships through the built-in http output too — the image
		// carries no plugin DLLs and no Go runtime at all.
		Expect(fluentBitConf).To(ContainSubstring(`"name": "http"`))
		Expect(fluentBitConf).To(ContainSubstring(`"uri": "/api/v1/flows/logs/bulk"`))
		Expect(fluentBitConf).To(ContainSubstring(`"uri": "/api/v1/audit/logs/ee/bulk"`))
		Expect(fluentBitConf).To(ContainSubstring(`"uri": "/api/v1/audit/logs/kube/bulk"`))
		Expect(fluentBitConf).To(ContainSubstring(`"bearer_token_file": "c:/var/run/secrets/kubernetes.io/serviceaccount/token"`))
		Expect(fluentBitConf).NotTo(ContainSubstring("plugins_file"))
		// The Windows image lays everything out under C:\fluent-bit.
		Expect(fluentBitConf).To(ContainSubstring(`"script": "c:/fluent-bit/record_transformer.lua"`))
		// Windows tails only the log types the fluentd Windows variant shipped.
		Expect(fluentBitConf).To(ContainSubstring("c:/var/log/calico/flowlogs/flows.log"))
		Expect(fluentBitConf).NotTo(ContainSubstring("dnslogs"))
		Expect(ds.Spec.Template.Spec.Containers[0].Command).To(Equal([]string{"c:/fluent-bit/fluent-bit.exe"}))
		Expect(ds.Spec.Template.Spec.Containers[0].Args).To(Equal([]string{"-c", "c:/etc/fluent-bit/conf/fluent-bit.yaml"}))
		// The Windows pos-migrator runs with c:-prefixed dirs.
		initContainers := ds.Spec.Template.Spec.InitContainers
		Expect(initContainers).To(HaveLen(1))
		Expect(initContainers[0].Command).To(Equal([]string{"c:/fluent-bit/pos-migrator.exe"}))
		Expect(initContainers[0].Env).To(ContainElement(corev1.EnvVar{Name: "DB_DIR", Value: "c:/var/log/calico/calico-fluent-bit"}))

		container := ds.Spec.Template.Spec.Containers[0]

		Expect(container.ReadinessProbe.HTTPGet).NotTo(BeNil())
		Expect(container.ReadinessProbe.HTTPGet.Path).To(Equal("/api/v1/health"))
		Expect(container.ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.LivenessProbe.HTTPGet).NotTo(BeNil())
		Expect(container.LivenessProbe.HTTPGet.Path).To(Equal("/api/v1/uptime"))
		Expect(container.LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.LivenessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.StartupProbe.HTTPGet).NotTo(BeNil())
		Expect(container.StartupProbe.HTTPGet.Path).To(Equal("/api/v1/uptime"))
		Expect(container.StartupProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.StartupProbe.PeriodSeconds).To(BeEquivalentTo(60))
		Expect(container.StartupProbe.FailureThreshold).To(BeEquivalentTo(10))

		Expect(container.SecurityContext).To(BeNil())
	})

	It("should render with S3 configuration", func() {
		cfg.S3Credential = &logcollector.S3Credential{
			KeyId:     []byte("IdForTheKey"),
			KeySecret: []byte("SecretForTheKey"),
		}
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			S3: &operatorv1.S3StoreSpec{
				Region:     "anyplace",
				BucketName: "thebucket",
				BucketPath: "bucketpath",
			},
		}

		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsService, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "log-collector-s3-credentials", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
		}

		// Should render the correct resources.
		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)
		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/s3-credentials"))

		// S3 credential env vars are still set for the container to consume.
		envs := ds.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "AWS_ACCESS_KEY_ID",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "log-collector-s3-credentials"},
					Key:                  "key-id",
				},
			},
		}))
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "AWS_SECRET_ACCESS_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "log-collector-s3-credentials"},
					Key:                  "key-secret",
				},
			},
		}))

		// S3 output configuration is now in the ConfigMap.
		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		Expect(cm.Data).To(HaveKey("fluent-bit.yaml"))
		fluentBitConf := cm.Data["fluent-bit.yaml"]
		Expect(fluentBitConf).To(ContainSubstring("s3"))
		Expect(fluentBitConf).To(ContainSubstring("thebucket"))
		Expect(fluentBitConf).To(ContainSubstring("anyplace"))
		Expect(fluentBitConf).To(ContainSubstring("bucketpath"))
	})

	It("should render with Syslog configuration", func() {
		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsService, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
		}

		var ps int32 = 180
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				Endpoint:   "tcp://1.2.3.4:80",
				PacketSize: &ps,
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogDNS,
					operatorv1.SyslogLogFlows,
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)
		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(4))

		// Syslog configuration is now in the ConfigMap.
		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		Expect(cm.Data).To(HaveKey("fluent-bit.yaml"))
		fluentBitConf := cm.Data["fluent-bit.yaml"]
		Expect(fluentBitConf).To(ContainSubstring("syslog"))
		Expect(fluentBitConf).To(ContainSubstring("1.2.3.4"))
		Expect(fluentBitConf).To(ContainSubstring("80"))
	})

	It("should render with Syslog configuration with TLS and user's corporate CA", func() {
		cfg.UseSyslogCertificate = true
		var ps int32 = 180
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				Endpoint:   "tcp://1.2.3.4:80",
				Encryption: operatorv1.EncryptionTLS,
				PacketSize: &ps,
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogDNS,
					operatorv1.SyslogLogFlows,
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		resources, _ := component.Objects()

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(4))

		var volnames []string
		for _, vol := range ds.Spec.Template.Spec.Volumes {
			volnames = append(volnames, vol.Name)
		}
		Expect(volnames).To(ContainElement("calico-fluent-bit-ca-bundle-system-certs"))

		// Syslog TLS configuration is in the ConfigMap.
		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		fluentBitConf := cm.Data["fluent-bit.yaml"]
		Expect(fluentBitConf).To(ContainSubstring("syslog"))
		Expect(fluentBitConf).To(ContainSubstring("1.2.3.4"))
		Expect(fluentBitConf).To(ContainSubstring("tls"))
	})

	It("should render with Syslog configuration with TLS and Internet CA", func() {
		cfg.UseSyslogCertificate = false
		var ps int32 = 180
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				Endpoint:   "tcp://1.2.3.4:80",
				Encryption: operatorv1.EncryptionTLS,
				PacketSize: &ps,
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogDNS,
					operatorv1.SyslogLogFlows,
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		resources, _ := component.Objects()

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(4))

		// Syslog TLS configuration is in the ConfigMap.
		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		fluentBitConf := cm.Data["fluent-bit.yaml"]
		Expect(fluentBitConf).To(ContainSubstring("syslog"))
		Expect(fluentBitConf).To(ContainSubstring("1.2.3.4"))
		Expect(fluentBitConf).To(ContainSubstring("tls"))
	})

	It("should render with splunk configuration", func() {
		cfg.SplkCredential = &logcollector.SplunkCredential{
			Token: []byte("TokenForHEC"),
		}
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Splunk: &operatorv1.SplunkStoreSpec{
				Endpoint: "https://1.2.3.4:8088",
			},
		}

		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsService, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "logcollector-splunk-credentials", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
		}

		// Should render the correct resources.
		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)
		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(4))

		// Splunk HEC token credential env var is still set.
		envs := ds.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "SPLUNK_HEC_TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "logcollector-splunk-credentials"},
					Key:                  "token",
				},
			},
		}))

		// Splunk output configuration is now in the ConfigMap.
		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		Expect(cm.Data).To(HaveKey("fluent-bit.yaml"))
		fluentBitConf := cm.Data["fluent-bit.yaml"]
		Expect(fluentBitConf).To(ContainSubstring("splunk"))
		Expect(fluentBitConf).To(ContainSubstring("1.2.3.4"))
		Expect(fluentBitConf).To(ContainSubstring("8088"))
	})

	It("should honor hostScope and preserve legacy store semantics for the additional stores", func() {
		// Parses the rendered config and returns the match tags per output
		// plugin, plus the raw output maps for property assertions.
		renderOutputs := func() map[string][]map[string]interface{} {
			resources, _ := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux).Objects()
			cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
			var conf struct {
				Pipeline struct {
					Outputs []map[string]interface{} `json:"outputs"`
				} `json:"pipeline"`
			}
			Expect(json.Unmarshal([]byte(cm.Data["fluent-bit.yaml"]), &conf)).NotTo(HaveOccurred())
			byName := map[string][]map[string]interface{}{}
			for _, out := range conf.Pipeline.Outputs {
				name := out["name"].(string)
				byName[name] = append(byName[name], out)
			}
			return byName
		}
		matchTags := func(outs []map[string]interface{}) []string {
			var tags []string
			for _, out := range outs {
				tags = append(tags, out["match"].(string))
			}
			return tags
		}

		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			S3: &operatorv1.S3StoreSpec{Region: "anyplace", BucketName: "thebucket", BucketPath: "bucketpath"},
			Syslog: &operatorv1.SyslogStoreSpec{
				Endpoint: "tcp://1.2.3.4:80",
				LogTypes: []operatorv1.SyslogLogType{operatorv1.SyslogLogFlows, operatorv1.SyslogLogDNS},
			},
			Splunk: &operatorv1.SplunkStoreSpec{Endpoint: "https://1.2.3.4:8088"},
		}

		// Default (hostScope All): cluster logs plus non-cluster flows.
		byName := renderOutputs()

		// S3 archives the fluentd set — never WAF, BGP, IDS events or policy
		// activity — and non-cluster flows ship alongside cluster logs.
		Expect(matchTags(byName["s3"])).To(ConsistOf(
			"flows", "dns", "l7", "runtime", "audit.tsee", "audit.kube", "compliance.reports", "non_cluster_flows"))
		for _, out := range byName["s3"] {
			// Legacy archives were gzipped (fluent-plugin-s3 default store_as).
			Expect(out).To(HaveKeyWithValue("compression", "gzip"), "s3 output %v", out["match"])
		}
		// The S3 keys use a directory per log type — a deliberate,
		// release-noted layout change from fluentd's flat
		// `<path>/flows20260101_<n>.gz` keys (see addS3Outputs); non-cluster
		// flows get their own directory, and the object suffix is $UUID
		// (out_s3's index is not restart-safe).
		for _, out := range byName["s3"] {
			switch out["match"] {
			case "audit.tsee":
				Expect(out["s3_key_format"]).To(Equal("bucketpath/audit_tsee/%Y%m%d_$UUID.gz"))
			case "non_cluster_flows":
				Expect(out["s3_key_format"]).To(Equal("bucketpath/non_cluster_flows/%Y%m%d_$UUID.gz"))
			}
		}

		Expect(matchTags(byName["syslog"])).To(ConsistOf("flows", "non_cluster_flows", "dns"))
		for _, out := range byName["syslog"] {
			// syslog_severity_preset is an integer property; rendering "info"
			// would atoi to 0/Emergency. The default (6) already is info.
			Expect(out).NotTo(HaveKey("syslog_severity_preset"))
			// Node-name fallback for tags whose records carry no host key.
			Expect(out).To(HaveKeyWithValue("syslog_hostname_preset", "${NODENAME}"))
		}

		// No l7: deployed fluentd never enabled SPLUNK_L7_LOG, so adding it
		// would be a new data flow to customer HEC endpoints, not parity.
		Expect(matchTags(byName["splunk"])).To(ConsistOf(
			"flows", "dns", "audit.tsee", "audit.kube", "non_cluster_flows"))

		// NonClusterOnly: cluster *flows* are the only type the scope gates —
		// the other cluster types keep shipping, and non-cluster flows always do.
		nonClusterOnly := operatorv1.HostScopeNonClusterOnly
		cfg.LogCollector.Spec.AdditionalStores.S3.HostScope = &nonClusterOnly
		cfg.LogCollector.Spec.AdditionalStores.Syslog.HostScope = &nonClusterOnly
		cfg.LogCollector.Spec.AdditionalStores.Splunk.HostScope = &nonClusterOnly
		byName = renderOutputs()
		Expect(matchTags(byName["s3"])).To(ConsistOf(
			"dns", "l7", "runtime", "audit.tsee", "audit.kube", "compliance.reports", "non_cluster_flows"))
		Expect(matchTags(byName["syslog"])).To(ConsistOf("non_cluster_flows", "dns"))
		Expect(matchTags(byName["splunk"])).To(ConsistOf(
			"dns", "audit.tsee", "audit.kube", "non_cluster_flows"))
	})

	It("should render with filter", func() {
		cfg.Filters = &logcollector.FluentBitFilters{
			Flow: "- name: grep\n  exclude: dest_namespace noisy\n",
		}

		expectedResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsService, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
		}

		// Should render the correct resources.
		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)

		rtest.ExpectResources(resources, expectedResources)

		// User filters are inlined into the rendered config, scoped to the log
		// type's tag, and roll the pods via the config hash annotation.
		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, "calico-system", "", "v1", "ConfigMap").(*corev1.ConfigMap)
		conf := cm.Data["fluent-bit.yaml"]
		Expect(conf).To(ContainSubstring(`"name": "grep"`))
		Expect(conf).To(ContainSubstring(`"exclude": "dest_namespace noisy"`))
		Expect(conf).To(ContainSubstring(`"match": "flows"`))

		ds := rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/fluent-bit-config"))
	})

	It("flags filter ConfigMap keys that are not valid fluent-bit YAML", func() {
		var nilFilters *logcollector.FluentBitFilters
		Expect(nilFilters.InvalidKeys()).To(BeNil())

		Expect((&logcollector.FluentBitFilters{}).InvalidKeys()).To(BeEmpty())

		valid := &logcollector.FluentBitFilters{
			Flow: "- name: grep\n  exclude: dest_namespace noisy\n",
			DNS:  "- name: grep\n  exclude: qname foo\n",
		}
		Expect(valid.InvalidKeys()).To(BeEmpty())

		// A leftover fluentd <filter> block does not parse as a fluent-bit YAML list.
		mixed := &logcollector.FluentBitFilters{
			Flow: "<filter flows>\n  @type grep\n</filter>\n",
			DNS:  "- name: grep\n  exclude: qname foo\n",
		}
		Expect(mixed.InvalidKeys()).To(ConsistOf(logcollector.FluentBitFilterFlowName))
	})

	It("skips invalid user filter content during render and still renders the daemonset", func() {
		cfg.Filters = &logcollector.FluentBitFilters{
			Flow: "<filter flows>\n  @type grep\n</filter>\n", // invalid fluent-bit YAML (fluentd syntax)
			DNS:  "- name: grep\n  exclude: qname foo\n",      // valid
		}

		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		resources, _ := component.Objects()

		cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, "calico-system", "", "v1", "ConfigMap").(*corev1.ConfigMap)
		conf := cm.Data["fluent-bit.yaml"]
		// The valid DNS filter is inlined and scoped to its tag.
		Expect(conf).To(ContainSubstring(`"exclude": "qname foo"`))
		Expect(conf).To(ContainSubstring(`"match": "dns"`))
		// The invalid fluentd-syntax flow filter is dropped, not inlined.
		Expect(conf).NotTo(ContainSubstring("@type"))
		// The daemonset still renders despite the bad filter.
		Expect(rtest.GetResource(resources, "calico-fluent-bit", "calico-system", "apps", "v1", "DaemonSet")).NotTo(BeNil())
	})

	It("should render with EKS Cloudwatch Log", func() {
		expectedResources := getExpectedResourcesForEKS(false)
		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider:      operatorv1.ProviderEKS,
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		rtest.ExpectResources(resources, expectedResources)
		deploy := rtest.GetResource(resources, "eks-log-forwarder", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)

		// The fluentd-era startup init container is gone: the in_eks input
		// plugin resolves its own resume point from Linseed on every start.
		Expect(deploy.Spec.Template.Spec.InitContainers).To(BeEmpty())
		Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/eks-cloudwatch-log-credentials"))
		Expect(deploy.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/fluent-bit-config"))
		Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElement(t))

		Expect(deploy.Spec.Template.Spec.Containers[0].Command).To(Equal([]string{"/usr/bin/fluent-bit"}))
		Expect(deploy.Spec.Template.Spec.Containers[0].Args).To(Equal([]string{"-c", "/etc/fluent-bit/fluent-bit.yaml"}))

		envs := deploy.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "AWS_REGION", Value: cfg.EKSConfig.AwsRegion}))

		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		expectedEnvVars := []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "info", ValueFrom: nil},
			{Name: "EKS_CLOUDWATCH_LOG_GROUP", Value: "dummy-eks-cluster-cloudwatch-log-group"},
			{Name: "AWS_REGION", Value: "us-west-1", ValueFrom: nil},
			{
				Name: "AWS_ACCESS_KEY_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-eks-log-forwarder-secret",
						},
						Key: "aws-id",
					},
				},
			},
			{
				Name: "AWS_SECRET_ACCESS_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-eks-log-forwarder-secret",
						},
						Key:      "aws-key",
						Optional: nil,
					},
				},
			},
			{Name: "LINSEED_ENDPOINT", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			{Name: "LINSEED_CA_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "TLS_CRT_PATH", Value: "/tigera-eks-log-forwarder-tls/tls.crt"},
			{Name: "TLS_KEY_PATH", Value: "/tigera-eks-log-forwarder-tls/tls.key"},
			{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
			// streamPrefix is unset in this render config (the controller
			// would have defaulted it), so the env var is omitted and the
			// plugin's kube-apiserver-audit- default applies; fetchInterval
			// is set (900) so it is rendered.
			{Name: "EKS_CLOUDWATCH_POLL_INTERVAL", Value: "900s"},
		}

		Expect(envs).To(Equal(expectedEnvVars))

		// The rendered config wires the in_eks input into the Linseed http
		// output.
		cm := rtest.GetResource(resources, logcollector.EKSLogForwarderConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		eksConf := cm.Data["fluent-bit.yaml"]
		Expect(eksConf).To(ContainSubstring(`"name": "in_eks"`))
		Expect(eksConf).To(ContainSubstring(`"plugins_file": "/etc/fluent-bit/plugins.conf"`))
		Expect(eksConf).To(ContainSubstring(`"name": "http"`))
		Expect(eksConf).To(ContainSubstring(`"uri": "/api/v1/audit/logs/kube/bulk"`))
		Expect(eksConf).To(ContainSubstring(`"tls.verify_hostname": "on"`))
	})

	It("should omit unset EKS CloudWatch settings so plugin defaults apply", func() {
		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		cfg.EKSConfig.FetchInterval = 0
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderEKS,
		}

		resources, _ := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux).Objects()
		deploy := rtest.GetResource(resources, "eks-log-forwarder", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		// The controller defaults these before render in production; this
		// pins the render-level defense in depth — an empty prefix or "0s"
		// interval must never reach the plugin, which would override its
		// envconfig defaults with broken settings.
		for _, env := range deploy.Spec.Template.Spec.Containers[0].Env {
			Expect(env.Name).NotTo(Equal("EKS_CLOUDWATCH_LOG_STREAM_PREFIX"))
			Expect(env.Name).NotTo(Equal("EKS_CLOUDWATCH_POLL_INTERVAL"))
		}
	})

	It("should render EKS Cloudwatch Log toleration on GKE", func() {
		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		resources, _ := component.Objects()
		deploy := rtest.GetResource(resources, "eks-log-forwarder", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deploy).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
	})

	It("should render with EKS Cloudwatch Log with resources", func() {
		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderEKS,
		}

		eksResources := corev1.ResourceRequirements{
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

		logCollectorcfg := operatorv1.LogCollector{
			Spec: operatorv1.LogCollectorSpec{
				EKSLogForwarderDeployment: &operatorv1.EKSLogForwarderDeployment{
					Spec: &operatorv1.EKSLogForwarderDeploymentSpec{
						Template: &operatorv1.EKSLogForwarderDeploymentPodTemplateSpec{
							Spec: &operatorv1.EKSLogForwarderDeploymentPodSpec{
								Containers: []operatorv1.EKSLogForwarderDeploymentContainer{{
									Name:      "eks-log-forwarder",
									Resources: &eksResources,
								}},
							},
						},
					},
				},
			},
		}

		cfg.LogCollector = &logCollectorcfg
		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		resources, _ := component.Objects()
		deploy := rtest.GetResource(resources, "eks-log-forwarder", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
		container := test.GetContainer(deploy.Spec.Template.Spec.Containers, "eks-log-forwarder")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(eksResources))

		Expect(deploy.Spec.Template.Spec.InitContainers).To(BeEmpty())
	})

	It("should render with EKS Cloudwatch Log with multi tenant envvars", func() {
		expectedResources := getExpectedResourcesForEKS(false)
		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider:      operatorv1.ProviderEKS,
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		cfg.ExternalElastic = true

		// Create the Tenant object.
		tenant := &operatorv1.Tenant{}
		tenant.Name = "default"
		tenant.Namespace = "tenant-namespace"
		tenant.Spec.ID = "test-tenant-id"
		cfg.Tenant = tenant

		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		rtest.ExpectResources(resources, expectedResources)

		deploy := rtest.GetResource(resources, "eks-log-forwarder", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		envs := deploy.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_ENDPOINT", Value: "https://tigera-linseed.tenant-namespace.svc"}))
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "test-tenant-id"}))
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"}))

		// The tenant header rides on the http output config.
		cm := rtest.GetResource(resources, logcollector.EKSLogForwarderConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		Expect(cm.Data["fluent-bit.yaml"]).To(ContainSubstring(`"header": "x-tenant-id test-tenant-id"`))
	})

	It("should render with EKS Cloudwatch Log for managed cluster with linseed token volume", func() {
		expectedResources := getExpectedResourcesForEKS(true)

		expectedResources = append(expectedResources,
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}})

		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider:      operatorv1.ProviderEKS,
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		cfg.ManagedCluster = true
		resources, _ := renderAll(cfg, rmeta.OSTypeLinux)
		Expect(len(resources)).To(Equal(len(expectedResources)))

		rtest.ExpectResources(resources, expectedResources)

		deploy := rtest.GetResource(resources, "eks-log-forwarder", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		envs := deploy.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/tigera.io/linseed/token"}))

		// The container mounts the operator-provisioned token for both the
		// in_eks resume-point query and the http output's bearer_token_file,
		// which re-reads it on every request.
		volumeMounts := deploy.Spec.Template.Spec.Containers[0].VolumeMounts
		Expect(volumeMounts).To(ContainElement(corev1.VolumeMount{Name: "linseed-token", MountPath: "/var/run/secrets/tigera.io/linseed/"}))

		cm := rtest.GetResource(resources, logcollector.EKSLogForwarderConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		Expect(cm.Data["fluent-bit.yaml"]).To(ContainSubstring(`"bearer_token_file": "/var/run/secrets/tigera.io/linseed/token"`))
	})

	DescribeTable("should render with a valid configuration for non-cluster host and forwarding enabled",
		func(destination string) {
			additionalStoreSpecAllHosts := additionalStoreSpecForDestinationAndScope(destination, operatorv1.HostScopeAll)
			additionalStoreSpecNonClusterHosts := additionalStoreSpecForDestinationAndScope(destination, operatorv1.HostScopeNonClusterOnly)

			By("establishing the base case with no non-cluster hosts or forwarding options")
			expectedResources := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsService, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
			}

			resources, _ := renderAll(cfg, rmeta.OSTypeLinux)
			rtest.ExpectResources(resources, expectedResources)

			// Base case: no additional store outputs in ConfigMap besides linseed.
			cm := rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
			baseConf := cm.Data["fluent-bit.yaml"]
			Expect(baseConf).To(ContainSubstring("linseed"))
			Expect(baseConf).NotTo(ContainSubstring(strings.ToLower(destination)))

			By("enabling non-cluster hosts and forwarding from all hosts")
			cfg.NonClusterHost = &operatorv1.NonClusterHost{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.NonClusterHostSpec{
					Endpoint: "https://1.2.3.4:5678",
				},
			}
			cfg.LogCollector.Spec.AdditionalStores = additionalStoreSpecAllHosts
			expectedResources = append(expectedResources, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.FluentBitInputService, Namespace: render.LogCollectorNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}})

			// Should render the correct resources.
			resources, _ = renderAll(cfg, rmeta.OSTypeLinux)
			rtest.ExpectResources(resources, expectedResources)

			// Service is rendered as expected.
			ms := rtest.GetResource(resources, render.FluentBitInputService, render.LogCollectorNamespace, "", "v1", "Service").(*corev1.Service)
			Expect(ms.Spec.Selector).To(Equal(map[string]string{"k8s-app": render.FluentBitNodeName}))
			Expect(ms.Spec.Ports).To(HaveLen(1))
			Expect(ms.Spec.Ports[0].Port).To(BeNumerically("==", logcollector.FluentBitInputPort))
			Expect(ms.Spec.Ports[0].TargetPort).To(Equal(intstr.FromInt32(logcollector.FluentBitInputPort)))
			Expect(ms.Spec.Ports[0].Protocol).To(Equal(corev1.ProtocolTCP))

			// ConfigMap should contain the destination output section (all hosts scope).
			cm = rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
			allHostsConf := cm.Data["fluent-bit.yaml"]
			Expect(allHostsConf).To(ContainSubstring(strings.ToLower(destination)))

			// The voltron-relayed non-cluster host tags each get their own http
			// output posting to the base tag's bulk URI; a tag without a
			// matching output would be silently dropped by the router.
			Expect(allHostsConf).To(ContainSubstring(`"match": "non_cluster_flows"`))
			Expect(allHostsConf).To(ContainSubstring(`"match": "non_cluster_dns"`))
			Expect(allHostsConf).To(ContainSubstring(`"match": "non_cluster_policy_activity"`))
			Expect(allHostsConf).To(ContainSubstring(`"uri": "/api/v1/policy_activity/logs/bulk"`))

			// The :9880 input accepts relayed batches up to fluentd's old
			// body_size_limit; in_http's ~4M default would silently reject
			// larger posts.
			Expect(allHostsConf).To(ContainSubstring(`"buffer_chunk_size": "5M"`))
			Expect(allHostsConf).To(ContainSubstring(`"buffer_max_size": "100M"`))

			By("enabling forwarding of only non-cluster logs")
			cfg.LogCollector.Spec.AdditionalStores = additionalStoreSpecNonClusterHosts
			resources, _ = renderAll(cfg, rmeta.OSTypeLinux)
			rtest.ExpectResources(resources, expectedResources)

			// ConfigMap should still contain the destination output section (non-cluster scope).
			cm = rtest.GetResource(resources, logcollector.FluentBitConfConfigMapName, render.LogCollectorNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
			nonClusterConf := cm.Data["fluent-bit.yaml"]
			Expect(nonClusterConf).To(ContainSubstring(strings.ToLower(destination)))
		},
		Entry("S3", "S3"),
		Entry("Syslog", "Syslog"),
		Entry("Splunk", "Splunk"))

	Context("calico-system rendering", func() {
		policyName := types.NamespacedName{Name: "calico-system.allow-calico-fluent-bit", Namespace: "calico-system"}

		getExpectedPolicy := func(scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
			if scenario.ManagedCluster {
				return expectedFluentBitPolicyForManaged
			} else {
				return testutils.SelectPolicyByProvider(scenario, expectedFluentBitPolicyForUnmanaged, expectedFluentBitPolicyForUnmanagedOpenshift)
			}
		}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				if scenario.OpenShift {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
				} else {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
				}
				cfg.ManagedCluster = scenario.ManagedCluster

				resources, _ := logcollector.FluentBitShared(cfg).Objects()

				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
		)

		It("should render calico-system policy for the non-cluster-host scenario", func() {
			resourcesWithoutNonClusterHosts, _ := logcollector.FluentBitShared(cfg).Objects()
			policyWithoutNonClusterHosts := testutils.GetCalicoSystemPolicyFromResources(policyName, resourcesWithoutNonClusterHosts)
			cfg.NonClusterHost = &operatorv1.NonClusterHost{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.NonClusterHostSpec{
					Endpoint: "https://1.2.3.4:5678",
				},
			}
			resourcesWithNonClusterHosts, _ := logcollector.FluentBitShared(cfg).Objects()
			policyWithNonClusterHosts := testutils.GetCalicoSystemPolicyFromResources(policyName, resourcesWithNonClusterHosts)

			// Validate that we have a single ingress rule added for the fluent-bit service.
			Expect(policyWithoutNonClusterHosts.Spec.Egress).To(Equal(policyWithNonClusterHosts.Spec.Egress))
			Expect(len(policyWithoutNonClusterHosts.Spec.Ingress)).To(Equal(len(policyWithNonClusterHosts.Spec.Ingress) - 1))
			Expect(len(policyWithNonClusterHosts.Spec.Ingress)).To(Equal(2))
			Expect(policyWithNonClusterHosts.Spec.Ingress[1]).To(Equal(v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Source: v3.EntityRule{
					Selector:          fmt.Sprintf("k8s-app == '%s'", render.ManagerDeploymentName),
					NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", render.ManagerNamespace),
				},
				Destination: v3.EntityRule{
					Ports: networkpolicy.Ports(logcollector.FluentBitInputPort),
				},
			}))
		})
	})

	It("should move DaemonSet to toDelete when LicenseExpired is true", func() {
		cfg.LicenseExpired = true
		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		Expect(component.ResolveImages(nil)).To(BeNil())
		toCreate, toDelete := component.Objects()

		// DaemonSet should not be in toCreate.
		for _, obj := range toCreate {
			if ds, ok := obj.(*appsv1.DaemonSet); ok {
				Fail("DaemonSet should not be in toCreate when license is expired, but found: " + ds.Name)
			}
		}

		// DaemonSet should be in toDelete.
		found := false
		for _, obj := range toDelete {
			if ds, ok := obj.(*appsv1.DaemonSet); ok && ds.Name == "calico-fluent-bit" {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(), "Expected fluent-bit-node DaemonSet to be in toDelete")
	})

	It("should include DaemonSet in toCreate when LicenseExpired is false", func() {
		cfg.LicenseExpired = false
		component := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
		Expect(component.ResolveImages(nil)).To(BeNil())
		toCreate, _ := component.Objects()

		found := false
		for _, obj := range toCreate {
			if ds, ok := obj.(*appsv1.DaemonSet); ok && ds.Name == "calico-fluent-bit" {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(), "Expected fluent-bit-node DaemonSet to be in toCreate")
	})

	Context("shared component", func() {
		// The shared component renders the resources both OS installations
		// depend on, exactly once, so the per-OS components cannot contend
		// over them.
		It("should render only the NetworkPolicy plus the legacy cleanup by default", func() {
			createResources, deleteResources := logcollector.FluentBitShared(cfg).Objects()
			rtest.ExpectResources(createResources, []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}},
			})
			// Unmanaged: the managed-cluster Linseed plumbing is cleaned up,
			// alongside the legacy fluentd installation.
			rtest.ExpectResources(deleteResources, append([]client.Object{
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}},
			}, legacyFluentdDeleteResources()...))
		})

		It("should render the gated shared resources when configured", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
			cfg.ManagedCluster = true
			cfg.S3Credential = &logcollector.S3Credential{KeyId: []byte("id"), KeySecret: []byte("secret")}
			cfg.SplkCredential = &logcollector.SplunkCredential{Token: []byte("token")}

			createResources, deleteResources := logcollector.FluentBitShared(cfg).Objects()
			rtest.ExpectResources(createResources, []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace}},
				&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: resourcequota.TigeraCriticalResourceQuotaName, Namespace: render.LogCollectorNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: logcollector.S3FluentBitSecretName, Namespace: render.LogCollectorNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: logcollector.SplunkFluentBitTokenSecretName, Namespace: render.LogCollectorNamespace}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}},
			})
			rtest.ExpectResources(deleteResources, legacyFluentdDeleteResources())
		})

		It("should produce disjoint resources across the shared, Linux and Windows components", func() {
			// The controller renders all three from one configuration. Turn on
			// every gated feature so each component emits its full resource set,
			// then assert no two components create the same object — the property
			// that lets them share a single config without contending.
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
			cfg.ManagedCluster = true
			cfg.S3Credential = &logcollector.S3Credential{KeyId: []byte("id"), KeySecret: []byte("secret")}
			cfg.SplkCredential = &logcollector.SplunkCredential{Token: []byte("token")}
			cfg.NonClusterHost = &operatorv1.NonClusterHost{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec:       operatorv1.NonClusterHostSpec{Endpoint: "https://1.2.3.4:5678"},
			}

			shared := logcollector.FluentBitShared(cfg)
			linux := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeLinux)
			windows := logcollector.FluentBitOSSpecific(cfg, rmeta.OSTypeWindows)
			Expect(linux.ResolveImages(nil)).To(BeNil())
			Expect(windows.ResolveImages(nil)).To(BeNil())

			// Key on the Go type plus namespace/name: robust even when a
			// rendered object leaves TypeMeta unset, and still distinguishes
			// e.g. Role from ClusterRole (distinct Go types).
			key := func(o client.Object) string {
				return fmt.Sprintf("%T/%s/%s", o, o.GetNamespace(), o.GetName())
			}
			seen := map[string]string{}
			for name, comp := range map[string]render.Component{"shared": shared, "linux": linux, "windows": windows} {
				create, _ := comp.Objects()
				for _, o := range create {
					k := key(o)
					if prev, dup := seen[k]; dup {
						Fail(fmt.Sprintf("resource %s created by both %q and %q components", k, prev, name))
					}
					seen[k] = name
				}
			}
		})
	})
})

func setupEKSCloudwatchLogConfig() *logcollector.EksCloudwatchLogConfig {
	fetchInterval := int32(900)
	return &logcollector.EksCloudwatchLogConfig{
		AwsId:         []byte("aws-id"),
		AwsKey:        []byte("aws-key"),
		AwsRegion:     "us-west-1",
		GroupName:     "dummy-eks-cluster-cloudwatch-log-group",
		FetchInterval: fetchInterval,
	}
}

func getExpectedResourcesForEKS(isManagedcluster bool) []client.Object {
	expectedResources := []client.Object{
		&v3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace},
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		},

		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitMetricsService, Namespace: render.LogCollectorNamespace}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder", Namespace: "calico-system"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: "calico-system"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: logcollector.EKSLogForwarderConfConfigMapName, Namespace: render.LogCollectorNamespace}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder", Namespace: render.LogCollectorNamespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-eks-log-forwarder-secret", Namespace: render.LogCollectorNamespace}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit", Namespace: render.LogCollectorNamespace}},
	}

	if isManagedcluster {
		expectedResources = append(expectedResources,
			&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}})
	}
	return expectedResources
}

func additionalStoreSpecForDestinationAndScope(destination string, scope operatorv1.HostScope) *operatorv1.AdditionalLogStoreSpec {
	var spec operatorv1.AdditionalLogStoreSpec
	switch destination {
	case "S3":
		spec.S3 = &operatorv1.S3StoreSpec{
			Region:     "anyplace",
			BucketName: "thebucket",
			BucketPath: "bucketpath",
			HostScope:  &scope,
		}
	case "Syslog":
		var ps int32 = 180
		spec.Syslog = &operatorv1.SyslogStoreSpec{
			Endpoint:   "tcp://1.2.3.4:80",
			PacketSize: &ps,
			LogTypes: []operatorv1.SyslogLogType{
				operatorv1.SyslogLogDNS,
				operatorv1.SyslogLogFlows,
				operatorv1.SyslogLogIDSEvents,
			},
			HostScope: &scope,
		}
	case "Splunk":
		spec.Splunk = &operatorv1.SplunkStoreSpec{
			Endpoint:  "https://1.2.3.4:8088",
			HostScope: &scope,
		}
	}

	return &spec
}

// renderAll renders the shared and per-OS fluent-bit components together —
// the way the controller composes them — returning the merged create and
// delete lists.
func renderAll(cfg *logcollector.FluentBitConfiguration, osType rmeta.OSType) ([]client.Object, []client.Object) {
	component := logcollector.FluentBitOSSpecific(cfg, osType)
	Expect(component.ResolveImages(nil)).To(BeNil())
	sharedCreate, sharedDelete := logcollector.FluentBitShared(cfg).Objects()
	create, del := component.Objects()
	return append(sharedCreate, create...), append(sharedDelete, del...)
}

// legacyFluentdDeleteResources is the legacy-fluentd cleanup the shared
// component renders: the tigera-fluentd Namespace (cascade-deletes everything
// namespaced in it), the cluster-scoped fluentd RBAC and the operator-namespace
// copy of the fluentd certificate.
func legacyFluentdDeleteResources() []client.Object {
	return []client.Object{
		&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd-windows"}},
		&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd-windows"}},
		&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd-prometheus-tls", Namespace: common.OperatorNamespace()}},
	}
}
