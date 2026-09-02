// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package monitor_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sresource "k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/enterprise/render/monitor"
	"github.com/projectcalico/calico/operator/pkg/render"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/testutils"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("monitor rendering tests", func() {
	defaultAlertmanagerConfigSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.AlertmanagerConfigSecret,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string][]byte{
			"alertmanager.yaml": []byte("Alertmanager configuration secret"),
		},
	}
	expectedAlertmanagerPolicy := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/alertmanager.json")
	expectedAlertmanagerMeshPolicy := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/alertmanager-mesh.json")
	expectedPrometheusPolicy := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/prometheus.json")
	expectedPrometheusApiPolicy := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/prometheus-api.json")
	expectedPrometheusOperatorPolicy := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/prometheus-operator.json")
	expectedAlertmanagerPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/alertmanager_ocp.json")
	expectedAlertmanagerMeshPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/alertmanager-mesh_ocp.json")
	expectedPrometheusPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/prometheus_ocp.json")
	expectedPrometheusApiPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/prometheus-api_ocp.json")
	expectedPrometheusOperatorPolicyOpenshift := testutils.GetExpectedPolicyFromFile("../../../render/testutils/expected_policies/prometheus-operator_ocp.json")

	var cfg *monitor.Config
	var prometheusKeyPair certificatemanagement.KeyPairInterface

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		prometheusKeyPair, err = certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())

		prometheusClientKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())

		bundle := certificateManager.CreateTrustedBundle()
		cfg = &monitor.Config{
			Installation: &operatorv1.InstallationSpec{
				ControlPlaneReplicas: ptr.To(int32(3)),
			},
			Monitor: operatorv1.MonitorSpec{
				Alertmanager: &operatorv1.Alertmanager{
					AlertmanagerSpec: &operatorv1.AlertmanagerSpec{
						Replicas: ptr.To(int32(3)),
					},
				},
			},
			PullSecrets: []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
			},
			ServerTLSSecret:          prometheusKeyPair,
			ClientTLSSecret:          prometheusClientKeyPair,
			AlertmanagerConfigSecret: defaultAlertmanagerConfigSecret,
			ClusterDomain:            "example.org",
			TrustedCertBundle:        bundle,
		}
	})

	It("Should create the OpenTelemetry collector ServiceMonitor only while OTel is enabled", func() {
		// The ServiceMonitor selects a Service that only exists while the collector
		// does, so it has to track the collector rather than being rendered
		// unconditionally — otherwise disabling OTel leaves it behind.
		cfg.OpenTelemetryEnabled = false
		toCreate, toDelete := monitor.Monitor(cfg).Objects()
		Expect(rtest.GetResource(toCreate, render.OpenTelemetryCollectorName, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind)).To(BeNil())
		Expect(rtest.GetResource(toDelete, render.OpenTelemetryCollectorName, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind)).NotTo(BeNil())

		cfg.OpenTelemetryEnabled = true
		toCreate, toDelete = monitor.Monitor(cfg).Objects()
		sm, ok := rtest.GetResource(toCreate, render.OpenTelemetryCollectorName, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(sm.Spec.NamespaceSelector.MatchNames).To(ConsistOf(render.OpenTelemetryCollectorNamespace))
		Expect(sm.Spec.Endpoints).To(HaveLen(1))
		Expect(sm.Spec.Endpoints[0].Port).To(Equal(render.OpenTelemetryCollectorMetricsPort))
		Expect(rtest.GetResource(toDelete, render.OpenTelemetryCollectorName, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind)).To(BeNil())
	})

	It("Should let Prometheus reach the collector whenever it renders the ServiceMonitor", func() {
		// Both must appear together, or the scrape is blocked and reports up=0.
		otelEgress := func() []v3.Rule {
			toCreate, _ := monitor.MonitorPolicy(cfg).Objects()
			policy := rtest.GetResource(toCreate, monitor.PrometheusPolicyName, common.TigeraPrometheusNamespace, "projectcalico.org", "v3", "NetworkPolicy").(*v3.NetworkPolicy)
			matched := []v3.Rule{}
			for _, r := range policy.Spec.Egress {
				if svc := r.Destination.Services; svc != nil && svc.Name == render.OpenTelemetryCollectorName {
					matched = append(matched, r)
				}
			}
			return matched
		}

		cfg.OpenTelemetryEnabled = false
		Expect(otelEgress()).To(BeEmpty())

		cfg.OpenTelemetryEnabled = true
		rules := otelEgress()
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].Action).To(Equal(v3.Allow))
		Expect(rules[0].Destination.Services.Namespace).To(Equal(render.OpenTelemetryCollectorNamespace))
	})

	It("Should render Prometheus resources", func() {
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()

		// should render correct resources
		expectedResources := expectedBaseResources()
		rtest.ExpectResources(toCreate, expectedResources)

		Expect(toDelete).To(HaveLen(7))

		// Check the namespace.
		namespace := rtest.GetResource(toCreate, "tigera-prometheus", "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("baseline"))
		Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

		service := rtest.GetResource(toCreate, "prometheus-http-api", "tigera-prometheus", "", "v1", "Service").(*corev1.Service)
		Expect(service.Labels["k8s-app"]).To(Equal("tigera-prometheus"))
	})

	It("Should render Prometheus resources with resources requests and limits", func() {
		prometheusResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    k8sresource.MustParse("1"),
				"memory": k8sresource.MustParse("500Mi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    k8sresource.MustParse("101m"),
				"memory": k8sresource.MustParse("100Mi"),
			},
		}
		alertmanagerResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    k8sresource.MustParse("601m"),
				"memory": k8sresource.MustParse("600Mi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    k8sresource.MustParse("201m"),
				"memory": k8sresource.MustParse("200Mi"),
			},
		}

		cfg.Monitor.Prometheus = &operatorv1.Prometheus{
			PrometheusSpec: &operatorv1.PrometheusSpec{
				CommonPrometheusFields: &operatorv1.CommonPrometheusFields{
					Containers: []operatorv1.PrometheusContainer{
						{
							Name:      "authn-proxy",
							Resources: &prometheusResources,
						},
					},
					Resources: prometheusResources,
				},
			},
		}

		cfg.Monitor.Alertmanager = &operatorv1.Alertmanager{
			AlertmanagerSpec: &operatorv1.AlertmanagerSpec{
				Replicas:  ptr.To(int32(3)),
				Resources: alertmanagerResources,
			},
		}

		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		Expect(toDelete).To(HaveLen(7))

		// Prometheus
		prometheusObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())

		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers).To(HaveLen(1))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].Name).To(Equal("authn-proxy"))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].Resources).To(Equal(prometheusResources))

		Expect(prometheusObj.Spec.CommonPrometheusFields.Resources).To(Equal(prometheusResources))

		// Alertmanager
		alertmanagerObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind).(*monitoringv1.Alertmanager)
		Expect(ok).To(BeTrue())
		Expect(alertmanagerObj.Spec.Resources).To(Equal(alertmanagerResources))
	})

	It("Should render Prometheus resource Specs correctly", func() {
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, _ := component.Objects()

		// Prometheus Operator
		_, ok := rtest.GetResource(toCreate, "calico-prometheus-operator", "tigera-prometheus", "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
		Expect(ok).To(BeTrue())
		promOperClusterRoleObj, ok := rtest.GetResource(toCreate, "calico-prometheus-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(ok).To(BeTrue())
		Expect(promOperClusterRoleObj.Rules).To(HaveLen(10))
		Expect(promOperClusterRoleObj.Rules[0]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{"monitoring.coreos.com"},
			Resources: []string{
				"alertmanagers",
				"alertmanagers/finalizers",
				"alertmanagers/status",
				"alertmanagerconfigs",
				"prometheuses",
				"prometheuses/finalizers",
				"prometheuses/status",
				"prometheusagents",
				"prometheusagents/finalizers",
				"prometheusagents/status",
				"thanosrulers",
				"thanosrulers/finalizers",
				"thanosrulers/status",
				"scrapeconfigs",
				"servicemonitors",
				"podmonitors",
				"probes",
				"prometheusrules",
			},
			Verbs: []string{"*"},
		}))
		Expect(promOperClusterRoleObj.Rules[1]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"statefulsets"},
			Verbs:     []string{"*"},
		}))
		Expect(promOperClusterRoleObj.Rules[2]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{
				"configmaps",
			},
			Verbs: []string{"*"},
		}))
		Expect(promOperClusterRoleObj.Rules[3]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs: []string{
				"delete",
				"list",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[4]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{
				"services",
				"services/finalizers",
				"endpoints",
			},
			Verbs: []string{
				"get",
				"create",
				"update",
				"delete",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[5]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs: []string{
				"list",
				"watch",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[6]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[7]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs: []string{
				"patch",
				"create",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[8]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"ingresses"},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		}))
		Expect(promOperClusterRoleObj.Rules[9]).To(Equal(rbacv1.PolicyRule{
			APIGroups: []string{"storage.k8s.io"},
			Resources: []string{"storageclasses"},
			Verbs: []string{
				"get",
			},
		}))
		promOperClusterRoleBindingObj, ok := rtest.GetResource(toCreate, "calico-prometheus-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(ok).To(BeTrue())
		Expect(promOperClusterRoleBindingObj.Subjects).To(HaveLen(1))
		Expect(promOperClusterRoleBindingObj.Subjects[0]).To(Equal(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      "calico-prometheus-operator",
			Namespace: "tigera-prometheus",
		}))
		Expect(promOperClusterRoleBindingObj.RoleRef).To(Equal(rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-prometheus-operator",
		}))

		// Alertmanager
		alertmanagerObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind).(*monitoringv1.Alertmanager)
		Expect(ok).To(BeTrue())
		alertmanagerCom := components.ComponentPrometheusAlertmanager
		Expect(*alertmanagerObj.Spec.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, alertmanagerCom.Image, alertmanagerCom.Version)))
		Expect(*alertmanagerObj.Spec.Replicas).To(Equal(int32(3)))
		Expect(alertmanagerObj.Spec.Version).To(Equal(components.ComponentCoreOSAlertmanager.Version))
		Expect(*alertmanagerObj.Spec.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*alertmanagerObj.Spec.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*alertmanagerObj.Spec.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(alertmanagerObj.Spec.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// Alertmanager Service
		serviceObj, ok := rtest.GetResource(toCreate, "calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ok).To(BeTrue())
		Expect(serviceObj.Spec.Ports).To(HaveLen(1))
		Expect(serviceObj.Spec.Ports[0].Name).To(Equal("web"))
		Expect(serviceObj.Spec.Ports[0].Port).To(Equal(int32(9093)))
		Expect(serviceObj.Spec.Ports[0].Protocol).To(Equal(corev1.ProtocolTCP))
		Expect(serviceObj.Spec.Ports[0].TargetPort).To(Equal(intstr.FromString("web")))
		Expect(serviceObj.Spec.Selector).To(HaveLen(1))
		Expect(serviceObj.Spec.Selector["alertmanager"]).To(Equal("calico-node-alertmanager"))

		// Alertmanager configuration secret
		secretObj, ok := rtest.GetResource(toCreate, "alertmanager-calico-node-alertmanager", common.TigeraPrometheusNamespace, "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue())
		Expect(secretObj.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager configuration secret")))

		// Prometheus
		prometheusObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())
		prometheusCom := components.ComponentPrometheus
		Expect(*prometheusObj.Spec.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, prometheusCom.Image, prometheusCom.Version)))
		Expect(prometheusObj.Spec.ServiceAccountName).To(Equal("prometheus"))
		Expect(prometheusObj.Spec.ServiceMonitorSelector).To(Equal(&metav1.LabelSelector{}))
		Expect(prometheusObj.Spec.PodMonitorSelector).To(Equal(&metav1.LabelSelector{}))
		Expect(prometheusObj.Spec.Version).To(Equal(components.ComponentCoreOSPrometheus.Version))
		Expect(prometheusObj.Spec.Retention).To(BeEquivalentTo("24h"))
		Expect(prometheusObj.Spec.Resources.Requests.Memory().Equal(k8sresource.MustParse("400Mi"))).To(BeTrue())
		Expect(prometheusObj.Spec.RuleSelector.MatchLabels["prometheus"]).To(Equal("calico-node-prometheus"))
		Expect(prometheusObj.Spec.RuleSelector.MatchLabels["role"]).To(Equal("tigera-prometheus-rules"))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers).To(HaveLen(1))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Name).To(Equal("calico-node-alertmanager"))
		Expect(*prometheusObj.Spec.Alerting.Alertmanagers[0].Namespace).To(Equal("tigera-prometheus"))
		Expect(prometheusObj.Spec.Alerting.Alertmanagers[0].Port).To(Equal(intstr.FromString("web")))
		Expect(*prometheusObj.Spec.Alerting.Alertmanagers[0].RelabelConfigs[0].Replacement).To(Equal("http"))
		Expect(*prometheusObj.Spec.ReloadStrategy).To(BeEquivalentTo(monitoringv1.ProcessSignalReloadStrategyType))
		Expect(*prometheusObj.Spec.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*prometheusObj.Spec.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*prometheusObj.Spec.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(prometheusObj.Spec.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers).To(HaveLen(1))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].Name).To(Equal("authn-proxy"))
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(prometheusObj.Spec.CommonPrometheusFields.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// Prometheus ServiceAccount
		_, ok = rtest.GetResource(toCreate, "prometheus", common.TigeraPrometheusNamespace, "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
		Expect(ok).To(BeTrue())

		// Prometheus ClusterRole
		prometheusClusterRoleObj, ok := rtest.GetResource(toCreate, "prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(ok).To(BeTrue())
		Expect(prometheusClusterRoleObj.Rules).To(HaveLen(4))
		Expect(prometheusClusterRoleObj.Rules[0].APIGroups).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[0].APIGroups[0]).To(Equal(""))
		Expect(prometheusClusterRoleObj.Rules[0].Resources).To(HaveLen(4))
		Expect(prometheusClusterRoleObj.Rules[0].Resources).To(BeEquivalentTo([]string{
			"endpoints",
			"nodes",
			"pods",
			"services",
		}))
		Expect(prometheusClusterRoleObj.Rules[0].Verbs).To(HaveLen(3))
		Expect(prometheusClusterRoleObj.Rules[0].Verbs).To(BeEquivalentTo([]string{
			"get",
			"list",
			"watch",
		}))
		Expect(prometheusClusterRoleObj.Rules[1].APIGroups).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[1].APIGroups[0]).To(Equal(""))
		Expect(prometheusClusterRoleObj.Rules[1].Resources).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[1].Resources[0]).To(Equal("configmaps"))
		Expect(prometheusClusterRoleObj.Rules[1].Verbs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[1].Verbs[0]).To(Equal("get"))
		Expect(prometheusClusterRoleObj.Rules[2].APIGroups).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].APIGroups[0]).To(Equal(""))
		Expect(prometheusClusterRoleObj.Rules[2].Resources).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].Resources[0]).To(Equal("services/proxy"))
		Expect(prometheusClusterRoleObj.Rules[2].ResourceNames).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].ResourceNames[0]).To(Equal("https:calico-api:8080"))
		Expect(prometheusClusterRoleObj.Rules[2].Verbs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[2].Verbs[0]).To(Equal("get"))
		Expect(prometheusClusterRoleObj.Rules[3].NonResourceURLs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[3].NonResourceURLs[0]).To(Equal("/metrics"))
		Expect(prometheusClusterRoleObj.Rules[3].Verbs).To(HaveLen(1))
		Expect(prometheusClusterRoleObj.Rules[3].Verbs[0]).To(Equal("get"))

		// Prometheus ClusterRoleBinding
		prometheusClusterRolebindingObj, ok := rtest.GetResource(toCreate, "prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(ok).To(BeTrue())
		Expect(prometheusClusterRolebindingObj.RoleRef.APIGroup).To(Equal("rbac.authorization.k8s.io"))
		Expect(prometheusClusterRolebindingObj.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(prometheusClusterRolebindingObj.RoleRef.Name).To(Equal("prometheus"))
		Expect(prometheusClusterRolebindingObj.Subjects).To(HaveLen(1))
		Expect(prometheusClusterRolebindingObj.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(prometheusClusterRolebindingObj.Subjects[0].Name).To(Equal("prometheus"))
		Expect(prometheusClusterRolebindingObj.Subjects[0].Namespace).To(Equal("tigera-prometheus"))

		// Prometheus HTTP API service
		prometheusServiceObj, ok := rtest.GetResource(toCreate, "prometheus-http-api", common.TigeraPrometheusNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ok).To(BeTrue())
		Expect(prometheusServiceObj.Spec.Selector).To(HaveLen(1))
		Expect(prometheusServiceObj.Spec.Selector["prometheus"]).To(Equal("calico-node-prometheus"))
		Expect(prometheusServiceObj.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
		Expect(prometheusServiceObj.Spec.Ports).To(HaveLen(1))
		Expect(prometheusServiceObj.Spec.Ports[0].Port).To(Equal(int32(9090)))
		Expect(prometheusServiceObj.Spec.Ports[0].TargetPort).To(Equal(intstr.FromInt(9095)))

		// ServiceMonitor
		servicemonitorObj, ok := rtest.GetResource(toCreate, monitor.FluentBitMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(0))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(ConsistOf([]metav1.LabelSelectorRequirement{
			{
				Key:      "k8s-app",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"calico-fluent-bit", "calico-fluent-bit-windows"},
			},
		}))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("calico-system"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("fluent-bit-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))

		// PrometheusRule
		prometheusruleObj, ok := rtest.GetResource(toCreate, monitor.TigeraPrometheusRule, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusRuleKind).(*monitoringv1.PrometheusRule)
		Expect(ok).To(BeTrue())
		Expect(prometheusruleObj.ObjectMeta.Labels).To(HaveLen(2))
		Expect(prometheusruleObj.ObjectMeta.Labels["prometheus"]).To(Equal("calico-node-prometheus"))
		Expect(prometheusruleObj.ObjectMeta.Labels["role"]).To(Equal("tigera-prometheus-rules"))
		Expect(prometheusruleObj.Spec.Groups).To(HaveLen(1))
		Expect(prometheusruleObj.Spec.Groups[0].Name).To(Equal("calico.rules"))
		Expect(prometheusruleObj.Spec.Groups[0].Rules).To(HaveLen(1))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Alert).To(Equal("DeniedPacketsRate"))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Expr).To(Equal(intstr.FromString("rate(calico_denied_packets[10s]) > 50")))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Labels["severity"]).To(Equal("info"))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Annotations["summary"]).To(Equal("Instance {{$labels.instance}} - Large rate of packets denied"))
		Expect(prometheusruleObj.Spec.Groups[0].Rules[0].Annotations["description"]).To(Equal("{{$labels.instance}} with calico-node pod {{$labels.pod}} has been denying packets at a fast rate {{$labels.sourceIp}} by policy {{$labels.policy}}."))

		// ServiceMonitor
		servicemonitorObj, ok = rtest.GetResource(toCreate, monitor.CalicoNodeMonitor, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(0))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(ConsistOf([]metav1.LabelSelectorRequirement{
			{
				Key:      "k8s-app",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"calico-node", "calico-node-windows"},
			},
		}))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("calico-system"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(2))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("calico-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(*servicemonitorObj.Spec.Endpoints[0].RelabelConfigs[0].Replacement).To(Equal("https"))
		Expect(servicemonitorObj.Spec.Endpoints[1].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[1].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[1].Port).To(Equal("calico-bgp-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[1].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(*servicemonitorObj.Spec.Endpoints[1].RelabelConfigs[0].Replacement).To(Equal("https"))

		servicemonitorObj, ok = rtest.GetResource(toCreate, monitor.ElasticsearchMetrics, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels["k8s-app"]).To(Equal("tigera-elasticsearch-metrics"))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("tigera-elasticsearch"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(*servicemonitorObj.Spec.Endpoints[0].RelabelConfigs[0].Replacement).To(Equal("https"))

		servicemonitorObj, ok = rtest.GetResource(toCreate, "calico-fluent-bit-metrics", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(0))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchExpressions).To(ConsistOf([]metav1.LabelSelectorRequirement{
			{
				Key:      "k8s-app",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"calico-fluent-bit", "calico-fluent-bit-windows"},
			},
		}))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("calico-system"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("fluent-bit-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		// fluent-bit's monitoring server is plain HTTP (no TLS support), unlike
		// fluentd's mTLS prometheus exporter.
		Expect(servicemonitorObj.Spec.Endpoints[0].RelabelConfigs).To(BeEmpty())
		Expect(servicemonitorObj.Spec.Endpoints[0].TLSConfig).To(BeNil())

		servicemonitorObj, ok = rtest.GetResource(toCreate, "calico-api", common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())
		Expect(servicemonitorObj.Spec.Selector.MatchLabels).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Selector.MatchLabels["k8s-app"]).To(Equal("calico-api"))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.NamespaceSelector.MatchNames[0]).To(Equal("calico-system"))
		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(1))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("queryserver"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(*servicemonitorObj.Spec.Endpoints[0].RelabelConfigs[0].Replacement).To(Equal("https"))
		//nolint:staticcheck // Ignore SA1019 deprecated
		Expect(servicemonitorObj.Spec.Endpoints[0].BearerTokenFile).To(Equal("/var/run/secrets/kubernetes.io/serviceaccount/token"))

		// Role
		roleObj, ok := rtest.GetResource(toCreate, monitor.TigeraPrometheusRole, common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(ok).To(BeTrue())
		Expect(roleObj.Rules).To(HaveLen(1))
		Expect(roleObj.Rules[0].APIGroups).To(HaveLen(1))
		Expect(roleObj.Rules[0].APIGroups[0]).To(Equal("monitoring.coreos.com"))
		Expect(roleObj.Rules[0].Resources).To(HaveLen(6))
		Expect(roleObj.Rules[0].Resources).To(BeEquivalentTo([]string{
			"alertmanagers",
			"podmonitors",
			"prometheuses",
			"prometheusrules",
			"servicemonitors",
			"thanosrulers",
		}))
		Expect(roleObj.Rules[0].Verbs).To(HaveLen(6))
		Expect(roleObj.Rules[0].Verbs).To(BeEquivalentTo([]string{
			"create",
			"delete",
			"get",
			"list",
			"update",
			"watch",
		}))

		// RoleBinding
		rolebindingObj, ok := rtest.GetResource(toCreate, monitor.TigeraPrometheusRoleBinding, common.TigeraPrometheusNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(ok).To(BeTrue())
		Expect(rolebindingObj.RoleRef.APIGroup).To(Equal("rbac.authorization.k8s.io"))
		Expect(rolebindingObj.RoleRef.Kind).To(Equal("Role"))
		Expect(rolebindingObj.RoleRef.Name).To(Equal("tigera-prometheus-role"))
		Expect(rolebindingObj.Subjects).To(HaveLen(1))
		Expect(rolebindingObj.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(rolebindingObj.Subjects[0].Name).To(Equal("tigera-operator"))
		Expect(rolebindingObj.Subjects[0].Namespace).To(Equal(common.OperatorNamespace()))
	})

	It("should render toleration on GKE", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		prometheusObj, ok := rtest.GetResource(resources, monitor.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())
		alertmanagerObj, ok := rtest.GetResource(resources, monitor.CalicoNodeAlertmanager, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.AlertmanagersKind).(*monitoringv1.Alertmanager)
		Expect(ok).To(BeTrue())

		Expect(prometheusObj.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
		Expect(alertmanagerObj.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.OpenShift = true
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "calico-prometheus-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))

		role = rtest.GetResource(resources, "prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))

		role = rtest.GetResource(resources, "tigera-prometheus", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	It("Should render Prometheus resources when Dex is enabled", func() {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain:  "https://127.0.0.1",
				GroupsPrefix:   "g:",
				UsernamePrefix: "u:",
				OIDC:           &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email", GroupsClaim: "grp"},
			},
		}

		dexCfg := render.NewDexKeyValidatorConfig(authentication, dns.DefaultClusterDomain)
		cfg.KeyValidatorConfig = dexCfg
		cfg.ServerTLSSecret = prometheusKeyPair
		component := monitor.Monitor(cfg)

		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		rtest.ExpectResources(toCreate, expectedResources)

		Expect(toDelete).To(HaveLen(7))

		// Prometheus
		prometheusObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodePrometheus, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusesKind).(*monitoringv1.Prometheus)
		Expect(ok).To(BeTrue())
		prometheusCom := components.ComponentPrometheus
		Expect(*prometheusObj.Spec.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, prometheusCom.Image, prometheusCom.Version)))
		Expect(prometheusObj.Spec.Containers).To(HaveLen(1))
		proxy := prometheusObj.Spec.Containers[0]
		Expect(proxy.Env).To(ConsistOf([]corev1.EnvVar{
			{
				Name:      "PROMETHEUS_ENDPOINT_URL",
				Value:     "http://localhost:9090",
				ValueFrom: nil,
			},
			{
				Name:      "LISTEN_ADDR",
				Value:     ":9095",
				ValueFrom: nil,
			},
			{
				Name:      "TLS_KEY",
				Value:     "/calico-node-prometheus-tls/tls.key",
				ValueFrom: nil,
			},
			{
				Name:      "TLS_CERT",
				Value:     "/calico-node-prometheus-tls/tls.crt",
				ValueFrom: nil,
			},

			{
				Name:      "TLS_SERVER_SECRET_HASH_ANNOTATION",
				Value:     prometheusKeyPair.HashAnnotationValue(),
				ValueFrom: nil,
			},
			{
				Name:      "TLS_CLIENT_SECRET_HASH_ANNOTATION",
				Value:     cfg.ClientTLSSecret.HashAnnotationValue(),
				ValueFrom: nil,
			},
			{
				Name:      "TLS_CA_BUNDLE_HASH_ANNOTATION",
				Value:     rmeta.AnnotationHash(cfg.TrustedCertBundle.HashAnnotations()),
				ValueFrom: nil,
			},
			{
				Name:      "DEX_ENABLED",
				Value:     "true",
				ValueFrom: nil,
			},
			{
				Name:      "DEX_URL",
				Value:     "https://tigera-dex.tigera-dex.svc.cluster.local:5556/",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_ENABLED",
				Value:     "true",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_ISSUER",
				Value:     "https://127.0.0.1/dex",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_JWKSURL",
				Value:     "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_CLIENT_ID",
				Value:     "tigera-manager",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_USERNAME_CLAIM",
				Value:     "email",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_GROUPS_CLAIM",
				Value:     "groups",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_USERNAME_PREFIX",
				Value:     "u:",
				ValueFrom: nil,
			},
			{
				Name:      "OIDC_AUTH_GROUPS_PREFIX",
				Value:     "g:",
				ValueFrom: nil,
			},
		}))
	})

	Context("calico-system rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "calico-system.calico-node-alertmanager", Namespace: "tigera-prometheus"},
			{Name: "calico-system.calico-node-alertmanager-mesh", Namespace: "tigera-prometheus"},
			{Name: "calico-system.prometheus", Namespace: "tigera-prometheus"},
			{Name: "calico-system.tigera-prometheus-api", Namespace: "tigera-prometheus"},
			{Name: "calico-system.prometheus-operator", Namespace: "tigera-prometheus"},
		}

		getExpectedPolicy := func(name types.NamespacedName, scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
			switch name.Name {
			case "calico-system.calico-node-alertmanager":
				return testutils.SelectPolicyByProvider(scenario, expectedAlertmanagerPolicy, expectedAlertmanagerPolicyForOpenshift)
			case "calico-system.calico-node-alertmanager-mesh":
				return testutils.SelectPolicyByProvider(scenario, expectedAlertmanagerMeshPolicy, expectedAlertmanagerMeshPolicyForOpenshift)
			case "calico-system.prometheus":
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusPolicy, expectedPrometheusPolicyForOpenshift)
			case "calico-system.tigera-prometheus-api":
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusApiPolicy, expectedPrometheusApiPolicyForOpenshift)
			case "calico-system.prometheus-operator":
				return testutils.SelectPolicyByProvider(scenario, expectedPrometheusOperatorPolicy, expectedPrometheusOperatorPolicyOpenshift)
			}

			return nil
		}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				cfg.OpenShift = scenario.OpenShift
				cfg.KubeControllerPort = 9094

				component := monitor.MonitorPolicy(cfg)
				resourcesToCreate, _ := component.Objects()

				for _, policyName := range policyNames {
					policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resourcesToCreate)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
		)

		It("prometheus policy should omit kube-controller egress rule when kube-controller port is 0", func() {
			// Baseline case
			cfg.KubeControllerPort = 9094
			component := monitor.MonitorPolicy(cfg)
			resourcesToCreate, _ := component.Objects()
			baselinePolicy := testutils.GetCalicoSystemPolicyFromResources(types.NamespacedName{Name: "calico-system.prometheus", Namespace: "tigera-prometheus"}, resourcesToCreate)

			// kube-controllers port set to 0
			cfg.KubeControllerPort = 0
			component = monitor.MonitorPolicy(cfg)
			resourcesToCreate, _ = component.Objects()
			zeroedPolicy := testutils.GetCalicoSystemPolicyFromResources(types.NamespacedName{Name: "calico-system.prometheus", Namespace: "tigera-prometheus"}, resourcesToCreate)

			Expect(len(zeroedPolicy.Spec.Egress)).To(Equal(len(baselinePolicy.Spec.Egress) - 1))
		})
	})

	It("Should render external prometheus resources with service monitor", func() {
		cfg.Monitor.ExternalPrometheus = &operatorv1.ExternalPrometheus{
			ServiceMonitor: &operatorv1.ServiceMonitor{
				Endpoints: []operatorv1.Endpoint{
					{
						BearerTokenSecret: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-external-prometheus"},
						},
					},
				},
			},
			Namespace: "external-prometheus",
		}
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		expectedResources = append(expectedResources,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		)

		rtest.ExpectResources(toCreate, expectedResources)
		Expect(toDelete).To(HaveLen(7))
	})

	It("Should render external prometheus resources with service monitor and custom token", func() {
		cfg.Monitor.ExternalPrometheus = &operatorv1.ExternalPrometheus{
			ServiceMonitor: &operatorv1.ServiceMonitor{
				Endpoints: []operatorv1.Endpoint{
					{
						BearerTokenSecret: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "some-other-token"},
						},
					},
				},
			},
			Namespace: "external-prometheus",
		}
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		expectedResources = append(expectedResources,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		)

		rtest.ExpectResources(toCreate, expectedResources)
		Expect(toDelete).To(HaveLen(7))
	})

	It("Should render external prometheus resources without service monitor", func() {
		cfg.Monitor.ExternalPrometheus = &operatorv1.ExternalPrometheus{
			Namespace: "external-prometheus",
		}
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		expectedResources = append(expectedResources,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
		)

		rtest.ExpectResources(toCreate, expectedResources)
		Expect(toDelete).To(HaveLen(7))
	})

	It("Should render typha service monitor if typha metrics are enabled", func() {
		cfg.Installation.TyphaMetricsPort = ptr.To(int32(9093))
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()
		expectedResources := expectedBaseResources()
		expectedResources = append(expectedResources,
			&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-typha-metrics", Namespace: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		)

		rtest.ExpectResources(toCreate, expectedResources)
		Expect(toDelete).To(HaveLen(6))
		sm := rtest.GetResource(toCreate, "calico-typha-metrics", "tigera-prometheus", "monitoring.coreos.com", "v1", "ServiceMonitor").(*monitoringv1.ServiceMonitor)
		Expect(sm).To(Equal(&monitoringv1.ServiceMonitor{
			TypeMeta: metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: "monitoring.coreos.com/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-typha-metrics",
				Namespace: "tigera-prometheus",
			},
			Spec: monitoringv1.ServiceMonitorSpec{
				Endpoints: []monitoringv1.Endpoint{
					{
						HonorLabels:   true,
						Interval:      "5s",
						Port:          "calico-typha-metrics",
						ScrapeTimeout: "5s",
						RelabelConfigs: []monitoringv1.RelabelConfig{
							{
								TargetLabel: "__scheme__",
								Replacement: ptr.To("http"),
							},
						},
					},
				},
				NamespaceSelector: monitoringv1.NamespaceSelector{
					MatchNames: []string{common.CalicoNamespace},
				},
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						render.AppLabelName: render.TyphaMetricsName,
					},
				},
			},
		}))
	})

	It("Should render serviceMonitor with felix endpoint if FelixPrometheusMetricsEnabled", func() {
		cfg.FelixPrometheusMetricsEnabled = true
		component := monitor.Monitor(cfg)
		toCreate, _ := component.Objects()
		servicemonitorObj, ok := rtest.GetResource(toCreate, monitor.CalicoNodeMonitor, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.ServiceMonitorsKind).(*monitoringv1.ServiceMonitor)
		Expect(ok).To(BeTrue())

		Expect(servicemonitorObj.Spec.Endpoints).To(HaveLen(3))
		Expect(servicemonitorObj.Spec.Endpoints[0].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[0].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[0].Port).To(Equal("calico-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[0].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(*servicemonitorObj.Spec.Endpoints[0].RelabelConfigs[0].Replacement).To(Equal("https"))
		Expect(servicemonitorObj.Spec.Endpoints[1].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[1].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[1].Port).To(Equal("calico-bgp-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[1].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(*servicemonitorObj.Spec.Endpoints[1].RelabelConfigs[0].Replacement).To(Equal("https"))
		Expect(servicemonitorObj.Spec.Endpoints[2].HonorLabels).To(BeTrue())
		Expect(servicemonitorObj.Spec.Endpoints[2].Interval).To(BeEquivalentTo("5s"))
		Expect(servicemonitorObj.Spec.Endpoints[2].Port).To(Equal("felix-metrics-port"))
		Expect(servicemonitorObj.Spec.Endpoints[2].ScrapeTimeout).To(BeEquivalentTo("5s"))
		Expect(*servicemonitorObj.Spec.Endpoints[2].RelabelConfigs[0].Replacement).To(Equal("http"))
	})

	It("Should move ServiceMonitors to toDelete when LicenseExpired is true", func() {
		cfg.LicenseExpired = true
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()

		// ServiceMonitors should not be in toCreate.
		for _, obj := range toCreate {
			if _, ok := obj.(*monitoringv1.ServiceMonitor); ok {
				Fail("ServiceMonitor should not be in toCreate when license is expired, but found: " + obj.GetName())
			}
		}

		// ServiceMonitors should be in toDelete.
		serviceMonitorNames := []string{
			monitor.CalicoNodeMonitor,
			monitor.ElasticsearchMetrics,
			monitor.FluentBitMetrics,
			"calico-api",
			"calico-kube-controllers-metrics",
		}
		for _, name := range serviceMonitorNames {
			found := false
			for _, obj := range toDelete {
				if sm, ok := obj.(*monitoringv1.ServiceMonitor); ok && sm.Name == name {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Expected ServiceMonitor %s to be in toDelete", name)
		}
	})

	It("Should include ServiceMonitors in toCreate when LicenseExpired is false", func() {
		cfg.LicenseExpired = false
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, _ := component.Objects()

		serviceMonitorNames := []string{
			monitor.CalicoNodeMonitor,
			monitor.ElasticsearchMetrics,
			monitor.FluentBitMetrics,
			"calico-api",
			"calico-kube-controllers-metrics",
		}
		for _, name := range serviceMonitorNames {
			found := false
			for _, obj := range toCreate {
				if sm, ok := obj.(*monitoringv1.ServiceMonitor); ok && sm.Name == name {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Expected ServiceMonitor %s to be in toCreate", name)
		}
	})

	It("Should create operator metrics Service and ServiceMonitor when OperatorMetricsEnabled is true", func() {
		cfg.OperatorMetricsEnabled = true
		cfg.OperatorNamespace = "tigera-operator"
		cfg.OperatorName = "tigera-operator"
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, toDelete := component.Objects()

		// Operator metrics service should be in toCreate.
		svc := rtest.GetResource(toCreate, monitor.OperatorMetricsServiceName, "tigera-operator", "", "v1", "Service")
		Expect(svc).NotTo(BeNil())
		service := svc.(*corev1.Service)
		Expect(service.Spec.Ports[0].Port).To(Equal(int32(monitor.OperatorMetricsPort)))
		Expect(service.Spec.Selector["k8s-app"]).To(Equal("tigera-operator"))

		// Operator ServiceMonitor should be in toCreate.
		sm := rtest.GetResource(toCreate, monitor.OperatorMetricsServiceName, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", "ServiceMonitor")
		Expect(sm).NotTo(BeNil())
		serviceMonitor := sm.(*monitoringv1.ServiceMonitor)
		Expect(serviceMonitor.Spec.Endpoints[0].Port).To(Equal(monitor.OperatorMetricsPortName))

		// Neither should be in toDelete (only the legacy monitors, Deployment, typhaServiceMonitor).
		Expect(toDelete).To(HaveLen(5))
	})

	It("Should include operator alert rules in PrometheusRule when OperatorMetricsEnabled is true", func() {
		cfg.OperatorMetricsEnabled = true
		cfg.OperatorNamespace = "tigera-operator"
		cfg.OperatorName = "tigera-operator"
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, _ := component.Objects()

		prometheusruleObj, ok := rtest.GetResource(toCreate, monitor.TigeraPrometheusRule, common.TigeraPrometheusNamespace, "monitoring.coreos.com", "v1", monitoringv1.PrometheusRuleKind).(*monitoringv1.PrometheusRule)
		Expect(ok).To(BeTrue())
		rules := prometheusruleObj.Spec.Groups[0].Rules
		Expect(rules).To(HaveLen(9))

		// DeniedPacketsRate - base rule, severity downgraded to info
		Expect(rules[0].Alert).To(Equal("DeniedPacketsRate"))
		Expect(rules[0].Expr).To(Equal(intstr.FromString("rate(calico_denied_packets[10s]) > 50")))
		Expect(rules[0].Labels["severity"]).To(Equal("info"))
		Expect(rules[0].Annotations["summary"]).To(Equal("Instance {{$labels.instance}} - Large rate of packets denied"))
		Expect(rules[0].Annotations["description"]).To(Equal("{{$labels.instance}} with calico-node pod {{$labels.pod}} has been denying packets at a fast rate {{$labels.sourceIp}} by policy {{$labels.policy}}."))

		// TLS certificate expiry alerts
		Expect(rules[1].Alert).To(Equal("TLSCertExpiringWarning"))
		Expect(rules[1].Expr).To(Equal(intstr.FromString("tigera_operator_tls_certificate_expiry_timestamp_seconds - time() < (30 * 24 - 8) * 3600")))
		Expect(rules[1].Labels["severity"]).To(Equal("warning"))
		Expect(rules[1].Annotations["summary"]).To(Equal("TLS certificate {{ $labels.name }} expires in less than 30 days"))
		Expect(rules[1].Annotations["description"]).To(Equal("TLS certificate {{ $labels.name }} in namespace {{ $labels.namespace }} will expire in less than 30 days."))

		Expect(rules[2].Alert).To(Equal("TLSCertExpiringCritical"))
		Expect(rules[2].Expr).To(Equal(intstr.FromString("tigera_operator_tls_certificate_expiry_timestamp_seconds - time() < 7 * 24 * 3600")))
		Expect(rules[2].Labels["severity"]).To(Equal("critical"))
		Expect(rules[2].Annotations["summary"]).To(Equal("TLS certificate {{ $labels.name }} expires in less than 7 days"))
		Expect(rules[2].Annotations["description"]).To(Equal("TLS certificate {{ $labels.name }} in namespace {{ $labels.namespace }} will expire in less than 7 days."))

		// License expiry alerts
		Expect(rules[3].Alert).To(Equal("LicenseExpiringWarning"))
		Expect(rules[3].Expr).To(Equal(intstr.FromString("tigera_operator_license_expiry_timestamp_seconds - time() < 30 * 24 * 3600")))
		Expect(rules[3].Labels["severity"]).To(Equal("warning"))
		Expect(rules[3].Annotations["summary"]).To(Equal("Calico Enterprise license expires in less than 30 days"))
		Expect(rules[3].Annotations["description"]).To(Equal("The Calico Enterprise license will expire in less than 30 days."))

		Expect(rules[4].Alert).To(Equal("LicenseExpiringCritical"))
		Expect(rules[4].Expr).To(Equal(intstr.FromString("tigera_operator_license_expiry_timestamp_seconds - time() < 7 * 24 * 3600 or tigera_operator_license_valid == 0")))
		Expect(rules[4].Labels["severity"]).To(Equal("critical"))
		Expect(rules[4].Annotations["summary"]).To(Equal("Calico Enterprise license expires in less than 7 days or is invalid"))
		Expect(rules[4].Annotations["description"]).To(Equal("The Calico Enterprise license will expire in less than 7 days, or the license is invalid."))

		// Component status alerts
		Expect(rules[5].Alert).To(Equal("ComponentDegradedWarning"))
		Expect(rules[5].Expr).To(Equal(intstr.FromString(`tigera_operator_component_status{condition="degraded"} == 1`)))
		Expect(rules[5].For).To(Equal(ptr.To(monitoringv1.Duration("15m"))))
		Expect(rules[5].Labels["severity"]).To(Equal("warning"))
		Expect(rules[5].Annotations["summary"]).To(Equal("Component {{ $labels.component }} is degraded"))
		Expect(rules[5].Annotations["description"]).To(Equal("Component {{ $labels.component }} has been in a degraded state for more than 15 minutes."))

		Expect(rules[6].Alert).To(Equal("ComponentDegradedCritical"))
		Expect(rules[6].Expr).To(Equal(intstr.FromString(`tigera_operator_component_status{condition="degraded"} == 1`)))
		Expect(rules[6].For).To(Equal(ptr.To(monitoringv1.Duration("30m"))))
		Expect(rules[6].Labels["severity"]).To(Equal("critical"))
		Expect(rules[6].Annotations["summary"]).To(Equal("Component {{ $labels.component }} is degraded"))
		Expect(rules[6].Annotations["description"]).To(Equal("Component {{ $labels.component }} has been in a degraded state for more than 30 minutes."))

		Expect(rules[7].Alert).To(Equal("ComponentProgressingWarning"))
		Expect(rules[7].Expr).To(Equal(intstr.FromString(`tigera_operator_component_status{condition="progressing"} == 1`)))
		Expect(rules[7].For).To(Equal(ptr.To(monitoringv1.Duration("15m"))))
		Expect(rules[7].Labels["severity"]).To(Equal("warning"))
		Expect(rules[7].Annotations["summary"]).To(Equal("Component {{ $labels.component }} is progressing"))
		Expect(rules[7].Annotations["description"]).To(Equal("Component {{ $labels.component }} has been in a progressing state for more than 15 minutes."))

		Expect(rules[8].Alert).To(Equal("ComponentProgressingCritical"))
		Expect(rules[8].Expr).To(Equal(intstr.FromString(`tigera_operator_component_status{condition="progressing"} == 1`)))
		Expect(rules[8].For).To(Equal(ptr.To(monitoringv1.Duration("30m"))))
		Expect(rules[8].Labels["severity"]).To(Equal("critical"))
		Expect(rules[8].Annotations["summary"]).To(Equal("Component {{ $labels.component }} is progressing"))
		Expect(rules[8].Annotations["description"]).To(Equal("Component {{ $labels.component }} has been in a progressing state for more than 30 minutes."))
	})

	It("Should delete operator metrics resources when OperatorMetricsEnabled is false", func() {
		cfg.OperatorMetricsEnabled = false
		cfg.OperatorNamespace = "tigera-operator"
		cfg.OperatorName = "tigera-operator"
		component := monitor.Monitor(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		_, toDelete := component.Objects()

		// Both operator metrics resources should be in toDelete.
		found := 0
		for _, obj := range toDelete {
			if obj.GetName() == monitor.OperatorMetricsServiceName {
				found++
			}
		}
		Expect(found).To(Equal(2)) // Service + ServiceMonitor
	})
})

// expectedBaseResources These are the expected resources in the most basic setup.
func expectedBaseResources() []client.Object {
	return []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus-role", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator-secret", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus-role-binding", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator-secret", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-calico-node-alertmanager", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator", Namespace: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-prometheus-operator"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "prometheus", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&monitoringv1.Prometheus{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-prometheus", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Prometheus", APIVersion: "monitoring.coreos.com/v1"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-alertmanager", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
		&monitoringv1.Alertmanager{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-alertmanager", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Alertmanager", APIVersion: "monitoring.coreos.com/v1"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-http-api", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-prometheus"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		&monitoringv1.PrometheusRule{ObjectMeta: metav1.ObjectMeta{Name: monitor.TigeraPrometheusRule, Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "PrometheusRule", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-node-monitor", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "elasticsearch-metrics", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit-metrics", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers-metrics", Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceMonitor", APIVersion: "monitoring.coreos.com/v1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: common.TigeraPrometheusNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
	}
}
