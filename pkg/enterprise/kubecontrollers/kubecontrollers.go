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

// Package kubecontrollers holds the enterprise es-calico-kube-controllers assembly
// (a distinct deployment the logstorage controller reconciles) and the enterprise
// kube-controllers cluster role rules shared with the calico-kube-controllers
// modifier in pkg/enterprise/installation.
package kubecontrollers

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rkc "github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/url"
)

const (
	EsKubeController                  = "es-calico-kube-controllers"
	EsKubeControllerRole              = "es-calico-kube-controllers"
	EsKubeControllerRoleBinding       = "es-calico-kube-controllers"
	EsKubeControllerMetrics           = "es-calico-kube-controllers-metrics"
	EsKubeControllerNetworkPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "es-kube-controller-access"

	ElasticsearchKubeControllersUserSecret             = "tigera-ee-kube-controllers-elasticsearch-access"
	ElasticsearchKubeControllersUserName               = "tigera-ee-kube-controllers"
	ElasticsearchKubeControllersSecureUserSecret       = "tigera-ee-kube-controllers-elasticsearch-access-gateway"
	ElasticsearchKubeControllersVerificationUserSecret = "tigera-ee-kube-controllers-gateway-verification-credentials"
)

// NewElasticsearchKubeControllers fills the generic kube-controllers configuration
// for the enterprise es-calico-kube-controllers deployment and returns the rendered
// component. es-kube-controllers is a distinct deployment (talks to Elasticsearch via
// es-gateway) reconciled by the logstorage kube-controllers controller, so it's
// assembled here rather than through the render-time modifier mechanism.
func NewElasticsearchKubeControllers(cfg *rkc.KubeControllersConfiguration) render.Component {
	cfg.Name = EsKubeController
	cfg.ConfigName = "elasticsearch"
	cfg.RoleName = EsKubeControllerRole
	cfg.RoleBindingName = EsKubeControllerRoleBinding
	cfg.MetricsName = EsKubeControllerMetrics
	cfg.DisableConfigAPI = cfg.Tenant.MultiTenant()

	cfg.Rules = rkc.KubeControllersRoleCommonRules(cfg)
	cfg.Rules = append(cfg.Rules, KubeControllersEnterpriseCommonRules(false, cfg.ManagementClusterConnection != nil)...)
	// Calico Cloud's es-kube-controllers provisions RBAC for managed-cluster access, so it needs to
	// create and update cluster roles and bindings. Enterprise only reads them.
	clusterRoleVerbs := []string{"watch", "list", "get"}
	if cfg.Cloud {
		clusterRoleVerbs = append(clusterRoleVerbs, "create", "update")
	}

	cfg.Rules = append(cfg.Rules,
		rbacv1.PolicyRule{
			APIGroups: []string{"elasticsearch.k8s.elastic.co"},
			Resources: []string{"elasticsearches"},
			Verbs:     []string{"watch", "get", "list"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "clusterrolebindings"},
			Verbs:     clusterRoleVerbs,
		},
	)

	if !cfg.Tenant.MultiTenant() {
		// Zero and single tenant clusters need elasticsearch configuration.
		cfg.EnabledControllers = append(cfg.EnabledControllers, "authorization", "elasticsearchconfiguration")
		if cfg.ManagementCluster != nil && cfg.Tenant == nil {
			cfg.ManagedClusterWatchBinding = true
			// Enterprise requires the managedcluster controller to push licenses.
			cfg.EnabledControllers = append(cfg.EnabledControllers, "managedcluster")
		}
	}

	cfg.NetworkPolicy = esKubeControllersCalicoSystemPolicy(cfg)
	cfg.DeprecatedNetworkPolicyName = "es-kube-controller-access"
	cfg.ExtraEnv = esKubeControllersEnv(cfg)

	return rkc.NewKubeControllers(cfg)
}

// esKubeControllersEnv builds the enterprise env vars for es-calico-kube-controllers.
func esKubeControllersEnv(cfg *rkc.KubeControllersConfiguration) []corev1.EnvVar {
	var env []corev1.EnvVar

	if cfg.Tenant != nil {
		env = append(env, corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID})
	} else if cfg.TenantID != "" {
		// Calico Cloud reads the tenant from its cloud config rather than a Tenant CR.
		env = append(env, corev1.EnvVar{Name: "TENANT_ID", Value: cfg.TenantID})
	}

	// What started as a workaround is now the default behaviour. This feature uses our backend in order to
	// log into Kibana for users from external identity providers, rather than configuring an authn realm
	// in the Elastic stack.
	env = append(env, corev1.EnvVar{Name: "ENABLE_ELASTICSEARCH_OIDC_WORKAROUND", Value: "true"})
	if cfg.Authentication != nil {
		env = append(env,
			corev1.EnvVar{Name: "OIDC_AUTH_USERNAME_PREFIX", Value: cfg.Authentication.Spec.UsernamePrefix},
			corev1.EnvVar{Name: "OIDC_AUTH_GROUP_PREFIX", Value: cfg.Authentication.Spec.GroupsPrefix},
		)
	}

	if cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: cfg.TrustedBundle.MountPath()})
	}
	if cfg.Installation.CalicoNetwork != nil && cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	if !cfg.Tenant.MultiTenant() {
		_, esHost, esPort, _ := url.ParseEndpoint(relasticsearch.GatewayEndpoint(rmeta.OSTypeLinux, cfg.ClusterDomain, render.ElasticsearchNamespace))
		env = append(env,
			relasticsearch.ElasticHostEnvVar(esHost),
			relasticsearch.ElasticPortEnvVar(esPort),
			relasticsearch.ElasticUsernameEnvVar(ElasticsearchKubeControllersUserSecret),
			relasticsearch.ElasticPasswordEnvVar(ElasticsearchKubeControllersUserSecret),
			relasticsearch.ElasticCAEnvVar(rmeta.OSTypeLinux),
		)
	}

	return env
}

// KubeControllersEnterpriseCommonRules are the Calico Enterprise cluster role rules
// shared by calico-kube-controllers and es-calico-kube-controllers. gatewayAPIPresent
// adds the WAF v3 (Gateway API add-on) rules - gated on the GatewayAPI CR existing, not
// on waf.state == Enabled, so the applicationlayer controller keeps the RBAC it needs
// to delete the EnvoyExtensionPolicies it generated while WAF is disabled (EV-6751); the
// rule set is identical enabled vs disabled, so toggling waf.state causes no ClusterRole
// churn. managedCluster adds the license-push rule a managed cluster's kube-controllers
// needs.
func KubeControllersEnterpriseCommonRules(gatewayAPIPresent, managedCluster bool) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"watch", "list", "get", "update", "create", "delete"},
		},
		{
			// The Federated Services Controller needs access to the remote kubeconfig secret
			// in order to create a remote syncer.
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			// Needed to validate the license
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			// Needed to update the status of the LicenseKey with the result of license validation.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"licensekeys/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"packetcaptures/status"},
			Verbs:     []string{"update"},
		},
	}

	if gatewayAPIPresent {
		rules = append(rules, wafRules()...)
	}

	if managedCluster {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "create", "update", "list", "watch"},
			},
		)
	}

	return rules
}

// wafRules are the WAF v3 (Gateway API add-on) cluster role rules, gated by
// GatewayAPI.spec.extensions.waf.state == Enabled.
func wafRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		// Application-layer (gateway-addons) reconcilers reconcile WAF resources
		// against Gateway API targetRefs and emit events on the policy objects.
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies", "globalwafpolicies",
				"wafplugins", "globalwafplugins",
				"wafvalidationpolicies", "globalwafvalidationpolicies",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies/status", "globalwafpolicies/status",
				"wafplugins/status", "globalwafplugins/status",
				"wafvalidationpolicies/status", "globalwafvalidationpolicies/status",
			},
			Verbs: []string{"get", "update", "patch"},
		},
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"wafpolicies/finalizers", "globalwafpolicies/finalizers",
				"wafplugins/finalizers", "globalwafplugins/finalizers",
				"wafvalidationpolicies/finalizers", "globalwafvalidationpolicies/finalizers",
			},
			Verbs: []string{"update"},
		},
		{
			// Validate Gateway API targetRefs and surface attachment status.
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes", "tcproutes", "tlsroutes", "grpcroutes"},
			Verbs:     []string{"get", "list", "watch", "update", "patch"},
		},
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways/status", "httproutes/status", "tcproutes/status", "tlsroutes/status", "grpcroutes/status"},
			Verbs:     []string{"get", "update", "patch"},
		},
		// controller-runtime Reconcilers (e.g. the applicationlayer manager) record
		// events on watched objects via Recorder.Eventf; both core and events.k8s.io
		// API groups are emitted depending on the kubernetes version.
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
		{
			APIGroups: []string{"events.k8s.io"},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
		// Application-layer reconciler replicates the WAF wasm pull Secret from
		// the controller namespace (calico-system) into each WAFPolicy's
		// namespace so the rendered EnvoyExtensionPolicy can reference it. Also
		// replicates CA-cert ConfigMaps when WASM_CA_CERT is set.
		{
			APIGroups: []string{""},
			Resources: []string{"secrets", "configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Application-layer reconciler emits one EnvoyExtensionPolicy per WAF
		// targetRef to bind the Coraza wasm filter at the gateway / route.
		{
			APIGroups: []string{"gateway.envoyproxy.io"},
			Resources: []string{"envoyextensionpolicies"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Application-layer reconciler stamps each namespace with its allocated WAF
		// rule-id range (applicationlayer.projectcalico.org/waf-id-range annotation)
		// so application operators can author in-range rules. The base role already
		// grants namespaces get/list/watch; the annotation write needs patch/update.
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "patch", "update"},
		},
	}
}

func esKubeControllersCalicoSystemPolicy(cfg *rkc.KubeControllersConfiguration) *v3.NetworkPolicy {
	if cfg.ManagementClusterConnection != nil {
		return nil
	}

	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(443, 6443, 12388),
			},
		},
	}...)

	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().ESGatewayEntityRule(),
		},
	}...)

	networkpolicyHelper := networkpolicy.Helper(cfg.Tenant.MultiTenant(), cfg.Namespace)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ManagerEntityRule(),
		},
	}...)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsKubeControllerNetworkPolicyName,
			Namespace: cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(EsKubeController),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}
