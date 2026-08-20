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

package installation

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/gatewayapi"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	entkubecontrollers "github.com/tigera/operator/pkg/enterprise/kubecontrollers"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// modifyKubeControllersPolicy adds the WAF admission webhook ingress rule to the
// calico-kube-controllers calico-system network policy, so the kube-apiserver can
// reach the in-process webhook on :9443 (EV-6386). Without it the calico-system
// default-deny drops the apiserver->:9443 call and WAF admission times out.
func modifyKubeControllersPolicy(ri render.Inputs, objs, del []client.Object) ([]client.Object, []client.Object) {
	data := installationData(ri)

	// The non-cluster-host typha policy renders here, with the other component
	// policies, so it lands after the API server is up.
	if data.nonClusterHost.enabled {
		add, remove := nonClusterHostPolicy(ri)
		objs = append(objs, add...)
		del = append(del, remove...)
	}

	policy, ok := extensions.FindObject[*v3.NetworkPolicy](objs, kubecontrollers.KubeControllerNetworkPolicyName)
	if !ok {
		return objs, del
	}

	// kube-controllers reaches the manager through Guardian on a managed cluster and
	// directly otherwise.
	manager := networkpolicy.DefaultHelper().ManagerEntityRule()
	if data.managedCluster {
		manager = render.GuardianEntityRule
	}
	policy.Spec.Egress = append(policy.Spec.Egress, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: manager,
	})

	if data.waf.enabled {
		policy.Spec.Ingress = append(policy.Spec.Ingress, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(applicationlayer.WAFWebhookContainerPort)),
			},
		})
	}
	return objs, del
}

// modifyKubeControllers layers the full Calico Enterprise surface onto the rendered
// calico-kube-controllers objects: the enterprise cluster role rules, the enterprise
// enabled controllers, the metrics serving TLS, and the WAF v3 (Gateway API add-on)
// surface. The modifier only runs for the enterprise variant, so everything it adds
// is enterprise-only by construction - the base render carries none of it. The
// controller-side inputs (keypairs, the resolved wasm image, the pull secret) are
// produced by the installation hook and handed in through ri.
func modifyKubeControllers(ri render.Inputs, objs, del []client.Object) ([]client.Object, []client.Object) {
	data := installationData(ri)

	// Nothing is created while the installation is terminating.
	if role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, kubecontrollers.KubeControllerRole); ok {
		role.Rules = append(role.Rules, data.kubeControllerRules...)
	}

	// Only a management cluster watches managed clusters.
	if data.managementCluster {
		objs = append(objs, rcomp.ClusterRoleBinding(
			kubecontrollers.ManagedClustersWatchRoleBindingName,
			render.ManagedClustersWatchClusterRoleName,
			kubecontrollers.KubeControllerServiceAccount,
			[]string{common.CalicoNamespace},
		))
	}

	// The deployment is queued for deletion, not created, when no controllers are enabled.
	if dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController); ok {
		modifyKubeControllersDeployment(ri, dp, data)
	}

	// The WAF admission webhook surface (Service + ValidatingWebhookConfiguration),
	// the wasm pull secret, and the wasm CA bundle. Created when WAF is enabled,
	// deleted otherwise so toggling the extension off cleans them up.
	webhookObjs := applicationlayer.WAFAdmissionWebhookComponents(data.waf.caBundle)
	if data.waf.enabled {
		objs = append(objs, webhookObjs...)
		if data.waf.pullSecret != nil {
			objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(common.CalicoNamespace, data.waf.pullSecret)...)...)
		}
		if data.waf.caCert != nil {
			objs = append(objs, data.waf.caCert)
		}
	} else {
		del = append(del, webhookObjs...)
	}

	// The rbacsync controller's namespaced Role/RoleBinding. Deleted when RBAC
	// management is off, so switching the gate off cleans them up.
	if data.rbacManagementEnabled {
		objs = append(objs, rbacSyncIDPGroupsRole()...)
	} else {
		del = append(del, rbacSyncIDPGroupsRole()...)
	}

	return objs, del
}

func modifyKubeControllersDeployment(ri render.Inputs, dp *appsv1.Deployment, data installationRenderData) {
	spec := &dp.Spec.Template.Spec
	if dp.Spec.Template.Annotations == nil {
		dp.Spec.Template.Annotations = map[string]string{}
	}

	if tls := data.kubeControllerTLS; tls != nil {
		spec.Volumes = append(spec.Volumes, tls.Volume())
		dp.Spec.Template.Annotations[tls.HashAnnotationKey()] = tls.HashAnnotationValue()
	}
	if waf := data.waf; waf.enabled && waf.webhookTLS != nil {
		spec.Volumes = append(spec.Volumes, waf.webhookTLS.Volume())
	}

	{
		c := render.MustContainer(spec, kubecontrollers.KubeController)

		appendEnabledControllers(c, data.kubeControllerControllers)
		c.Env = append(c.Env, enterpriseEnv(ri)...)

		if tls := data.kubeControllerTLS; tls != nil {
			c.Env = append(c.Env,
				corev1.EnvVar{Name: "TLS_KEY_PATH", Value: tls.VolumeMountKeyFilePath()},
				corev1.EnvVar{Name: "TLS_CRT_PATH", Value: tls.VolumeMountCertificateFilePath()},
				corev1.EnvVar{Name: "CLIENT_COMMON_NAME", Value: monitor.PrometheusClientTLSSecretName},
			)
			c.VolumeMounts = append(c.VolumeMounts, tls.VolumeMount(rmeta.OSTypeLinux))
			if tls.UseCertificateManagement() {
				spec.InitContainers = append(spec.InitContainers, tls.InitContainer(common.CalicoNamespace, c.SecurityContext))
			}
		}

		// The applicationlayer WAF reconcilers are wired whenever the GatewayAPI CR is
		// present (see calicoKubeControllersEnterpriseControllers), so they can tear
		// down the EnvoyExtensionPolicies they generated when WAF is disabled.
		// WAF_GATEWAY_EXTENSION_ENABLED tells them whether to program (enabled) or
		// de-program (disabled) - EV-6751. Absent => the reconciler defaults to enabled,
		// so an older operator that predates this var is unaffected.
		if data.waf.gatewayAPIPresent {
			c.Env = append(c.Env, corev1.EnvVar{Name: "WAF_GATEWAY_EXTENSION_ENABLED", Value: strconv.FormatBool(data.waf.enabled)})
		}

		if waf := data.waf; waf.enabled {
			c.Env = append(c.Env, wafEnv(waf)...)
			c.Ports = append(c.Ports, corev1.ContainerPort{
				Name:          "waf-webhook",
				ContainerPort: applicationlayer.WAFWebhookContainerPort,
				Protocol:      corev1.ProtocolTCP,
			})
			if waf.webhookTLS != nil {
				c.VolumeMounts = append(c.VolumeMounts, waf.webhookTLS.VolumeMount(rmeta.OSTypeLinux))
				if waf.webhookTLS.UseCertificateManagement() {
					spec.InitContainers = append(spec.InitContainers, waf.webhookTLS.InitContainer(common.CalicoNamespace, c.SecurityContext))
				}
			}
		}
	}
}

// appendEnabledControllers folds the enterprise controllers into the existing
// ENABLED_CONTROLLERS env the base render set (node,loadbalancer).
func appendEnabledControllers(c *corev1.Container, extra []string) {
	if len(extra) == 0 {
		return
	}
	for i := range c.Env {
		if c.Env[i].Name == "ENABLED_CONTROLLERS" {
			c.Env[i].Value = c.Env[i].Value + "," + strings.Join(extra, ",")
			return
		}
	}
}

// enterpriseEnv is the static enterprise env for calico-kube-controllers. The
// modifier runs only for the enterprise variant, so these are never rendered for core.
func enterpriseEnv(ri render.Inputs) []corev1.EnvVar {
	var env []corev1.EnvVar
	if ri.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: ri.TrustedBundle.MountPath()})
	}
	if in := ri.Installation; in != nil && in.CalicoNetwork != nil && in.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: in.CalicoNetwork.MultiInterfaceMode.Value()})
	}
	return env
}

// wafEnv is the WAF v3 env the kube-controllers binary consumes to program WAF policy
// attachments. WASM_IMAGE is the pre-resolved reference the hook produced.
func wafEnv(waf wafRenderData) []corev1.EnvVar {
	var env []corev1.EnvVar
	if waf.wasmImage != "" {
		env = append(env, corev1.EnvVar{Name: "WASM_IMAGE", Value: waf.wasmImage})
	}
	if waf.pullSecret != nil {
		env = append(env, corev1.EnvVar{Name: "WASM_PULL_SECRET", Value: waf.pullSecret.Name})
	}
	if waf.caCert != nil {
		env = append(env, corev1.EnvVar{Name: "WASM_CA_CERT", Value: waf.caCert.Name})
	}
	if waf.webhookTLS != nil {
		env = append(env, corev1.EnvVar{Name: "WAF_WEBHOOK_CERT_DIR", Value: filepath.Dir(waf.webhookTLS.VolumeMountCertificateFilePath())})
	}
	return env
}

const (
	// WASMPullSecretName is the dedicated image-pull Secret (a merged copy of the
	// install pull secrets) the WAF reconciler replicates into tenant namespaces for
	// the Coraza wasm OCI pull. A dedicated name avoids clashing with the
	// operator-managed tigera-pull-secret the GatewayAPI render also copies there (EV-6386).
	WASMPullSecretName = "tigera-waf-pull-secret"

	// WASMCACertName is the dedicated CA-bundle ConfigMap the WAF reconciler
	// replicates into tenant namespaces for the Coraza wasm OCI registry TLS check -
	// a dedicated name avoids clashing with the operator-managed tigera-ca-bundle the
	// GatewayAPI render also copies there (EV-6386). It is a renamed copy of the trusted bundle.
	WASMCACertName = "tigera-waf-ca-bundle"
)

// calicoKubeControllersEnterpriseRules are the enterprise cluster role rules layered
// onto calico-kube-controllers: the shared enterprise rules plus the calico-specific
// ones (federated endpoints, license usage reporting), and the rbacsync controller
// rules when RBAC management is enabled.
func calicoKubeControllersEnterpriseRules(gatewayAPIPresent, managedCluster, rbacManagementEnabled bool) []rbacv1.PolicyRule {
	rules := entkubecontrollers.KubeControllersEnterpriseCommonRules(gatewayAPIPresent, managedCluster)
	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"remoteclusterconfigurations"},
			Verbs:     []string{"watch", "list", "get"},
		},
		rbacv1.PolicyRule{
			// The node controller's IPAM syncer watches Networks to reserve their subnet edges.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"watch", "list", "get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"endpoints"},
			Verbs:     []string{"create", "update", "delete"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"usage.tigera.io"},
			Resources: []string{"licenseusagereports"},
			Verbs:     []string{"create", "update", "delete", "watch", "list", "get"},
		},
	)
	if rbacManagementEnabled {
		rules = append(rules, rbacSyncControllerRules()...)
	}
	return rules
}

// calicoKubeControllersEnterpriseControllers are the enterprise controllers added to
// the calico-kube-controllers ENABLED_CONTROLLERS list (on top of the base
// node,loadbalancer). applicationlayer is wired whenever the GatewayAPI CR is present,
// not only when WAF is enabled, so it stays running and can tear down the
// EnvoyExtensionPolicies it generated when WAF is disabled (it de-programs vs programs
// based on WAF_GATEWAY_EXTENSION_ENABLED - EV-6751). rbacsync is added only when RBAC
// management is enabled.
func calicoKubeControllersEnterpriseControllers(gatewayAPIPresent, rbacManagementEnabled bool) []string {
	controllers := []string{"service", "federatedservices", "usage"}
	if gatewayAPIPresent {
		controllers = append(controllers, "applicationlayer")
	}
	if rbacManagementEnabled {
		controllers = append(controllers, "rbacsync")
	}
	return controllers
}

// rbacSyncIDPGroupsRole returns the Role + RoleBinding that grants rbacsync
// read access to the tigera-idp-groups ConfigMap in calico-system, its only
// namespaced dependency.
func rbacSyncIDPGroupsRole() []client.Object {
	name := "calico-kube-controllers-rbac-sync"
	return []client.Object{
		&rbacv1.Role{
			TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: common.CalicoNamespace},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					ResourceNames: []string{"tigera-idp-groups"},
					Verbs:         []string{"get", "list", "watch"},
				},
			},
		},
		&rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: common.CalicoNamespace},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      kubecontrollers.KubeControllerServiceAccount,
					Namespace: common.CalicoNamespace,
				},
			},
		},
	}
}

// rbacSyncControllerRules returns the cluster-scoped rules the rbacsync
// controller holds. The controller reconciles the ClusterRoles that back the
// Manager UI's RBAC management feature, and each rule below lets it manage the
// access one Calico Enterprise UI feature (and its view or modify state)
// requires. The controller runs only when RBAC management is enabled.
//
// Under Kubernetes' privilege-escalation guard the controller can only grant
// permissions it already holds, so each rule mirrors a grant made by one of the
// managed calico-ui-* ClusterRoles the rbacsync controller generates in
// calico-private (kube-controllers/pkg/controllers/rbacsync: resourceroles.go
// defines the calico-ui-<feature>-{view,mod} and calico-ui-logs-view-* roles,
// tierroles.go the calico-ui-{np,gnp}-{view,mod}-<tier> and calico-ui-cluster-
// context roles). The comment on each rule names the managed role(s) it covers.
//
// Only the grants unique to the managed roles live here. Core resources those
// roles also grant (namespaces, nodes, services, pods, clusterinformations,
// hostendpoints, serviceaccounts, tiers) are already held by the common
// kube-controllers rules above, which satisfy the escalation guard for them.
func rbacSyncControllerRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		// RBAC management: the ClusterRoles and bindings the controller
		// reconciles for the feature. Not a mirrored grant — this is the
		// controller's own reconcile target for every managed calico-ui-* role.
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "clusterrolebindings", "rolebindings"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Network Policy tiers, view and modify: the per-tier and all-tiers
		// Policies and Global Policies roles cover the tiers and tier-scoped
		// (tier.*) policy resources. The plain networkpolicies and
		// stagednetworkpolicies come from Policy Recommendations, which
		// references them directly. Mirrors calico-ui-{np,gnp}-{view,mod}-<tier>
		// (and -all), calico-ui-get-tier-* and calico-ui-policy-recommendations-
		// {view,mod}.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
				"tier.networkpolicies",
				"tier.stagednetworkpolicies",
				"tier.globalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"networkpolicies",
				"stagednetworkpolicies",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Network Policy tiers, view and modify: Kubernetes network policies
		// within a tier. Mirrors calico-ui-np-{view,mod}-<tier> (and -all).
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// The per-feature pages, view and modify: Dashboards, Managed Clusters,
		// Global Network Sets, Network Sets, Policy Recommendations, Packet
		// Captures, Alerts and Security Events, Threat Feeds, Compliance
		// Reports, Webhooks, Deep Packet Inspection, and Egress Gateways.
		// Mirrors the matching calico-ui-<feature>-{view,mod} roles
		// (e.g. calico-ui-managed-clusters-{view,mod}, calico-ui-alerts-
		// {view,mod}, calico-ui-egress-gateways-{view,mod}).
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"uisettings",
				"uisettingsgroups",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"deeppacketinspections",
				"deeppacketinspections/status",
				"egressgatewaypolicies",
				"externalnetworks",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"alertexceptions",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"globalreports",
				"globalreports/status",
				"globalreporttypes",
				"packetcaptures",
				"packetcaptures/files",
				"securityeventwebhooks",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Dashboards, view and modify: the cluster-settings and user-settings
		// dashboard layouts stored on the UISettingsGroups data subresource.
		// Mirrors calico-ui-dashboards-{view,mod}.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettingsgroups/data"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		// Manager UI load: the authorization self-check the UI runs on load.
		// Packet Captures: authenticating a capture-file download. Mirrors the
		// authorizationreviews grant on calico-ui-cluster-context and the
		// authenticationreviews grant on calico-ui-packet-captures-{view,mod}.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authorizationreviews", "authenticationreviews"},
			Verbs:     []string{"create"},
		},
		// Manager UI load: Felix configuration read for cluster-wide settings.
		// Mirrors calico-ui-cluster-context.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Webhooks, modify: creating and updating the Secret that stores the
		// webhook credentials. Mirrors calico-ui-webhooks-mod.
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{"webhooks-secret"},
			Verbs:         []string{"patch"},
		},
		// Logs, view: Flow, DNS, Audit, L7, and Events log access, per managed
		// cluster and for the management cluster. Mirrors calico-ui-logs-view-*
		// (all/audit/dns/events/flows/l7, plus their per-cluster and
		// all-clusters variants).
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"cluster"},
			Verbs:     []string{"get"},
		},
		// Manager UI load: the Compliance feature-enabled check. Mirrors the
		// unscoped compliances grant on calico-ui-cluster-context. (The
		// calico-ui-compliance-reports-{view,mod} roles also read compliances
		// but scope it to the tigera-secure CR; this rule must stay unscoped to
		// cover cluster-context, whose feature check is not resource-scoped.)
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"compliances"},
			Verbs:     []string{"get"},
		},
		// Manager UI load: feature-enabled checks for Application Layer / WAF,
		// Packet Capture, and Intrusion Detection. Mirrors calico-ui-cluster-
		// context (which bundles the compliances check above into the same rule).
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "intrusiondetections"},
			Verbs:     []string{"get"},
		},
		// Global Network Sets and Network Sets, view and modify: listing the
		// pods a network set selects. Mirrors the pods grant on calico-ui-
		// {global-network-sets,network-sets}-{view,mod} and calico-ui-service-
		// graph-{view,mod}. (The common kube-controllers rules above already
		// grant pods get/list/watch for IPAM GC, so this is also covered there.)
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		// Service Graph: the service accounts the flow view references. The only
		// managed role granting serviceaccounts, so mirrors calico-ui-service-
		// graph-{view,mod}. (That role also grants services, namespaces and
		// hostendpoints, all covered by the common kube-controllers rules above.)
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"get", "list"},
		},
		// Manager UI load: the statistics proxy to the Calico API server and
		// the node Prometheus. Mirrors calico-ui-cluster-context.
		{
			APIGroups:     []string{""},
			Resources:     []string{"services/proxy"},
			ResourceNames: []string{"https:calico-api:8080", "calico-node-prometheus:9090"},
			Verbs:         []string{"get", "create"},
		},
	}
}

// wafRenderData is the controller-produced WAF v3 (Gateway API add-on) state the
// installation hook hands the kube-controllers modifier through the render inputs.
// The zero value (both flags false) means the modifier deletes the webhook objects
// and wires none of the WAF surface.
//
// The two flags are deliberately distinct (EV-6751). gatewayAPIPresent means the
// GatewayAPI CR exists regardless of waf.state; it keeps the applicationlayer
// controller wired, its EnvoyExtensionPolicy RBAC in place, and the
// WAF_GATEWAY_EXTENSION_ENABLED env present, so the controller can tear down the
// EnvoyExtensionPolicies it generated when WAF is turned off instead of losing its
// RBAC in the same reconcile. enabled means waf.state == Enabled and gates the
// active surface: the admission webhook, its serving cert, and the WASM env.
type wafRenderData struct {
	gatewayAPIPresent bool
	enabled           bool
	wasmImage         string
	pullSecret        *corev1.Secret
	caCert            *corev1.ConfigMap
	webhookTLS        certificatemanagement.KeyPairInterface
	caBundle          []byte
}

// buildWAFData reads the GatewayAPI CR and, when the WAF extension is enabled,
// produces everything the modifier needs that it can't compute itself: the resolved
// wasm image, the webhook serving keypair (also returned as a managed keypair), the
// merged wasm pull secret, the wasm CA bundle ConfigMap, and the operator CA PEM.
func buildWAFData(ctx context.Context, ci controller.Inputs) (wafRenderData, certificatemanagement.KeyPairInterface, error) {
	gw, msg, err := gatewayapi.GetGatewayAPI(ctx, ci.Client)
	if err != nil && !apierrors.IsNotFound(err) {
		if msg != "" {
			return wafRenderData{}, nil, extensions.Degradedf(operatorv1.ResourceReadError, "%s: %w", msg, err)
		}
		return wafRenderData{}, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading GatewayAPI: %w", err)
	}
	if gw == nil {
		return wafRenderData{}, nil, nil
	}
	// The GatewayAPI CR exists. Keep the WAF controller wired and its RBAC/env
	// present even while WAF is disabled, so kube-controllers can tear down the
	// EnvoyExtensionPolicies it generated (EV-6751). The active surface below is
	// gated separately on waf.state == Enabled.
	if !gw.Spec.IsWAFGatewayExtensionEnabled() {
		return wafRenderData{gatewayAPIPresent: true}, nil, nil
	}

	in := ci.RenderInputs.Installation
	// The wasm is baked into the gateway envoy-proxy image. Resolve it with the same
	// GetReference the base render uses for every image; the hook has the ImageSet here.
	imageSet, err := imageset.GetImageSet(ctx, ci.Client, in.Variant)
	if err != nil {
		return wafRenderData{}, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error getting ImageSet: %w", err)
	}
	wasmImage, err := components.GetReference(components.ComponentGatewayAPIEnvoyProxy, in.Registry, in.ImagePath, in.ImagePrefix, imageSet)
	if err != nil {
		return wafRenderData{}, nil, extensions.Degradedf(operatorv1.ResourceUpdateError, "error with images from ImageSet: %w", err)
	}

	webhookTLS, err := ci.CertificateManager.GetOrCreateKeyPair(
		ci.Client,
		applicationlayer.WAFWebhookServerTLSSecretName,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(applicationlayer.WAFWebhookServiceName, common.CalicoNamespace, ci.RenderInputs.ClusterDomain),
	)
	if err != nil {
		return wafRenderData{}, nil, extensions.Degradedf(operatorv1.ResourceCreateError, "error creating the WAF admission webhook TLS certificate: %w", err)
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(in, ci.Client)
	if err != nil {
		return wafRenderData{}, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error retrieving pull secrets: %w", err)
	}
	var pullSecret *corev1.Secret
	if len(pullSecrets) > 0 {
		pullSecret, _ = MergeWAFPullSecret(pullSecrets)
	}

	var caCert *corev1.ConfigMap
	if ci.RenderInputs.TrustedBundle != nil {
		caCert = ci.RenderInputs.TrustedBundle.ConfigMap(common.CalicoNamespace)
		caCert.Name = WASMCACertName
	}

	return wafRenderData{
		gatewayAPIPresent: true,
		enabled:           true,
		wasmImage:         wasmImage,
		pullSecret:        pullSecret,
		caCert:            caCert,
		webhookTLS:        webhookTLS,
		caBundle:          ci.CertificateManager.KeyPair().GetCertificatePEM(),
	}, webhookTLS, nil
}

// MergeWAFPullSecret synthesizes the dedicated WAF wasm pull secret
// (tigera-waf-pull-secret) by merging the registry auths of every Installation pull
// secret. The EnvoyExtensionPolicy image source takes a single pullSecretRef, so a
// merged secret is the only way to honor multiple Installation pull secrets for the
// Coraza wasm OCI pull (e.g. the Tigera pull secret plus a private registry mirror).
//
// If the same registry appears in more than one secret, the first secret in
// Installation order wins. Secrets that cannot be parsed are skipped and their names
// returned, so the caller can log them without failing the reconcile. Returns a nil
// Secret when no registry auths could be collected.
func MergeWAFPullSecret(pullSecrets []*corev1.Secret) (*corev1.Secret, []string) {
	merged := map[string]json.RawMessage{}
	var skipped []string
	for _, s := range pullSecrets {
		auths, err := registryAuths(s)
		if err != nil {
			skipped = append(skipped, s.Name)
			continue
		}
		for registry, auth := range auths {
			if _, ok := merged[registry]; !ok {
				merged[registry] = auth
			}
		}
	}
	if len(merged) == 0 {
		return nil, skipped
	}

	// Marshalling a map sorts its keys, so the rendered bytes are deterministic and
	// do not churn the object on every reconcile.
	data, err := json.Marshal(map[string]map[string]json.RawMessage{"auths": merged})
	if err != nil {
		// Each auth entry round-trips from a successful Unmarshal above, so this
		// cannot fail in practice; treat it as nothing to render.
		return nil, skipped
	}

	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WASMPullSecretName, Namespace: common.CalicoNamespace},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: data},
	}, skipped
}

// registryAuths extracts the per-registry auth entries from a pull secret of either
// the dockerconfigjson type (auths nested under an "auths" key) or the legacy
// dockercfg type (a bare registry -> auth map).
func registryAuths(s *corev1.Secret) (map[string]json.RawMessage, error) {
	if raw, ok := s.Data[corev1.DockerConfigJsonKey]; ok {
		var cfg struct {
			Auths map[string]json.RawMessage `json:"auths"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, err
		}
		if len(cfg.Auths) == 0 {
			return nil, fmt.Errorf("secret %s has no auths entries", s.Name)
		}
		return cfg.Auths, nil
	}
	if raw, ok := s.Data[corev1.DockerConfigKey]; ok {
		var auths map[string]json.RawMessage
		if err := json.Unmarshal(raw, &auths); err != nil {
			return nil, err
		}
		if len(auths) == 0 {
			return nil, fmt.Errorf("secret %s has no auths entries", s.Name)
		}
		return auths, nil
	}
	return nil, fmt.Errorf("secret %s has neither a %s nor a %s key", s.Name, corev1.DockerConfigJsonKey, corev1.DockerConfigKey)
}
