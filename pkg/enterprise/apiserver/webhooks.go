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

package apiserver

import (
	"fmt"

	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/webhooks"
)

const (
	// webhookConfigName is shared by the validating and mutating webhook configurations.
	webhookConfigName = "api.projectcalico.org"

	webhookAuditLogVolumeName = "audit-logs"
	webhookAuditLogPath       = "/var/log/calico/audit"
)

// modifyWebhooks layers audit logging, the mutating webhooks, the extra RBAC, and
// management-cluster support onto the rendered objects.
func modifyWebhooks(cfg *webhooks.Configuration, mc *operatorv1.ManagementCluster, multiTenant bool, create, del []client.Object) ([]client.Object, []client.Object) {
	dep := extensions.MustFindObject[*appsv1.Deployment](create, webhooks.WebhooksName)
	enableAuditLogging(dep, cfg.Installation)

	vwc := extensions.MustFindObject[*admregv1.ValidatingWebhookConfiguration](create, webhookConfigName)
	vwc.Webhooks = append(vwc.Webhooks, auditLoggingWebhook(cfg))

	cr := extensions.MustFindObject[*rbacv1.ClusterRole](create, webhooks.WebhooksName)
	cr.Rules = append(cr.Rules, enterpriseRules()...)

	mwc := mutatingWebhookConfiguration(cfg)
	if mc == nil {
		// Not a management cluster, so clean up the tunnel secret RBAC.
		return append(create, mwc), append(del, tunnelSecretRBACMeta()...)
	}

	ctr := render.MustContainer(&dep.Spec.Template.Spec, webhooks.WebhooksName)
	ctr.Args = append(ctr.Args, managedClusterArgs(mc, multiTenant)...)
	mwc.Webhooks = append(mwc.Webhooks, managedClusterWebhook(cfg))
	create = append(create, mwc)
	create = append(create, render.TunnelSecretRBAC(webhooks.WebhooksSecretsRBACName, webhooks.WebhooksName, tunnelSecretName(mc), multiTenant)...)

	return create, del
}

// cleanupWebhooks deletes the mutating webhooks and tunnel secret RBAC a prior Enterprise
// installation left behind.
func cleanupWebhooks(create, del []client.Object) ([]client.Object, []client.Object) {
	del = append(del, &admregv1.MutatingWebhookConfiguration{
		TypeMeta:   metav1.TypeMeta{Kind: "MutatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: webhookConfigName},
	})
	return create, append(del, tunnelSecretRBACMeta()...)
}

// enableAuditLogging gives the webhook container the root context and host mount it needs
// to write audit logs to the node.
func enableAuditLogging(dep *appsv1.Deployment, installation *operatorv1.InstallationSpec) {
	podSpec := &dep.Spec.Template.Spec
	ctr := render.MustContainer(podSpec, webhooks.WebhooksName)
	ctr.SecurityContext = securitycontext.NewRootContext(installation.KubernetesProvider.IsOpenShift())
	ctr.VolumeMounts = append(ctr.VolumeMounts, corev1.VolumeMount{
		Name:      webhookAuditLogVolumeName,
		MountPath: webhookAuditLogPath,
	})
	podSpec.Volumes = append(podSpec.Volumes, corev1.Volume{
		Name: webhookAuditLogVolumeName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: webhookAuditLogPath,
				Type: ptr.To(corev1.HostPathDirectoryOrCreate),
			},
		},
	})
}

// auditLoggingWebhook feeds every v3 write to the /audit handler, which only Enterprise
// serves.
func auditLoggingWebhook(cfg *webhooks.Configuration) admregv1.ValidatingWebhook {
	return admregv1.ValidatingWebhook{
		Name: "audit-logging.api.projectcalico.org",
		Rules: []admregv1.RuleWithOperations{
			{
				Operations: []admregv1.OperationType{
					admregv1.Create,
					admregv1.Update,
					admregv1.Delete,
					admregv1.Connect,
				},
				Rule: admregv1.Rule{
					APIGroups:   []string{"projectcalico.org"},
					APIVersions: []string{"v3"},
					Resources:   []string{"*"},
					Scope:       ptr.To(admregv1.AllScopes),
				},
			},
		},
		ClientConfig: admregv1.WebhookClientConfig{
			Service: &admregv1.ServiceReference{
				Namespace: common.CalicoNamespace,
				Name:      webhooks.WebhooksName,
				Path:      ptr.To("/audit"),
			},
			CABundle: cfg.KeyPair.GetCertificatePEM(),
		},
		AdmissionReviewVersions: []string{"v1"},
		SideEffects:             ptr.To(admregv1.SideEffectClassNone),
		TimeoutSeconds:          ptr.To(int32(5)),
		FailurePolicy:           ptr.To(admregv1.Ignore),
		MatchPolicy:             ptr.To(admregv1.Exact),
	}
}

// mutatingWebhookConfiguration holds the Enterprise mutating webhooks, none of which have a
// Calico counterpart.
func mutatingWebhookConfiguration(cfg *webhooks.Configuration) *admregv1.MutatingWebhookConfiguration {
	return &admregv1.MutatingWebhookConfiguration{
		TypeMeta:   metav1.TypeMeta{Kind: "MutatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: webhookConfigName},
		Webhooks:   []admregv1.MutatingWebhook{uiSettingsWebhook(cfg)},
	}
}

// uiSettingsWebhook sets owner references and user fields on UISettings, and authorizes
// every operation against the parent UISettingsGroup.
func uiSettingsWebhook(cfg *webhooks.Configuration) admregv1.MutatingWebhook {
	return admregv1.MutatingWebhook{
		Name: "uisettings.api.projectcalico.org",
		Rules: []admregv1.RuleWithOperations{
			{
				Operations: []admregv1.OperationType{
					admregv1.Create,
					admregv1.Update,
					admregv1.Delete,
				},
				Rule: admregv1.Rule{
					APIGroups:   []string{"projectcalico.org"},
					APIVersions: []string{"v3"},
					Resources:   []string{"uisettings"},
					Scope:       ptr.To(admregv1.AllScopes),
				},
			},
		},
		ClientConfig: admregv1.WebhookClientConfig{
			Service: &admregv1.ServiceReference{
				Namespace: common.CalicoNamespace,
				Name:      webhooks.WebhooksName,
				Path:      ptr.To("/uisettings"),
			},
			CABundle: cfg.KeyPair.GetCertificatePEM(),
		},
		AdmissionReviewVersions: []string{"v1"},
		SideEffects:             ptr.To(admregv1.SideEffectClassNone),
		TimeoutSeconds:          ptr.To(int32(10)),
		FailurePolicy:           ptr.To(admregv1.Fail),
		MatchPolicy:             ptr.To(admregv1.Exact),
	}
}

// enterpriseRules are the permissions the Enterprise-only webhook handlers need on top of
// the base webhook RBAC.
func enterpriseRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{
			// The ManagedCluster cleanup controller watches ManagedCluster objects and clears their
			// installation manifest field after creation.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"managedclusters"},
			Verbs:     []string{"list", "watch", "update"},
		},
		{
			// The UISettings webhook needs to GET UISettingsGroups to verify group existence
			// and build owner references when creating UISettings.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettingsgroups"},
			Verbs:     []string{"get"},
		},
	}
}

// managedClusterArgs are the flags the ManagedCluster webhook needs to generate the
// installation manifest with the correct tunnel address and certs.
func managedClusterArgs(mc *operatorv1.ManagementCluster, multiTenant bool) []string {
	var args []string
	if mc.Spec.Address != "" {
		args = append(args, fmt.Sprintf("--mcm-management-cluster-addr=%s", mc.Spec.Address))
	}
	secretName := tunnelSecretName(mc)
	args = append(args, fmt.Sprintf("--mcm-tunnel-secret-name=%s", secretName))
	if secretName == render.ManagerTLSSecretName {
		args = append(args, "--mcm-management-cluster-ca-type=Public")
	}
	if multiTenant {
		args = append(args, "--multi-tenant=true")
	}
	return args
}

// managedClusterWebhook generates the installation manifest (including tunnel certs) when a
// ManagedCluster CR is created.
func managedClusterWebhook(cfg *webhooks.Configuration) admregv1.MutatingWebhook {
	return admregv1.MutatingWebhook{
		Name: "managedclusters.api.projectcalico.org",
		Rules: []admregv1.RuleWithOperations{
			{
				Operations: []admregv1.OperationType{
					admregv1.Create,
				},
				Rule: admregv1.Rule{
					APIGroups:   []string{"projectcalico.org"},
					APIVersions: []string{"v3"},
					Resources:   []string{"managedclusters"},
					Scope:       ptr.To(admregv1.AllScopes),
				},
			},
		},
		ClientConfig: admregv1.WebhookClientConfig{
			Service: &admregv1.ServiceReference{
				Namespace: common.CalicoNamespace,
				Name:      webhooks.WebhooksName,
				Path:      ptr.To("/managedcluster"),
			},
			CABundle: cfg.KeyPair.GetCertificatePEM(),
		},
		AdmissionReviewVersions: []string{"v1"},
		SideEffects:             ptr.To(admregv1.SideEffectClassNone),
		TimeoutSeconds:          ptr.To(int32(10)),
		FailurePolicy:           ptr.To(admregv1.Fail),
	}
}

// tunnelSecretRBACMeta identifies the webhooks tunnel secret RBAC objects, in both their
// single-tenant and multi-tenant forms.
func tunnelSecretRBACMeta() []client.Object {
	return []client.Object{
		&rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksSecretsRBACName}},
		&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksSecretsRBACName}},
		&rbacv1.Role{TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksSecretsRBACName, Namespace: common.CalicoNamespace}},
		&rbacv1.RoleBinding{TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksSecretsRBACName, Namespace: common.CalicoNamespace}},
	}
}
