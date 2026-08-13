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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/webhooks"
)

// modifyWebhooks adds the management-cluster behavior the base render omits: the
// ManagedCluster webhook, its flags, and the tunnel secret RBAC.
func modifyWebhooks(cfg *webhooks.Configuration, managementCluster *operatorv1.ManagementCluster, multiTenant bool, create, del []client.Object) ([]client.Object, []client.Object) {
	if managementCluster == nil {
		// Not a management cluster, so clean up the tunnel secret RBAC.
		return create, append(del, tunnelSecretRBACMeta()...)
	}

	if dep, ok := extensions.FindObject[*appsv1.Deployment](create, webhooks.WebhooksName); ok {
		ctr := render.MustContainer(&dep.Spec.Template.Spec, webhooks.WebhooksName)
		ctr.Args = append(ctr.Args, managedClusterArgs(managementCluster, multiTenant)...)
	}
	if mwc, ok := extensions.FindObject[*admregv1.MutatingWebhookConfiguration](create, "api.projectcalico.org"); ok {
		mwc.Webhooks = append(mwc.Webhooks, managedClusterWebhook(cfg))
	}
	create = append(create, render.TunnelSecretRBAC(webhooks.WebhooksSecretsRBACName, webhooks.WebhooksName, managementCluster, multiTenant)...)

	return create, del
}

// cleanupWebhooks deletes the tunnel secret RBAC a prior Enterprise installation left
// behind.
func cleanupWebhooks(create, del []client.Object) ([]client.Object, []client.Object) {
	return create, append(del, tunnelSecretRBACMeta()...)
}

// managedClusterArgs are the flags the ManagedCluster webhook needs to generate the
// installation manifest with the correct tunnel address and certs.
func managedClusterArgs(mc *operatorv1.ManagementCluster, multiTenant bool) []string {
	var args []string
	if mc.Spec.Address != "" {
		args = append(args, fmt.Sprintf("--mcm-management-cluster-addr=%s", mc.Spec.Address))
	}
	args = append(args, fmt.Sprintf("--mcm-tunnel-secret-name=%s", render.TunnelSecretName(mc)))
	if mc.Spec.TLS != nil && mc.Spec.TLS.SecretName == render.ManagerTLSSecretName {
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
