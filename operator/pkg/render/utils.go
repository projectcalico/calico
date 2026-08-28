// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package render

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
)

const (
	TigeraOperatorSecrets = "tigera-operator-secrets"
)

// LinseedNamespace determine the namespace in which Linseed is running.
// For management and standalone clusters, this is always the tigera-elasticsearch
// namespace. For multi-tenant management clusters, this is the tenant namespace
func LinseedNamespace(tenant *operatorv1.Tenant) string {
	if tenant.MultiTenant() {
		return tenant.Namespace
	}
	return ElasticsearchNamespace
}

// ManagerService determine the name of the calico manager service.
// For management and standalone clusters, this is always the calico-manager.calico-system
// namespace. For multi-tenant management clusters, this is a service that resides within the
// tenant namespace
func ManagerService(tenant *operatorv1.Tenant) string {
	if tenant.MultiTenant() {
		return fmt.Sprintf("https://%s.%s.svc:%d", ManagerServiceName, tenant.Namespace, ManagerPort)
	}
	return fmt.Sprintf("https://%s.%s.svc:%d", ManagerServiceName, ManagerNamespace, ManagerPort)
}

// CreateOperatorSecretsRoleBinding binds the tigera-operator-secrets ClusterRole to the operator's ServiceAccount
// in the given namespace, granting permission to manipulate secrets.
func CreateOperatorSecretsRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraOperatorSecrets,
			Namespace: namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     TigeraOperatorSecrets,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      common.OperatorServiceAccount(),
				Namespace: common.OperatorNamespace(),
			},
		},
	}
}
