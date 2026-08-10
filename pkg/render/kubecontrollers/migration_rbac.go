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

package kubecontrollers

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
)

const (
	MigrationClusterRoleName        = "calico-kube-controllers-migration"
	migrationClusterRoleBindingName = "calico-kube-controllers-migration"
)

// migrationRBACObjects returns the ClusterRole and ClusterRoleBinding that grant
// calico-kube-controllers broad access to both API groups during a datastore migration.
// These permissions are time-bounded: they are only created while a DatastoreMigration
// CR exists and are automatically cleaned up when migration completes.
func migrationRBACObjects() []client.Object {
	return []client.Object{
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: MigrationClusterRoleName},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
					Resources: []string{"*"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{"apiregistration.k8s.io"},
					Resources: []string{"apiservices"},
					Verbs:     []string{"get", "list", "watch", "create", "delete"},
				},
				{
					APIGroups: []string{"apiextensions.k8s.io"},
					Resources: []string{"customresourcedefinitions"},
					Verbs:     []string{"get", "list", "watch", "delete"},
				},
				{
					// The migration controller checks calico-node and calico-typha for the
					// v3 API group env var and monitors their rollout status.
					APIGroups: []string{"apps"},
					Resources: []string{"daemonsets", "deployments"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					// Without this the migration controller reads the cluster as manifest
					// managed and tells the user to do the cutover by hand.
					APIGroups: []string{"operator.tigera.io"},
					Resources: []string{"installations"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: migrationClusterRoleBindingName},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     MigrationClusterRoleName,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "calico-kube-controllers",
					Namespace: common.CalicoNamespace,
				},
			},
		},
	}
}

// MigrationRBACComponent returns a render component that creates or deletes the
// migration RBAC. When migrationActive is true, kube-controllers needs broad
// access to both API groups to read v1 resources and write v3 resources.
// When false, the extra permissions are cleaned up.
func MigrationRBACComponent(migrationActive bool) render.Component {
	if migrationActive {
		return render.NewCreationPassthrough(migrationRBACObjects()...)
	}
	return render.NewDeletionPassthrough(migrationRBACObjects()...)
}
