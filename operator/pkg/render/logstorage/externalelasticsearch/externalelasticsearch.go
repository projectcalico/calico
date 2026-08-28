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

package externalelasticsearch

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

// ExternalElasticsearch is used when Elasticsearch doesn't exist in this cluster, but we still need to set up resources
// related to Elasticsearch in the cluster.
func ExternalElasticsearch(install *operatorv1.InstallationSpec, clusterConfig *relasticsearch.ClusterConfig, pullSecrets []*corev1.Secret, multiTenant bool) render.Component {
	return &externalElasticsearch{
		installation:  install,
		clusterConfig: clusterConfig,
		pullSecrets:   pullSecrets,
		multiTenant:   multiTenant,
	}
}

type externalElasticsearch struct {
	installation  *operatorv1.InstallationSpec
	clusterConfig *relasticsearch.ClusterConfig
	pullSecrets   []*corev1.Secret
	multiTenant   bool
}

func (e externalElasticsearch) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (e externalElasticsearch) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, e.clusterConfig.ConfigMap())
	toCreate = append(toCreate, e.oidcUserRole())
	toCreate = append(toCreate, e.oidcUserRoleBinding())

	if !e.multiTenant {
		// We need to allow to es-kube-controllers to managed secrets in the management clusters
		// before pushing the Linseed - Voltron certificate to the tunnel. This certificate is pushed
		// from es-kube-controllers for Single Tenant Management cluster. These types of cluster
		// are using external ES. Similar RBAC is created in logstorage renderer that gets executed
		// for management clusters with zero tenants or single tenant management clusters with internal
		// elasticsearch
		roles, bindings := e.kubeControllersRolesAndBindings()
		for _, r := range roles {
			toCreate = append(toCreate, r)
		}
		for _, b := range bindings {
			toCreate = append(toCreate, b)
		}
	}

	return toCreate, toDelete
}

func (e externalElasticsearch) Ready() bool {
	return true
}

func (e externalElasticsearch) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e externalElasticsearch) oidcUserRole() client.Object {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.EsManagerRole,
			Namespace: render.ElasticsearchNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{render.OIDCUsersConfigMapName},
				Verbs:         []string{"update", "patch"},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{render.OIDCUsersESSecretName},
				Verbs:         []string{"get", "list"},
			},
		},
	}
}

func (e externalElasticsearch) oidcUserRoleBinding() client.Object {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.EsManagerRoleBinding,
			Namespace: render.ElasticsearchNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     render.EsManagerRole,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.ManagerServiceAccount,
				Namespace: render.ManagerNamespace,
			},
		},
	}
}

func (e externalElasticsearch) kubeControllersRolesAndBindings() ([]*rbacv1.Role, []*rbacv1.RoleBinding) {

	secretsRole := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.CalicoKubeControllerSecret,
			Namespace: render.ElasticsearchNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"create", "delete", "deletecollection", "update"},
			},
		},
	}

	operatorSecretsRole := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.CalicoKubeControllerSecret,
			Namespace: common.OperatorNamespace(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"create", "delete", "deletecollection", "update"},
			},
		},
	}

	secretBinding := &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.CalicoKubeControllerSecret,
			Namespace: render.ElasticsearchNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     render.CalicoKubeControllerSecret,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-kube-controllers",
				Namespace: common.CalicoNamespace,
			},
		},
	}

	// Bind the secrets permission to the operator namespace. This binding now adds permissions for kube controllers to manipulate
	// secrets in the tigera-operator namespace
	operatorSecretBinding := &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.CalicoKubeControllerSecret,
			Namespace: common.OperatorNamespace(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     render.CalicoKubeControllerSecret,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-kube-controllers",
				Namespace: common.CalicoNamespace,
			},
		},
	}

	return []*rbacv1.Role{secretsRole, operatorSecretsRole}, []*rbacv1.RoleBinding{secretBinding, operatorSecretBinding}
}
