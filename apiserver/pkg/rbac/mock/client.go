// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package mock

import (
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	log "github.com/sirupsen/logrus"

	core_v1 "k8s.io/api/core/v1"
	rbac_v1 "k8s.io/api/rbac/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

type MockClient struct {
	Roles               map[string][]rbac_v1.PolicyRule
	RoleBindings        map[string][]string
	ClusterRoles        map[string][]rbac_v1.PolicyRule
	ClusterRoleBindings []string
	Namespaces          []string
	Tiers               []string
	ResourcesQueries    int
}

func (m *MockClient) ServerPreferredResources() ([]*meta_v1.APIResourceList, error) {
	rl := []*meta_v1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []meta_v1.APIResource{
				{Name: "pods", Namespaced: true},
				{Name: "namespaces", Namespaced: false},
			},
		},
		{
			GroupVersion: "extensions/v1beta1",
			APIResources: []meta_v1.APIResource{
				{Name: "networkpolicies", Namespaced: true},
			},
		},
		{
			GroupVersion: "networking.k8s.io/v1",
			APIResources: []meta_v1.APIResource{
				{Name: "networkpolicies", Namespaced: true},
			},
		},
		{
			GroupVersion: "projectcalico.org/v3",
			APIResources: []meta_v1.APIResource{
				{Name: "hostendpoints", Namespaced: false},
				{Name: "tiers", Namespaced: false},
				{Name: "networkpolicies", Namespaced: true},
				{Name: "globalnetworkpolicies", Namespaced: false},
				{Name: "networksets", Namespaced: true},
				{Name: "globalnetworksets", Namespaced: false},
			},
		},

		// Add a fake resource with a resource name that clocks with the number of times this is invoked. This is used
		// to test recaching of the data.
		{
			GroupVersion: "fake/v3",
			APIResources: []meta_v1.APIResource{
				{Name: fmt.Sprintf("dummy%d", m.ResourcesQueries), Namespaced: true},
			},
		},
	}

	log.Debugf("Included resource dummy%d.fake", m.ResourcesQueries)
	m.ResourcesQueries++

	return rl, nil
}

func (m *MockClient) GetRole(namespace, name string) (*rbac_v1.Role, error) {
	rules := m.Roles[namespace+"/"+name]
	if rules == nil {
		log.Debug("GetRole returning error")
		return nil, fmt.Errorf("Role(%s/%s) does not exist", namespace, name)
	}

	log.Debug("GetRole returning no error")
	return &rbac_v1.Role{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Rules: rules,
	}, nil
}

func (m *MockClient) ListRoleBindings(namespace string) ([]*rbac_v1.RoleBinding, error) {
	if m.RoleBindings == nil {
		log.Debug("ListRoleBindings returning error")
		return nil, fmt.Errorf("no RoleBindings set")
	}

	names := m.RoleBindings[namespace]

	log.Debugf("ListRoleBindings returning %d results", len(names))
	bindings := make([]*rbac_v1.RoleBinding, len(names))
	for i, name := range names {
		kind := "ClusterRole"
		if name[0] == '/' {
			name = name[1:]
			kind = "Role"
		}
		bindings[i] = &rbac_v1.RoleBinding{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      fmt.Sprintf("role-binding-%d", i),
				Namespace: namespace,
			},
			Subjects: []rbac_v1.Subject{{
				Kind: "User",
				Name: "my-user",
			}},
			RoleRef: rbac_v1.RoleRef{
				Kind: kind,
				Name: name,
			},
		}
	}
	return bindings, nil
}

func (m *MockClient) GetClusterRole(name string) (*rbac_v1.ClusterRole, error) {
	rules := m.ClusterRoles[name]
	if rules == nil {
		log.Debug("GetClusterRole returning error")
		return nil, k8serrors.NewNotFound(schema.ParseGroupResource("clusterrole.rbac.authorization.k8s.io"), name)
	}

	log.Debug("GetClusterRole returning no error")
	return &rbac_v1.ClusterRole{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
		},
		Rules: rules,
	}, nil
}

func (m *MockClient) ListClusterRoleBindings() ([]*rbac_v1.ClusterRoleBinding, error) {
	if m.ClusterRoleBindings == nil {
		return nil, fmt.Errorf("no ClusterRoleBindings set")
	}

	names := m.ClusterRoleBindings
	log.Debugf("ListClusterRoleBindings returning %d results", len(names))

	bindings := make([]*rbac_v1.ClusterRoleBinding, len(names))
	for i, name := range names {
		bindings[i] = &rbac_v1.ClusterRoleBinding{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: fmt.Sprintf("clusterrole-binding-%d", i),
			},
			Subjects: []rbac_v1.Subject{{
				Kind: "User",
				Name: "my-user",
			}},
			RoleRef: rbac_v1.RoleRef{
				Kind: "ClusterRole",
				Name: name,
			},
		}
	}
	return bindings, nil
}

func (m *MockClient) ListNamespaces() ([]*core_v1.Namespace, error) {
	if m.Namespaces == nil {
		log.Debug("ListNamespaces returning error")
		return nil, fmt.Errorf("no Namespaces set")
	}
	log.Debugf("ListNamespaces returning %d results", len(m.Namespaces))
	namespaces := make([]*core_v1.Namespace, len(m.Namespaces))
	for i, name := range m.Namespaces {
		namespaces[i] = &core_v1.Namespace{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
			},
		}
	}
	return namespaces, nil
}

func (m *MockClient) ListTiers() ([]*v3.Tier, error) {
	if m.Tiers == nil {
		log.Debug("ListTiers returning error")
		return nil, fmt.Errorf("no Tiers set")
	}
	log.Debugf("ListTiers returning %d results", len(m.Tiers))
	tiers := make([]*v3.Tier, len(m.Tiers))
	for i, name := range m.Tiers {
		tiers[i] = &v3.Tier{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
			},
		}
	}
	return tiers, nil
}
