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

package logcollector

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
)

func (c *fluentBitComponent) fluentBitServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.fluentBitNodeName(), Namespace: LogCollectorNamespace},
	}
}

func (c *fluentBitComponent) fluentBitClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.fluentBitName(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     c.fluentBitName(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      c.fluentBitNodeName(),
				Namespace: LogCollectorNamespace,
			},
		},
	}
}

func (c *fluentBitComponent) fluentBitClusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.fluentBitName(),
		},
		Rules: []rbacv1.PolicyRule{linseedWriteRule()},
	}

	if c.cfg.Installation.KubernetesProvider.IsOpenShift() {
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.Privileged},
		})
	}
	return role
}

// linseedWriteRule grants create on every Linseed log API a log collector ships to.
func linseedWriteRule() rbacv1.PolicyRule {
	return rbacv1.PolicyRule{
		APIGroups: []string{"linseed.tigera.io"},
		Resources: []string{
			"flowlogs",
			"kube_auditlogs",
			"ee_auditlogs",
			"dnslogs",
			"l7logs",
			"events",
			"bgplogs",
			"waflogs",
			"runtimereports",
			"policyactivity",
		},
		Verbs: []string{"create"},
	}
}

// legacyLogCollectorClientClusterRole grants the Linseed write access needed by a fluentd
// log collector.
func (c *fluentBitComponent) legacyLogCollectorClientClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: legacyLogCollectorClientName},
		Rules:      []rbacv1.PolicyRule{linseedWriteRule()},
	}
}

// legacyLogCollectorClientClusterRoleBinding binds the fluentd service accounts of managed
// clusters. Linseed resolves a managed-cluster client to
// system:serviceaccount:<namespace>:<name> and runs the SubjectAccessReview against this
// cluster, so these names need a local binding even though nothing by those names runs
// here. A managed cluster's token carries its own cluster ID, so the binding cannot widen
// what any one cluster may write.
func (c *fluentBitComponent) legacyLogCollectorClientClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return legacyClientClusterRoleBinding(legacyLogCollectorClientName, legacyFluentdNodeName, legacyFluentdNodeWindowsName)
}

// legacyEKSLogForwarderClientClusterRole and ...Binding do the same for a
// fluentd-era EKS log forwarder, which had narrower access than the node
// collectors.
func (c *fluentBitComponent) legacyEKSLogForwarderClientClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: legacyEKSLogForwarderClientName},
		Rules:      eksLogForwarderLinseedRules(),
	}
}

func (c *fluentBitComponent) legacyEKSLogForwarderClientClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return legacyClientClusterRoleBinding(legacyEKSLogForwarderClientName, EKSLogForwarderName)
}

func legacyClientClusterRoleBinding(name string, serviceAccounts ...string) *rbacv1.ClusterRoleBinding {
	subjects := make([]rbacv1.Subject, 0, len(serviceAccounts))
	for _, sa := range serviceAccounts {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      sa,
			Namespace: legacyFluentdNamespace,
		})
	}

	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     name,
		},
		Subjects: subjects,
	}
}
