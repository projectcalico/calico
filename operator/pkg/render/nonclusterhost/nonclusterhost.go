// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package nonclusterhost

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	NonClusterHostObjectName = "tigera-noncluster-host"
)

type Config struct {
	NonClusterHost operatorv1.NonClusterHostSpec
}

func NonClusterHost(cfg *Config) render.Component {
	return &nonClusterHostComponent{
		cfg: cfg,
	}
}

type nonClusterHostComponent struct {
	cfg *Config
}

func (c *nonClusterHostComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (c *nonClusterHostComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (c *nonClusterHostComponent) Objects() ([]client.Object, []client.Object) {
	toCreate := []client.Object{
		c.serviceAccount(),
		c.tokenSecret(),
		c.clusterRole(),
		c.clusterRoleBinding(),
	}
	return toCreate, nil
}

func (c *nonClusterHostComponent) Ready() bool {
	return true
}

func (c *nonClusterHostComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NonClusterHostObjectName,
			Namespace: common.CalicoNamespace,
		},
	}
}

func (c *nonClusterHostComponent) tokenSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NonClusterHostObjectName,
			Namespace: common.CalicoNamespace,
			// The annotation below will result in the auto-creation of spec.data.token.
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": NonClusterHostObjectName,
			},
		},
		Type: "kubernetes.io/service-account-token",
	}
}

func (c *nonClusterHostComponent) clusterRole() *rbacv1.ClusterRole {
	// Calico node rules
	rules := []rbacv1.PolicyRule{
		{
			// Calico uses endpoint slices for service-based network policy rules.
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"list", "watch"},
		},
		{
			// Used to discover Typha endpoints and service IPs for advertisement.
			APIGroups: []string{""},
			Resources: []string{"endpoints", "services"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			// For enforcing network policies.
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"watch", "list"},
		},
		{
			// For enforcing k8s cluster network policies.
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		{
			// Metadata from these are used in conjunction with network policy.
			APIGroups: []string{""},
			Resources: []string{"pods", "namespaces", "serviceaccounts"},
			Verbs:     []string{"watch", "list"},
		},
		{
			// Calico monitors nodes for some networking configuration.
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// For non-cluster host to get tigera-ca-bundle config map.
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get"},
		},
		{
			// For monitoring Calico-specific configuration.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"bfdconfigurations",
				"bgpconfigurations",
				"clusterinformations",
				"egressgatewaypolicies",
				"externalnetworks",
				"felixconfigurations",
				"globalnetworkpolicies",
				"globalnetworksets",
				"hostendpoints",
				"ipamblocks",
				"ippools",
				"licensekeys",
				"networkpolicies",
				"networks",
				"networksets",
				"packetcaptures",
				"remoteclusterconfigurations",
				"stagedglobalnetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"stagednetworkpolicies",
				"tiers",
			},
			Verbs: []string{"get", "list", "watch"},
		},
	}

	// Calico fluent-bit rules
	rules = append(rules, []rbacv1.PolicyRule{
		{
			// Used for creating service account tokens to be used by the linseed out plugin.
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		},
		{
			// Used to read endpoint field from the NonClusterHost resource.
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"nonclusterhosts"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// Allow posting flow logs, DNS logs, and policy activity logs to linseed.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"flowlogs", "dnslogs", "policyactivity"},
			Verbs:     []string{"create"},
		},
	}...)

	// For non-cluster host to request a operator signed certificate.
	rules = append(rules, []rbacv1.PolicyRule{
		{
			APIGroups: []string{"certificates.k8s.io"},
			Resources: []string{"certificatesigningrequests"},
			Verbs:     []string{"create", "delete", "list", "watch"},
		},
		{
			APIGroups:     []string{"certificates.tigera.io"},
			Resources:     []string{"certificatesigningrequests/common-name"},
			Verbs:         []string{"create"},
			ResourceNames: []string{render.TyphaCommonName + render.TyphaNonClusterHostSuffix},
		},
	}...)

	// For non-cluster host init process
	rules = append(rules, []rbacv1.PolicyRule{
		{
			// Used to update labels on the HostEndpoint resource.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"list", "update"},
		},
		{
			// Used to get BYO certificate secrets.
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get"},
			ResourceNames: []string{
				render.NodeTLSSecretNameNonClusterHost,
				render.TyphaTLSSecretNameNonClusterHost,
			},
		},
	}...)

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: NonClusterHostObjectName,
		},
		Rules: rules,
	}
}

func (c *nonClusterHostComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: NonClusterHostObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     NonClusterHostObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      NonClusterHostObjectName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}
