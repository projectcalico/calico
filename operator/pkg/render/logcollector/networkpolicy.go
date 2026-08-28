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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/resourcequota"
)

func (c *fluentBitComponent) nonClusterHostInputService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      FluentBitInputService,
			Namespace: LogCollectorNamespace,
			Labels:    map[string]string{"k8s-app": c.fluentBitNodeName()},
		},
		// We do not treat this service as a headless service, as we want to ensure traffic is load-balanced. This is because:
		// - We have no guarantee that the client (voltron) will perform load balancing across the returned records. The
		//   golang dialer implementation appears to prefer the first record returned (see dialSerial in the go SDK)
		// - We have no guarantee that the DNS server will perform load-balancing or randomize the order of records returned
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.fluentBitNodeName()},
			Ports: []corev1.ServicePort{
				{
					Name:       FluentBitInputPortName,
					Port:       int32(FluentBitInputPort),
					TargetPort: intstr.FromInt(FluentBitInputPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *fluentBitComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	// For managed clusters, we must create a role binding to allow Linseed to manage access token secrets
	// in our namespace.
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-linseed",
			Namespace: LogCollectorNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.TigeraLinseedSecretsClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.GuardianServiceAccountName,
				Namespace: render.GuardianNamespace,
			},
		},
	}
}

func (c *fluentBitComponent) externalLinseedService() *corev1.Service {
	// For managed clusters, we must create an external service for fluent-bit to forward requests to guardian.
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-linseed",
			Namespace: LogCollectorNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.svc.%s", render.GuardianServiceName, render.GuardianNamespace, c.cfg.ClusterDomain),
		},
	}
}

func (c *fluentBitComponent) fluentBitResourceQuota() *corev1.ResourceQuota {
	criticalPriorityClasses := []string{render.NodePriorityClassName}
	return resourcequota.ResourceQuotaForPriorityClassScope(resourcequota.TigeraCriticalResourceQuotaName, LogCollectorNamespace, criticalPriorityClasses)
}

func (c *fluentBitComponent) s3CredentialSecret() *corev1.Secret {
	if c.cfg.S3Credential == nil {
		return nil
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      S3FluentBitSecretName,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string][]byte{
			S3KeyIdName:     c.cfg.S3Credential.KeyId,
			S3KeySecretName: c.cfg.S3Credential.KeySecret,
		},
	}
}

func (c *fluentBitComponent) splunkCredentialSecret() []*corev1.Secret {
	if c.cfg.SplkCredential == nil {
		return nil
	}
	return []*corev1.Secret{
		{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      SplunkFluentBitTokenSecretName,
				Namespace: LogCollectorNamespace,
			},
			Data: map[string][]byte{
				SplunkFluentBitSecretTokenKey: c.cfg.SplkCredential.Token,
			},
		},
	}
}

func (c *fluentBitComponent) calicoSystemPolicy() *v3.NetworkPolicy {
	multiTenant := false
	tenantNamespace := ""
	if c.cfg.Tenant != nil {
		multiTenant = true
		tenantNamespace = c.cfg.Tenant.Namespace
	}
	policyHelper := networkpolicy.Helper(multiTenant, tenantNamespace)

	egressRules := []v3.Rule{}
	if c.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", render.GuardianNamespace),
				Selector:          networkpolicy.KubernetesAppSelector(render.GuardianServiceName),
				NotPorts:          networkpolicy.Ports(8080),
			},
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", render.ElasticsearchNamespace),
				Selector:          networkpolicy.KubernetesAppSelector("tigera-secure-es-gateway"),
				NotPorts:          networkpolicy.Ports(5554),
			},
		})
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", render.ElasticsearchNamespace),
				Selector:          networkpolicy.KubernetesAppSelector("tigera-linseed"),
				NotPorts:          networkpolicy.Ports(8444),
			},
		})
		egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Installation.KubernetesProvider.IsOpenShift())
	}
	egressRules = append(egressRules, v3.Rule{
		Action: v3.Allow,
	})

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   networkpolicy.PrometheusSourceEntityRule,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(FluentBitMetricsPort),
			},
		},
	}

	if c.cfg.NonClusterHost != nil {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   policyHelper.ManagerSourceEntityRule(),
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(FluentBitInputPort),
			},
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      FluentBitPolicyName,
			Namespace: LogCollectorNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:                  &networkpolicy.HighPrecedenceOrder,
			Tier:                   networkpolicy.CalicoTierName,
			Selector:               networkpolicy.KubernetesAppSelector(FluentBitNodeName, fluentBitNodeWindowsName),
			ServiceAccountSelector: "",
			Types:                  []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:                ingressRules,
			Egress:                 egressRules,
		},
	}
}
