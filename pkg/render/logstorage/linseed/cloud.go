// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linseed

import (
	"strconv"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Name of the network policy that adds CC specific rules to Linseed.
	CloudPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "cloud-linseed-access"
)

// modifyDeploymentForCloud applies Calico Cloud specific tweaks to the Linseed deployment. It is
// only called when rendering for cloud (gated by Config.Cloud), so it never affects enterprise.
func (c *linseed) modifyDeploymentForCloud(d *appsv1.Deployment) {
	envs := d.Spec.Template.Spec.Containers[0].Env

	// Replica count for the policy activity index, kept consistent with the other index replicas.
	envs = append(envs, corev1.EnvVar{Name: "ELASTIC_POLICY_ACTIVITY_INDEX_REPLICAS", Value: strconv.Itoa(c.cfg.ESClusterConfig.Replicas())})

	// Enable prometheus metrics endpoint at :METRICS_PORT/metrics (Default is 9095).
	// We use the same certificate for TLS on the metrics endpoint as we do for the main API.
	envs = append(envs, corev1.EnvVar{Name: "LINSEED_ENABLE_METRICS", Value: "true"})
	envs = append(envs, corev1.EnvVar{Name: "LINSEED_METRICS_CERT", Value: c.cfg.KeyPair.VolumeMountCertificateFilePath()})
	envs = append(envs, corev1.EnvVar{Name: "LINSEED_METRICS_KEY", Value: c.cfg.KeyPair.VolumeMountKeyFilePath()})

	if c.cfg.Tenant != nil {
		if c.cfg.ExternalElastic {
			// Overwrite policy activity index name until we create the tenant CR on all environments
			envs = append(envs, corev1.EnvVar{Name: "ELASTIC_POLICY_ACTIVITY_BASE_INDEX_NAME", Value: "calico_policy_activity_standard"})
		}
	}
	d.Spec.Template.Spec.Containers[0].Env = envs
}

func (c *linseed) getCloudObjects() (toCreate, toDelete []client.Object) {
	s := []client.Object{}
	s = append(s, c.allowTigeraPolicyForCloud())

	// allow-tigera Tier was renamed to calico-system
	toDelete = append(toDelete,
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("cloud-linseed-access", c.namespace),
	)

	return s, toDelete
}

func (c *linseed) allowTigeraPolicyForCloud() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	if c.cfg.ElasticClientSecret != nil {
		// TODO: At the moment, we only support mTLS for Elasticsearch when using an external ES cluster.
		// That allows us to use the presence of the secret as a proxy for whether we should append this egress rule.
		// In the future, we should support mTLS for internal ES clusters as well and switch this to a better check.

		// Allow egress traffic to the external Elasticsearch.
		egressRules = append(egressRules,
			v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Ports:   []numorstring.Port{{MinPort: 443, MaxPort: 443}},
					Domains: []string{c.cfg.ElasticHost},
				},
			},
		)
	}

	ingressRules := []v3.Rule{
		{
			// Allow ingress traffic from Calico Cloud monitoring stack to the Linseed
			// metrics port.
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				NamespaceSelector: "projectcalico.org/name == 'monitoring'",
				Selector:          "app == 'prometheus'",
			},
			Destination: v3.EntityRule{
				Ports: []numorstring.Port{{MinPort: 9095, MaxPort: 9095}},
			},
		},
	}
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CloudPolicyName,
			Namespace: c.namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(DeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}
