// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
//
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

package names

const (
	DefaultTierName      = "default"
	KubeAdminTierName    = "kube-admin"
	KubeBaselineTierName = "kube-baseline"

	// K8sNetworkPolicyNamePrefix is the prefix used when translating a
	// Kubernetes network policy into a Calico one.
	K8sNetworkPolicyNamePrefix = "knp.default."
	// K8sCNPAdminTierNamePrefix, and K8sCNPBaselineTierNamePrefix are the prefixes for
	// ClusterNetworkPolicy (Admin and Baseline tiers) resources, which is cluster-scoped.
	K8sCNPAdminTierNamePrefix    = "kcnp.kube-admin."
	K8sCNPBaselineTierNamePrefix = "kcnp.kube-baseline."

	// OpenStackNetworkPolicyNamePrefix is the prefix for OpenStack security groups.
	OpenStackNetworkPolicyNamePrefix = "ossg."
)

// TierOrDefault returns the tier name, or the default if blank.
func TierOrDefault(tier string) string {
	if len(tier) == 0 {
		return DefaultTierName
	} else {
		return tier
	}
}

func TierIsStatic(name string) bool {
	return name == DefaultTierName || name == KubeAdminTierName || name == KubeBaselineTierName
}
