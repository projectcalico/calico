// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
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

import "reflect"

const (
	DefaultTierName      = "default"
	KubeAdminTierName    = "kube-admin"
	KubeBaselineTierName = "kube-baseline"

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

// TierFromPolicy extracts the tier name from a policy object using reflection.
// It looks for a Spec.Tier string field, which most Calico policy types have
// (GlobalNetworkPolicy, NetworkPolicy, StagedGlobalNetworkPolicy,
// StagedNetworkPolicy). Returns the tier name and true if found, or empty
// string and false if the object doesn't have a Spec.Tier field (e.g.,
// StagedKubernetesNetworkPolicy).
func TierFromPolicy(obj any) (string, bool) {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	spec := v.FieldByName("Spec")
	if !spec.IsValid() {
		return "", false
	}
	tier := spec.FieldByName("Tier")
	if !tier.IsValid() || tier.Kind() != reflect.String {
		return "", false
	}
	return TierOrDefault(tier.String()), true
}

func TierIsStatic(name string) bool {
	return name == DefaultTierName || name == KubeAdminTierName || name == KubeBaselineTierName
}
