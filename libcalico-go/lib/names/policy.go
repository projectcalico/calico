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

import (
	"errors"
)

const (
	DefaultTierName                    = "default"
	AdminNetworkPolicyTierName         = "adminnetworkpolicy"
	BaselineAdminNetworkPolicyTierName = "baselineadminnetworkpolicy"

	// K8sNetworkPolicyNamePrefix is the prefix used when translating a
	// Kubernetes network policy into a Calico one.
	K8sNetworkPolicyNamePrefix = "knp.default."
	// K8sAdminNetworkPolicyNamePrefix is the prefix for a Kubernetes
	// AdminNetworkPolicy resources, which are cluster-scoped and live in a
	// tier ahead of the default tier.
	K8sAdminNetworkPolicyNamePrefix = "kanp.adminnetworkpolicy."
	// K8sBaselineAdminNetworkPolicyNamePrefix is the prefix for the singleton
	// BaselineAdminNetworkPolicy resource, which is cluster-scoped and lives
	// in a tier after the default tier.
	K8sBaselineAdminNetworkPolicyNamePrefix = "kbanp.baselineadminnetworkpolicy."

	// OpenStackNetworkPolicyNamePrefix is the prefix for OpenStack security groups.
	OpenStackNetworkPolicyNamePrefix = "ossg."
)

// ValidateTieredPolicyName is deprecated and only kept for backward compatibility.
func ValidateTieredPolicyName(policy, tier string) error {
	if policy == "" {
		return errors.New("Policy name is empty")
	}
	return nil
}

// TierOrDefault returns the tier name, or the default if blank.
func TierOrDefault(tier string) string {
	if len(tier) == 0 {
		return DefaultTierName
	} else {
		return tier
	}
}
