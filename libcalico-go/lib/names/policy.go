// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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
	"fmt"
	"strings"
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

	// OssNetworkPolicyNamePrefix is the prefix for OpenStack security groups.
	OssNetworkPolicyNamePrefix = "ossg."
)

// TierFromPolicyName extracts the tier from a tiered policy name.
// If the policy is a K8s policy (with prefix "knp.default"), then tier name is
// is the "default" tier. If there are no tier name prefix, then again the
// "default" tier name is returned.
// Otherwise, the first full word that occurs before the first "." (dot) is returned
// as the tier value.
func TierFromPolicyName(name string) (string, error) {
	if name == "" {
		return "", errors.New("Tiered policy name is empty")
	}
	// If it is a K8s (admin) network policy, then simply return the policy name as is.
	if strings.HasPrefix(name, K8sNetworkPolicyNamePrefix) {
		return DefaultTierName, nil
	}
	if strings.HasPrefix(name, K8sAdminNetworkPolicyNamePrefix) {
		return AdminNetworkPolicyTierName, nil
	}
	if strings.HasPrefix(name, K8sBaselineAdminNetworkPolicyNamePrefix) {
		return BaselineAdminNetworkPolicyTierName, nil
	}
	parts := strings.SplitN(name, ".", 2)
	if len(parts) < 2 {
		// A name without a prefix.
		return DefaultTierName, nil
	}
	// Return the first word before the first dot.
	return parts[0], nil
}

// BackendTieredPolicyName returns a policy name suitable for use by any
// backend. It will always return a policy name prefixed with the appropriate
// tier or error. The tier name is passed in as-is from the Policy Spec of a
// (Staged)NetworkPolicy or a (Staged)GlobalNetworkPolicy resource.
func BackendTieredPolicyName(policy, tier string) (string, error) {
	tieredPolicy := TieredPolicyName(policy)
	return tieredPolicy, validateBackendTieredPolicyName(tieredPolicy, tier)
}

func validateBackendTieredPolicyName(policy, tier string) error {
	if policy == "" {
		return errors.New("Policy name is empty")
	}
	if policyNameIsFormatted(policy) {
		return nil
	}

	t := TierOrDefault(tier)
	parts := strings.SplitN(policy, ".", 2)
	if len(parts) != 2 || !strings.HasPrefix(policy, t+".") {
		return fmt.Errorf("Incorrectly formatted policy name %s", policy)
	}
	return nil
}

func TieredPolicyName(policy string) string {
	if policy == "" {
		return ""
	}
	if policyNameIsFormatted(policy) {
		return policy
	}

	parts := strings.SplitN(policy, ".", 2)
	if len(parts) == 1 {
		// Default tier name.
		return fmt.Sprintf("default.%v", policy)
	} else if len(parts) == 2 {
		// The policy name is already prefixed appropriately.
		return policy
	}
	return ""
}

// ClientTieredPolicyName returns a policy name suitable for returning to
// the user of the client. The tier name is passed in as-is from the Policy
// spec for (Staged)NetworkPolicy or a (Staged)GlobalNetworkPolicy.
func ClientTieredPolicyName(policy string) (string, error) {
	if policy == "" {
		return "", errors.New("Policy name is empty")
	}
	if policyNameIsFormatted(policy) {
		return policy, nil
	}
	parts := strings.SplitN(policy, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("Invalid policy name %s", policy)
	} else if parts[0] == DefaultTierName {
		return parts[1], nil
	}
	return policy, nil
}

func policyNameIsFormatted(policy string) bool {
	// If it is a K8s (admin) network policy or OSSG, we expect the policy name to be formatted properly in the first place.
	return strings.HasPrefix(policy, K8sNetworkPolicyNamePrefix) ||
		strings.HasPrefix(policy, K8sAdminNetworkPolicyNamePrefix) ||
		strings.HasPrefix(policy, K8sBaselineAdminNetworkPolicyNamePrefix) ||
		strings.HasPrefix(policy, OssNetworkPolicyNamePrefix)
}

// TierOrDefault returns the tier name, or the default if blank.
func TierOrDefault(tier string) string {
	if len(tier) == 0 {
		return DefaultTierName
	} else {
		return tier
	}
}
