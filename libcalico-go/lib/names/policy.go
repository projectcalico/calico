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
	"fmt"
	"strings"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

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
	// If it is a K8s (cluster) network policy, then simply return the policy name as is.
	if strings.HasPrefix(name, K8sNetworkPolicyNamePrefix) {
		return DefaultTierName, nil
	}
	if strings.HasPrefix(name, K8sCNPAdminTierNamePrefix) {
		return KubeAdminTierName, nil
	}
	if strings.HasPrefix(name, K8sCNPBaselineTierNamePrefix) {
		return KubeBaselineTierName, nil
	}
	// Policy derived from OpenStack security groups is named as "ossg.default.<security group
	// ID>", but should go into the default tier.
	if strings.HasPrefix(name, OpenStackNetworkPolicyNamePrefix) {
		return DefaultTierName, nil
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

// ValidateTieredPolicyName validates v3 policy name, policies in the default tier can be named without the default. prefix.
// Policy names in non default tier have to be in a format of tier.name
func ValidateTieredPolicyName(policy, tier string) error {
	if policy == "" {
		return errors.New("Policy name is empty")
	}
	if policyNameIsFormatted(policy) {
		return nil
	}

	tier = TierOrDefault(tier)
	parts := strings.SplitN(policy, ".", 2)

	if len(parts) == 1 && tier == "default" {
		// Policy in default tier, without the default. prefix
		return nil
	}

	if len(parts) == 2 && strings.HasPrefix(policy, tier+".") {
		// Policy in format of tier.name with tier matching the prefix
		return nil
	}

	// If we reached here the policy name is invalid. Either incorrect prefix or with additional . in the name
	return fmt.Errorf("Incorrectly formatted policy name %s", policy)
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
	// If it is a K8s (cluster) network policy, or derived from an OpenStack security group, we
	// expect the policy name to be formatted properly in the first place.
	return strings.HasPrefix(policy, K8sNetworkPolicyNamePrefix) ||
		strings.HasPrefix(policy, K8sCNPAdminTierNamePrefix) ||
		strings.HasPrefix(policy, K8sCNPBaselineTierNamePrefix) ||
		strings.HasPrefix(policy, OpenStackNetworkPolicyNamePrefix)
}

// TierOrDefault returns the tier name, or the default if blank.
func TierOrDefault(tier string) string {
	if len(tier) == 0 {
		return DefaultTierName
	} else {
		return tier
	}
}

// deconstructPolicyName deconstructs the v1 policy name that is constructed by the SyncerUpdateProcessors in
// libcalico-go and extracts the v3 fields: namespace, tier, name.
//
// The v1 policy name is of the format:
// -  <namespace>/<tier>.<name> for a namespaced NetworkPolicies
// -  <tier>.<name> for GlobalNetworkPolicies.
// -  <namespace>/knp.default.<name> for a k8s NetworkPolicies
// -  kcnp.kube-admin.<name> for a k8s ClusterNetworkPolicies (Admin tier)
// -  kcnp.kube-baseline.<name> for a k8s ClusterNetworkPolicies (Baseline tier)
// and for the staged counterparts, respectively:
// -  <namespace>/staged:<tier>.<name>
// -  staged:<tier>.<name>
// -  <namespace>/staged:knp.default.<name>
//
// The namespace is returned blank for GlobalNetworkPolicies.
// For k8s network policies, the tier is always "default" and the name will be returned including the
// knp.default prefix.
//
// Staged policies will have the simplified name prefixed with "staged:", eg:
// - <namespace>/staged:<tier>.<name>      => Name=staged:<name>, Namespace=<namespace>, Tier=<tier>
// - staged:<tier>.<name>                  => Name=staged:<name>, Namespace=<namespace>, Tier=<tier>
// - <namespace>/staged:knp.default.<name> => Name=staged:knp.default.<name>, Namespace=<name>, Tier=default
func DeconstructPolicyName(name string) (string, string, string, error) {
	var namespace string

	// Split the name to extract the namespace.
	parts := strings.Split(name, "/")
	switch len(parts) {
	case 1: // GlobalNetworkPolicy
		name = parts[0]
	case 2: // NetworkPolicy (Calico or Kubernetes)
		namespace = parts[0]
		name = parts[1]
	default:
		return "", "", "", fmt.Errorf("could not parse policy %s", name)
	}

	// Remove the staged prefix if present so we can extract the tier.
	var stagedPrefix string
	if model.PolicyIsStaged(name) {
		stagedPrefix = model.PolicyNamePrefixStaged
		name = name[len(model.PolicyNamePrefixStaged):]
	}

	// If policy name starts with "knp.default" then this is k8s network policy.
	if strings.HasPrefix(name, K8sNetworkPolicyNamePrefix) {
		return namespace, DefaultTierName, stagedPrefix + name, nil
	}
	// If policy name starts with "kcnp.kube-admin" then this is k8s cluster network policy in Admin tier.
	if strings.HasPrefix(name, K8sCNPAdminTierNamePrefix) {
		return namespace, KubeAdminTierName, stagedPrefix + name, nil
	}
	// If policy name starts with "kcnp.kube-baseline" then this is k8s cluster network policy in Baseline tier.
	if strings.HasPrefix(name, K8sCNPBaselineTierNamePrefix) {
		return namespace, KubeBaselineTierName, stagedPrefix + name, nil
	}

	// This is a non-kubernetes policy, so extract the tier name from the policy name.
	if parts = strings.SplitN(name, ".", 2); len(parts) == 2 {
		return namespace, parts[0], stagedPrefix + parts[1], nil
	}

	return "", "", "", fmt.Errorf("could not parse policy %s", name)
}

func TierIsStatic(name string) bool {
	return name == DefaultTierName || name == KubeAdminTierName || name == KubeBaselineTierName
}
