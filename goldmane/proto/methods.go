// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proto

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/kubernetes/pkg/apis/core/validation"
)

// ToString converts a PolicyHit struct into a string label.
// TODO: This is a temporary solution - we should be pushing the structured PolicyHit representation
// further down the stack, rather than converting between string / struct.
func (h *PolicyHit) ToString() (string, error) {
	// Format is: "<policy index>|<tier>|<namePart>|<action>|<rule index>"
	tmpl := "%d|%s|%s|%s|%d"

	if err := h.Validate(); err != nil {
		logrus.WithFields(h.fields()).WithError(err).Error("Failed to validate policy hit")
		return "", err
	}

	var namePart string
	var err error
	if h.Kind == PolicyKind_EndOfTier {
		namePart, err = makeNamePart(h.Trigger)
	} else {
		namePart, err = makeNamePart(h)
	}
	if err != nil {
		logrus.WithFields(h.fields()).WithError(err).Error("Failed to generate name part")
		return "", err
	}

	tier := h.Tier
	if h.Kind == PolicyKind_Profile {
		// Profiles are a special case where the tier is always __PROFILE__.
		tier = "__PROFILE__"
	}

	// Convert action from enum to string.
	action := strings.ToLower(Action_name[int32(h.Action)])

	return fmt.Sprintf(tmpl, h.PolicyIndex, tier, namePart, action, h.RuleIndex), nil
}

func (h *PolicyHit) Validate() error {
	if _, ok := Action_name[int32(h.Action)]; !ok {
		return fmt.Errorf("unexpected action: %v", h.Action)
	}

	switch h.Kind {
	case PolicyKind_GlobalNetworkPolicy,
		PolicyKind_StagedGlobalNetworkPolicy,
		PolicyKind_AdminNetworkPolicy,
		PolicyKind_BaselineAdminNetworkPolicy:
		if h.Namespace != "" {
			return fmt.Errorf("unexpected namespace for global policy")
		}
	case PolicyKind_EndOfTier:
		if h.Trigger == nil {
			return fmt.Errorf("EndOfTier hit missing trigger")
		}
	}
	return nil
}

func (h *PolicyHit) fields() logrus.Fields {
	return logrus.Fields{
		"PolicyIndex": h.PolicyIndex,
		"Tier":        h.Tier,
		"Name":        h.Name,
		"Namespace":   h.Namespace,
		"Action":      h.Action,
		"RuleIndex":   h.RuleIndex,
		"Kind":        h.Kind,
	}
}

func makeNamePart(h *PolicyHit) (string, error) {
	logrus.WithFields(h.fields()).Debug("Generating name part from policy hit")
	var namePart string
	switch h.Kind {
	case PolicyKind_GlobalNetworkPolicy:
		namePart = fmt.Sprintf("%s.%s", h.Tier, h.Name)
	case PolicyKind_CalicoNetworkPolicy:
		namePart = fmt.Sprintf("%s/%s.%s", h.Namespace, h.Tier, h.Name)
	case PolicyKind_NetworkPolicy:
		namePart = fmt.Sprintf("%s/knp.default.%s", h.Namespace, h.Name)
	case PolicyKind_StagedKubernetesNetworkPolicy:
		namePart = fmt.Sprintf("%s/staged:knp.default.%s", h.Namespace, h.Name)
	case PolicyKind_StagedGlobalNetworkPolicy:
		namePart = fmt.Sprintf("%s.staged:%s", h.Tier, h.Name)
	case PolicyKind_StagedNetworkPolicy:
		namePart = fmt.Sprintf("%s/%s.staged:%s", h.Namespace, h.Tier, h.Name)
	case PolicyKind_AdminNetworkPolicy:
		namePart = fmt.Sprintf("kanp.adminnetworkpolicy.%s", h.Name)
	case PolicyKind_BaselineAdminNetworkPolicy:
		namePart = fmt.Sprintf("kbanp.baselineadminnetworkpolicy.%s", h.Name)
	case PolicyKind_Profile:
		// Profile names are __PROFILE__.name. The name part may include indicators of the kind of
		// profile - e.g., __PROFILE__.kns.default, __PROFILE__.ksa.svcacct.
		namePart = fmt.Sprintf("__PROFILE__.%s", h.Name)
	default:
		logrus.WithFields(h.fields()).Error("Unexpected policy kind")
		return "", fmt.Errorf("unexpected policy kind: %v", h.Kind)
	}
	logrus.WithFields(h.fields()).WithField("namePart", namePart).Debug("Generated name part")
	return namePart, nil
}

// HitFromString parses a policy hit label string into a PolicyHit struct.
// TODO: This is a temporary solution - we should be pushing the structured PolicyHit representation
// further down the stack, rather than converting between string / struct.
func HitFromString(s string) (*PolicyHit, error) {
	parts := strings.Split(s, "|")
	if len(parts) != 5 {
		return nil, fmt.Errorf("unexpected policy label format: %s", s)
	}

	polIdx, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, err
	}

	tier := parts[1]
	namePart := parts[2]
	a := parts[3]

	// Translate the action string into an Action value.
	var action Action
	switch strings.ToLower(a) {
	case "allow":
		action = Action_Allow
	case "deny":
		action = Action_Deny
	case "pass":
		action = Action_Pass
	default:
		return nil, fmt.Errorf("unexpected action: %s", a)
	}

	ruleIdx, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return nil, err
	}

	var kind PolicyKind
	var name string
	var ns string
	nameParts := strings.Split(namePart, "/")
	if len(nameParts) == 1 {
		// No namespace, must be a global policy.
		// Name format is "(staged:)tier.name".
		n := nameParts[0]

		if strings.Contains(n, "staged:") {
			kind = PolicyKind_StagedGlobalNetworkPolicy
			n = strings.Replace(n, "staged:", "", 1)
		} else if strings.HasPrefix(n, "kanp.") {
			kind = PolicyKind_AdminNetworkPolicy
			n = strings.TrimPrefix(n, "kanp.")
		} else if strings.HasPrefix(n, "kbanp.") {
			kind = PolicyKind_BaselineAdminNetworkPolicy
			n = strings.TrimPrefix(n, "kbanp.")
		} else if strings.HasPrefix(n, "__PROFILE__.") {
			kind = PolicyKind_Profile
		} else {
			kind = PolicyKind_GlobalNetworkPolicy
		}

		// At this point, n is "tier.name". The name may of dots in it, so
		// we need to recombine the parts except for the tier.
		name = strings.Join(strings.Split(n, ".")[1:], ".")

		// Verify the "tier" part of "tier.name" matches the tier.
		if strings.Split(n, ".")[0] != tier {
			return nil, fmt.Errorf("tier does not match: %s != %s", strings.Split(n, ".")[0], tier)
		}
	} else if len(nameParts) == 2 {
		// Namespaced.
		// Name format for Calico policies is "tier.(staged:)name".
		// Name format for K8s policies is "(staged:)knp.default.name".
		n := nameParts[1]
		ns = nameParts[0]
		if strings.HasPrefix(n, "staged:knp.") {
			// StagedKubernetesNetworkPolicy.
			kind = PolicyKind_StagedKubernetesNetworkPolicy
			n = strings.TrimPrefix(n, "staged:knp.")
		} else if strings.HasPrefix(n, "knp.") {
			// KubernetesNetworkPolicy.
			kind = PolicyKind_NetworkPolicy
			n = strings.TrimPrefix(n, "knp.")
		} else {
			// This is either a Calico NetworkPolicy or Calico StagedNetworkPolicy.
			if strings.Contains(n, "staged:") {
				kind = PolicyKind_StagedNetworkPolicy
				n = strings.Replace(n, "staged:", "", 1)
			} else {
				// Calico NetworkPolicy.
				// Name format is already "tier.name".
				kind = PolicyKind_CalicoNetworkPolicy
			}
		}

		// At this point, n is "tier.name". The name may of dots in it, so
		// we need to recombine the parts except for the tier.
		name = strings.Join(strings.Split(n, ".")[1:], ".")

		// Verify the "tier" part of "tier.name" matches the tier.
		if strings.Split(n, ".")[0] != tier {
			return nil, fmt.Errorf("tier does not match: %s != %s", strings.Split(n, ".")[0], tier)
		}
	}

	// Verify the name is valid.
	if name == "" {
		return nil, fmt.Errorf("invalid name: %s", namePart)
	}
	if res := validation.ValidatePodName(name, true); res != nil {
		return nil, fmt.Errorf("invalid name: %s: %s", name, strings.Join(res, ", "))
	}

	// Verify the namespace is valid.
	if ns != "" {
		if res := validation.ValidateNamespaceName(ns, true); res != nil {
			return nil, fmt.Errorf("invalid namespace: %s: %s", ns, strings.Join(res, ", "))
		}
	}

	if tier == "" {
		return nil, fmt.Errorf("tier is required")
	} else {
		if tier == "__PROFILE__" {
			// __PROFILE__ is a special internal tier used for Profiles, but we don't
			// want to show this in the API as it's not a real v3 Tier.
			tier = ""
		} else {
			if res := validation.ValidatePodName(tier, true); res != nil {
				return nil, fmt.Errorf("invalid tier: %s: %s", tier, strings.Join(res, ", "))
			}
		}
	}

	if ruleIdx == -1 {
		// This is an EndOfTier rule, which recontextualizes the values we learned above.
		// The policy information indicates the triggering policy that caused the end of the tier
		// to be activated.
		return &PolicyHit{
			Kind:        PolicyKind_EndOfTier,
			Tier:        tier,
			Action:      action,
			RuleIndex:   ruleIdx,
			PolicyIndex: polIdx,
			Trigger: &PolicyHit{
				Kind:      kind,
				Name:      name,
				Namespace: ns,
				Tier:      tier,
			},
		}, nil
	}

	hit := &PolicyHit{
		PolicyIndex: polIdx,
		Tier:        tier,
		Name:        name,
		Namespace:   ns,
		Action:      action,
		RuleIndex:   ruleIdx,
		Kind:        kind,
	}
	logrus.WithFields(hit.fields()).Debug("Parsed policy hit")
	return hit, nil
}
