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
)

// ToString converts a PolicyHit struct into a string label.
// TODO: This is a temporary solution - we should be pushing the structured PolicyHit representation
// further down the stack, rather than converting between string / struct.
func (h *PolicyHit) ToString() string {
	// Format is: "<policy index>|<tier>|<namePart>|<action>|<rule index>"
	tmpl := "%d|%s|%s|%s|%d"

	var namePart string
	switch h.Kind {
	case PolicyKind_CalicoGlobalNetworkPolicy:
		namePart = fmt.Sprintf("%s.%s", h.Tier, h.Name)
	case PolicyKind_CalicoNetworkPolicy:
		namePart = fmt.Sprintf("%s/%s.%s", h.Namespace, h.Tier, h.Name)
	case PolicyKind_NetworkPolicy:
		namePart = fmt.Sprintf("%s/knp.default.%s", h.Namespace, h.Name)
	case PolicyKind_StagedKubernetesNetworkPolicy:
		namePart = fmt.Sprintf("%s/staged:knp.default.%s", h.Namespace, h.Name)
	case PolicyKind_CalicoStagedGlobalNetworkPolicy:
		namePart = fmt.Sprintf("staged:%s.%s", h.Tier, h.Name)
	case PolicyKind_CalicoStagedNetworkPolicy:
		namePart = fmt.Sprintf("%s/staged:%s.%s", h.Namespace, h.Tier, h.Name)
	case PolicyKind_AdminNetworkPolicy:
		namePart = fmt.Sprintf("anp.adminnetworkpolicy.%s", h.Name)
	case PolicyKind_Profile:
		namePart = fmt.Sprintf("__PROFILE__.%s", h.Name)
	default:
		logrus.WithField("kind", h.Kind).Panic("Unexpected policy kind")
	}

	return fmt.Sprintf(tmpl, h.PolicyIndex, h.Tier, namePart, h.Action, h.RuleIndex)
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
	action := parts[3]

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

		if strings.HasPrefix(n, "staged:") {
			kind = PolicyKind_CalicoStagedGlobalNetworkPolicy
			n = strings.TrimPrefix(n, "staged:")
		} else if strings.HasPrefix(n, "anp.") {
			kind = PolicyKind_AdminNetworkPolicy
			n = strings.TrimPrefix(n, "anp.")
		} else if strings.HasPrefix(n, "__PROFILE__.") {
			kind = PolicyKind_Profile
		} else {
			kind = PolicyKind_CalicoGlobalNetworkPolicy
		}

		// At this point, n is "tier.name". The name may of dots in it, so
		// we need to recombine the parts except for the tier.
		name = strings.Join(strings.Split(n, ".")[1:], ".")
	} else if len(nameParts) == 2 {
		// Namespaced.
		// Name format is "(staged:)(kind.)tier.name".
		n := nameParts[1]
		ns = nameParts[0]
		if strings.HasPrefix(n, "staged:") {
			n = strings.TrimPrefix(n, "staged:")
			if strings.HasPrefix(n, "knp.") {
				kind = PolicyKind_StagedKubernetesNetworkPolicy
				n = strings.TrimPrefix(n, "knp.")
			} else {
				kind = PolicyKind_CalicoStagedNetworkPolicy
			}
		} else {
			if strings.HasPrefix(n, "knp.") {
				kind = PolicyKind_NetworkPolicy
				n = strings.TrimPrefix(n, "knp.")
			} else {
				kind = PolicyKind_CalicoNetworkPolicy
			}
		}

		// At this point, n is "tier.name". The name may of dots in it, so
		// we need to recombine the parts except for the tier.
		name = strings.Join(strings.Split(n, ".")[1:], ".")
	}

	return &PolicyHit{
		PolicyIndex: polIdx,
		Tier:        tier,
		Name:        name,
		Namespace:   ns,
		Action:      action,
		RuleIndex:   ruleIdx,
		Kind:        kind,
	}, nil
}
