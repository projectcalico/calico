// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package types

import (
	"unique"

	"github.com/projectcalico/calico/goldmane/proto"
)

// Matches returns true if the given flow Matches the given filter.
func Matches(filter *proto.Filter, key *FlowKey) bool {
	if filter == nil {
		// No filter provided - all Flows match.
		return true
	}

	comps := []matcher{
		&simpleComparison[string]{filterVal: filter.SourceName, flowVal: key.SourceName},
		&simpleComparison[string]{filterVal: filter.DestName, flowVal: key.DestName},
		&simpleComparison[string]{filterVal: filter.SourceNamespace, flowVal: key.SourceNamespace},
		&simpleComparison[string]{filterVal: filter.DestNamespace, flowVal: key.DestNamespace},
		&simpleComparison[string]{filterVal: filter.Protocol, flowVal: key.Proto},
		&simpleComparison[string]{filterVal: filter.Action, flowVal: key.Action},
		&simpleComparison[int64]{filterVal: filter.DestPort, flowVal: key.DestPort},
		&policyComparison{filterVal: filter.Policy, flowVal: key.Policies},
	}
	for _, c := range comps {
		if !c.matches() {
			return false
		}
	}

	// All specified filters match. Return true.
	return true
}

type matcher interface {
	matches() bool
}

type simpleComparison[E comparable] struct {
	filterVal E
	flowVal   E
}

func (c simpleComparison[E]) matches() bool {
	var empty E
	if c.filterVal == empty {
		// No filter value specified, so this comparison matches.
		return true
	}

	// TODO: Should support partial matches in the case of strings.
	return c.filterVal == c.flowVal
}

type policyComparison struct {
	filterVal *proto.PolicyMatch
	flowVal   unique.Handle[PolicyTrace]
}

func (c policyComparison) matches() bool {
	if c.filterVal == nil {
		// No filter value specified, so this comparison matches.
		return true
	}

	// We need to unfurl the policy trace to see if the filter matches.
	// Return a match if any of the policy hits match.
	flowVal := FlowLogPolicyToProto(c.flowVal)
	for _, hit := range flowVal.EnforcedPolicies {
		if c.policyHitMatches(hit) {
			return true
		}
	}
	for _, hit := range flowVal.PendingPolicies {
		if c.policyHitMatches(hit) {
			return true
		}
	}
	return false
}

func (c policyComparison) policyHitMatches(h *proto.PolicyHit) bool {
	// Check Name, Kind, Namespace, Tier, Action.
	if c.filterVal.Name != "" && h.Name != c.filterVal.Name {
		return false
	}
	if c.filterVal.Kind != proto.PolicyKind_KindUnspecified && h.Kind != c.filterVal.Kind {
		return false
	}
	if c.filterVal.Namespace != "" && h.Namespace != c.filterVal.Namespace {
		return false
	}
	if c.filterVal.Tier != "" && h.Tier != c.filterVal.Tier {
		return false
	}
	if c.filterVal.Action != "" && h.Action != c.filterVal.Action {
		return false
	}

	return true
}
