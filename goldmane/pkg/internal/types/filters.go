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
	"slices"
	"strings"

	"github.com/projectcalico/calico/goldmane/proto"
)

// Matches returns true if the given flow Matches the given filter.
func Matches(filter *proto.Filter, key *FlowKey) bool {
	if filter == nil {
		// No filter provided - all Flows match.
		return true
	}

	// We use closures to avoid unpacking the unique.Handle values until we know we need them,
	// as not every filter will need every value.
	srcName := func() string { return key.SourceName() }
	srcNs := func() string { return key.SourceNamespace() }
	dstName := func() string { return key.DestName() }
	dstNs := func() string { return key.DestNamespace() }
	protocol := func() string { return key.Proto() }

	comps := []matcher{
		&stringComparison{filter: filter.SourceNames, val: srcName},
		&stringComparison{filter: filter.DestNames, val: dstName},
		&stringComparison{filter: filter.SourceNamespaces, val: srcNs},
		&stringComparison{filter: filter.DestNamespaces, val: dstNs},
		&stringComparison{filter: filter.Protocols, val: protocol},
		&actionMatch{filter: filter.Actions, key: key},
		&portComparison{filter: filter.DestPorts, key: key},
		&policyComparison{filter: filter.Policies, key: key},
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

type actionMatch struct {
	filter []proto.Action
	key    *FlowKey
}

func (a *actionMatch) matches() bool {
	if len(a.filter) == 0 {
		// No filter value specified, so this comparison matches.
		return true
	}
	return slices.Contains(a.filter, a.key.Action())
}

type portComparison struct {
	filter []*proto.PortMatch
	key    *FlowKey
}

func (p *portComparison) matches() bool {
	if len(p.filter) == 0 {
		// No filter value specified, so this comparison matches.
		return true
	}
	val := p.key.DestPort()
	for _, filter := range p.filter {
		if filter.Port == val {
			return true
		}
	}
	return false
}

type stringComparison struct {
	filter []*proto.StringMatch
	val    func() string
}

func (c stringComparison) matches() bool {
	if len(c.filter) == 0 {
		// No filter value specified, so this comparison matches.
		return true
	}

	return slices.ContainsFunc(c.filter, c.matchFilter)
}

func (c stringComparison) matchFilter(filter *proto.StringMatch) bool {
	val := c.val()

	if filter.Type == proto.MatchType_Exact {
		return val == filter.Value
	}

	// Match type is not exact, so we need to do a substring match.
	return strings.Contains(val, filter.Value)
}

type policyComparison struct {
	filter []*proto.PolicyMatch
	key    *FlowKey
}

func (c policyComparison) matches() bool {
	if c.filter == nil {
		// No filter value specified, so this comparison matches.
		return true
	}

	// We need to unfurl the policy trace to see if the filter matches.
	// Return a match if any of the policy hits match.
	flowVal := FlowLogPolicyToProto(c.key.Policies)

	// Check the enforced and pending policies.
	if slices.ContainsFunc(flowVal.EnforcedPolicies, c.policyHitMatches) {
		return true
	}
	if slices.ContainsFunc(flowVal.PendingPolicies, c.policyHitMatches) {
		return true
	}

	return false
}

func (c policyComparison) policyHitMatches(h *proto.PolicyHit) bool {
	for _, filter := range c.filter {
		if c.filterMatches(h, filter) {
			return true
		}
	}
	return false
}

func (c policyComparison) filterMatches(h *proto.PolicyHit, filter *proto.PolicyMatch) bool {
	// Check Name, Kind, Namespace, Tier, Action.
	if filter.Name != "" && h.Name != filter.Name {
		return false
	}
	if filter.Kind != proto.PolicyKind_KindUnspecified && h.Kind != filter.Kind {
		return false
	}
	if filter.Namespace != "" && h.Namespace != filter.Namespace {
		return false
	}
	if filter.Tier != "" && h.Tier != filter.Tier {
		return false
	}
	if filter.Action != proto.Action_ActionUnspecified && h.Action != filter.Action {
		return false
	}

	return true
}
