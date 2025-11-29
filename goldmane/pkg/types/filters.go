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

const (
	pub    = "pub"
	pvt    = "pvt"
	global = "Global"
)

// The UI displays some values differently than they are stored within Goldmane. As such,
// users may sends filters for the UI displayed values, but we need to match against the
// actual stored values. For example, the UI displays "PUBLIC NETWORK" but the stored value
// is "pub".
func names(valFn func() string) func() []string {
	return func() []string {
		n := valFn()
		switch n {
		case pub:
			return []string{"PUBLIC NETWORK", pub}
		case pvt:
			return []string{"PRIVATE NETWORK", pvt}

		}
		return []string{n}
	}
}

func namespaces(valFn func() string) func() []string {
	return func() []string {
		n := valFn()
		switch n {
		case global:
			return []string{"-", global}
		}
		return []string{n}
	}
}

// Matches returns true if the given flow Matches the given filter.
func Matches(filter *proto.Filter, key *FlowKey) bool {
	if filter == nil {
		// No filter provided - all Flows match.
		return true
	}

	comps := []matcher{
		&stringComparison{filter: filter.SourceNames, genVals: names(key.SourceName)},
		&stringComparison{filter: filter.DestNames, genVals: names(key.DestName)},
		&stringComparison{filter: filter.SourceNamespaces, genVals: namespaces(key.SourceNamespace)},
		&stringComparison{filter: filter.DestNamespaces, genVals: namespaces(key.DestNamespace)},
		&stringComparison{filter: filter.Protocols, genVals: func() []string { return []string{key.Proto()} }},
		&actionMatch{filter: filter.Actions, key: key},
		&reporterMatch{filter: filter.Reporters, key: key},
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

type reporterMatch struct {
	filter []proto.Reporter
	key    *FlowKey
}

func (r *reporterMatch) matches() bool {
	if len(r.filter) == 0 {
		// No filter value specified, so this comparison matches.
		return true
	}
	return slices.Contains(r.filter, r.key.Reporter())
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

	// genVals returns a list of values on the underlying object to compare against the filter.
	// If any of the values match, the comparison is considered a match.
	genVals func() []string
}

func (c stringComparison) matches() bool {
	if len(c.filter) == 0 {
		// No filter value specified, so this comparison matches.
		return true
	}

	return slices.ContainsFunc(c.filter, c.matchFilter)
}

func (c stringComparison) matchFilter(filter *proto.StringMatch) bool {
	vals := c.genVals()

	if filter.Type == proto.MatchType_Exact {
		return slices.Contains(vals, filter.Value)
	}

	// Match type is not exact, so we need to do a substring match.
	for _, val := range vals {
		if strings.Contains(val, filter.Value) {
			return true
		}
	}
	return false
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
	flowVal := FlowLogPolicyToProto(c.key.Policies())

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
