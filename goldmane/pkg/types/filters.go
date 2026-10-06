// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
// is "pub". nameAlias and namespaceAlias return the displayed value, or "" when there is none.
func nameAlias(n string) string {
	switch n {
	case pub:
		return "PUBLIC NETWORK"
	case pvt:
		return "PRIVATE NETWORK"
	}
	return ""
}

func namespaceAlias(n string) string {
	if n == global {
		return "-"
	}
	return ""
}

// Matches returns true if the given flow Matches the given filter.
func Matches(filter *proto.Filter, key *FlowKey) bool {
	if filter == nil {
		// No filter provided - all Flows match.
		return true
	}

	if len(filter.SourceNames) > 0 {
		n := key.SourceName()
		if !stringMatches(filter.SourceNames, n, nameAlias(n)) {
			return false
		}
	}
	if len(filter.DestNames) > 0 {
		n := key.DestName()
		if !stringMatches(filter.DestNames, n, nameAlias(n)) {
			return false
		}
	}
	if len(filter.SourceNamespaces) > 0 {
		n := key.SourceNamespace()
		if !stringMatches(filter.SourceNamespaces, n, namespaceAlias(n)) {
			return false
		}
	}
	if len(filter.DestNamespaces) > 0 {
		n := key.DestNamespace()
		if !stringMatches(filter.DestNamespaces, n, namespaceAlias(n)) {
			return false
		}
	}
	if len(filter.Protocols) > 0 && !stringMatches(filter.Protocols, key.Proto(), "") {
		return false
	}
	if len(filter.Actions) > 0 && !slices.Contains(filter.Actions, key.Action()) {
		return false
	}
	if filter.Reporter != proto.Reporter_ReporterUnspecified && filter.Reporter != key.Reporter() {
		return false
	}
	if len(filter.DestPorts) > 0 && !portMatches(filter.DestPorts, key.DestPort()) {
		return false
	}
	if len(filter.PendingActions) > 0 && !pendingActionMatches(filter.PendingActions, key) {
		return false
	}

	// A non-nil but empty policy filter matches no flows, since no hit can satisfy it.
	if filter.Policies != nil && !policyMatches(filter.Policies, key) {
		return false
	}

	// All specified filters match. Return true.
	return true
}

// stringMatches reports whether val, or its UI alias when one exists, satisfies any of the filters.
func stringMatches(filters []*proto.StringMatch, val, alias string) bool {
	for _, f := range filters {
		if f.Type == proto.MatchType_Exact {
			if val == f.Value || (alias != "" && alias == f.Value) {
				return true
			}
			continue
		}

		// Match type is not exact, so we need to do a substring match.
		if strings.Contains(val, f.Value) || (alias != "" && strings.Contains(alias, f.Value)) {
			return true
		}
	}
	return false
}

func portMatches(filters []*proto.PortMatch, port int64) bool {
	for _, f := range filters {
		if f.Port == port {
			return true
		}
	}
	return false
}

func pendingActionMatches(actions []proto.Action, key *FlowKey) bool {
	for _, hit := range CachedPolicyTrace(key.Policies()).PendingPolicies {
		if slices.Contains(actions, hit.Action) {
			return true
		}
	}
	return false
}

// policyMatches reports whether any enforced or pending hit in the key's trace satisfies any
// of the filters.
func policyMatches(filters []*proto.PolicyMatch, key *FlowKey) bool {
	trace := CachedPolicyTrace(key.Policies())
	for _, hits := range [2][]*proto.PolicyHit{trace.EnforcedPolicies, trace.PendingPolicies} {
		for _, h := range hits {
			for _, f := range filters {
				if policyHitMatches(h, f) {
					return true
				}
			}
		}
	}
	return false
}

func policyHitMatches(h *proto.PolicyHit, filter *proto.PolicyMatch) bool {
	// Check Name, Kind, Namespace, Tier, Action.
	if !StringMatchMatches(filter.Name, h.Name) {
		return false
	}
	if filter.Kind != proto.PolicyKind_KindUnspecified && h.Kind != filter.Kind {
		return false
	}
	if !StringMatchMatches(filter.Namespace, h.Namespace) {
		return false
	}
	if !StringMatchMatches(filter.Tier, h.Tier) {
		return false
	}
	if filter.Action != proto.Action_ActionUnspecified && h.Action != filter.Action {
		return false
	}

	return true
}

// StringMatchMatches returns true if the given value matches the StringMatch filter.
// A nil filter or empty value means no filter is specified, so it always matches.
func StringMatchMatches(sm *proto.StringMatch, val string) bool {
	if sm == nil || sm.Value == "" {
		return true
	}
	if sm.Type == proto.MatchType_Exact {
		return val == sm.Value
	}
	// Fuzzy match uses substring matching, consistent with stringMatches.
	return strings.Contains(val, sm.Value)
}
