// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package types_test

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

func TestMatchesEndpoints(t *testing.T) {
	key := func(srcNs, src, dstNs, dst string) *types.FlowKey {
		return types.NewFlowKey(
			&types.FlowKeySource{SourceNamespace: srcNs, SourceName: src},
			&types.FlowKeyDestination{DestNamespace: dstNs, DestName: dst, DestPort: 443},
			&types.FlowKeyMeta{Proto: "tcp"},
			&proto.PolicyTrace{},
		)
	}
	exact := func(v string) *proto.StringMatch { return &proto.StringMatch{Value: v} }
	fuzzy := func(v string) *proto.StringMatch { return &proto.StringMatch{Value: v, Type: proto.MatchType_Fuzzy} }
	endpointOf := func(ns, name string) *proto.EndpointMatch {
		m := &proto.EndpointMatch{}
		if ns != "" {
			m.Namespace = exact(ns)
		}
		if name != "" {
			m.Name = exact(name)
		}
		return m
	}
	endpoints := func(entries ...*proto.FlowEndpointsMatch) *proto.Filter {
		return &proto.Filter{Endpoints: entries}
	}

	flow := key("acme", "x", "other", "y")
	vmToPublic := key("default", "vmToPublic", "-", "pub")

	type endpointFilterCase struct {
		name   string
		filter *proto.Filter
		key    *types.FlowKey
		want   bool
	}
	tests := []endpointFilterCase{
		{"no endpoints", &proto.Filter{}, flow, true},
		{"either matches the source", endpoints(&proto.FlowEndpointsMatch{Either: endpointOf("acme", "x")}), flow, true},
		{"either pairs namespace and name per side", endpoints(&proto.FlowEndpointsMatch{Either: endpointOf("acme", "y")}), flow, false},
		{"either matches the dest namespace", endpoints(&proto.FlowEndpointsMatch{Either: endpointOf("other", "")}), flow, true},
		{"source namespace", endpoints(&proto.FlowEndpointsMatch{Source: endpointOf("acme", "")}), flow, true},
		{"source does not match the dest namespace", endpoints(&proto.FlowEndpointsMatch{Source: endpointOf("other", "")}), flow, false},
		{"dest namespace and name", endpoints(&proto.FlowEndpointsMatch{Dest: endpointOf("other", "y")}), flow, true},
		{
			"source and dest both match",
			endpoints(&proto.FlowEndpointsMatch{Source: endpointOf("acme", ""), Dest: endpointOf("other", "")}),
			flow, true,
		},
		{
			"source matches but dest does not",
			endpoints(&proto.FlowEndpointsMatch{Source: endpointOf("acme", ""), Dest: endpointOf("acme", "")}),
			flow, false,
		},
		{
			"source name only with dest namespace",
			endpoints(&proto.FlowEndpointsMatch{Source: endpointOf("", "x"), Dest: endpointOf("other", "")}),
			flow, true,
		},
		{
			"entries are ORed",
			endpoints(&proto.FlowEndpointsMatch{Source: endpointOf("zzz", "")}, &proto.FlowEndpointsMatch{Dest: endpointOf("other", "")}),
			flow, true,
		},
		{
			"no entry matches",
			endpoints(&proto.FlowEndpointsMatch{Source: endpointOf("zzz", "")}, &proto.FlowEndpointsMatch{Dest: endpointOf("zzz", "")}),
			flow, false,
		},
		{
			"either takes precedence over per-side ends",
			endpoints(&proto.FlowEndpointsMatch{Either: endpointOf("other", ""), Source: endpointOf("zzz", "")}),
			flow, true,
		},
		{
			"ANDs with the other filters",
			&proto.Filter{
				Endpoints: []*proto.FlowEndpointsMatch{{Source: endpointOf("acme", "x")}},
				DestPorts: []*proto.PortMatch{{Port: 80}},
			},
			flow, false,
		},
		{
			"fuzzy name",
			endpoints(&proto.FlowEndpointsMatch{Dest: &proto.EndpointMatch{Namespace: exact("other"), Name: fuzzy("y")}}),
			flow, true,
		},
		{
			"fuzzy name that matches neither side",
			endpoints(&proto.FlowEndpointsMatch{Either: &proto.EndpointMatch{Namespace: exact("other"), Name: fuzzy("nope")}}),
			flow, false,
		},
		{
			"public network display value on dest",
			endpoints(&proto.FlowEndpointsMatch{Dest: endpointOf("Global", "PUBLIC NETWORK")}),
			vmToPublic, true,
		},
		{
			"global display value does not match the source",
			endpoints(&proto.FlowEndpointsMatch{Source: endpointOf("Global", "")}),
			vmToPublic, false,
		},
		{
			"fuzzy global namespace display value",
			endpoints(&proto.FlowEndpointsMatch{Dest: &proto.EndpointMatch{Namespace: fuzzy("Glob")}}),
			vmToPublic, true,
		},
		{
			"fuzzy global namespace display value on a per-side filter",
			&proto.Filter{DestNamespaces: []*proto.StringMatch{fuzzy("Glob")}},
			vmToPublic, true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, types.Matches(tc.filter, tc.key))
		})
	}
}

// TestMatchesAgainstReference compares Matches with the closure-based implementation it
// replaced, over generated keys and filters that exercise every filter field, the UI aliases,
// and the empty-but-non-nil policy filter.
func TestMatchesAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	keys := make([]*types.FlowKey, 200)
	for i := range keys {
		keys[i] = randomFilterKey(rng)
	}

	var matched, rejected int
	for range 2000 {
		filter := randomFilter(rng)
		for _, k := range keys {
			want := referenceMatches(filter, k)
			require.Equal(t, want, types.Matches(filter, k), "filter %v, key %v", filter, k.Fields())
			if want {
				matched++
			} else {
				rejected++
			}
		}
	}

	// Both outcomes have to be common, or the comparison would pass for a trivial Matches.
	require.Greater(t, matched, 20000)
	require.Greater(t, rejected, 20000)
}

func TestMatchesEmptyPolicyFilter(t *testing.T) {
	k := types.ProtoToFlowKey(&proto.FlowKey{
		Policies: &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{{Name: "p"}}},
	})
	require.True(t, types.Matches(&proto.Filter{}, k), "a nil policy filter must match")
	require.False(t, types.Matches(&proto.Filter{Policies: []*proto.PolicyMatch{}}, k), "an empty policy filter matches nothing")
}

var (
	filterKeyNames      = []string{"pub", "pvt", "client-1", "server-*", ""}
	filterKeyNamespaces = []string{"-", "ns-1", "ns-2", ""}
	filterKeyPolicies   = []string{"allow-dns", "deny-all", "staged-allow"}
	filterKeyTiers      = []string{"default", "security"}
	filterValues        = []string{"pub", "PUBLIC NETWORK", "PRIVATE", "NET", "-", "Global", "ns", "ns-1", "client", "server-*", "allow", "staged-allow", "default", ""}
	filterActions       = []proto.Action{proto.Action_ActionUnspecified, proto.Action_Allow, proto.Action_Deny, proto.Action_Pass}
	filterKinds         = []proto.PolicyKind{proto.PolicyKind_KindUnspecified, proto.PolicyKind_CalicoNetworkPolicy, proto.PolicyKind_NetworkPolicy, proto.PolicyKind_EndOfTier}
)

func pick[E any](rng *rand.Rand, s []E) E {
	return s[rng.IntN(len(s))]
}

func randomFilterHits(rng *rand.Rand, n int) []*proto.PolicyHit {
	var hits []*proto.PolicyHit
	for i := range n {
		hits = append(hits, &proto.PolicyHit{
			Kind:        pick(rng, filterKinds[1:]),
			Name:        pick(rng, filterKeyPolicies),
			Namespace:   pick(rng, filterKeyNamespaces),
			Tier:        pick(rng, filterKeyTiers),
			Action:      pick(rng, filterActions[1:]),
			PolicyIndex: int64(i),
		})
	}
	return hits
}

func randomFilterKey(rng *rand.Rand) *types.FlowKey {
	return types.ProtoToFlowKey(&proto.FlowKey{
		SourceName:      pick(rng, filterKeyNames),
		SourceNamespace: pick(rng, filterKeyNamespaces),
		DestName:        pick(rng, filterKeyNames),
		DestNamespace:   pick(rng, filterKeyNamespaces),
		DestPort:        pick(rng, []int64{0, 80, 443}),
		Proto:           pick(rng, []string{"tcp", "udp"}),
		Reporter:        pick(rng, []proto.Reporter{proto.Reporter_Src, proto.Reporter_Dst}),
		Action:          pick(rng, filterActions[1:]),
		Policies: &proto.PolicyTrace{
			EnforcedPolicies: randomFilterHits(rng, rng.IntN(3)),
			PendingPolicies:  randomFilterHits(rng, rng.IntN(3)),
		},
	})
}

// randomFilter leaves each field unset most of the time, so filters combine a few fields.
func randomFilter(rng *rand.Rand) *proto.Filter {
	if rng.IntN(50) == 0 {
		return nil
	}
	set := func() bool { return rng.IntN(4) == 0 }
	strs := func() []*proto.StringMatch {
		if !set() {
			return nil
		}
		var out []*proto.StringMatch
		for range 1 + rng.IntN(2) {
			out = append(out, &proto.StringMatch{
				Value: pick(rng, filterValues),
				Type:  pick(rng, []proto.MatchType{proto.MatchType_Exact, proto.MatchType_Fuzzy}),
			})
		}
		return out
	}
	optStr := func() *proto.StringMatch {
		if m := strs(); m != nil {
			return m[0]
		}
		return nil
	}

	filter := &proto.Filter{
		SourceNames:      strs(),
		DestNames:        strs(),
		SourceNamespaces: strs(),
		DestNamespaces:   strs(),
		Protocols:        strs(),
	}
	if set() {
		filter.Actions = []proto.Action{pick(rng, filterActions[1:])}
	}
	if set() {
		filter.PendingActions = []proto.Action{pick(rng, filterActions[1:]), pick(rng, filterActions[1:])}
	}
	if set() {
		filter.Reporter = pick(rng, []proto.Reporter{proto.Reporter_Src, proto.Reporter_Dst})
	}
	if set() {
		for range 1 + rng.IntN(2) {
			entry := &proto.FlowEndpointsMatch{}
			if rng.IntN(2) == 0 {
				entry.Either = &proto.EndpointMatch{Namespace: optStr(), Name: optStr()}
			}
			if rng.IntN(2) == 0 {
				entry.Source = &proto.EndpointMatch{Namespace: optStr(), Name: optStr()}
			}
			if rng.IntN(2) == 0 {
				entry.Dest = &proto.EndpointMatch{Namespace: optStr(), Name: optStr()}
			}
			filter.Endpoints = append(filter.Endpoints, entry)
		}
	}
	if set() {
		filter.DestPorts = []*proto.PortMatch{{Port: pick(rng, []int64{0, 80, 8080})}}
	}
	switch rng.IntN(6) {
	case 0:
		filter.Policies = []*proto.PolicyMatch{}
	case 1, 2:
		for range 1 + rng.IntN(2) {
			filter.Policies = append(filter.Policies, &proto.PolicyMatch{
				Name:      optStr(),
				Namespace: optStr(),
				Tier:      optStr(),
				Kind:      pick(rng, filterKinds),
				Action:    pick(rng, filterActions),
			})
		}
	}
	return filter
}

// referenceMatches is the closure-based Matches implementation that built a matcher per field
// on every call, kept as an oracle.
func referenceMatches(filter *proto.Filter, key *types.FlowKey) bool {
	if filter == nil {
		return true
	}
	names := func(n string) []string {
		switch n {
		case "pub":
			return []string{"PUBLIC NETWORK", "pub"}
		case "pvt":
			return []string{"PRIVATE NETWORK", "pvt"}
		}
		return []string{n}
	}
	namespaces := func(n string) []string {
		if n == "-" {
			return []string{"-", "Global"}
		}
		return []string{n}
	}
	strMatch := func(filters []*proto.StringMatch, vals []string) bool {
		if len(filters) == 0 {
			return true
		}
		return slices.ContainsFunc(filters, func(f *proto.StringMatch) bool {
			if f.Type == proto.MatchType_Exact {
				return slices.Contains(vals, f.Value)
			}
			return slices.ContainsFunc(vals, func(v string) bool { return strings.Contains(v, f.Value) })
		})
	}
	trace := types.FlowLogPolicyToProto(key.Policies())

	if !strMatch(filter.SourceNames, names(key.SourceName())) ||
		!strMatch(filter.DestNames, names(key.DestName())) ||
		!strMatch(filter.SourceNamespaces, namespaces(key.SourceNamespace())) ||
		!strMatch(filter.DestNamespaces, namespaces(key.DestNamespace())) ||
		!strMatch(filter.Protocols, []string{key.Proto()}) {
		return false
	}
	if len(filter.Actions) > 0 && !slices.Contains(filter.Actions, key.Action()) {
		return false
	}
	if len(filter.PendingActions) > 0 && !slices.ContainsFunc(trace.PendingPolicies, func(h *proto.PolicyHit) bool {
		return slices.Contains(filter.PendingActions, h.Action)
	}) {
		return false
	}
	if filter.Reporter != proto.Reporter_ReporterUnspecified && filter.Reporter != key.Reporter() {
		return false
	}
	if len(filter.DestPorts) > 0 && !slices.ContainsFunc(filter.DestPorts, func(p *proto.PortMatch) bool {
		return p.Port == key.DestPort()
	}) {
		return false
	}
	if len(filter.Endpoints) > 0 && !slices.ContainsFunc(filter.Endpoints, func(e *proto.FlowEndpointsMatch) bool {
		side := func(m *proto.EndpointMatch, ns, name string) bool {
			field := func(sm *proto.StringMatch, vals []string) bool {
				return slices.ContainsFunc(vals, func(v string) bool { return types.StringMatchMatches(sm, v) })
			}
			return field(m.Namespace, namespaces(ns)) && field(m.Name, names(name))
		}
		if e.Either != nil {
			return side(e.Either, key.SourceNamespace(), key.SourceName()) || side(e.Either, key.DestNamespace(), key.DestName())
		}
		return (e.Source == nil || side(e.Source, key.SourceNamespace(), key.SourceName())) &&
			(e.Dest == nil || side(e.Dest, key.DestNamespace(), key.DestName()))
	}) {
		return false
	}
	if filter.Policies == nil {
		return true
	}
	hitMatches := func(h *proto.PolicyHit) bool {
		return slices.ContainsFunc(filter.Policies, func(f *proto.PolicyMatch) bool {
			return types.StringMatchMatches(f.Name, h.Name) &&
				(f.Kind == proto.PolicyKind_KindUnspecified || h.Kind == f.Kind) &&
				types.StringMatchMatches(f.Namespace, h.Namespace) &&
				types.StringMatchMatches(f.Tier, h.Tier) &&
				(f.Action == proto.Action_ActionUnspecified || h.Action == f.Action)
		})
	}
	return slices.ContainsFunc(trace.EnforcedPolicies, hitMatches) || slices.ContainsFunc(trace.PendingPolicies, hitMatches)
}

func TestMatchingSides(t *testing.T) {
	key := types.NewFlowKey(
		&types.FlowKeySource{SourceNamespace: "calico-system", SourceName: "calico-manager"},
		&types.FlowKeyDestination{DestNamespace: "kube-system", DestName: "coredns", DestPort: 53},
		&types.FlowKeyMeta{Proto: "udp"},
		&proto.PolicyTrace{},
	)
	either := func(e *proto.EndpointMatch) *proto.Filter {
		return &proto.Filter{Endpoints: []*proto.FlowEndpointsMatch{{Either: e}}}
	}

	tests := []matchingSidesCase{
		{"no endpoints", &proto.Filter{}, true, true},
		{"nil filter", nil, true, true},
		{
			"either name matches the dest only",
			either(&proto.EndpointMatch{Name: &proto.StringMatch{Value: "core", Type: proto.MatchType_Fuzzy}}),
			false, true,
		},
		{
			"either namespace matches the source only",
			either(&proto.EndpointMatch{Namespace: &proto.StringMatch{Value: "calico-system"}}),
			true, false,
		},
		{
			"either entry that matches neither side",
			either(&proto.EndpointMatch{Namespace: &proto.StringMatch{Value: "default"}}),
			false, false,
		},
		{
			"source-only entry is ignored",
			&proto.Filter{Endpoints: []*proto.FlowEndpointsMatch{{
				Source: &proto.EndpointMatch{Namespace: &proto.StringMatch{Value: "default"}},
			}}},
			true, true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source, dest := types.MatchingSides(tc.filter, key)
			require.Equal(t, tc.wantSource, source, "source")
			require.Equal(t, tc.wantDest, dest, "dest")
		})
	}
}

type matchingSidesCase struct {
	name       string
	filter     *proto.Filter
	wantSource bool
	wantDest   bool
}
