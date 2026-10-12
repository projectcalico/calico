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
	"fmt"
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

func benchFlow() *types.Flow {
	labels := func(p string) []string {
		var out []string
		for j := range 10 {
			out = append(out, fmt.Sprintf("%s.example.com/key-%d=value-%d", p, j, j))
		}
		return out
	}
	hit := func(name string, idx int64) *proto.PolicyHit {
		return &proto.PolicyHit{Kind: proto.PolicyKind_CalicoNetworkPolicy, Name: name, Namespace: "ns-1", Tier: "default", Action: proto.Action_Allow, PolicyIndex: idx, RuleIndex: 1}
	}
	return types.ProtoToFlow(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "client-*",
			SourceNamespace: "ns-1",
			DestName:        "server-*",
			DestNamespace:   "ns-1",
			Proto:           "tcp",
			Reporter:        proto.Reporter_Dst,
			Action:          proto.Action_Allow,
			DestPort:        8080,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{hit("a", 0), hit("b", 1)},
				PendingPolicies:  []*proto.PolicyHit{hit("staged", 0)},
			},
		},
		SourceLabels: labels("src"),
		DestLabels:   labels("dst"),
	})
}

func BenchmarkMatches(b *testing.B) {
	f := benchFlow()
	filters := []struct {
		name   string
		filter *proto.Filter
	}{
		{"empty", &proto.Filter{}},
		{"ns", &proto.Filter{SourceNamespaces: []*proto.StringMatch{{Value: "ns-3", Type: proto.MatchType_Exact}}}},
		{"policy", &proto.Filter{Policies: []*proto.PolicyMatch{{Name: &proto.StringMatch{Value: "staged", Type: proto.MatchType_Exact}}}}},
	}
	for _, tc := range filters {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				types.Matches(tc.filter, f.Key)
			}
		})
	}
}

func BenchmarkFlowIntoProto(b *testing.B) {
	f := benchFlow()
	pf := &proto.Flow{}
	b.ReportAllocs()
	for b.Loop() {
		types.FlowIntoProto(f, pf)
	}
}
