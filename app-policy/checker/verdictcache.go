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

package checker

import (
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	ftypes "github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// verdictKey decides whether a flow's verdict may be served from the store's cache and builds its
// key.
//
// A verdict is a function of the endpoint's applicable rules, the store's IP sets and the flow.
// The first two are covered by the store generation the cache is bound to; the key covers the
// flow. For a flow with no L7 attributes and no peer identity, the criteria in match() reduce to
// protocol, source and destination address, destination port, and source port; identity and HTTP
// criteria match such a flow whatever the rule says. So the key is those fields, with the source
// port included only when a rule that can apply to the endpoint looks at it, which is decided
// once per endpoint and generation.
//
// Flows that carry identity or HTTP attributes (Dikastes requests) are not cached: their verdict
// also depends on the peer's service account and namespace labels.
func verdictKey(store *policystore.PolicyStore, scope PolicyScope, dir rules.RuleDir, ep *proto.WorkloadEndpoint, flow Flow) (policystore.VerdictKey, bool) {
	if ep == nil || !isL4Only(flow) {
		return policystore.VerdictKey{}, false
	}
	src, dst := flow.GetSourceIP().To16(), flow.GetDestIP().To16()
	if src == nil || dst == nil {
		return policystore.VerdictKey{}, false
	}
	key := policystore.VerdictKey{
		Endpoint:  ep,
		Scope:     int8(scope),
		Direction: int8(dir),
		Protocol:  int32(flow.GetProtocol()),
		SrcPort:   -1,
		DstPort:   int32(flow.GetDestPort()),
	}
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	usesSrcPort := store.Verdicts.EndpointFlag(store.Generation, ep, int8(scope), int8(dir), func() bool {
		return endpointMatchesSourcePorts(store, ep, scope, dir)
	})
	if usesSrcPort {
		key.SrcPort = int32(flow.GetSourcePort())
	}
	return key, true
}

// isL4Only reports whether the flow carries nothing but its L3/L4 header, as flows from the
// collector do.
func isL4Only(flow Flow) bool {
	return flow.GetSourcePrincipal() == nil && flow.GetDestPrincipal() == nil &&
		flow.GetHttpMethod() == nil && flow.GetHttpPath() == nil &&
		len(flow.GetSourceLabels()) == 0 && len(flow.GetDestLabels()) == 0
}

// endpointMatchesSourcePorts reports whether any rule that can apply to the endpoint in the scope
// and direction matches on the source port. A policy or profile the store does not hold counts as
// if it did: the evaluation will fail or change once it arrives, and until then the finer key
// only costs hit rate.
func endpointMatchesSourcePorts(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, scope PolicyScope, dir rules.RuleDir) bool {
	for _, tier := range ep.Tiers {
		for _, pID := range getPoliciesByDirection(dir, tier) {
			if scope == EnforcedOnly && model.KindIsStaged(pID.Kind) {
				continue
			}
			policy := store.PolicyByID[ftypes.ProtoToPolicyID(pID)]
			if policy == nil {
				return true
			}
			if dir == rules.RuleDirEgress && rulesMatchSourcePorts(policy.OutboundRules) ||
				dir != rules.RuleDirEgress && rulesMatchSourcePorts(policy.InboundRules) {
				return true
			}
		}
	}
	for _, name := range ep.ProfileIds {
		profile := store.ProfileByID[ftypes.ProtoToProfileID(&proto.ProfileID{Name: name})]
		if profile == nil {
			return true
		}
		if dir == rules.RuleDirEgress && rulesMatchSourcePorts(profile.OutboundRules) ||
			dir != rules.RuleDirEgress && rulesMatchSourcePorts(profile.InboundRules) {
			return true
		}
	}
	return false
}

func rulesMatchSourcePorts(rs []*proto.Rule) bool {
	for _, r := range rs {
		if len(r.SrcPorts) > 0 || len(r.NotSrcPorts) > 0 ||
			len(r.SrcNamedPortIpSetIds) > 0 || len(r.NotSrcNamedPortIpSetIds) > 0 {
			return true
		}
	}
	return false
}
