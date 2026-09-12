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

package policyscale

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// Verdict is one entry of the rule trace the engine is expected to report: a Pass on the way, or
// the final Allow or Deny. It carries the fields of calc.RuleID that identify a rule.
type Verdict struct {
	Kind   string // GlobalNetworkPolicy, or Profile for the end-of-profiles deny.
	Tier   string
	Policy string
	Index  int    // Rule index in the policy; TierDefaultIndex for a tier or profile default.
	Action string // allow, deny or pass.
}

const (
	// TierDefaultIndex is the index the engine reports for a tier's default action, and for the
	// deny that ends an evaluation with no matching profile.
	TierDefaultIndex = -1
	// ProfileName is the tier and policy name the engine reports for that deny.
	ProfileName = "__PROFILE__"
)

func (v Verdict) String() string {
	return fmt.Sprintf("%s/%s/%s[%d]=%s", v.Kind, v.Tier, v.Policy, v.Index, v.Action)
}

// Expect returns the trace the engine must report for the flow in the given direction, computed
// from the generator's own model of each rule rather than from the proto the engine reads, so that
// the two are independent. It reproduces the engine's tier walk: policies of a tier in order,
// first matching rule decides; Allow or Deny ends the evaluation; Pass moves to the next tier; a
// tier none of whose policies matched applies its default action; and with no profiles on the
// endpoint, an evaluation that gets past every tier is denied.
func (fx *Fixture) Expect(dir Direction, f *Flow) []Verdict {
	var trace []Verdict
	for _, t := range fx.tiers {
		policies := t.policies[dir]
		if len(policies) == 0 {
			continue
		}
		matched := false
	Tier:
		for _, p := range policies {
			for i, r := range p.rules {
				if !fx.ruleMatches(r, f) {
					continue
				}
				matched = true
				trace = append(trace, Verdict{Kind: v3.KindGlobalNetworkPolicy, Tier: t.name, Policy: p.name, Index: i, Action: r.action})
				if r.action == "pass" {
					break Tier
				}
				return trace
			}
		}
		if !matched {
			action := strings.ToLower(t.defaultAction)
			trace = append(trace, Verdict{Kind: v3.KindGlobalNetworkPolicy, Tier: t.name, Policy: policies[0].name, Index: TierDefaultIndex, Action: action})
			if action != "pass" {
				return trace
			}
		}
	}
	return append(trace, Verdict{Kind: v3.KindProfile, Tier: ProfileName, Policy: ProfileName, Index: TierDefaultIndex, Action: "deny"})
}

// ruleMatches evaluates a rule's criteria against the flow. The criteria are the ones the
// generator emits; each mirrors the engine's semantics for that field:
//   - a protocol outside 1..255 matches no rule;
//   - a port list matches when it lists the flow's destination port;
//   - a CIDR matches when it contains the destination address;
//   - a positive IP set reference requires the address to be a member; a negated one requires it
//     not to be; a reference to a set the store does not hold is skipped, as the engine skips it;
//   - an address that is not an IP (nil) is a member of no set and inside no CIDR.
func (fx *Fixture) ruleMatches(r *ruleModel, f *Flow) bool {
	if f.Protocol < 1 || f.Protocol > 255 {
		return false
	}
	if len(r.dstPorts) > 0 && !slices.Contains(r.dstPorts, int32(f.DstPort)) {
		return false
	}
	if r.dstNet.IsValid() {
		a, ok := toAddr(f.DstIP)
		if !ok || !r.dstNet.Contains(a) {
			return false
		}
	}
	return fx.setAllows(r.srcSet, f.SrcIP, true) &&
		fx.setAllows(r.notSrcSet, f.SrcIP, false) &&
		fx.setAllows(r.dstSet, f.DstIP, true) &&
		fx.setAllows(r.notDstSet, f.DstIP, false)
}

// setAllows reports whether a (possibly negated) reference to a set lets the address through.
func (fx *Fixture) setAllows(setID string, ip net.IP, positive bool) bool {
	if setID == "" {
		return true
	}
	s := fx.sets[setID]
	if s.missing {
		return true
	}
	a, ok := toAddr(ip)
	if !ok {
		return !positive
	}
	_, member := s.addrs[a]
	return member == positive
}

func toAddr(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	return a.Unmap(), ok
}
