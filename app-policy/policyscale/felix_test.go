// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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
	"net/netip"
	"slices"
	"strings"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	googleproto "google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// The rendered resources, run through the update processors and Felix's rule scanner and IP set
// index, give exactly the policies the fixture puts in the engine's store: the same name and
// kind, and rule for rule the same fields, with each IP set holding the same members. Then the
// store, the oracle and a cluster all evaluate the same policy set, and the engine's per-rule
// work is a node's.
func TestRenderedResourcesReachFelixAsTheStoreHasThem(t *testing.T) {
	small := Composite()
	small.Baseline.Policies, small.Baseline.DenyRules = 20, 3
	small.Baseline.SizeHistogram = []SizeBucket{{40, 1, 9}, {5, 10, 99}}
	small.Egress.Policies, small.Egress.IPSets = 20, 50
	staged := DefaultShapes()
	staged.Staged = true
	for _, c := range []struct {
		name string
		spec Spec
	}{
		{"shapes", RuleShapes()},
		{"shapes with staged policies", Spec{Seed: DefaultSeed, Shapes: &staged}},
		{"composite", small},
	} {
		fx := Build(c.spec)
		for _, enforced := range []bool{true, false} {
			felix := felixPolicies(t, fx, fx.Resources(ResourceOptions{Enforced: enforced}))
			compared := 0
			for _, tm := range fx.tiers {
				for dir, policies := range tm.policies {
					for _, p := range policies {
						compared++
						kind := p.kind()
						if !enforced {
							kind = AsStaged([]Verdict{{Kind: kind}})[0].Kind
						}
						u := felix.updates[model.PolicyKey{Name: p.name, Kind: kind}]
						if u == nil {
							t.Errorf("%s enforced=%v: Felix has no %s %s", c.name, enforced, kind, p.name)
							continue
						}
						want, got := p.policy.InboundRules, u.Policy.InboundRules
						if Direction(dir) == Egress {
							want, got = p.policy.OutboundRules, u.Policy.OutboundRules
						}
						if len(want) != len(got) {
							t.Errorf("%s enforced=%v: %s has %d rules in Felix, %d in the store", c.name, enforced, p.name, len(got), len(want))
							continue
						}
						for i := range want {
							w := withSetMembers(want[i], func(id string) []string { return slices.Sorted(slices.Values(fx.sets[id].members)) })
							g := withSetMembers(got[i], felix.members)
							if !googleproto.Equal(w, g) {
								t.Errorf("%s enforced=%v: %s rule %d:\n  store %v\n  Felix %v", c.name, enforced, p.name, i, w, g)
							}
						}
					}
				}
			}
			if compared == 0 || len(felix.updates) != compared {
				t.Errorf("%s enforced=%v: Felix has %d policies, the fixture %d", c.name, enforced, len(felix.updates), compared)
			}
		}
	}
}

type felixView struct {
	updates map[model.PolicyKey]*proto.ActivePolicyUpdate
	sets    map[string]*calc.IPSetData
	byID    map[string]map[string]bool
}

func (f *felixView) members(id string) []string {
	return slices.Sorted(func(yield func(string) bool) {
		for m := range f.byID[id] {
			if !yield(m) {
				return
			}
		}
	})
}

// felixPolicies runs the resources through the update processors, the rule scanner and the IP set
// index, with an endpoint for each named port the fixture lists and the services' endpoints as
// the fixture describes them, and returns the policy updates and set members Felix would send.
func felixPolicies(t *testing.T, fx *Fixture, objs []runtime.Object) *felixView {
	t.Helper()
	out := &felixView{
		updates: map[model.PolicyKey]*proto.ActivePolicyUpdate{},
		sets:    map[string]*calc.IPSetData{},
		byID:    map[string]map[string]bool{},
	}
	parsed := &parsedPolicies{byKey: map[model.PolicyKey]*calc.ParsedRules{}}
	rs := calc.NewRuleScanner()
	rs.OnIPSetActive = func(d *calc.IPSetData) { out.sets[d.UniqueID()] = d }
	rs.OnIPSetInactive = func(*calc.IPSetData) {}
	rs.RulesUpdateCallbacks = parsed

	idx := labelindex.NewSelectorAndNamedPortIndex(false)
	idx.OnMemberAdded = func(id string, m ipsetmember.IPSetMember) {
		if out.byID[id] == nil {
			out.byID[id] = map[string]bool{}
		}
		out.byID[id][m.ToProtobufFormat()] = true
	}
	idx.OnMemberRemoved = func(id string, m ipsetmember.IPSetMember) { delete(out.byID[id], m.ToProtobufFormat()) }

	gnp := updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(v3.KindGlobalNetworkPolicy)
	sgnp := updateprocessors.NewStagedGlobalNetworkPolicyUpdateProcessor()
	gns := updateprocessors.NewGlobalNetworkSetUpdateProcessor()
	for _, obj := range objs {
		var kvps []*model.KVPair
		var err error
		switch o := obj.(type) {
		case *v3.GlobalNetworkPolicy:
			kvps, err = gnp.Process(&model.KVPair{Key: model.ResourceKey{Kind: v3.KindGlobalNetworkPolicy, Name: o.Name}, Value: o})
		case *v3.StagedGlobalNetworkPolicy:
			kvps, err = sgnp.Process(&model.KVPair{Key: model.ResourceKey{Kind: v3.KindStagedGlobalNetworkPolicy, Name: o.Name}, Value: o})
		case *v3.GlobalNetworkSet:
			kvps, err = gns.Process(&model.KVPair{Key: model.ResourceKey{Kind: v3.KindGlobalNetworkSet, Name: o.Name}, Value: o})
		default:
			continue
		}
		if err != nil {
			t.Fatalf("processing %T: %v", obj, err)
		}
		for _, kv := range kvps {
			switch k := kv.Key.(type) {
			case model.PolicyKey:
				rs.OnPolicyActive(k, kv.Value.(*model.Policy))
			case model.NetworkSetKey:
				idx.OnUpdate(api.Update{KVPair: *kv, UpdateType: api.UpdateTypeKVNew})
			}
		}
	}
	for i, np := range fx.NamedPorts() {
		wep := &model.WorkloadEndpoint{State: "active", Name: fmt.Sprintf("np%d", i), Labels: uniquelabels.Make(nil)}
		for _, a := range np.Addrs {
			n := cnet.MustParseCIDR(netip.PrefixFrom(a, a.BitLen()).String())
			if a.Is4() {
				wep.IPv4Nets = append(wep.IPv4Nets, n)
			} else {
				wep.IPv6Nets = append(wep.IPv6Nets, n)
			}
		}
		wep.Ports = []model.EndpointPort{{Name: np.Name, Protocol: numorstring.ProtocolFromString(np.Protocol), Port: uint16(np.Port)}}
		key := model.WorkloadEndpointKey{Hostname: "node", OrchestratorID: "k8s", WorkloadID: fmt.Sprintf("np%d", i), EndpointID: "eth0"}
		idx.OnUpdate(api.Update{KVPair: model.KVPair{Key: key, Value: wep}, UpdateType: api.UpdateTypeKVNew})
	}
	for id, d := range out.sets {
		if d.Service == "" {
			idx.UpdateIPSet(id, d.Selector, d.NamedPortProtocol, d.NamedPort)
			continue
		}
		out.byID[id] = map[string]bool{}
		for _, svc := range fx.Services() {
			if d.Service == svc.Namespace+"/"+svc.Name {
				for _, a := range svc.Addrs {
					out.byID[id][fmt.Sprintf("%s,%s:%d", a, strings.ToLower(svc.Protocol), svc.Port)] = true
				}
			}
		}
	}
	for k, r := range parsed.byKey {
		out.updates[k] = calc.ParsedRulesToActivePolicyUpdate(k, r)
	}
	return out
}

type parsedPolicies struct {
	byKey map[model.PolicyKey]*calc.ParsedRules
}

func (p *parsedPolicies) OnPolicyActive(k model.PolicyKey, r *calc.ParsedRules)   { p.byKey[k] = r }
func (p *parsedPolicies) OnPolicyInactive(model.PolicyKey)                         {}
func (p *parsedPolicies) OnProfileActive(model.ProfileRulesKey, *calc.ParsedRules) {}
func (p *parsedPolicies) OnProfileInactive(model.ProfileRulesKey)                  {}

// withSetMembers replaces each IP set reference with the set's members, and clears the fields
// Felix fills in that the engine doesn't read.
func withSetMembers(r *proto.Rule, members func(id string) []string) *proto.Rule {
	c := googleproto.Clone(r).(*proto.Rule)
	c.RuleId = ""
	c.OriginalSrcSelector, c.OriginalDstSelector = "", ""
	c.OriginalNotSrcSelector, c.OriginalNotDstSelector = "", ""
	c.OriginalSrcNamespaceSelector, c.OriginalDstNamespaceSelector = "", ""
	c.OriginalDstService, c.OriginalDstServiceNamespace = "", ""
	c.OriginalSrcService, c.OriginalSrcServiceNamespace = "", ""
	for _, ids := range []*[]string{
		&c.SrcIpSetIds, &c.DstIpSetIds, &c.NotSrcIpSetIds, &c.NotDstIpSetIds,
		&c.SrcNamedPortIpSetIds, &c.DstNamedPortIpSetIds, &c.NotSrcNamedPortIpSetIds, &c.NotDstNamedPortIpSetIds,
		&c.DstIpPortSetIds,
	} {
		var out []string
		for _, id := range *ids {
			out = append(out, "{"+strings.Join(members(id), " ")+"}")
		}
		*ids = out
	}
	return c
}
