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
	"fmt"
	"net"
	"reflect"
	"runtime"
	"testing"

	. "github.com/onsi/gomega"
	"google.golang.org/genproto/googleapis/rpc/status"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// compileStoreForTest compiles every policy and profile already present in
// the store, as the store itself does when it applies updates with a
// compiler configured. Tests build stores by direct map assignment, which
// bypasses the store's compile-on-update hooks.
func compileStoreForTest(store *policystore.PolicyStore) {
	c := policyCompiler{}
	for id, p := range store.PolicyByID {
		if cp := c.CompilePolicy(store, p); cp != nil {
			store.CompiledPolicyByID[id] = cp
		}
	}
	for id, p := range store.ProfileByID {
		if cp := c.CompileProfile(store, p); cp != nil {
			store.CompiledProfileByID[id] = cp
		}
	}
}

func clearCompiledForTest(store *policystore.PolicyStore) {
	clear(store.CompiledPolicyByID)
	clear(store.CompiledProfileByID)
}

// checkStoreBothEngines runs checkStore with the store's policies
// interpreted, then again with them all compiled, asserts the two engines
// agree, and returns the (interpreted) result. It is a drop-in replacement
// for checkStore in tests, making every checkStore-level test case an
// equivalence test between the two engines.
func checkStoreBothEngines(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir rules.RuleDir, req Flow) *status.Status {
	s, _ := checkTiersBothEngines(store, ep, dir, req)
	return s
}

// checkTiersBothEngines is checkStoreBothEngines for callers that also want
// the rule trace.
func checkTiersBothEngines(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir rules.RuleDir, req Flow) (*status.Status, []*calc.RuleID) {
	s, trace := checkTiers(store, ep, dir, req)
	compileStoreForTest(store)
	compiledS, compiledTrace := checkTiers(store, ep, dir, req)
	clearCompiledForTest(store)
	ExpectWithOffset(2, googleproto.Equal(&compiledS, &s)).To(BeTrue(),
		"compiled and interpreted engines returned different statuses: %v vs %v", &compiledS, &s)
	ExpectWithOffset(2, compiledTrace).To(Equal(trace), "compiled and interpreted engines returned different traces")
	return &s, trace
}

// TestCompiledPolicyEquivalence verifies that the compiled evaluation path returns the same
// (action, index) as the uncompiled checkRules path, for every criterion type a rule can carry,
// with flows chosen to exercise both the matching and non-matching side of each criterion.
func TestCompiledPolicyEquivalence(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	addIPSet(store, "ipset-hit", "10.0.0.1")
	netSet := policystore.NewIPSet(proto.IPSetUpdate_NET)
	netSet.AddString("10.0.0.0/24")
	store.IPSetByID["netset-hit"] = netSet
	addIPSet(store, "portset-src", "1234") // Named port set holding the flows' source port.
	ipPortSet := policystore.NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	ipPortSet.AddString("192.168.1.1,tcp:80")
	store.IPSetByID["ipportset-hit"] = ipPortSet
	// "ipset-missing" is deliberately absent from the store.

	spiffe := func(ns, sa string) *string {
		s := fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", ns, sa)
		return &s
	}
	httpGet := "GET"
	httpPath := "/foo/bar"

	flows := []Flow{
		// Plain L4 flow, matching the IP sets above on the source side.
		&MockFlow{
			SourceIP:   net.ParseIP("10.0.0.1"),
			DestIP:     net.ParseIP("192.168.1.1"),
			SourcePort: 1234,
			DestPort:   80,
			Protocol:   6,
		},
		// Reversed flow: matches the IP sets on the destination side, UDP.
		&MockFlow{
			SourceIP:   net.ParseIP("192.168.1.1"),
			DestIP:     net.ParseIP("10.0.0.1"),
			SourcePort: 80,
			DestPort:   1234,
			Protocol:   17,
		},
		// Flow with peer identities, labels and HTTP data.
		&MockFlow{
			SourceIP:        net.ParseIP("10.0.0.1"),
			DestIP:          net.ParseIP("10.0.0.2"),
			SourcePort:      1234,
			DestPort:        80,
			Protocol:        6,
			SourcePrincipal: spiffe("ns-src", "sa-src"),
			DestPrincipal:   spiffe("ns-dst", "sa-dst"),
			SourceLabels:    map[string]string{"app": "client"},
			HttpMethod:      &httpGet,
			HttpPath:        &httpPath,
		},
		// Out-of-range protocol: the uncompiled path fails every rule on it.
		&MockFlow{
			SourceIP:   net.ParseIP("10.0.0.1"),
			DestIP:     net.ParseIP("192.168.1.1"),
			SourcePort: 1234,
			DestPort:   80,
			Protocol:   0,
		},
	}

	ruleVariants := []*proto.Rule{
		{}, // Empty rule: matches everything.
		{SrcIpSetIds: []string{"ipset-hit"}},
		{SrcIpSetIds: []string{"netset-hit"}},
		{SrcIpSetIds: []string{"ipset-missing"}},
		{NotSrcIpSetIds: []string{"netset-hit"}},
		{DstIpSetIds: []string{"netset-hit"}},
		{DstIpSetIds: []string{"ipset-missing"}},
		{DstIpSetIds: []string{"netset-hit", "ipset-missing"}},
		{NotDstIpSetIds: []string{"netset-hit"}},
		{DstIpPortSetIds: []string{"ipportset-hit"}},
		{DstIpPortSetIds: []string{"ipset-missing"}},
		{SrcPorts: []*proto.PortRange{{First: 1234, Last: 1234}}},
		{SrcPorts: []*proto.PortRange{{First: 65001, Last: 65001}}},
		{NotSrcPorts: []*proto.PortRange{{First: 1234, Last: 1234}}},
		{DstPorts: []*proto.PortRange{{First: 80, Last: 80}}},
		{NotDstPorts: []*proto.PortRange{{First: 80, Last: 80}}},
		{SrcNet: []string{"10.0.0.0/8"}},
		{SrcNet: []string{"172.16.0.0/12"}},
		{NotSrcNet: []string{"10.0.0.0/8"}},
		{DstNet: []string{"192.168.0.0/16"}},
		{NotDstNet: []string{"192.168.0.0/16"}},
		{SrcServiceAccountMatch: &proto.ServiceAccountMatch{Names: []string{"sa-src"}}},
		{SrcServiceAccountMatch: &proto.ServiceAccountMatch{Names: []string{"other-sa"}}},
		{SrcServiceAccountMatch: &proto.ServiceAccountMatch{Selector: "app == 'client'"}},
		{SrcServiceAccountMatch: &proto.ServiceAccountMatch{Selector: "&& not a selector"}},
		{DstServiceAccountMatch: &proto.ServiceAccountMatch{Names: []string{"sa-dst"}}},
		{OriginalSrcNamespaceSelector: "name == 'ns-src'"},
		{OriginalSrcNamespaceSelector: "&& not a selector"},
		{OriginalSrcSelector: "app == 'client'"},
		{OriginalDstNamespaceSelector: "name == 'ns-dst'"},
		{HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}}},
		{HttpMatch: &proto.HTTPMatch{Methods: []string{"POST"}}},
		{HttpMatch: &proto.HTTPMatch{Paths: []*proto.HTTPMatch_PathMatch{
			{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foo"}},
		}}},
		{HttpMatch: &proto.HTTPMatch{Paths: []*proto.HTTPMatch_PathMatch{
			{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/nope"}},
		}}},
		{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}}},
		{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 17}}},
		{NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}}},
		{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "no-such-protocol"}}},
		{NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "no-such-protocol"}}},
		{
			Protocol:    &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 17}},
		},
		{
			Protocol:    &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
		},
		// Malformed CIDRs: matchNet checks CIDRs in order, so an earlier matching
		// net wins before the malformed one is reached.
		{SrcNet: []string{"10.0.0.0/8", "not-a-cidr"}},
		{SrcNet: []string{"not-a-cidr", "10.0.0.0/8"}},
		{SrcNet: []string{"172.16.0.0/12", "not-a-cidr"}},
		{NotSrcNet: []string{"not-a-cidr"}},
		{DstNet: []string{"192.168.0.0/16"}, NotDstNet: []string{"not-a-cidr"}},
		// Named port sets.
		{SrcNamedPortIpSetIds: []string{"portset-src"}},
		{NotSrcNamedPortIpSetIds: []string{"portset-src"}},
		{DstNamedPortIpSetIds: []string{"portset-src"}},
		{DstNamedPortIpSetIds: []string{"ipset-missing"}},
		// Combined criteria, mirroring the baseline-policy benchmark's rule shape.
		{SrcIpSetIds: []string{"ipset-missing"}, SrcPorts: []*proto.PortRange{{First: 65001, Last: 65001}}},
		{DstIpSetIds: []string{"netset-hit"}, DstPorts: []*proto.PortRange{{First: 80, Last: 80}}},
	}

	actions := []string{"allow", "deny", "pass", "log"}

	// Every rule variant becomes a policy of three rules (log rules exercise the
	// "matched but keep going" path), evaluated standalone against each flow, in both
	// namespaced and global form and in both directions.
	for _, namespace := range []string{"", "policy-ns"} {
		for vi, variant := range ruleVariants {
			for _, action := range actions {
				rule := googleproto.Clone(variant).(*proto.Rule)
				rule.Action = action
				ruleSet := []*proto.Rule{
					{Action: "log"}, // Always matches; evaluation must continue past it.
					rule,
					{Action: "allow"}, // Backstop so a non-matching variant still yields index 2.
				}
				cp := compilePolicy(store, ruleSet, ruleSet, namespace)
				Expect(cp).NotTo(BeNil())
				for fi, flow := range flows {
					for _, dir := range []rules.RuleDir{rules.RuleDirIngress, rules.RuleDirEgress} {
						req := NewRequestCache(store, flow)
						wantAction, wantIndex := checkRules(ruleSet, req, namespace)

						req = NewRequestCache(store, flow)
						gotAction, gotIndex := cp.check(dir, req)

						desc := fmt.Sprintf("variant=%d action=%s namespace=%q flow=%d dir=%v", vi, action, namespace, fi, dir)
						Expect(gotAction).To(Equal(wantAction), desc)
						Expect(gotIndex).To(Equal(wantIndex), desc)
					}
				}
			}
		}
	}
}

// TestCompilePolicyBadAction verifies the compile-failure path: a rule with an
// invalid action makes CompilePolicy return nil (instead of panicking), and a
// store built through ProcessUpdate keeps no compiled entry for the policy, so
// evaluation falls back to the interpreted path and preserves its semantics
// (panic at evaluate time, recovered into INVALID_ARGUMENT).
func TestCompilePolicyBadAction(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStoreWithCompiler(policyCompiler{})
	policyID := &proto.PolicyID{Name: "bad-action"}
	store.ProcessUpdate("", &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
		ActivePolicyUpdate: &proto.ActivePolicyUpdate{
			Id:     policyID,
			Policy: &proto.Policy{InboundRules: []*proto.Rule{{Action: "not-an-action"}}},
		},
	}}, false)
	Expect(store.PolicyByID).To(HaveLen(1))
	Expect(store.CompiledPolicyByID).To(BeEmpty())

	ep := &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{{
			Name:            "tier1",
			IngressPolicies: []*proto.PolicyID{policyID},
			DefaultAction:   "Deny",
		}},
	}
	flow := &MockFlow{
		SourceIP: net.ParseIP("10.0.0.1"),
		DestIP:   net.ParseIP("10.0.0.2"),
		Protocol: 6,
	}
	s := checkStore(store, ep, rules.RuleDirIngress, flow)
	Expect(s.Code).To(Equal(INVALID_ARGUMENT))
}

// TestCompiledIPSetReplacement verifies end to end that a full IPSetUpdate
// (which replaces the IPSet object held by compiled matchers) recompiles the
// referencing policy so the compiled path picks up the new set.
func TestCompiledIPSetReplacement(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStoreWithCompiler(policyCompiler{})
	ipSetUpdate := func(member string) *proto.ToDataplane {
		return &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetUpdate{
			IpsetUpdate: &proto.IPSetUpdate{Id: "set-a", Type: proto.IPSetUpdate_NET, Members: []string{member}},
		}}
	}
	store.ProcessUpdate("", ipSetUpdate("10.0.0.1/32"), false)
	policyID := &proto.PolicyID{Name: "policy-a"}
	store.ProcessUpdate("", &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
		ActivePolicyUpdate: &proto.ActivePolicyUpdate{
			Id:     policyID,
			Policy: &proto.Policy{InboundRules: []*proto.Rule{{Action: "allow", SrcIpSetIds: []string{"set-a"}}}},
		},
	}}, false)
	Expect(store.CompiledPolicyByID).To(HaveLen(1))

	ep := &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{{
			Name:            "tier1",
			IngressPolicies: []*proto.PolicyID{policyID},
			DefaultAction:   "Deny",
		}},
	}
	flow := &MockFlow{
		SourceIP: net.ParseIP("10.0.0.2"),
		DestIP:   net.ParseIP("192.168.1.1"),
		Protocol: 6,
	}
	s := checkStore(store, ep, rules.RuleDirIngress, flow)
	Expect(s.Code).To(Equal(PERMISSION_DENIED))

	// Replace the set with one that contains the flow's source IP.
	store.ProcessUpdate("", ipSetUpdate("10.0.0.2/32"), false)
	s = checkStore(store, ep, rules.RuleDirIngress, flow)
	Expect(s.Code).To(Equal(OK))
}

// TestCompiledStaleEndpointReference covers the deleted-endpoint race: the
// felix collector's endpoint cache can hold an endpoint whose TierInfo
// references a policy that has since been removed from the store. The
// compiled dispatch must preserve the interpreted path's behavior for that
// case (checkPolicy(nil)).
func TestCompiledStaleEndpointReference(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	ep := &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{{
			Name:            "tier1",
			IngressPolicies: []*proto.PolicyID{{Name: "removed-policy"}},
			DefaultAction:   "Deny",
		}},
	}
	flow := &MockFlow{
		SourceIP: net.ParseIP("10.0.0.1"),
		DestIP:   net.ParseIP("10.0.0.2"),
		Protocol: 6,
	}
	checkStoreBothEngines(store, ep, rules.RuleDirIngress, flow)
}

// TestCompilerCoversRuleFields fails when proto.Rule grows a field the
// compiler was not written to handle. Every field must be listed either as
// compiled (appendRuleMatchers emits a matcher for it) or as ignored (the
// interpreted path does not evaluate it either, so the compiled path must not
// start doing so). A new field in neither list means the two engines may have
// diverged: extend appendRuleMatchers (and the equivalence test) or record it
// as ignored.
func TestCompilerCoversRuleFields(t *testing.T) {
	compiledFields := map[string]bool{
		"Action":                       true,
		"Protocol":                     true,
		"NotProtocol":                  true,
		"SrcNet":                       true,
		"NotSrcNet":                    true,
		"DstNet":                       true,
		"NotDstNet":                    true,
		"SrcPorts":                     true,
		"NotSrcPorts":                  true,
		"DstPorts":                     true,
		"NotDstPorts":                  true,
		"SrcIpSetIds":                  true,
		"NotSrcIpSetIds":               true,
		"DstIpSetIds":                  true,
		"NotDstIpSetIds":               true,
		"DstIpPortSetIds":              true,
		"SrcNamedPortIpSetIds":         true,
		"NotSrcNamedPortIpSetIds":      true,
		"DstNamedPortIpSetIds":         true,
		"NotDstNamedPortIpSetIds":      true,
		"SrcServiceAccountMatch":       true,
		"DstServiceAccountMatch":       true,
		"OriginalSrcSelector":          true,
		"OriginalNotSrcSelector":       true,
		"OriginalDstSelector":          true,
		"OriginalNotDstSelector":       true,
		"OriginalSrcNamespaceSelector": true,
		"OriginalDstNamespaceSelector": true,
		"HttpMatch":                    true,
	}
	ignoredFields := map[string]bool{
		// Not evaluated by the interpreted match path either.
		"IpVersion":                   true,
		"Icmp":                        true,
		"NotIcmp":                     true,
		"OriginalSrcService":          true,
		"OriginalSrcServiceNamespace": true,
		"OriginalDstService":          true,
		"OriginalDstServiceNamespace": true,
		"Metadata":                    true,
		"RuleId":                      true,
	}

	ruleType := reflect.TypeOf(proto.Rule{})
	for i := 0; i < ruleType.NumField(); i++ {
		f := ruleType.Field(i)
		if !f.IsExported() {
			continue
		}
		if !compiledFields[f.Name] && !ignoredFields[f.Name] {
			t.Errorf("proto.Rule field %s is not handled by the policy compiler: "+
				"extend appendRuleMatchers and TestCompiledPolicyEquivalence, or record it as ignored", f.Name)
		}
	}
}

// TestCompileMemoryFootprint reports the heap cost of compiling the full
// baseline-scale policy set. Not an assertion, a measurement; run with -v to
// see the numbers.
func TestCompileMemoryFootprint(t *testing.T) {
	store, _, _ := buildBaselinePolicyStore(defaultBaselinePolicyScaleParams())

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	compiled := make([]*compiledPolicy, 0, len(store.PolicyByID))
	for _, p := range store.PolicyByID {
		compiled = append(compiled, compilePolicy(store, p.InboundRules, p.OutboundRules, p.Namespace))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("compiled policy set: retained=%dKB totalAlloc=%dKB mallocs=%d",
		(after.HeapAlloc-before.HeapAlloc)/1024,
		(after.TotalAlloc-before.TotalAlloc)/1024,
		after.Mallocs-before.Mallocs)
	runtime.KeepAlive(compiled)
}
