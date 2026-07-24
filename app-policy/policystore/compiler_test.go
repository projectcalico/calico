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

package policystore

import (
	"reflect"
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// fakeCompiler counts compilations and returns a fresh marker value per
// compile, so tests can tell recompilations apart. Policies whose first
// inbound rule has RuleId "fail" refuse to compile (return nil).
type fakeCompiler struct {
	policyCompiles  map[types.PolicyID]int
	profileCompiles map[types.ProfileID]int
}

func newFakeCompiler() *fakeCompiler {
	return &fakeCompiler{
		policyCompiles:  map[types.PolicyID]int{},
		profileCompiles: map[types.ProfileID]int{},
	}
}

type fakeCompiled struct{ generation int }

func (c *fakeCompiler) CompilePolicy(store *PolicyStore, policy *proto.Policy) CompiledPolicy {
	id := findPolicyID(store, policy)
	c.policyCompiles[id]++
	if len(policy.InboundRules) > 0 && policy.InboundRules[0].RuleId == "fail" {
		return nil
	}
	return &fakeCompiled{generation: c.policyCompiles[id]}
}

func (c *fakeCompiler) CompileProfile(store *PolicyStore, profile *proto.Profile) CompiledPolicy {
	id := findProfileID(store, profile)
	c.profileCompiles[id]++
	return &fakeCompiled{generation: c.profileCompiles[id]}
}

func findPolicyID(store *PolicyStore, policy *proto.Policy) types.PolicyID {
	for id, p := range store.PolicyByID {
		if p == policy {
			return id
		}
	}
	return types.PolicyID{}
}

func findProfileID(store *PolicyStore, profile *proto.Profile) types.ProfileID {
	for id, p := range store.ProfileByID {
		if p == profile {
			return id
		}
	}
	return types.ProfileID{}
}

func policyUpdate(name string, policy *proto.Policy) *proto.ToDataplane {
	return &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
		ActivePolicyUpdate: &proto.ActivePolicyUpdate{Id: &proto.PolicyID{Name: name}, Policy: policy},
	}}
}

func policyRemove(name string) *proto.ToDataplane {
	return &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyRemove{
		ActivePolicyRemove: &proto.ActivePolicyRemove{Id: &proto.PolicyID{Name: name}},
	}}
}

func profileUpdate(name string, profile *proto.Profile) *proto.ToDataplane {
	return &proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{
		ActiveProfileUpdate: &proto.ActiveProfileUpdate{Id: &proto.ProfileID{Name: name}, Profile: profile},
	}}
}

func profileRemove(name string) *proto.ToDataplane {
	return &proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileRemove{
		ActiveProfileRemove: &proto.ActiveProfileRemove{Id: &proto.ProfileID{Name: name}},
	}}
}

func ipSetUpdate(id string, members ...string) *proto.ToDataplane {
	return &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetUpdate{
		IpsetUpdate: &proto.IPSetUpdate{Id: id, Type: proto.IPSetUpdate_IP, Members: members},
	}}
}

func ipSetDeltaUpdate(id string, added ...string) *proto.ToDataplane {
	return &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetDeltaUpdate{
		IpsetDeltaUpdate: &proto.IPSetDeltaUpdate{Id: id, AddedMembers: added},
	}}
}

func ipSetRemove(id string) *proto.ToDataplane {
	return &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetRemove{
		IpsetRemove: &proto.IPSetRemove{Id: id},
	}}
}

func pID(name string) types.PolicyID {
	return types.ProtoToPolicyID(&proto.PolicyID{Name: name})
}

func prID(name string) types.ProfileID {
	return types.ProtoToProfileID(&proto.ProfileID{Name: name})
}

// TestCompileOnUpdate verifies that policies and profiles are compiled as
// their updates are applied, recompiled when replaced, and dropped when
// removed.
func TestCompileOnUpdate(t *testing.T) {
	RegisterTestingT(t)

	compiler := newFakeCompiler()
	store := NewPolicyStoreWithCompiler(compiler)

	store.ProcessUpdate("", policyUpdate("policy1", &proto.Policy{}), false)
	Expect(store.CompiledPolicyByID).To(HaveKey(pID("policy1")))
	Expect(compiler.policyCompiles[pID("policy1")]).To(Equal(1))

	// Replacing the policy recompiles it.
	first := store.CompiledPolicyByID[pID("policy1")]
	store.ProcessUpdate("", policyUpdate("policy1", &proto.Policy{}), false)
	Expect(compiler.policyCompiles[pID("policy1")]).To(Equal(2))
	Expect(store.CompiledPolicyByID[pID("policy1")]).NotTo(BeIdenticalTo(first))

	store.ProcessUpdate("", policyRemove("policy1"), false)
	Expect(store.CompiledPolicyByID).To(BeEmpty())

	store.ProcessUpdate("", profileUpdate("profile1", &proto.Profile{}), false)
	Expect(store.CompiledProfileByID).To(HaveKey(prID("profile1")))
	Expect(compiler.profileCompiles[prID("profile1")]).To(Equal(1))

	store.ProcessUpdate("", profileRemove("profile1"), false)
	Expect(store.CompiledProfileByID).To(BeEmpty())
}

// TestCompileFailureLeavesNoEntry verifies that a policy the compiler cannot
// compile gets no compiled entry (so evaluation falls back to interpreting
// it), and that a later working replacement compiles again.
func TestCompileFailureLeavesNoEntry(t *testing.T) {
	RegisterTestingT(t)

	compiler := newFakeCompiler()
	store := NewPolicyStoreWithCompiler(compiler)

	store.ProcessUpdate("", policyUpdate("policy1", &proto.Policy{
		InboundRules: []*proto.Rule{{RuleId: "fail"}},
	}), false)
	Expect(store.PolicyByID).To(HaveKey(pID("policy1")))
	Expect(store.CompiledPolicyByID).To(BeEmpty())

	store.ProcessUpdate("", policyUpdate("policy1", &proto.Policy{}), false)
	Expect(store.CompiledPolicyByID).To(HaveKey(pID("policy1")))
}

// TestNilPolicyUpdateCompilesNothing verifies that a malformed update
// carrying a nil policy/profile does not crash the compile hooks and leaves
// no compiled entry (evaluation falls back to interpreting the stored nil,
// as before).
func TestNilPolicyUpdateCompilesNothing(t *testing.T) {
	RegisterTestingT(t)

	compiler := newFakeCompiler()
	store := NewPolicyStoreWithCompiler(compiler)

	// Replace a healthy policy/profile with a nil one: the compiled entry
	// (and the reverse-index entries) must be dropped.
	store.ProcessUpdate("", ipSetUpdate("set-a", "10.0.0.1"), false)
	store.ProcessUpdate("", policyUpdate("policy1", &proto.Policy{
		InboundRules: []*proto.Rule{{SrcIpSetIds: []string{"set-a"}}},
	}), false)
	store.ProcessUpdate("", profileUpdate("profile1", &proto.Profile{}), false)
	Expect(store.CompiledPolicyByID).To(HaveLen(1))
	Expect(store.CompiledProfileByID).To(HaveLen(1))

	store.ProcessUpdate("", policyUpdate("policy1", nil), false)
	store.ProcessUpdate("", profileUpdate("profile1", nil), false)
	Expect(store.CompiledPolicyByID).To(BeEmpty())
	Expect(store.CompiledProfileByID).To(BeEmpty())
	Expect(store.ipSetPolicyRefs).To(BeEmpty())
}

// TestIPSetInvalidation verifies the reverse index: replacing or removing an
// IP set recompiles exactly the policies and profiles that reference it,
// while membership deltas (which mutate the IPSet object in place) recompile
// nothing.
func TestIPSetInvalidation(t *testing.T) {
	RegisterTestingT(t)

	compiler := newFakeCompiler()
	store := NewPolicyStoreWithCompiler(compiler)

	store.ProcessUpdate("", ipSetUpdate("set-a", "10.0.0.1"), false)
	store.ProcessUpdate("", ipSetUpdate("set-b", "10.0.0.2"), false)
	store.ProcessUpdate("", policyUpdate("refs-a", &proto.Policy{
		InboundRules: []*proto.Rule{{SrcIpSetIds: []string{"set-a"}}},
	}), false)
	store.ProcessUpdate("", policyUpdate("refs-b", &proto.Policy{
		OutboundRules: []*proto.Rule{{NotDstNamedPortIpSetIds: []string{"set-b"}}},
	}), false)
	store.ProcessUpdate("", profileUpdate("profile-a", &proto.Profile{
		InboundRules: []*proto.Rule{{DstIpPortSetIds: []string{"set-a"}}},
	}), false)
	Expect(compiler.policyCompiles).To(Equal(map[types.PolicyID]int{pID("refs-a"): 1, pID("refs-b"): 1}))
	Expect(compiler.profileCompiles).To(Equal(map[types.ProfileID]int{prID("profile-a"): 1}))

	// Replacing set-a recompiles only its referrers.
	store.ProcessUpdate("", ipSetUpdate("set-a", "10.0.0.3"), false)
	Expect(compiler.policyCompiles).To(Equal(map[types.PolicyID]int{pID("refs-a"): 2, pID("refs-b"): 1}))
	Expect(compiler.profileCompiles).To(Equal(map[types.ProfileID]int{prID("profile-a"): 2}))

	// A delta update mutates the set in place: no recompilation.
	store.ProcessUpdate("", ipSetDeltaUpdate("set-a", "10.0.0.4"), false)
	Expect(compiler.policyCompiles[pID("refs-a")]).To(Equal(2))
	Expect(compiler.profileCompiles[prID("profile-a")]).To(Equal(2))

	// Removing set-b recompiles its referrer (defensively; felix should have
	// removed the reference first).
	store.ProcessUpdate("", ipSetRemove("set-b"), false)
	Expect(compiler.policyCompiles).To(Equal(map[types.PolicyID]int{pID("refs-a"): 2, pID("refs-b"): 2}))

	// Replacing refs-a with a policy that no longer references set-a must
	// drop the reverse-index entry: a further set-a replace recompiles only
	// the profile.
	store.ProcessUpdate("", policyUpdate("refs-a", &proto.Policy{}), false)
	Expect(compiler.policyCompiles[pID("refs-a")]).To(Equal(3))
	store.ProcessUpdate("", ipSetUpdate("set-a", "10.0.0.5"), false)
	Expect(compiler.policyCompiles[pID("refs-a")]).To(Equal(3))
	Expect(compiler.profileCompiles[prID("profile-a")]).To(Equal(3))

	// Removing the policies and profile cleans up their index entries: a
	// further replace recompiles nothing.
	store.ProcessUpdate("", policyRemove("refs-a"), false)
	store.ProcessUpdate("", policyRemove("refs-b"), false)
	store.ProcessUpdate("", profileRemove("profile-a"), false)
	store.ProcessUpdate("", ipSetUpdate("set-a", "10.0.0.6"), false)
	Expect(compiler.policyCompiles[pID("refs-a")]).To(Equal(3))
	Expect(compiler.profileCompiles[prID("profile-a")]).To(Equal(3))
	Expect(store.ipSetPolicyRefs).To(BeEmpty())
	Expect(store.ipSetProfileRefs).To(BeEmpty())
}

// TestNilCompilerIsNoOp verifies that a store without a compiler applies
// updates as before and keeps no compiled state.
func TestNilCompilerIsNoOp(t *testing.T) {
	RegisterTestingT(t)

	store := NewPolicyStore()
	store.ProcessUpdate("", ipSetUpdate("set-a", "10.0.0.1"), false)
	store.ProcessUpdate("", policyUpdate("policy1", &proto.Policy{
		InboundRules: []*proto.Rule{{SrcIpSetIds: []string{"set-a"}}},
	}), false)
	store.ProcessUpdate("", profileUpdate("profile1", &proto.Profile{}), false)
	store.ProcessUpdate("", ipSetUpdate("set-a", "10.0.0.2"), false)
	store.ProcessUpdate("", ipSetRemove("set-a"), false)

	Expect(store.PolicyByID).To(HaveLen(1))
	Expect(store.ProfileByID).To(HaveLen(1))
	Expect(store.CompiledPolicyByID).To(BeEmpty())
	Expect(store.CompiledProfileByID).To(BeEmpty())
}

// TestManagerThreadsCompilerThroughReconnect verifies the manager gives every
// store it creates the compiler — in particular the fresh pending store built
// by OnReconnecting, where forgetting it would silently disable compilation
// after the first reconnect.
func TestManagerThreadsCompilerThroughReconnect(t *testing.T) {
	RegisterTestingT(t)

	compiler := newFakeCompiler()
	m := NewPolicyStoreManagerWithOpts(WithPolicyCompiler(compiler))

	sync := func() {
		m.DoWithLock(func(s *PolicyStore) {
			s.ProcessUpdate("", policyUpdate("policy1", &proto.Policy{}), false)
		})
		m.OnInSync()
	}

	sync()
	m.DoWithReadLock(func(s *PolicyStore) {
		Expect(s.CompiledPolicyByID).To(HaveKey(pID("policy1")))
	})

	// Reconnect: updates go to a fresh pending store, which must also
	// compile; after the in-sync swap the compiled entries are visible.
	m.OnReconnecting()
	sync()
	m.DoWithReadLock(func(s *PolicyStore) {
		Expect(s.CompiledPolicyByID).To(HaveKey(pID("policy1")))
	})
	Expect(compiler.policyCompiles[pID("policy1")]).To(Equal(2))
}

// TestForEachIPSetRefCoversRuleFields fails when proto.Rule grows a new IP
// set reference field that forEachRuleIPSetRef does not walk: such a field
// would leave compiled policies holding a stale IPSet object after a full
// IPSetUpdate replaces it. Any []string field whose name mentions IP sets
// must be visited.
func TestForEachIPSetRefCoversRuleFields(t *testing.T) {
	RegisterTestingT(t)

	rule := &proto.Rule{}
	want := map[string]bool{}
	v := reflect.ValueOf(rule).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if !f.IsExported() || f.Type != reflect.TypeOf([]string(nil)) {
			continue
		}
		if !strings.Contains(f.Name, "IpSetIds") && !strings.Contains(f.Name, "IpPortSetIds") {
			continue
		}
		sentinel := "sentinel-" + f.Name
		v.Field(i).Set(reflect.ValueOf([]string{sentinel}))
		want[sentinel] = true
	}
	Expect(want).NotTo(BeEmpty())

	got := map[string]bool{}
	forEachRuleIPSetRef([]*proto.Rule{rule}, func(id string) { got[id] = true })
	Expect(got).To(Equal(want),
		"forEachRuleIPSetRef missed an IP set reference field on proto.Rule; add it to the walker (and the compiler)")
}
