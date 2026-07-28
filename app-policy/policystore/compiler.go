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
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// CompiledPolicy is the compiled form of a policy or profile, and
// CompiledEndpoint that of an endpoint's tier/profile structure, both produced
// by a PolicyCompiler. They are opaque to the policy store: the checker
// package both produces the values and consumes them at evaluate time
// (type-asserting back to its concrete types). The types live here rather than
// in checker so that the store can own the compiled artifacts' lifecycle
// without importing checker (checker imports policystore).
type (
	CompiledPolicy   interface{}
	CompiledEndpoint interface{}
)

// PolicySlot holds a policy's (or profile's) compiled form behind a pointer
// that is stable for as long as the policy exists. A compiled endpoint holds
// the slots of the policies its tiers name, so recompiling a policy — on a
// policy update, or when an IP set it references is replaced — publishes
// through the slot and leaves every compiled endpoint referencing it
// untouched. Without the indirection, a single policy update would have to
// rebuild every endpoint that names the policy, which for an
// all-endpoints policy is every endpoint on the node.
type PolicySlot struct {
	compiled CompiledPolicy
}

// Compiled returns the policy's compiled form, or nil if it has none (not
// compiled yet, compilation failed, or the policy has been removed). It is
// nil-receiver-safe so that callers can treat "no slot" and "empty slot"
// alike.
func (s *PolicySlot) Compiled() CompiledPolicy {
	if s == nil {
		return nil
	}
	return s.compiled
}

// PolicyCompiler compiles policies, profiles and endpoints into a form that is
// cheap to evaluate per flow. The store invokes it eagerly as updates are
// applied (off the flow evaluation hot path, under the store's write lock),
// and again for affected policies when an IP set they reference is replaced or
// removed. A nil return means the input could not be compiled; the store keeps
// no compiled entry for it and evaluation falls back to interpreting the
// uncompiled form.
type PolicyCompiler interface {
	CompilePolicy(store *PolicyStore, policy *proto.Policy) CompiledPolicy
	CompileProfile(store *PolicyStore, profile *proto.Profile) CompiledPolicy
	// CompileEndpoint resolves an endpoint's tier and profile references to
	// the store's PolicySlots, so that evaluation walks a slice instead of
	// hashing every policy ID per flow. Felix sends policies and profiles
	// before the endpoints that name them, so the slots exist by now; one
	// that does not (a staged policy the store drops, or an out-of-sync
	// store) simply falls back to the by-ID lookup for that policy.
	CompileEndpoint(store *PolicyStore, ep *proto.WorkloadEndpoint) CompiledEndpoint
}

// SetPolicyCompiler configures the store's compiler and compiles everything
// already in it; updates applied afterwards are compiled as they arrive. It is
// for callers that populate a store directly rather than through ProcessUpdate
// — the store manager wires a compiler into the stores it creates with
// WithPolicyCompiler instead.
func (store *PolicyStore) SetPolicyCompiler(compiler PolicyCompiler) {
	store.compiler = compiler
	store.ipSetPolicyRefs = nil
	store.ipSetProfileRefs = nil
	if compiler == nil {
		return
	}
	for id, p := range store.PolicyByID {
		store.onPolicyUpdate(id, nil, p)
	}
	for id, p := range store.ProfileByID {
		store.onProfileUpdate(id, nil, p)
	}
	// Endpoints last: their compiled form resolves the policy and profile
	// slots compiled above.
	store.onEndpointUpdate(nil, store.Endpoint)
	for _, ep := range store.Endpoints {
		store.onEndpointUpdate(nil, ep)
	}
}

// onPolicyUpdate maintains the compiled form and the IP set reverse index for
// a stored (or replaced) policy. old is the policy previously stored under
// the ID, or nil.
func (store *PolicyStore) onPolicyUpdate(id types.PolicyID, old, updated *proto.Policy) {
	if store.compiler == nil {
		return
	}
	if old != nil {
		forEachIPSetRef(old, func(setID string) {
			deleteRef(store.ipSetPolicyRefs, setID, id)
		})
	}
	if updated != nil {
		forEachIPSetRef(updated, func(setID string) {
			addRef(&store.ipSetPolicyRefs, setID, id)
		})
	}
	store.compilePolicy(id, updated)
}

// onPolicyRemove drops a removed policy's compiled form and reverse-index
// entries. old is the policy previously stored under the ID, or nil.
func (store *PolicyStore) onPolicyRemove(id types.PolicyID, old *proto.Policy) {
	if store.compiler == nil {
		return
	}
	if old != nil {
		forEachIPSetRef(old, func(setID string) {
			deleteRef(store.ipSetPolicyRefs, setID, id)
		})
	}
	// Empty the slot as well as dropping it: a compiled endpoint that still
	// names the removed policy holds the slot, and must stop evaluating it.
	if slot, ok := store.CompiledPolicyByID[id]; ok {
		slot.compiled = nil
		delete(store.CompiledPolicyByID, id)
	}
}

// onProfileUpdate is onPolicyUpdate for profiles.
func (store *PolicyStore) onProfileUpdate(id types.ProfileID, old, updated *proto.Profile) {
	if store.compiler == nil {
		return
	}
	if old != nil {
		forEachProfileIPSetRef(old, func(setID string) {
			deleteRef(store.ipSetProfileRefs, setID, id)
		})
	}
	if updated != nil {
		forEachProfileIPSetRef(updated, func(setID string) {
			addRef(&store.ipSetProfileRefs, setID, id)
		})
	}
	store.compileProfile(id, updated)
}

// onProfileRemove is onPolicyRemove for profiles.
func (store *PolicyStore) onProfileRemove(id types.ProfileID, old *proto.Profile) {
	if store.compiler == nil {
		return
	}
	if old != nil {
		forEachProfileIPSetRef(old, func(setID string) {
			deleteRef(store.ipSetProfileRefs, setID, id)
		})
	}
	if slot, ok := store.CompiledProfileByID[id]; ok {
		slot.compiled = nil
		delete(store.CompiledProfileByID, id)
	}
}

// onIPSetReplaced recompiles the policies and profiles that reference an IP
// set whose object was replaced (full IPSetUpdate) or removed. Compiled
// matchers hold the IPSet object itself, so a replaced object would otherwise
// leave them evaluating the stale set. Membership deltas mutate the set in
// place and do NOT come through here. During the initial resync this is free:
// felix sends IP sets before the policies that reference them, so the reverse
// index is empty when the sets arrive.
func (store *PolicyStore) onIPSetReplaced(setID string) {
	if store.compiler == nil {
		return
	}
	for policyID := range store.ipSetPolicyRefs[setID] {
		store.compilePolicy(policyID, store.PolicyByID[policyID])
	}
	for profileID := range store.ipSetProfileRefs[setID] {
		store.compileProfile(profileID, store.ProfileByID[profileID])
	}
}

// compilePolicy and compileProfile publish a policy's compiled form through
// its slot, reusing the slot when there is one so that compiled endpoints
// holding it see the new form. A nil policy/profile (a malformed update, or a
// stale reverse-index entry) is treated as not compilable: the slot is
// emptied and evaluation falls back to interpreting the stored value.
func (store *PolicyStore) compilePolicy(id types.PolicyID, policy *proto.Policy) {
	var cp CompiledPolicy
	if policy != nil {
		cp = store.compiler.CompilePolicy(store, policy)
	}
	if slot, ok := store.CompiledPolicyByID[id]; ok {
		slot.compiled = cp
		return
	}
	if cp != nil {
		store.CompiledPolicyByID[id] = &PolicySlot{compiled: cp}
	}
}

func (store *PolicyStore) compileProfile(id types.ProfileID, profile *proto.Profile) {
	var cp CompiledPolicy
	if profile != nil {
		cp = store.compiler.CompileProfile(store, profile)
	}
	if slot, ok := store.CompiledProfileByID[id]; ok {
		slot.compiled = cp
		return
	}
	if cp != nil {
		store.CompiledProfileByID[id] = &PolicySlot{compiled: cp}
	}
}

// onEndpointUpdate compiles a stored (or replaced) endpoint. old is the
// endpoint previously stored under the same ID, or nil; its compiled form is
// dropped, since compiled endpoints are keyed by the identity of the endpoint
// object they were built from.
func (store *PolicyStore) onEndpointUpdate(old, updated *proto.WorkloadEndpoint) {
	if store.compiler == nil {
		return
	}
	if old != nil {
		delete(store.CompiledEndpoints, old)
	}
	if updated == nil {
		return
	}
	if ce := store.compiler.CompileEndpoint(store, updated); ce != nil {
		store.CompiledEndpoints[updated] = ce
	}
}

// onEndpointRemove drops a removed endpoint's compiled form.
func (store *PolicyStore) onEndpointRemove(old *proto.WorkloadEndpoint) {
	if store.compiler == nil || old == nil {
		return
	}
	delete(store.CompiledEndpoints, old)
}

// forEachIPSetRef calls f once per IP set ID referenced by the policy's
// rules (duplicates included). The field list must cover every proto.Rule
// field holding IP set IDs so that a replaced IP set recompiles every policy
// whose compiled form resolved it; TestForEachIPSetRefCoversRuleFields fails
// if proto.Rule grows an IP set reference field that is missing here.
func forEachIPSetRef(policy *proto.Policy, f func(setID string)) {
	forEachRuleIPSetRef(policy.InboundRules, f)
	forEachRuleIPSetRef(policy.OutboundRules, f)
}

func forEachProfileIPSetRef(profile *proto.Profile, f func(setID string)) {
	forEachRuleIPSetRef(profile.InboundRules, f)
	forEachRuleIPSetRef(profile.OutboundRules, f)
}

func forEachRuleIPSetRef(rules []*proto.Rule, f func(setID string)) {
	for _, r := range rules {
		for _, ids := range [][]string{
			r.SrcIpSetIds,
			r.NotSrcIpSetIds,
			r.SrcNamedPortIpSetIds,
			r.NotSrcNamedPortIpSetIds,
			r.DstIpSetIds,
			r.NotDstIpSetIds,
			r.DstNamedPortIpSetIds,
			r.NotDstNamedPortIpSetIds,
			r.DstIpPortSetIds,
		} {
			for _, id := range ids {
				f(id)
			}
		}
	}
}

// addRef and deleteRef maintain a reverse index from IP set ID to the
// policies (or profiles) whose compiled form references it. Reference counts
// are not needed: deleteRef is only called with every ref of a policy at
// once, and duplicate adds are idempotent.
func addRef[ID comparable](index *map[string]map[ID]struct{}, setID string, id ID) {
	if *index == nil {
		*index = make(map[string]map[ID]struct{})
	}
	refs := (*index)[setID]
	if refs == nil {
		refs = make(map[ID]struct{})
		(*index)[setID] = refs
	}
	refs[id] = struct{}{}
}

func deleteRef[ID comparable](index map[string]map[ID]struct{}, setID string, id ID) {
	refs := index[setID]
	delete(refs, id)
	if len(refs) == 0 {
		delete(index, setID)
	}
}
