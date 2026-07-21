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

// CompiledPolicy is the compiled form of a policy or profile, produced by a
// PolicyCompiler. It is opaque to the policy store: the checker package both
// produces the values and consumes them at evaluate time (type-asserting back
// to its concrete type). The type lives here rather than in checker so that
// the store can own the compiled artifacts' lifecycle without importing
// checker (checker imports policystore).
type CompiledPolicy interface{}

// PolicyCompiler compiles policies and profiles into a form that is cheap to
// evaluate per flow. The store invokes it eagerly as updates are applied (off
// the flow evaluation hot path, under the store's write lock), and again for
// affected policies when an IP set they reference is replaced or removed. A
// nil return means the policy could not be compiled; the store keeps no
// compiled entry for it and evaluation falls back to interpreting the
// uncompiled policy.
type PolicyCompiler interface {
	CompilePolicy(store *PolicyStore, policy *proto.Policy) CompiledPolicy
	CompileProfile(store *PolicyStore, profile *proto.Profile) CompiledPolicy
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
	delete(store.CompiledPolicyByID, id)
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
	delete(store.CompiledProfileByID, id)
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

// compilePolicy and compileProfile treat a nil policy/profile (a malformed
// update, or a stale reverse-index entry) as not compilable: the entry is
// dropped and evaluation falls back to interpreting the stored value.
func (store *PolicyStore) compilePolicy(id types.PolicyID, policy *proto.Policy) {
	var cp CompiledPolicy
	if policy != nil {
		cp = store.compiler.CompilePolicy(store, policy)
	}
	if cp != nil {
		store.CompiledPolicyByID[id] = cp
	} else {
		delete(store.CompiledPolicyByID, id)
	}
}

func (store *PolicyStore) compileProfile(id types.ProfileID, profile *proto.Profile) {
	var cp CompiledPolicy
	if profile != nil {
		cp = store.compiler.CompileProfile(store, profile)
	}
	if cp != nil {
		store.CompiledProfileByID[id] = cp
	} else {
		delete(store.CompiledProfileByID, id)
	}
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
