// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	"fmt"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dataplane/mock"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// A state represents a particular state of the datastore and the expected
// result of the calculation graph for that state.
type State struct {
	Name string
	// List of KVPairs that are in the datastore.  Stored as a list rather
	// than a map to give us a deterministic ordering of injection.
	DatastoreState                       []model.KVPair
	ExpectedIPSets                       map[string]set.Set
	ExpectedPolicyIDs                    set.Set
	ExpectedUntrackedPolicyIDs           set.Set
	ExpectedPreDNATPolicyIDs             set.Set
	ExpectedProfileIDs                   set.Set
	ExpectedRoutes                       set.Set
	ExpectedVTEPs                        set.Set
	ExpectedEndpointPolicyOrder          map[string][]mock.TierInfo
	ExpectedUntrackedEndpointPolicyOrder map[string][]mock.TierInfo
	ExpectedPreDNATEndpointPolicyOrder   map[string][]mock.TierInfo
	ExpectedNumberOfALPPolicies          int
	ExpectedEncapsulation                proto.Encapsulation
}

func (s State) String() string {
	if s.Name == "" {
		return fmt.Sprintf("Unnamed State: %#v", s)
	}
	return s.Name
}

func NewState() State {
	return State{
		DatastoreState:                       []model.KVPair{},
		ExpectedIPSets:                       make(map[string]set.Set),
		ExpectedPolicyIDs:                    set.New(),
		ExpectedUntrackedPolicyIDs:           set.New(),
		ExpectedPreDNATPolicyIDs:             set.New(),
		ExpectedProfileIDs:                   set.New(),
		ExpectedRoutes:                       set.New(),
		ExpectedVTEPs:                        set.New(),
		ExpectedEndpointPolicyOrder:          make(map[string][]mock.TierInfo),
		ExpectedUntrackedEndpointPolicyOrder: make(map[string][]mock.TierInfo),
		ExpectedPreDNATEndpointPolicyOrder:   make(map[string][]mock.TierInfo),
	}
}

// copy returns a deep copy of the state.
func (s State) Copy() State {
	cpy := NewState()
	cpy.DatastoreState = append(cpy.DatastoreState, s.DatastoreState...)
	for k, ips := range s.ExpectedIPSets {
		cpy.ExpectedIPSets[k] = ips.Copy()
	}
	for k, v := range s.ExpectedEndpointPolicyOrder {
		cpy.ExpectedEndpointPolicyOrder[k] = v
	}
	for k, v := range s.ExpectedUntrackedEndpointPolicyOrder {
		cpy.ExpectedUntrackedEndpointPolicyOrder[k] = v
	}
	for k, v := range s.ExpectedPreDNATEndpointPolicyOrder {
		cpy.ExpectedPreDNATEndpointPolicyOrder[k] = v
	}

	cpy.ExpectedPolicyIDs = s.ExpectedPolicyIDs.Copy()
	cpy.ExpectedUntrackedPolicyIDs = s.ExpectedUntrackedPolicyIDs.Copy()
	cpy.ExpectedPreDNATPolicyIDs = s.ExpectedPreDNATPolicyIDs.Copy()
	cpy.ExpectedProfileIDs = s.ExpectedProfileIDs.Copy()
	cpy.ExpectedRoutes = s.ExpectedRoutes.Copy()
	cpy.ExpectedVTEPs = s.ExpectedVTEPs.Copy()
	cpy.ExpectedNumberOfALPPolicies = s.ExpectedNumberOfALPPolicies
	cpy.ExpectedEncapsulation = s.ExpectedEncapsulation

	cpy.Name = s.Name
	return cpy
}

// withKVUpdates returns a deep copy of the state, incorporating the passed KVs.
// If a new KV is an update to an existing KV, the existing KV is discarded and
// the new KV is appended.  If the value of a new KV is nil, it is removed.
func (s State) withKVUpdates(kvs ...model.KVPair) (newState State) {
	// Start with a clean copy.
	newState = s.Copy()
	// But replace the datastoreState, which we're about to modify.
	newState.DatastoreState = make([]model.KVPair, 0, len(kvs)+len(s.DatastoreState))
	// Make a set containing the new keys.
	newKeys := make(map[string]bool)
	for _, kv := range kvs {
		path, err := model.KeyToDefaultPath(kv.Key)
		if err != nil {
			logrus.WithField("key", kv.Key).Panic("Unable to convert key to default path")
		}
		newKeys[path] = true
	}
	// Copy across the old KVs, skipping ones that are in the updates set.
	for _, kv := range s.DatastoreState {
		path, err := model.KeyToDefaultPath(kv.Key)
		if err != nil {
			logrus.WithField("key", kv.Key).Panic("Unable to convert key to default path")
		}
		if newKeys[path] {
			continue
		}
		newState.DatastoreState = append(newState.DatastoreState, kv)
	}
	// Copy in the updates in order.
	for _, kv := range kvs {
		if kv.Value == nil {
			continue
		}
		newState.DatastoreState = append(newState.DatastoreState, kv)
	}
	return
}

func (s State) withIPSet(name string, members []string) (newState State) {
	// Start with a clean copy.
	newState = s.Copy()
	if members == nil {
		delete(newState.ExpectedIPSets, name)
	} else {
		set := set.New()
		for _, ip := range members {
			set.Add(ip)
		}
		newState.ExpectedIPSets[name] = set
	}
	return
}

func (s State) withEndpoint(id string, tiers []mock.TierInfo) State {
	return s.withEndpointUntracked(id, tiers, []mock.TierInfo{}, []mock.TierInfo{})
}

func (s State) withEndpointUntracked(id string, tiers, untrackedTiers, preDNATTiers []mock.TierInfo) State {
	newState := s.Copy()
	if tiers == nil {
		delete(newState.ExpectedEndpointPolicyOrder, id)
		delete(newState.ExpectedUntrackedEndpointPolicyOrder, id)
		delete(newState.ExpectedPreDNATEndpointPolicyOrder, id)
	} else {
		newState.ExpectedEndpointPolicyOrder[id] = tiers
		newState.ExpectedUntrackedEndpointPolicyOrder[id] = untrackedTiers
		newState.ExpectedPreDNATEndpointPolicyOrder[id] = preDNATTiers
	}
	return newState
}

func (s State) withName(name string) (newState State) {
	newState = s.Copy()
	newState.Name = name
	return newState
}

func (s State) withActivePolicies(ids ...proto.PolicyID) (newState State) {
	newState = s.Copy()
	newState.ExpectedPolicyIDs = set.New()
	for _, id := range ids {
		newState.ExpectedPolicyIDs.Add(id)
	}
	return newState
}

func (s State) withTotalALPPolicies(count int) (newState State) {
	newState = s.Copy()
	newState.ExpectedNumberOfALPPolicies = count
	return newState
}

func (s State) withUntrackedPolicies(ids ...proto.PolicyID) (newState State) {
	newState = s.Copy()
	newState.ExpectedUntrackedPolicyIDs = set.New()
	for _, id := range ids {
		newState.ExpectedUntrackedPolicyIDs.Add(id)
	}
	return newState
}

func (s State) withPreDNATPolicies(ids ...proto.PolicyID) (newState State) {
	newState = s.Copy()
	newState.ExpectedPreDNATPolicyIDs = set.New()
	for _, id := range ids {
		newState.ExpectedPreDNATPolicyIDs.Add(id)
	}
	return newState
}

func (s State) withActiveProfiles(ids ...proto.ProfileID) (newState State) {
	newState = s.Copy()
	newState.ExpectedProfileIDs = set.New()
	for _, id := range ids {
		newState.ExpectedProfileIDs.Add(id)
	}
	return newState
}

func (s State) withVTEPs(vteps ...proto.VXLANTunnelEndpointUpdate) (newState State) {
	newState = s.Copy()
	newState.ExpectedVTEPs = set.FromArray(vteps)
	return newState
}

func (s State) withRoutes(routes ...proto.RouteUpdate) (newState State) {
	newState = s.Copy()
	newState.ExpectedRoutes = set.FromArray(routes)
	return newState
}

func (s State) withExpectedEncapsulation(encap proto.Encapsulation) (newState State) {
	newState = s.Copy()
	newState.ExpectedEncapsulation = encap
	return newState
}

func (s State) Keys() set.Set {
	set := set.New()
	for _, kv := range s.DatastoreState {
		set.Add(kvToPath(kv))
	}
	return set
}

func (s State) KVsCopy() map[string]interface{} {
	kvs := make(map[string]interface{})
	for _, kv := range s.DatastoreState {
		kvs[kvToPath(kv)] = kv.Value
	}
	return kvs
}

func kvToPath(kv model.KVPair) string {
	path, err := model.KeyToDefaultPath(kv.Key)
	if err != nil {
		logrus.WithField("key", kv.Key).Panic("Unable to convert key to default path")
	}
	return path
}

func (s State) KVDeltas(prev State) []api.Update {
	newAndUpdatedKVs := s.KVsCopy()
	updatedKVs := make(map[string]bool)
	for _, kv := range prev.DatastoreState {
		if reflect.DeepEqual(newAndUpdatedKVs[kvToPath(kv)], kv.Value) {
			// Key had same value in both states so we ignore it.
			delete(newAndUpdatedKVs, kvToPath(kv))
		} else {
			// Key has changed
			updatedKVs[kvToPath(kv)] = true
		}
	}
	currentKeys := s.Keys()
	deltas := make([]api.Update, 0)
	for _, kv := range prev.DatastoreState {
		if !currentKeys.Contains(kvToPath(kv)) {
			deltas = append(
				deltas,
				api.Update{KVPair: model.KVPair{Key: kv.Key}, UpdateType: api.UpdateTypeKVDeleted},
			)
		}
	}
	for _, kv := range s.DatastoreState {
		if _, ok := newAndUpdatedKVs[kvToPath(kv)]; ok {
			updateType := api.UpdateTypeKVNew
			if updatedKVs[kvToPath(kv)] {
				updateType = api.UpdateTypeKVUpdated
			}
			deltas = append(deltas, api.Update{KVPair: kv, UpdateType: updateType})
		}
	}
	return deltas
}

func (s State) NumPolicies() int {
	return s.ActiveKeys(model.PolicyKey{}).Len()
}

func (s State) NumProfileRules() int {
	return s.ActiveKeys(model.ProfileRulesKey{}).Len()
}

func (s State) NumALPPolicies() int {
	return s.ExpectedNumberOfALPPolicies
}

func (s State) ActiveKeys(keyTypeExample interface{}) set.Set {
	// Need to be a little careful here, the DatastoreState can contain an ordered sequence of updates and deletions
	// We need to track which keys are actually still live at the end of it.
	keys := set.New()
	for _, u := range s.DatastoreState {
		if reflect.TypeOf(u.Key) != reflect.TypeOf(keyTypeExample) {
			continue
		}
		if u.Value == nil {
			keys.Discard(u.Key)
		} else {
			keys.Add(u.Key)
		}
	}
	return keys
}
