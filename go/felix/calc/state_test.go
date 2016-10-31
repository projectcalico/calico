// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	. "github.com/projectcalico/libcalico-go/lib/backend/model"
	"reflect"
)

// A state represents a particular state of the datastore and the expected
// result of the calculation graph for that state.
type State struct {
	Name string
	// List of KVPairs that are in the datastore.  Stored as a list rather
	// than a map to give us a deterministic ordering of injection.
	DatastoreState              []KVPair
	ExpectedIPSets              map[string]set.Set
	ExpectedPolicyIDs           set.Set
	ExpectedProfileIDs          set.Set
	ExpectedEndpointPolicyOrder map[string][]tierInfo
}

func (s State) String() string {
	if s.Name == "" {
		return fmt.Sprintf("Unnamed State: %#v", s)
	}
	return s.Name
}

func NewState() State {
	return State{
		DatastoreState:              []KVPair{},
		ExpectedIPSets:              make(map[string]set.Set),
		ExpectedPolicyIDs:           set.New(),
		ExpectedProfileIDs:          set.New(),
		ExpectedEndpointPolicyOrder: make(map[string][]tierInfo),
	}
}

// copy returns a deep copy of the state.
func (s State) copy() State {
	cpy := NewState()
	cpy.DatastoreState = append(cpy.DatastoreState, s.DatastoreState...)
	for k, ips := range s.ExpectedIPSets {
		cpy.ExpectedIPSets[k] = ips.Copy()
	}
	for k, v := range s.ExpectedEndpointPolicyOrder {
		cpy.ExpectedEndpointPolicyOrder[k] = v
	}
	s.ExpectedPolicyIDs.Iter(func(item interface{}) error {
		cpy.ExpectedPolicyIDs.Add(item)
		return nil
	})
	s.ExpectedProfileIDs.Iter(func(item interface{}) error {
		cpy.ExpectedProfileIDs.Add(item)
		return nil
	})
	cpy.Name = s.Name
	return cpy
}

// withKVUpdates returns a deep copy of the state, incorporating the passed KVs.
// If a new KV is an update to an existing KV, the existing KV is discarded and
// the new KV is appended.  If the value of a new KV is nil, it is removed.
func (s State) withKVUpdates(kvs ...KVPair) (newState State) {
	// Start with a clean copy.
	newState = s.copy()
	// But replace the datastoreState, which we're about to modify.
	newState.DatastoreState = make([]KVPair, 0, len(kvs)+len(s.DatastoreState))
	// Make a set containing the new keys.
	newKeys := make(map[Key]bool)
	for _, kv := range kvs {
		newKeys[kv.Key] = true
	}
	// Copy across the old KVs, skipping ones that are in the updates set.
	for _, kv := range s.DatastoreState {
		if newKeys[kv.Key] {
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
	newState = s.copy()
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

func (s State) withEndpoint(id string, tiers []tierInfo) State {
	newState := s.copy()
	if tiers == nil {
		delete(newState.ExpectedEndpointPolicyOrder, id)
	} else {
		newState.ExpectedEndpointPolicyOrder[id] = tiers
	}
	return newState
}

func (s State) withName(name string) (newState State) {
	newState = s.copy()
	newState.Name = name
	return newState
}

func (s State) withActivePolicies(ids ...proto.PolicyID) (newState State) {
	newState = s.copy()
	newState.ExpectedPolicyIDs = set.New()
	for _, id := range ids {
		newState.ExpectedPolicyIDs.Add(id)
	}
	return newState
}

func (s State) withActiveProfiles(ids ...proto.ProfileID) (newState State) {
	newState = s.copy()
	newState.ExpectedProfileIDs = set.New()
	for _, id := range ids {
		newState.ExpectedProfileIDs.Add(id)
	}
	return newState
}

func (s State) Keys() set.Set {
	set := set.New()
	for _, kv := range s.DatastoreState {
		set.Add(kv.Key)
	}
	return set
}

func (s State) KVsCopy() map[Key]interface{} {
	kvs := make(map[Key]interface{})
	for _, kv := range s.DatastoreState {
		kvs[kv.Key] = kv.Value
	}
	return kvs
}

func (s State) KVDeltas(prev State) []api.Update {
	newAndUpdatedKVs := s.KVsCopy()
	updatedKVs := make(map[Key]bool)
	for _, kv := range prev.DatastoreState {
		if reflect.DeepEqual(newAndUpdatedKVs[kv.Key], kv.Value) {
			// Key had same value in both states so we ignore it.
			delete(newAndUpdatedKVs, kv.Key)
		} else {
			// Key has changed
			updatedKVs[kv.Key] = true
		}
	}
	currentKeys := s.Keys()
	deltas := make([]api.Update, 0)
	for _, kv := range prev.DatastoreState {
		if !currentKeys.Contains(kv.Key) {
			deltas = append(
				deltas,
				api.Update{KVPair{Key: kv.Key}, api.UpdateTypeKVDeleted},
			)
		}
	}
	for _, kv := range s.DatastoreState {
		if _, ok := newAndUpdatedKVs[kv.Key]; ok {
			updateType := api.UpdateTypeKVNew
			if updatedKVs[kv.Key] {
				updateType = api.UpdateTypeKVUpdated
			}
			deltas = append(deltas, api.Update{kv, updateType})
		}
	}
	return deltas
}
