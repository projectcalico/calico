// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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
	"maps"
	"reflect"

	"github.com/sirupsen/logrus"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/dataplane/mock"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
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
	ExpectedIPSets                       map[string]set.Set[string]
	ExpectedPolicyIDs                    set.Set[types.PolicyID]
	ExpectedUntrackedPolicyIDs           set.Set[types.PolicyID]
	ExpectedPreDNATPolicyIDs             set.Set[types.PolicyID]
	ExpectedProfileIDs                   set.Set[types.ProfileID]
	ExpectedRoutes                       set.Set[types.RouteUpdate]
	ExpectedVTEPs                        set.Set[types.VXLANTunnelEndpointUpdate]
	ExpectedWireguardEndpoints           set.Set[types.WireguardEndpointUpdate]
	ExpectedWireguardV6Endpoints         set.Set[types.WireguardEndpointV6Update]
	ExpectedEndpointPolicyOrder          map[string][]mock.TierInfo
	ExpectedUntrackedEndpointPolicyOrder map[string][]mock.TierInfo
	ExpectedPreDNATEndpointPolicyOrder   map[string][]mock.TierInfo
	ExpectedHostMetadataV4V6             map[string]*proto.HostMetadataV4V6Update
	ExpectedEndpointComputedData         map[string]map[calc.EndpointComputedDataKind]calc.EndpointComputedData
	ExpectedNumberOfALPPolicies          int
	ExpectedNumberOfTiers                int
	ExpectedNumberOfPolicies             int
	ExpectedEncapsulation                *proto.Encapsulation
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
		ExpectedIPSets:                       make(map[string]set.Set[string]),
		ExpectedPolicyIDs:                    set.New[types.PolicyID](),
		ExpectedUntrackedPolicyIDs:           set.New[types.PolicyID](),
		ExpectedPreDNATPolicyIDs:             set.New[types.PolicyID](),
		ExpectedProfileIDs:                   set.New[types.ProfileID](),
		ExpectedRoutes:                       set.New[types.RouteUpdate](),
		ExpectedVTEPs:                        set.New[types.VXLANTunnelEndpointUpdate](),
		ExpectedWireguardEndpoints:           set.New[types.WireguardEndpointUpdate](),
		ExpectedWireguardV6Endpoints:         set.New[types.WireguardEndpointV6Update](),
		ExpectedEndpointPolicyOrder:          make(map[string][]mock.TierInfo),
		ExpectedUntrackedEndpointPolicyOrder: make(map[string][]mock.TierInfo),
		ExpectedPreDNATEndpointPolicyOrder:   make(map[string][]mock.TierInfo),
		ExpectedHostMetadataV4V6:             make(map[string]*proto.HostMetadataV4V6Update),
		ExpectedEndpointComputedData:         make(map[string]map[calc.EndpointComputedDataKind]calc.EndpointComputedData),
		ExpectedNumberOfPolicies:             -1,
		ExpectedNumberOfTiers:                -1,
		ExpectedEncapsulation:                &proto.Encapsulation{},
	}
}

// copy returns a deep copy of the state.
func (s State) Copy() State {
	cpy := NewState()
	cpy.DatastoreState = append(cpy.DatastoreState, s.DatastoreState...)
	for k, ips := range s.ExpectedIPSets {
		cpy.ExpectedIPSets[k] = ips.Copy()
	}
	maps.Copy(cpy.ExpectedEndpointPolicyOrder, s.ExpectedEndpointPolicyOrder)
	maps.Copy(cpy.ExpectedUntrackedEndpointPolicyOrder, s.ExpectedUntrackedEndpointPolicyOrder)
	maps.Copy(cpy.ExpectedPreDNATEndpointPolicyOrder, s.ExpectedPreDNATEndpointPolicyOrder)
	maps.Copy(cpy.ExpectedHostMetadataV4V6, s.ExpectedHostMetadataV4V6)
	maps.Copy(cpy.ExpectedEndpointComputedData, s.ExpectedEndpointComputedData)

	cpy.ExpectedPolicyIDs = s.ExpectedPolicyIDs.Copy()
	cpy.ExpectedUntrackedPolicyIDs = s.ExpectedUntrackedPolicyIDs.Copy()
	cpy.ExpectedPreDNATPolicyIDs = s.ExpectedPreDNATPolicyIDs.Copy()
	cpy.ExpectedProfileIDs = s.ExpectedProfileIDs.Copy()
	cpy.ExpectedRoutes = s.ExpectedRoutes.Copy()
	cpy.ExpectedVTEPs = s.ExpectedVTEPs.Copy()
	cpy.ExpectedWireguardEndpoints = s.ExpectedWireguardEndpoints.Copy()
	cpy.ExpectedWireguardV6Endpoints = s.ExpectedWireguardV6Endpoints.Copy()
	cpy.ExpectedNumberOfALPPolicies = s.ExpectedNumberOfALPPolicies
	cpy.ExpectedNumberOfTiers = s.ExpectedNumberOfTiers
	cpy.ExpectedNumberOfPolicies = s.ExpectedNumberOfPolicies
	cpy.ExpectedEncapsulation = googleproto.Clone(s.ExpectedEncapsulation).(*proto.Encapsulation)

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
		newKeys[kvToPath(kv)] = true
	}
	// Copy across the old KVs, skipping ones that are in the updates set.
	for _, kv := range s.DatastoreState {
		if newKeys[kvToPath(kv)] {
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
		memSet := set.New[string]()
		for _, member := range members {
			memSet.Add(member)
		}
		newState.ExpectedIPSets[name] = memSet
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

func (s State) withActivePolicies(ids ...types.PolicyID) (newState State) {
	newState = s.Copy()
	newState.ExpectedPolicyIDs = set.New[types.PolicyID]()
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

func (s State) withTotalTiers(count int) (newState State) {
	newState = s.Copy()
	newState.ExpectedNumberOfTiers = count
	return newState
}

func (s State) withTotalActivePolicies(count int) (newState State) {
	newState = s.Copy()
	newState.ExpectedNumberOfPolicies = count
	return newState
}

func (s State) withUntrackedPolicies(ids ...types.PolicyID) (newState State) {
	newState = s.Copy()
	newState.ExpectedUntrackedPolicyIDs = set.New[types.PolicyID]()
	for _, id := range ids {
		newState.ExpectedUntrackedPolicyIDs.Add(id)
	}
	return newState
}

func (s State) withPreDNATPolicies(ids ...types.PolicyID) (newState State) {
	newState = s.Copy()
	newState.ExpectedPreDNATPolicyIDs = set.New[types.PolicyID]()
	for _, id := range ids {
		newState.ExpectedPreDNATPolicyIDs.Add(id)
	}
	return newState
}

func (s State) withActiveProfiles(ids ...types.ProfileID) (newState State) {
	newState = s.Copy()
	newState.ExpectedProfileIDs = set.New[types.ProfileID]()
	for _, id := range ids {
		newState.ExpectedProfileIDs.Add(id)
	}
	return newState
}

func (s State) withVTEPs(vteps ...types.VXLANTunnelEndpointUpdate) (newState State) {
	newState = s.Copy()
	newState.ExpectedVTEPs = set.FromArray(vteps)
	return newState
}

func (s State) withRoutes(routes ...types.RouteUpdate) (newState State) {
	newState = s.Copy()
	newState.ExpectedRoutes = set.FromArray(routes)
	return newState
}

func (s State) withHostMetadataV4V6(hostMetas ...*proto.HostMetadataV4V6Update) (newState State) {
	newState = s.Copy()
	newState.ExpectedHostMetadataV4V6 = make(map[string]*proto.HostMetadataV4V6Update)
	for _, v := range hostMetas {
		newState.ExpectedHostMetadataV4V6[v.Hostname] = v
	}
	return newState
}

func (s State) withExpectedEncapsulation(encap *proto.Encapsulation) (newState State) {
	newState = s.Copy()
	newState.ExpectedEncapsulation = googleproto.Clone(encap).(*proto.Encapsulation)
	return newState
}

func (s State) withWireguardEndpoints(endpoints ...types.WireguardEndpointUpdate) (newState State) {
	newState = s.Copy()
	newState.ExpectedWireguardEndpoints = set.FromArray(endpoints)
	return newState
}

func (s State) withWireguardV6Endpoints(endpoints ...types.WireguardEndpointV6Update) (newState State) {
	newState = s.Copy()
	newState.ExpectedWireguardV6Endpoints = set.FromArray(endpoints)
	return newState
}

func (s State) Keys() set.Set[string] {
	set := set.New[string]()
	for _, kv := range s.DatastoreState {
		set.Add(kvToPath(kv))
	}
	return set
}

func (s State) KVsCopy() map[string]any {
	kvs := make(map[string]any)
	for _, kv := range s.DatastoreState {
		kvs[kvToPath(kv)] = kv.Value
	}
	return kvs
}

func kvToPath(kv model.KVPair) string {
	path, err := model.KeyToDefaultPath(kv.Key)
	if err != nil {
		logrus.WithError(err).WithField("key", kv.Key).Panic("Unable to convert key to default path")
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

func (s State) NumTiers() int {
	if s.ExpectedNumberOfTiers == -1 {
		return s.ActiveKeys(model.TierKey{}).Len()
	} else {
		return s.ExpectedNumberOfTiers
	}
}

func (s State) NumPolicies() int {
	if s.ExpectedNumberOfPolicies == -1 {
		return s.ActiveKeys(model.PolicyKey{}).Len()
	} else {
		return s.ExpectedNumberOfPolicies
	}
}

func (s State) NumProfileRules() int {
	return s.ActiveKeys(model.ProfileRulesKey{}).Len()
}

func (s State) NumALPPolicies() int {
	return s.ExpectedNumberOfALPPolicies
}

func (s State) ActiveKeys(keyTypeExample any) set.Set[model.Key] {
	// Need to be a little careful here, the DatastoreState can contain an ordered sequence of updates and deletions
	// We need to track which keys are actually still live at the end of it.
	keys := set.New[model.Key]()
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
