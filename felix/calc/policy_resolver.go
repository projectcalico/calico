// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package calc

import (
	"maps"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/multidict"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	gaugeNumActiveEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_active_local_endpoints",
		Help: "Number of active endpoints on this host.",
	})
	gaugeNumActivePolicies = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_active_local_policies",
		Help: "Number of active policies on this host.",
	})
)

func init() {
	prometheus.MustRegister(gaugeNumActiveEndpoints)
	prometheus.MustRegister(gaugeNumActivePolicies)
}

// PolicyResolver marries up the active policies with local endpoints and
// calculates the complete, ordered set of policies that apply to each endpoint.
// As policies and endpoints are added/removed/updated, it emits events
// via the PolicyResolverCallbacks with the updated set of matching policies.
//
// The PolicyResolver doesn't figure out which policies are currently active, it
// expects to be told via its OnPolicyMatch(Stopped) methods which policies match
// which endpoints.  The ActiveRulesCalculator does that calculation.
type PolicyResolver struct {
	policyIDToEndpointIDs multidict.Multidict[model.PolicyKey, model.EndpointKey]
	endpointIDToPolicyIDs multidict.Multidict[model.EndpointKey, model.PolicyKey]
	allPolicies           map[model.PolicyKey]policyMetadata // Only storing metadata for lower occupancy.
	sortedTierData        []*TierInfo
	endpoints             map[model.Key]model.Endpoint // Local WEPs/HEPs only.
	dirtyEndpoints        set.Set[model.EndpointKey]
	endpointComputedData  map[model.WorkloadEndpointKey]map[EndpointComputedDataKind]EndpointComputedData
	policySorter          *PolicySorter
	Callbacks             []PolicyResolverCallbacks
	InSync                bool
	endpointBGPPeerData   map[model.WorkloadEndpointKey]EndpointBGPPeer

	// Track policy updates as they come in - these will be resolved on flush.
	pendingPolicyUpdates set.Set[model.PolicyKey]
}

type PolicyResolverCallbacks interface {
	OnEndpointTierUpdate(endpointKey model.EndpointKey, endpoint model.Endpoint, computedData []EndpointComputedData, peerData *EndpointBGPPeer, filteredTiers []TierInfo)
}

type EndpointComputedDataUpdater func(model.WorkloadEndpointKey, EndpointComputedDataKind, EndpointComputedData)

func NewPolicyResolver() *PolicyResolver {
	return &PolicyResolver{
		policyIDToEndpointIDs: multidict.New[model.PolicyKey, model.EndpointKey](),
		endpointIDToPolicyIDs: multidict.New[model.EndpointKey, model.PolicyKey](),
		allPolicies:           map[model.PolicyKey]policyMetadata{},
		endpoints:             make(map[model.Key]model.Endpoint),
		endpointComputedData:  make(map[model.WorkloadEndpointKey]map[EndpointComputedDataKind]EndpointComputedData),
		dirtyEndpoints:        set.New[model.EndpointKey](),
		endpointBGPPeerData:   map[model.WorkloadEndpointKey]EndpointBGPPeer{},
		policySorter:          NewPolicySorter(),
		Callbacks:             []PolicyResolverCallbacks{},
		pendingPolicyUpdates:  set.New[model.PolicyKey](),
	}
}

func (pr *PolicyResolver) RegisterWith(allUpdDispatcher, localEndpointDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.PolicyKey{}, pr.OnUpdate)
	allUpdDispatcher.Register(model.TierKey{}, pr.OnUpdate)
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, pr.OnUpdate)
	localEndpointDispatcher.Register(model.HostEndpointKey{}, pr.OnUpdate)
	localEndpointDispatcher.RegisterStatusHandler(pr.OnDatamodelStatus)
}

func (pr *PolicyResolver) RegisterCallback(cb PolicyResolverCallbacks) {
	pr.Callbacks = append(pr.Callbacks, cb)
}

func (pr *PolicyResolver) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.EndpointKey:
		if update.Value != nil {
			pr.endpoints[key] = update.Value.(model.Endpoint)
		} else {
			delete(pr.endpoints, key)
			if wlKey, ok := key.(model.WorkloadEndpointKey); ok {
				delete(pr.endpointComputedData, wlKey)
			}
		}
		pr.dirtyEndpoints.Add(key)
		gaugeNumActiveEndpoints.Set(float64(len(pr.endpoints)))
	case model.PolicyKey:
		log.Debugf("Policy update: %v", key)
		if update.Value == nil {
			delete(pr.allPolicies, key)
			pr.pendingPolicyUpdates.Discard(key)
		} else {
			policy := update.Value.(*model.Policy)
			pr.allPolicies[key] = ExtractPolicyMetadata(policy)
		}
		if !pr.policyIDToEndpointIDs.ContainsKey(key) {
			return
		}
		policiesDirty := pr.policySorter.OnUpdate(update)
		if policiesDirty {
			pr.markEndpointsMatchingPolicyDirty(key)
		}
	case model.TierKey:
		log.Debugf("Tier update: %v", key)
		pr.policySorter.OnUpdate(update)
		pr.markAllEndpointsDirty()
	}
	gaugeNumActivePolicies.Set(float64(pr.policyIDToEndpointIDs.Len()))
	return
}

func (pr *PolicyResolver) OnDatamodelStatus(status api.SyncStatus) {
	if status == api.InSync {
		pr.InSync = true
	}
}

func (pr *PolicyResolver) markAllEndpointsDirty() {
	log.Debugf("Marking all endpoints dirty")
	pr.endpointIDToPolicyIDs.IterKeys(func(epID model.EndpointKey) {
		pr.dirtyEndpoints.Add(epID)
	})
}

func (pr *PolicyResolver) markEndpointsMatchingPolicyDirty(polKey model.PolicyKey) {
	log.Debugf("Marking all endpoints matching %v dirty", polKey)
	pr.policyIDToEndpointIDs.Iter(polKey, func(epID model.EndpointKey) {
		pr.dirtyEndpoints.Add(epID)
	})
}

func (pr *PolicyResolver) OnPolicyMatch(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	log.Debugf("Storing policy match %v -> %v", policyKey, endpointKey)
	// If it's first time the policy become matched, add it to the tier
	if !pr.policySorter.HasPolicy(policyKey) {
		// Add a pending policy update to be resolved on flush.
		pr.pendingPolicyUpdates.Add(policyKey)
	}
	pr.policyIDToEndpointIDs.Put(policyKey, endpointKey)
	pr.endpointIDToPolicyIDs.Put(endpointKey, policyKey)
	pr.dirtyEndpoints.Add(endpointKey)
}

func (pr *PolicyResolver) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	log.Debugf("Deleting policy match %v -> %v", policyKey, endpointKey)
	pr.policyIDToEndpointIDs.Discard(policyKey, endpointKey)
	pr.endpointIDToPolicyIDs.Discard(endpointKey, policyKey)

	// This policy is not active anymore, we no longer need to track it for sorting.
	if !pr.policyIDToEndpointIDs.ContainsKey(policyKey) {
		pr.policySorter.UpdatePolicy(policyKey, nil)
	}

	pr.dirtyEndpoints.Add(endpointKey)
}

func (pr *PolicyResolver) OnComputedSelectorMatch(_ string, _ model.EndpointKey)        {}
func (pr *PolicyResolver) OnComputedSelectorMatchStopped(_ string, _ model.EndpointKey) {}

func (pr *PolicyResolver) Flush() {
	if !pr.InSync {
		log.Debugf("Not in sync, skipping flush")
		return
	}
	// Resolve any pending policy updates, and clear the set.
	pr.pendingPolicyUpdates.Iter(func(polKey model.PolicyKey) error {
		policy, ok := pr.allPolicies[polKey]
		if !ok {
			log.Warnf("PolicyResolver missing policy metadata for %s during flush", polKey)
			return nil
		}
		pr.policySorter.UpdatePolicy(polKey, &policy)

		// Continue iteration, removing item from the dirty set.
		return set.RemoveItem
	})

	pr.sortedTierData = pr.policySorter.Sorted()
	for endpointID := range pr.dirtyEndpoints.All() {
		pr.sendEndpointUpdate(endpointID)
	}
	pr.dirtyEndpoints.Clear()
}

func (pr *PolicyResolver) sendEndpointUpdate(endpointID model.EndpointKey) {
	log.Debugf("Sending tier update for endpoint %v", endpointID)
	endpoint, ok := pr.endpoints[endpointID.(model.Key)]
	if !ok {
		log.Debugf("Endpoint is unknown, sending nil update")
		for _, cb := range pr.Callbacks {
			cb.OnEndpointTierUpdate(endpointID, nil, nil, nil, []TierInfo{})
		}
		return
	}

	applicableTiers := []TierInfo{}
	for _, tier := range pr.sortedTierData {
		if !tier.Valid {
			log.Debugf("Tier %v invalid, skipping", tier.Name)
		}
		tierMatches := false
		filteredTier := TierInfo{
			Name:          tier.Name,
			Order:         tier.Order,
			DefaultAction: tier.DefaultAction,
			Valid:         true,
		}
		for _, polKV := range tier.OrderedPolicies {
			log.Debugf("Checking if policy %v matches %v", polKV.Key, endpointID)
			if pr.endpointIDToPolicyIDs.Contains(endpointID, polKV.Key) {
				log.Debugf("Policy %v matches %v", polKV.Key, endpointID)
				tierMatches = true
				filteredTier.OrderedPolicies = append(filteredTier.OrderedPolicies, polKV)
			}
		}
		if tierMatches {
			log.Debugf("Tier %v matches %v", tier.Name, endpointID)
			applicableTiers = append(applicableTiers, filteredTier)
		}
	}

	var computedData []EndpointComputedData
	if key, ok := endpointID.(model.WorkloadEndpointKey); ok {
		computedData = slices.Collect(maps.Values(pr.endpointComputedData[key]))
	}

	log.Debugf("Endpoint tier update: %v -> %v", endpointID, applicableTiers)

	var peerData *EndpointBGPPeer
	if key, ok := endpointID.(model.WorkloadEndpointKey); ok {
		data := pr.endpointBGPPeerData[key]
		if !data.Empty() {
			peerData = &data
		}
	}

	for _, cb := range pr.Callbacks {
		cb.OnEndpointTierUpdate(endpointID, endpoint, computedData, peerData, applicableTiers)
	}
}

func (pr *PolicyResolver) OnEndpointComputedDataUpdate(
	key model.WorkloadEndpointKey,
	kind EndpointComputedDataKind,
	computedData EndpointComputedData,
) {
	epComputedData, exists := pr.endpointComputedData[key]
	if !exists {
		if computedData == nil {
			return
		}
		epComputedData = map[EndpointComputedDataKind]EndpointComputedData{}
		pr.endpointComputedData[key] = epComputedData
	}

	// We can skip a nil -> nil no-op update, but we can't otherwise compare the passed value
	// easily since it may be a pointer type or have unexported fields.
	if computedData == nil && epComputedData[kind] == nil {
		return
	}

	// update
	if computedData != nil {
		epComputedData[kind] = computedData
	} else {
		delete(epComputedData, kind)
		if len(epComputedData) == 0 {
			delete(pr.endpointComputedData, key)
		}
	}
	pr.dirtyEndpoints.Add(key)
}

func (pr *PolicyResolver) OnEndpointBGPPeerDataUpdate(key model.WorkloadEndpointKey, peerData *EndpointBGPPeer) {
	if peerData != nil {
		pr.endpointBGPPeerData[key] = *peerData
	} else {
		delete(pr.endpointBGPPeerData, key)
	}
	pr.dirtyEndpoints.Add(key)
}
