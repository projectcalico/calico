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
	"iter"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
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

type polResolverLabelIndex interface {
	SelectorMatches(selID any, epID any) bool
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
	labelIndex          polResolverLabelIndex
	sortedTierData      []*TierInfo
	endpoints           map[model.EndpointKey]model.Endpoint // Local WEPs/HEPs only.
	dirtyEndpoints      set.Set[model.EndpointKey]
	policySorter        *PolicySorter
	Callbacks           []PolicyResolverCallbacks
	InSync              bool
	endpointBGPPeerData map[model.WorkloadEndpointKey]EndpointBGPPeer
}

type PolicyResolverCallbacks interface {
	OnEndpointTierUpdate(endpointKey model.EndpointKey, endpoint model.Endpoint, peerData *EndpointBGPPeer, filteredTiers []TierInfo)
}

func NewPolicyResolver(li polResolverLabelIndex) *PolicyResolver {
	return &PolicyResolver{
		labelIndex:          li,
		endpoints:           make(map[model.EndpointKey]model.Endpoint),
		dirtyEndpoints:      set.New[model.EndpointKey](),
		endpointBGPPeerData: map[model.WorkloadEndpointKey]EndpointBGPPeer{},
		policySorter:        NewPolicySorter(),
		Callbacks:           []PolicyResolverCallbacks{},
	}
}

func (pr *PolicyResolver) RegisterWith(allUpdDispatcher, localEndpointDispatcher *dispatcher.Dispatcher) {
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
		}
		pr.dirtyEndpoints.Add(key)
		gaugeNumActiveEndpoints.Set(float64(len(pr.endpoints)))
	case model.TierKey:
		log.Debugf("Tier update: %v", key)
		pr.policySorter.OnUpdate(update)
		pr.markAllEndpointsDirty()
	}
	// FIXME Gauge
	//gaugeNumActivePolicies.Set(float64(pr.policyIDToEndpointIDs.LenA()))
	return
}

func (pr *PolicyResolver) OnDatamodelStatus(status api.SyncStatus) {
	if status == api.InSync {
		pr.InSync = true
	}
}

func (pr *PolicyResolver) markAllEndpointsDirty() {
	log.Debugf("Marking all endpoints dirty")
	for epID := range pr.endpoints {
		pr.dirtyEndpoints.Add(epID)
	}
}

func (pr *PolicyResolver) OnPolicyActive(policyKey model.PolicyKey, policy *model.Policy, affectedEndpoints iter.Seq[any]) {
	metadata := ExtractPolicyMetadata(policy)
	policiesDirty := pr.policySorter.UpdatePolicy(policyKey, &metadata)
	if policiesDirty {
		for epID := range affectedEndpoints {
			if epID, ok := epID.(model.EndpointKey); ok {
				pr.dirtyEndpoints.Add(epID)
			}
		}
	}
}

func (pr *PolicyResolver) OnPolicyMatch(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	log.Debugf("Storing policy match %v -> %v", policyKey, endpointKey)
	pr.dirtyEndpoints.Add(endpointKey)
}

func (pr *PolicyResolver) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	log.Debugf("Deleting policy match %v -> %v", policyKey, endpointKey)
	pr.dirtyEndpoints.Add(endpointKey)
}

func (pr *PolicyResolver) OnPolicyInactive(key model.PolicyKey) {
	// This policy is not active anymore, we no longer need to track it for sorting.
	pr.policySorter.UpdatePolicy(key, nil)
}

func (pr *PolicyResolver) Flush() {
	if !pr.InSync {
		log.Debugf("Not in sync, skipping flush")
		return
	}
	pr.sortedTierData = pr.policySorter.Sorted()
	pr.dirtyEndpoints.Iter(pr.sendEndpointUpdate)
	pr.dirtyEndpoints.Clear()
}

func (pr *PolicyResolver) sendEndpointUpdate(endpointID model.EndpointKey) error {
	log.Debugf("Sending tier update for endpoint %v", endpointID)
	endpoint, ok := pr.endpoints[endpointID]
	if !ok {
		log.Debugf("Endpoint is unknown, sending nil update")
		for _, cb := range pr.Callbacks {
			cb.OnEndpointTierUpdate(endpointID, nil, nil, []TierInfo{})
		}
		return nil
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
			if pr.labelIndex.SelectorMatches(polKV.Key, endpointID) {
				log.Debugf("Policy %v matches %v", polKV.Key, endpointID)
				tierMatches = true
				filteredTier.OrderedPolicies = append(filteredTier.OrderedPolicies,
					polKV)
			}
		}
		if tierMatches {
			log.Debugf("Tier %v matches %v", tier.Name, endpointID)
			applicableTiers = append(applicableTiers, filteredTier)
		}
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
		cb.OnEndpointTierUpdate(endpointID, endpoint, peerData, applicableTiers)
	}
	return nil
}

func (pr *PolicyResolver) OnEndpointBGPPeerDataUpdate(key model.WorkloadEndpointKey, peerData *EndpointBGPPeer) {
	if peerData != nil {
		pr.endpointBGPPeerData[key] = *peerData
	} else {
		delete(pr.endpointBGPPeerData, key)
	}
	pr.dirtyEndpoints.Add(key)
}
