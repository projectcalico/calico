// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	policyIDToEndpointIDs multidict.Multidict[model.PolicyKey, any]
	endpointIDToPolicyIDs multidict.Multidict[any, model.PolicyKey]
	allPolicies           map[model.PolicyKey]*model.Policy
	sortedTierData        *TierInfo
	endpoints             map[model.Key]interface{}
	dirtyEndpoints        set.Set[any] /* FIXME model.WorkloadEndpointKey or model.HostEndpointKey */
	policySorter          *PolicySorter
	Callbacks             PolicyResolverCallbacks
	InSync                bool
}

type PolicyResolverCallbacks interface {
	OnEndpointTierUpdate(endpointKey model.Key, endpoint interface{}, filteredTiers []TierInfo)
}

func NewPolicyResolver() *PolicyResolver {
	return &PolicyResolver{
		policyIDToEndpointIDs: multidict.New[model.PolicyKey, any](),
		endpointIDToPolicyIDs: multidict.New[any, model.PolicyKey](),
		allPolicies:           map[model.PolicyKey]*model.Policy{},
		sortedTierData:        NewTierInfo("default"),
		endpoints:             make(map[model.Key]interface{}),
		dirtyEndpoints:        set.New[any](),
		policySorter:          NewPolicySorter(),
	}
}

func (pr *PolicyResolver) RegisterWith(allUpdDispatcher, localEndpointDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.PolicyKey{}, pr.OnUpdate)
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, pr.OnUpdate)
	localEndpointDispatcher.Register(model.HostEndpointKey{}, pr.OnUpdate)
	localEndpointDispatcher.RegisterStatusHandler(pr.OnDatamodelStatus)
}

func (pr *PolicyResolver) OnUpdate(update api.Update) (filterOut bool) {
	policiesDirty := false
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey, model.HostEndpointKey:
		if update.Value != nil {
			pr.endpoints[key] = update.Value
		} else {
			delete(pr.endpoints, key)
		}
		pr.dirtyEndpoints.Add(key)
		gaugeNumActiveEndpoints.Set(float64(len(pr.endpoints)))
	case model.PolicyKey:
		log.Debugf("Policy update: %v", key)
		if update.Value == nil {
			delete(pr.allPolicies, key)
		} else {
			policy := update.Value.(*model.Policy)
			pr.allPolicies[key] = policy
		}
		if !pr.policyIDToEndpointIDs.ContainsKey(key) {
			return
		}
		policiesDirty = pr.policySorter.OnUpdate(update)
		if policiesDirty {
			pr.markEndpointsMatchingPolicyDirty(key)
		}
	}
	gaugeNumActivePolicies.Set(float64(pr.policyIDToEndpointIDs.Len()))
	return
}

func (pr *PolicyResolver) OnDatamodelStatus(status api.SyncStatus) {
	if status == api.InSync {
		pr.InSync = true
	}
}

func (pr *PolicyResolver) markEndpointsMatchingPolicyDirty(polKey model.PolicyKey) {
	log.Debugf("Marking all endpoints matching %v dirty", polKey)
	pr.policyIDToEndpointIDs.Iter(polKey, func(epID interface{}) {
		pr.dirtyEndpoints.Add(epID)
	})
}

func (pr *PolicyResolver) OnPolicyMatch(policyKey model.PolicyKey, endpointKey interface{}) {
	log.Debugf("Storing policy match %v -> %v", policyKey, endpointKey)
	// If it's first time the policy become matched, add it to the tier
	if !pr.policySorter.HasPolicy(policyKey) {
		policy := pr.allPolicies[policyKey]
		pr.policySorter.UpdatePolicy(policyKey, policy)
	}
	pr.policyIDToEndpointIDs.Put(policyKey, endpointKey)
	pr.endpointIDToPolicyIDs.Put(endpointKey, policyKey)
	pr.dirtyEndpoints.Add(endpointKey)
}

func (pr *PolicyResolver) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey interface{}) {
	log.Debugf("Deleting policy match %v -> %v", policyKey, endpointKey)
	pr.policyIDToEndpointIDs.Discard(policyKey, endpointKey)
	pr.endpointIDToPolicyIDs.Discard(endpointKey, policyKey)

	// This policy is not active anymore, we no longer need to track it for sorting.
	if !pr.policyIDToEndpointIDs.ContainsKey(policyKey) {
		pr.policySorter.UpdatePolicy(policyKey, nil)
	}

	pr.dirtyEndpoints.Add(endpointKey)
}

func (pr *PolicyResolver) Flush() {
	if !pr.InSync {
		log.Debugf("Not in sync, skipping flush")
		return
	}
	pr.sortedTierData = pr.policySorter.Sorted()
	pr.dirtyEndpoints.Iter(pr.sendEndpointUpdate)
	pr.dirtyEndpoints = set.New[any]()
}

func (pr *PolicyResolver) sendEndpointUpdate(endpointID interface{}) error {
	log.Debugf("Sending tier update for endpoint %v", endpointID)
	endpoint, ok := pr.endpoints[endpointID.(model.Key)]
	if !ok {
		log.Debugf("Endpoint is unknown, sending nil update")
		pr.Callbacks.OnEndpointTierUpdate(endpointID.(model.Key),
			nil, []TierInfo{})
		return nil
	}
	applicableTiers := []TierInfo{}
	tier := pr.sortedTierData
	tierMatches := false
	filteredTier := TierInfo{
		Name:  tier.Name,
		Order: tier.Order,
	}
	for _, polKV := range tier.OrderedPolicies {
		log.Debugf("Checking if policy %v matches %v", polKV.Key, endpointID)
		if pr.endpointIDToPolicyIDs.Contains(endpointID, polKV.Key) {
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
	log.Debugf("Endpoint tier update: %v -> %v", endpointID, applicableTiers)
	pr.Callbacks.OnEndpointTierUpdate(endpointID.(model.Key),
		endpoint, applicableTiers)
	return nil
}
