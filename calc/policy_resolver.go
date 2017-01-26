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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/multidict"
	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

// PolicyResolver marries up the active policies with local endpoints and
// calculates the complete, ordered set of policies that apply to each endpoint.
// As policies and endpoints are added/removed/updated, it emits events
// via the PolicyResolverCallbacks with the updated set of matching policies.
//
// The PolicyResolver doesn't figure out which policies are currently active, it
// expects to be told via its OnPolicyMatch(Stopped) methods which policies match
// which endpoints.  The ActiveRulesCalculator does that calculation.
type PolicyResolver struct {
	policyIDToEndpointIDs multidict.IfaceToIface
	endpointIDToPolicyIDs multidict.IfaceToIface
	sortedTierData        *tierInfo
	endpoints             map[model.Key]interface{}
	dirtyEndpoints        set.Set
	sortRequired          bool
	policySorter          *PolicySorter
	Callbacks             PolicyResolverCallbacks
	InSync                bool
}

type PolicyResolverCallbacks interface {
	OnEndpointTierUpdate(endpointKey model.Key, endpoint interface{}, filteredTiers []tierInfo)
}

func NewPolicyResolver() *PolicyResolver {
	return &PolicyResolver{
		policyIDToEndpointIDs: multidict.NewIfaceToIface(),
		endpointIDToPolicyIDs: multidict.NewIfaceToIface(),
		sortedTierData:        NewTierInfo("default"),
		endpoints:             make(map[model.Key]interface{}),
		dirtyEndpoints:        set.New(),
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
	case model.PolicyKey:
		log.Debugf("Policy update: %v", key)
		policiesDirty = pr.policySorter.OnUpdate(update)
		pr.markEndpointsMatchingPolicyDirty(key)
	}
	pr.sortRequired = pr.sortRequired || policiesDirty
	pr.maybeFlush()
	return
}

func (pr *PolicyResolver) OnDatamodelStatus(status api.SyncStatus) {
	if status == api.InSync {
		pr.InSync = true
		pr.maybeFlush()
	}
}

func (pr *PolicyResolver) refreshSortOrder() {
	pr.sortedTierData = pr.policySorter.Sorted()
	pr.sortRequired = false
	log.Debugf("New sort order: %v", pr.sortedTierData)
}

func (pr *PolicyResolver) markEndpointsMatchingPolicyDirty(polKey model.PolicyKey) {
	log.Debugf("Marking all endpoints matching %v dirty", polKey)
	pr.policyIDToEndpointIDs.Iter(polKey, func(epID interface{}) {
		pr.dirtyEndpoints.Add(epID)
	})
}

func (pr *PolicyResolver) OnPolicyMatch(policyKey model.PolicyKey, endpointKey interface{}) {
	log.Debugf("Storing policy match %v -> %v", policyKey, endpointKey)
	pr.policyIDToEndpointIDs.Put(policyKey, endpointKey)
	pr.endpointIDToPolicyIDs.Put(endpointKey, policyKey)
	pr.dirtyEndpoints.Add(endpointKey)
	pr.maybeFlush()
}

func (pr *PolicyResolver) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey interface{}) {
	log.Debugf("Deleting policy match %v -> %v", policyKey, endpointKey)
	pr.policyIDToEndpointIDs.Discard(policyKey, endpointKey)
	pr.endpointIDToPolicyIDs.Discard(endpointKey, policyKey)
	pr.dirtyEndpoints.Add(endpointKey)
	pr.maybeFlush()
}

func (pr *PolicyResolver) maybeFlush() {
	if !pr.InSync {
		log.Debugf("Not in sync, skipping flush")
		return
	}
	if pr.sortRequired {
		pr.refreshSortOrder()
	}
	pr.dirtyEndpoints.Iter(pr.sendEndpointUpdate)
	pr.dirtyEndpoints = set.New()
}

func (pr *PolicyResolver) sendEndpointUpdate(endpointID interface{}) error {
	log.Debugf("Sending tier update for endpoint %v", endpointID)
	endpoint, ok := pr.endpoints[endpointID.(model.Key)]
	if !ok {
		log.Debugf("Endpoint is unknown, sending nil update")
		pr.Callbacks.OnEndpointTierUpdate(endpointID.(model.Key),
			nil, []tierInfo{})
		return nil
	}
	applicableTiers := []tierInfo{}
	tier := pr.sortedTierData
	tierMatches := false
	filteredTier := tierInfo{
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
