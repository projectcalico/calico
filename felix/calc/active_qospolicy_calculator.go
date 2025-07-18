// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"reflect"

	"github.com/google/btree"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/multidict"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

type ActiveQoSPolicyCalculator struct {
	allPolicies map[string]*v3.QoSPolicy

	sortedQoSPolicies *btree.BTreeG[qosPolicyKey]

	// Policy/profile ID to matching endpoint sets.
	policyIDToEndpointIDs multidict.Multidict[string, model.EndpointKey]
	endpointIDToPolicyIDs multidict.Multidict[model.EndpointKey, string]

	// Label index, matching policy selectors against local endpoints.
	labelIndex *labelindex.InheritIndex

	// Callback objects.
	OnQoSPolicyDataUpdate func(id model.EndpointKey, qosPolicy *endpointQoSPolicy)
}

type endpointQoSPolicy struct {
	v3QoSPolicyName string
}

type qosPolicyKey struct {
	Name  string
	Order *float64
}

type qosPolicyInfo struct {
	Order float64
}

func NewActiveQoSPolicyCalculator() *ActiveQoSPolicyCalculator {
	aqpc := &ActiveQoSPolicyCalculator{
		allPolicies:           map[string]*v3.QoSPolicy{},
		sortedQoSPolicies:     btree.NewG[qosPolicyKey](2, qosPolicyLess),
		policyIDToEndpointIDs: multidict.New[string, model.EndpointKey](),
		endpointIDToPolicyIDs: multidict.New[model.EndpointKey, string](),
	}
	aqpc.labelIndex = labelindex.NewInheritIndex(aqpc.onMatchStarted, aqpc.onMatchStopped)
	return aqpc
}

func (aqpc *ActiveQoSPolicyCalculator) RegisterWith(localEndpointDispatcher, allUpdDispatcher *dispatcher.Dispatcher) {
	// It needs all local endpoints.
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, aqpc.OnUpdate)
	localEndpointDispatcher.Register(model.HostEndpointKey{}, aqpc.OnUpdate)
	// It also needs QoS Policy resource.
	allUpdDispatcher.Register(model.ResourceKey{}, aqpc.OnUpdate)
}

func (aqpc *ActiveQoSPolicyCalculator) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.EndpointKey:
		aqpc.labelIndex.OnUpdate(update)
	case model.ResourceKey:
		aqpc.labelIndex.OnUpdate(update)

		switch key.Kind {
		case v3.KindQoSPolicy:
			if update.Value != nil {
				log.Debugf("Updating AQPC for qos policy %v", key)
				policy := update.Value.(*v3.QoSPolicy)
				oldPolicy, exists := aqpc.allPolicies[key.Name]
				if exists && reflect.DeepEqual(oldPolicy, policy) {
					if log.IsLevelEnabled(log.DebugLevel) {
						log.WithField("key", update.Key).Debug("No-op qos policy change; ignoring.")
					}
					return
				}

				aqpc.allPolicies[key.Name] = policy
				aqpc.onPolicyActive(policy)
			} else {
				log.Debugf("Deleting qos policy %v from ARC", key)
				delete(aqpc.allPolicies, key.Name)
				aqpc.OnPolicyInactive(key.Name)
			}
		default:
			// Ignore other kinds of v3 resource.
		}
	default:
		logrus.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return
}

func (aqpc *ActiveQoSPolicyCalculator) onPolicyActive(policy *v3.QoSPolicy) {
	name := policy.Name

	// Update the index, which will call us back if the selector no
	// longer matches.  Note: we can't skip this even if the
	// policy is force-programmed because we're also responsible
	// for propagating the notification to the policy resolver.
	sel, err := selector.Parse(policy.Spec.Selector)
	if err != nil {
		log.WithError(err).Panic("Failed to parse selector")
	}
	aqpc.labelIndex.UpdateSelector(name, sel)

	if aqpc.policyIDToEndpointIDs.ContainsKey(name) {
		// If we get here, the selector still matches something,
		// update the rules.
		log.Debug("QoS policy updated while active, telling listener")
		aqpc.sendPolicyUpdate(name, policy)
	}
}

func (aqpc *ActiveQoSPolicyCalculator) OnPolicyInactive(name string) {
	// No need to call updateQoSPolicy() because we'll have got a matchStopped callback.
	aqpc.labelIndex.DeleteSelector(name)
}

func (aqpc *ActiveQoSPolicyCalculator) onMatchStarted(policyName any, endpointID any) {
	id := endpointID.(model.EndpointKey)
	polName := policyName.(string)
	policyWasActive := aqpc.policyIDToEndpointIDs.ContainsKey(polName)
	aqpc.policyIDToEndpointIDs.Put(polName, endpointID)
	if !policyWasActive {
		// Policy wasn't active before, tell the listener.  The policy
		// must be in allPolicies because we can only match on a policy
		// that we've seen.
		log.Debugf("Policy %v now active", polName)
		policy, known := aqpc.allPolicies[polName]
		if !known {
			log.WithField("policy", polName).Panic("Policy active but missing from allPolicies.")
		}

		aqpc.sendPolicyUpdate(id, policy)
	}
	/*if labelId, ok := labelId.(model.EndpointKey); ok {
		for _, l := range aqpc.PolicyMatchListeners {
			l.OnPolicyMatch(polKey, labelId)
		}
	}*/
}

func (aqpc *ActiveQoSPolicyCalculator) onMatchStopped(selID, labelId interface{}) {
	polKey := selID.(string)
	aqpc.policyIDToEndpointIDs.Discard(polKey, labelId)
	if !aqpc.policyIDToEndpointIDs.ContainsKey(polKey) {
		// Policy no longer active.
		log.Debugf("Policy %v no longer active", polKey)
		policy, _ := aqpc.allPolicies[polKey]
		aqpc.sendPolicyUpdate(endpointID, policy)
	}
	/*if labelId, ok := labelId.(model.EndpointKey); ok {
		for _, l := range aqpc.PolicyMatchListeners {
			l.OnPolicyMatchStopped(polKey, labelId)
		}
	}*/
}

func (aqpc *ActiveQoSPolicyCalculator) sendPolicyUpdate(id model.EndpointKey, policyKey string, policy *v3.QoSPolicy) {
	known := policy != nil
	active := aqpc.policyIDToEndpointIDs.ContainsKey(policyKey)
	log.Debugf("Sending qos policy update for policy %v (known: %v, active: %v)", policyKey, known, active)
	if active {
		if !known {
			// This shouldn't happen because a policy can only become active if
			// we know its selector, which is inside the policy struct.
			log.WithField("policyKey", policyKey).Panic("Unknown qos policy became active!")
		}
		//aqpc.RuleScanner.OnPolicyActive(policyKey, policy)
		aqpc.OnQoSPolicyDataUpdate(id, nil) // we need to send the sorted list here.
	} else {
		//aqpc.RuleScanner.OnPolicyInactive(policyKey)
		aqpc.OnQoSPolicyDataUpdate(id, nil)
	}
}

func qosPolicyLess(i, j qosPolicyKey) bool {
	// TODO(mazdak): need to add valid?
	/*if !i.Valid && j.Valid {
		return false
	} else if i.Valid && !j.Valid {
		return true
	}*/

	if i.Order == nil && j.Order != nil {
		return false
	} else if i.Order != nil && j.Order == nil {
		return true
	}
	if i.Order == j.Order || *i.Order == *j.Order {
		return i.Name < j.Name
	}
	return *i.Order < *j.Order
}

func (aqpc *ActiveQoSPolicyCalculator) HasQoSPolicy(key string) bool {
	_, exists := aqpc.allPolicies[key]
	return exists
}

func (aqpc *ActiveQoSPolicyCalculator) UpdateQoSPolicy(key model.ResourceKey, newPolicy *v3.QoSPolicy) {
	var polInfo qosPolicyInfo
	if newPolicy != nil {
		if newPolicy.Spec.Order != nil {
			polInfo.Order = *newPolicy.Spec.Order
		} else {
			polInfo.Order = polMetaDefaultOrder
		}
	}

	oldPolicy := aqpc.allPolicies[key.Name]
	if equalQoSPolicy(newPolicy, oldPolicy) {
		return
	}
	if newPolicy != nil {
		if oldPolicy != nil {
			// Need to do delete prior to ReplaceOrInsert because we don't insert strictly based on key but rather a
			// combination of key + value so if for instance we add PolKV{k1, v1} then add PolKV{k1, v2} we'll simply have
			// both KVs in the tree instead of only {k1, v2} like we want. By deleting first we guarantee that only the
			// newest value remains in the tree.
			aqpc.sortedQoSPolicies.Delete(qosPolicyKey{Name: key.Name, Order: &oldPolicy.Order})
		}
		aqpc.sortedQoSPolicies.ReplaceOrInsert(qosPolicyKey{Name: key.Name, Order: &oldPolicy.Order})
		aqpc.allPolicies[key.Name] = newPolicy
	} else {
		if oldPolicy != nil {
			aqpc.sortedQoSPolicies.Delete(qosPolicyKey{Name: key.Name, Order: &oldPolicy.Order})
			delete(aqpc.allPolicies, key.Name)
			return
		}
	}
	return
}

func (aqpc *ActiveQoSPolicyCalculator) Sorted() []qosPolicyKey {
	var policies []qosPolicyKey
	if aqpc.sortedQoSPolicies.Len() > 0 {
		policies = make([]qosPolicyKey, 0, len(aqpc.allPolicies))
		aqpc.sortedQoSPolicies.Ascend(func(p qosPolicyKey) bool {
			policies = append(policies, p)
			return true
		})
	}
	return policies
}

func equalQoSPolicy(n, o *qosPolicyInfo) bool {
	if n != nil && o != nil {
		return *n == *o
	}
	return n == o
}
