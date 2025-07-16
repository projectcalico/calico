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

type qosRuleScanner interface {
	OnPolicyActive(string, *v3.QoSPolicy)
	OnPolicyInactive(string)
}

type QoSPolicyMatchListener interface {
	OnPolicyMatch(policyKey string, endpointKey model.EndpointKey)
	OnPolicyMatchStopped(policyKey string, endpointKey model.EndpointKey)
}

type ActiveQoSPolicyCalculator struct {
	allPolicies map[string]*v3.QoSPolicy

	// Policy/profile ID to matching endpoint sets.
	policyIDToEndpointKeys multidict.Multidict[string, any]

	// Label index, matching policy selectors against local endpoints.
	labelIndex *labelindex.InheritIndex

	// Callback objects.
	RuleScanner          qosRuleScanner
	PolicyMatchListeners []QoSPolicyMatchListener
	RulesUpdateCallbacks qosRulesUpdateCallbacks
}

func NewActiveQoSPolicyCalculator() *ActiveQoSPolicyCalculator {
	aqpc := &ActiveQoSPolicyCalculator{
		allPolicies:            map[string]*v3.QoSPolicy{},
		policyIDToEndpointKeys: multidict.New[string, any](),
	}
	aqpc.labelIndex = labelindex.NewInheritIndex(aqpc.onMatchStarted, aqpc.onMatchStopped)
	return aqpc
}

func (aqpc *ActiveQoSPolicyCalculator) RegisterWith(localEndpointDispatcher, allUpdDispatcher *dispatcher.Dispatcher) {
	// It needs all local endpoints.
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, aqpc.OnUpdate)
	// It also needs QoS Policy resource.
	allUpdDispatcher.Register(model.ResourceKey{}, aqpc.OnUpdate)
}

func (aqpc *ActiveQoSPolicyCalculator) RegisterPolicyMatchListener(listener QoSPolicyMatchListener) {
	aqpc.PolicyMatchListeners = append(aqpc.PolicyMatchListeners, listener)
}

func (aqpc *ActiveQoSPolicyCalculator) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.ResourceKey:
		aqpc.labelIndex.OnUpdate(update)
		switch key.Kind {
		case v3.KindQoSPolicy:
			if update.Value != nil {
				log.Debugf("Updating ARC for qos policy %v", key)
				policy := update.Value.(*v3.QoSPolicy)
				oldPolicy, exists := aqpc.allPolicies[key.Name]
				if exists && reflect.DeepEqual(oldPolicy, policy) {
					if log.IsLevelEnabled(log.DebugLevel) {
						log.WithField("key", update.Key).Debug("No-op qos policy change; ignoring.")
					}
					return
				}

				aqpc.allPolicies[key.Name] = policy

				// Update the index, which will call us back if the selector no
				// longer matches.  Note: we can't skip this even if the
				// policy is force-programmed because we're also responsible
				// for propagating the notification to the policy resolver.
				sel, err := selector.Parse(policy.Spec.Selector)
				if err != nil {
					log.WithError(err).Panic("Failed to parse selector")
				}
				aqpc.labelIndex.UpdateSelector(key, sel)

				if aqpc.policyIDToEndpointKeys.ContainsKey(key.Name) {
					// If we get here, the selector still matches something,
					// update the rules.
					log.Debug("QoS policy updated while active, telling listener")
					aqpc.sendPolicyUpdate(key.Name, policy)
				}
			} else {
				log.Debugf("Deleting qos policy %v from ARC", key)
				delete(aqpc.allPolicies, key.Name)

				aqpc.labelIndex.DeleteSelector(key)
				// No need to call updateQoSPolicy() because we'll have got a matchStopped
				// callback.
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

func (aqpc *ActiveQoSPolicyCalculator) sendPolicyUpdate(policyKey string, policy *v3.QoSPolicy) {
	known := policy != nil
	active := aqpc.policyIDToEndpointKeys.ContainsKey(policyKey)
	log.Debugf("Sending qos policy update for policy %v (known: %v, active: %v)", policyKey, known, active)
	if active {
		if !known {
			// This shouldn't happen because a policy can only become active if
			// we know its selector, which is inside the policy struct.
			log.WithField("policyKey", policyKey).Panic("Unknown qos policy became active!")
		}
		aqpc.RuleScanner.OnPolicyActive(policyKey, policy)
	} else {
		aqpc.RuleScanner.OnPolicyInactive(policyKey)
	}
}

func (aqpc *ActiveQoSPolicyCalculator) onMatchStarted(selID, labelId interface{}) {
	polKey := selID.(string)
	policyWasActive := aqpc.policyIDToEndpointKeys.ContainsKey(polKey)
	aqpc.policyIDToEndpointKeys.Put(polKey, labelId)
	if !policyWasActive {
		// Policy wasn't active before, tell the listener.  The policy
		// must be in allPolicies because we can only match on a policy
		// that we've seen.
		log.Debugf("Policy %v now active", polKey)
		policy, known := aqpc.allPolicies[polKey]
		if !known {
			log.WithField("policy", polKey).Panic("Policy active but missing from allPolicies.")
		}
		aqpc.sendPolicyUpdate(polKey, policy)
	}
	if labelId, ok := labelId.(model.EndpointKey); ok {
		for _, l := range aqpc.PolicyMatchListeners {
			l.OnPolicyMatch(polKey, labelId)
		}
	}
}

func (aqpc *ActiveQoSPolicyCalculator) onMatchStopped(selID, labelId interface{}) {
	polKey := selID.(string)
	aqpc.policyIDToEndpointKeys.Discard(polKey, labelId)
	if !aqpc.policyIDToEndpointKeys.ContainsKey(polKey) {
		// Policy no longer active.
		log.Debugf("Policy %v no longer active", polKey)
		policy, _ := aqpc.allPolicies[polKey]
		aqpc.sendPolicyUpdate(polKey, policy)
	}
	if labelId, ok := labelId.(model.EndpointKey); ok {
		for _, l := range aqpc.PolicyMatchListeners {
			l.OnPolicyMatchStopped(polKey, labelId)
		}
	}
}
