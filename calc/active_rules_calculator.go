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
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/labelindex"
	"github.com/projectcalico/felix/multidict"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type ruleScanner interface {
	OnPolicyActive(model.PolicyKey, *model.Policy)
	OnPolicyInactive(model.PolicyKey)
	OnProfileActive(model.ProfileRulesKey, *model.ProfileRules)
	OnProfileInactive(model.ProfileRulesKey)
}

type FelixSender interface {
	SendUpdateToFelix(update model.KVPair)
}

type PolicyMatchListener interface {
	OnPolicyMatch(policyKey model.PolicyKey, endpointKey interface{})
	OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey interface{})
}

// ActiveRulesCalculator calculates the set of policies and profiles (i.e. the rules) that
// are active for the particular endpoints that it's been told about.  It emits events
// when the set of active rules changes.
//
// For example, if the ActiveRulesCalculator is fed *all* the policies/profiles along with
// the endpoints that are on the local host then its output (via the callback objects) will
// indicate exactly which policies/profiles are active on the local host.
//
// When looking at policies, the ActiveRules calculator is only interested in the selector
// attached to the policy itself (which determines the set of endpoints that it applies to).
// The rules in a policy may also contain selectors; those are are ignored here; they are
// mapped to IP sets by the RuleScanner.
type ActiveRulesCalculator struct {
	// Caches of all known policies/profiles.
	allPolicies     map[model.PolicyKey]*model.Policy
	allProfileRules map[string]*model.ProfileRules

	// Policy/profile ID to matching endpoint sets.
	policyIDToEndpointKeys  multidict.IfaceToIface
	profileIDToEndpointKeys multidict.IfaceToIface

	// Label index, matching policy selectors against local endpoints.
	labelIndex *labelindex.InheritIndex

	// Cache of profile IDs by local endpoint.
	endpointKeyToProfileIDs *EndpointKeyToProfileIDMap

	// True if we've got the in-sync message from the datastore.
	datastoreInSync bool
	// Set containing the names of any profiles that were missing during the resync.  Used to
	// log out those profiles at the end of the resync.
	missingProfiles set.Set

	// Callback objects.
	RuleScanner         ruleScanner
	PolicyMatchListener PolicyMatchListener
}

func NewActiveRulesCalculator() *ActiveRulesCalculator {
	arc := &ActiveRulesCalculator{
		// Caches of all known policies/profiles.
		allPolicies:     make(map[model.PolicyKey]*model.Policy),
		allProfileRules: make(map[string]*model.ProfileRules),

		// Policy/profile ID to matching endpoint sets.
		policyIDToEndpointKeys:  multidict.NewIfaceToIface(),
		profileIDToEndpointKeys: multidict.NewIfaceToIface(),
		missingProfiles:         set.New(),

		// Cache of profile IDs by local endpoint.
		endpointKeyToProfileIDs: NewEndpointKeyToProfileIDMap(),
	}
	arc.labelIndex = labelindex.NewInheritIndex(arc.onMatchStarted, arc.onMatchStopped)
	return arc
}

func (arc *ActiveRulesCalculator) RegisterWith(localEndpointDispatcher, allUpdDispatcher *dispatcher.Dispatcher) {
	// It needs the filtered endpoints...
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, arc.OnUpdate)
	localEndpointDispatcher.Register(model.HostEndpointKey{}, arc.OnUpdate)
	// ...as well as all the policies and profiles.
	allUpdDispatcher.Register(model.PolicyKey{}, arc.OnUpdate)
	allUpdDispatcher.Register(model.ProfileRulesKey{}, arc.OnUpdate)
	allUpdDispatcher.Register(model.ProfileLabelsKey{}, arc.OnUpdate)
	allUpdDispatcher.Register(model.ProfileTagsKey{}, arc.OnUpdate)
	allUpdDispatcher.RegisterStatusHandler(arc.OnStatusUpdate)
}

func (arc *ActiveRulesCalculator) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			log.Debugf("Updating ARC with endpoint %v", key)
			endpoint := update.Value.(*model.WorkloadEndpoint)
			profileIDs := endpoint.ProfileIDs
			arc.updateEndpointProfileIDs(key, profileIDs)
		} else {
			log.Debugf("Deleting endpoint %v from ARC", key)
			arc.updateEndpointProfileIDs(key, []string{})
		}
		arc.labelIndex.OnUpdate(update)
	case model.HostEndpointKey:
		if update.Value != nil {
			// Figure out what's changed and update the cache.
			log.Debugf("Updating ARC for host endpoint %v", key)
			endpoint := update.Value.(*model.HostEndpoint)
			profileIDs := endpoint.ProfileIDs
			arc.updateEndpointProfileIDs(key, profileIDs)
		} else {
			log.Debugf("Deleting host endpoint %v from ARC", key)
			arc.updateEndpointProfileIDs(key, []string{})
		}
		arc.labelIndex.OnUpdate(update)
	case model.ProfileLabelsKey:
		arc.labelIndex.OnUpdate(update)
	case model.ProfileTagsKey:
		arc.labelIndex.OnUpdate(update)
	case model.ProfileRulesKey:
		if update.Value != nil {
			rules := update.Value.(*model.ProfileRules)
			arc.allProfileRules[key.Name] = rules
			if arc.profileIDToEndpointKeys.ContainsKey(key.Name) {
				log.Debugf("Profile rules updated while active: %v", key.Name)
				arc.sendProfileUpdate(key.Name)
			} else {
				log.Debugf("Profile rules updated while inactive: %v", key.Name)
			}
		} else {
			delete(arc.allProfileRules, key.Name)
			if arc.profileIDToEndpointKeys.ContainsKey(key.Name) {
				log.Debug("Profile rules deleted while active, telling listener/felix")
				arc.sendProfileUpdate(key.Name)
			} else {
				log.Debugf("Profile rules deleted while inactive: %v", key.Name)
			}
		}
	case model.PolicyKey:
		if update.Value != nil {
			log.Debugf("Updating ARC for policy %v", key)
			policy := update.Value.(*model.Policy)
			arc.allPolicies[key] = policy
			// Update the index, which will call us back if the selector no
			// longer matches.
			sel, err := selector.Parse(policy.Selector)
			if err != nil {
				log.WithError(err).Panic("Failed to parse selector")
			}
			arc.labelIndex.UpdateSelector(key, sel)

			if arc.policyIDToEndpointKeys.ContainsKey(key) {
				// If we get here, the selector still matches something,
				// update the rules.
				log.Debug("Policy updated while active, telling listener")
				arc.sendPolicyUpdate(key)
			}
		} else {
			log.Debugf("Removing policy %v from ARC", key)
			delete(arc.allPolicies, key)
			arc.labelIndex.DeleteSelector(key)
			// No need to call updatePolicy() because we'll have got a matchStopped
			// callback.
		}
	default:
		log.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}
	return
}

func (arc *ActiveRulesCalculator) OnStatusUpdate(status api.SyncStatus) {
	if status == api.InSync && !arc.datastoreInSync {
		arc.datastoreInSync = true
		if arc.missingProfiles.Len() > 0 {
			// Log out any profiles that were missing during the resync.  We defer
			// this until now because we may hear about profiles or endpoints first.
			arc.missingProfiles.Iter(func(item interface{}) error {
				log.WithField("profileID", item).Warning(
					"End of resync: local endpoints refer to missing " +
						"or invalid profile, profile's rules replaced " +
						"with drop rules.")
				return set.RemoveItem
			})
		}
	}
}

func (arc *ActiveRulesCalculator) updateEndpointProfileIDs(key model.Key, profileIDs []string) {
	// Figure out which profiles have been added/removed.
	log.Debugf("Endpoint %#v now has profile IDs: %v", key, profileIDs)
	removedIDs, addedIDs := arc.endpointKeyToProfileIDs.Update(key, profileIDs)

	// Update the index of required profile IDs for added profiles,
	// triggering events for profiles that just became active.
	for id := range addedIDs {
		wasActive := arc.profileIDToEndpointKeys.ContainsKey(id)
		arc.profileIDToEndpointKeys.Put(id, key)
		if !wasActive {
			// This profile is now active.
			arc.sendProfileUpdate(id)
		}
	}

	// Update the index for no-longer required profile IDs, triggering
	// events for profiles that just became inactive.
	for id := range removedIDs {
		arc.profileIDToEndpointKeys.Discard(id, key)
		if !arc.profileIDToEndpointKeys.ContainsKey(id) {
			// No endpoint refers to this ID any more.  Clean it
			// up.
			arc.sendProfileUpdate(id)
		}
	}
}

func (arc *ActiveRulesCalculator) onMatchStarted(selID, labelId interface{}) {
	polKey := selID.(model.PolicyKey)
	policyWasActive := arc.policyIDToEndpointKeys.ContainsKey(polKey)
	arc.policyIDToEndpointKeys.Put(selID, labelId)
	if !policyWasActive {
		// Policy wasn't active before, tell the listener.  The policy
		// must be in allPolicies because we can only match on a policy
		// that we've seen.
		log.Debugf("Policy %v now matches a local endpoint", polKey)
		arc.sendPolicyUpdate(polKey)
	}
	arc.PolicyMatchListener.OnPolicyMatch(polKey, labelId)
}

func (arc *ActiveRulesCalculator) onMatchStopped(selID, labelId interface{}) {
	polKey := selID.(model.PolicyKey)
	arc.policyIDToEndpointKeys.Discard(selID, labelId)
	if !arc.policyIDToEndpointKeys.ContainsKey(selID) {
		// Policy no longer active.
		polKey := selID.(model.PolicyKey)
		log.Debugf("Policy %v no longer matches a local endpoint", polKey)
		arc.sendPolicyUpdate(polKey)
	}
	arc.PolicyMatchListener.OnPolicyMatchStopped(polKey, labelId)
}

var (
	DummyDropRules = model.ProfileRules{
		InboundRules:  []model.Rule{{Action: "deny"}},
		OutboundRules: []model.Rule{{Action: "deny"}},
	}
)

func (arc *ActiveRulesCalculator) sendProfileUpdate(profileID string) {
	active := arc.profileIDToEndpointKeys.ContainsKey(profileID)
	rules, known := arc.allProfileRules[profileID]
	log.Debugf("Sending profile update for profile %v (known: %v, active: %v)",
		profileID, known, active)
	key := model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: profileID}}

	// We'll re-add the profile to the set if it's still missing below.
	arc.missingProfiles.Discard(key.Name)
	if active {
		if !known {
			if arc.datastoreInSync {
				// We're in sync so we know the profile is missing from the
				// datastore or it failed validation
				log.WithField("profileID", profileID).Warn(
					"Profile not known or invalid, generating dummy profile " +
						"that drops all traffic.")
			} else {
				// Not in sync, the profile may still show up.  Keep a record of its
				// name so we can log it out at the end of the resync.
				arc.missingProfiles.Add(profileID)
				log.WithField("profileID", profileID).Debug(
					"Profile unknown during resync.")
			}
			rules = &DummyDropRules
		}
		arc.RuleScanner.OnProfileActive(key, rules)
	} else {
		arc.RuleScanner.OnProfileInactive(key)
	}
}

func (arc *ActiveRulesCalculator) sendPolicyUpdate(policyKey model.PolicyKey) {
	policy, known := arc.allPolicies[policyKey]
	active := arc.policyIDToEndpointKeys.ContainsKey(policyKey)
	log.Debugf("Sending policy update for policy %v (known: %v, active: %v)",
		policyKey, known, active)
	if active {
		if !known {
			// This shouldn't happen because a policy can only become active if
			// we know its selector, which is inside the policy struct.
			log.WithField("policyKey", policyKey).Panic("Unknown policy became active!")
		}
		arc.RuleScanner.OnPolicyActive(policyKey, policy)
	} else {
		arc.RuleScanner.OnPolicyInactive(policyKey)
	}
}

// EndpointKeyToProfileIDMap is a specialised map that calculates the deltas to the profile IDs
// when making an update.
type EndpointKeyToProfileIDMap struct {
	endpointKeyToProfileIDs map[model.Key][]string
}

func NewEndpointKeyToProfileIDMap() *EndpointKeyToProfileIDMap {
	return &EndpointKeyToProfileIDMap{
		endpointKeyToProfileIDs: make(map[model.Key][]string),
	}
}

func (idx EndpointKeyToProfileIDMap) Update(
	key model.Key,
	profileIDs []string,
) (
	removedIDs, addedIDs map[string]bool,
) {
	oldIDs := idx.endpointKeyToProfileIDs[key]
	removedIDs = make(map[string]bool)
	for _, id := range oldIDs {
		removedIDs[id] = true
	}
	addedIDs = make(map[string]bool)
	for _, id := range profileIDs {
		if removedIDs[id] {
			delete(removedIDs, id)
		} else {
			addedIDs[id] = true
		}
	}

	// Store off the update in our cache.
	if len(profileIDs) > 0 {
		idx.endpointKeyToProfileIDs[key] = profileIDs
	} else {
		// No profiles is equivalent to deletion so we may as well
		// clean up completely.
		delete(idx.endpointKeyToProfileIDs, key)
	}

	return removedIDs, addedIDs
}
