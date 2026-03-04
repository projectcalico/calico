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
	"reflect"
	"slices"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/multidict"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/packedmap"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
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
	OnPolicyMatch(policyKey model.PolicyKey, endpointKey model.EndpointKey)
	OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey model.EndpointKey)
	OnComputedSelectorMatch(cs string, endpointKey model.EndpointKey)
	OnComputedSelectorMatchStopped(cs string, endpointKey model.EndpointKey)
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
// The rules in a policy may also contain selectors; those are ignored here; they are
// mapped to IP sets by the RuleScanner.
type ActiveRulesCalculator struct {
	// Caches of all known tiers/policies/profiles.
	allTiers map[string]*model.Tier
	// We need to cache all the policies, and the policy Rule struct is very
	// sparse (which makes it very wasteful). The packed map stores the policies
	// in compressed format to save a lot of RAM.
	allPolicies packedmap.Map[model.PolicyKey, *model.Policy]
	// Similarly, profiles are sparse and wasteful, we use a deduped packed map
	// because they're also often identical.
	allProfileRules packedmap.Deduped[string, *model.ProfileRules]

	// Caches for ALP policies for stat collector.
	allALPPolicies set.Set[model.PolicyKey]

	// Policy/profile ID to matching endpoint sets.
	policyIDToEndpointKeys  multidict.Multidict[any, any]
	profileIDToEndpointKeys multidict.Multidict[string, any]

	// Label index, matching policy selectors against local endpoints.
	labelIndex *labelindex.InheritIndex

	// Cache of profile IDs by local endpoint.
	endpointKeyToProfileIDs *EndpointKeyToProfileIDMap

	// True if we've got the in-sync message from the datastore.
	datastoreInSync bool
	// Set containing the names of any profiles that were missing during the resync.  Used to
	// log out those profiles at the end of the resync.
	missingProfiles set.Set[string]

	// Callback objects.
	RuleScanner           ruleScanner
	PolicyMatchListeners  []PolicyMatchListener
	PolicyLookupCache     ruleScanner
	OnPolicyCountsChanged func(numTiers, numPolicies, numProfiles, numALPPolicies int)
	OnAlive               func()
}

type computedSelector string

func NewActiveRulesCalculator() *ActiveRulesCalculator {
	arc := &ActiveRulesCalculator{
		// Caches of all known policies/profiles and tiers.
		allPolicies:     packedmap.MakeCompressedJSON[model.PolicyKey, *model.Policy](),
		allProfileRules: packedmap.MakeDedupedCompressedJSON[string, *model.ProfileRules](),
		allTiers:        make(map[string]*model.Tier),

		allALPPolicies: set.New[model.PolicyKey](),

		// Policy/profile ID to matching endpoint sets.
		policyIDToEndpointKeys:  multidict.New[any, any](),
		profileIDToEndpointKeys: multidict.New[string, any](),
		missingProfiles:         set.New[string](),

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
	allUpdDispatcher.Register(model.ResourceKey{}, arc.OnUpdate)
	// ... and tiers as well. only required for stats update.
	allUpdDispatcher.Register(model.TierKey{}, arc.OnUpdate)
	allUpdDispatcher.RegisterStatusHandler(arc.OnStatusUpdate)
}

func (arc *ActiveRulesCalculator) RegisterPolicyMatchListener(listener PolicyMatchListener) {
	arc.PolicyMatchListeners = append(arc.PolicyMatchListeners, listener)
}

// forceProgrammedDummyKey is a special value used in place of an endpoint key
// when recording that the policy is force-programmed.
const forceProgrammedDummyKey = "PolicyAlwaysProgrammed"

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
	case model.ResourceKey:
		arc.labelIndex.OnUpdate(update)
	case model.ProfileRulesKey:
		if update.Value != nil {
			rules := update.Value.(*model.ProfileRules)
			oldRules, _ := arc.allProfileRules.Get(key.Name)
			if reflect.DeepEqual(oldRules, rules) {
				if log.IsLevelEnabled(log.DebugLevel) {
					log.WithField("key", update.Key).Debug("No-op profile change; ignoring.")
				}
				return
			}
			arc.allProfileRules.Set(key.Name, rules)
			if arc.profileIDToEndpointKeys.ContainsKey(key.Name) {
				log.Debugf("Profile rules updated while active: %v", key.Name)
				arc.sendProfileUpdate(key.Name, rules)
			} else {
				log.Debugf("Profile rules updated while inactive: %v", key.Name)
			}
		} else {
			arc.allProfileRules.Delete(key.Name)
			if arc.profileIDToEndpointKeys.ContainsKey(key.Name) {
				log.Debug("Profile rules deleted while active, telling listener/felix")
				arc.sendProfileUpdate(key.Name, nil)
			} else {
				log.Debugf("Profile rules deleted while inactive: %v", key.Name)
			}
		}
		// Update the tier/policy/profile counts.
		arc.updateStats()
	case model.PolicyKey:
		oldPolicy, _ := arc.allPolicies.Get(key)
		oldPolicyWasForceProgrammed := policyForceProgrammed(oldPolicy)
		if update.Value != nil {
			log.Debugf("Updating ARC for policy %v", key)
			policy := update.Value.(*model.Policy)
			if reflect.DeepEqual(oldPolicy, policy) {
				if log.IsLevelEnabled(log.DebugLevel) {
					log.WithField("key", update.Key).Debug("No-op policy change; ignoring.")
				}
				return
			}
			arc.allPolicies.Set(key, policy)

			// If the policy transitions to be force-programmed, simulate
			// a match with a dummy endpoint key.
			newPolicyForceProgrammed := policyForceProgrammed(policy)
			if !oldPolicyWasForceProgrammed && newPolicyForceProgrammed {
				log.Debugf("Policy %v force-programmed.", key)
				arc.onMatchStarted(key, forceProgrammedDummyKey)
			}

			// Update the index, which will call us back if the selector no
			// longer matches.  Note: we can't skip this even if the
			// policy is force-programmed because we're also responsible
			// for propagating the notification to the policy resolver.
			sel, err := selector.Parse(policy.Selector)
			if err != nil {
				log.WithError(err).Panic("Failed to parse selector")
			}
			arc.labelIndex.UpdateSelector(key, sel)

			// If the policy transitions to not be force-programmed,
			// remove the dummy match.  We do this after adding the
			// selector into the index to avoid flapping.
			if oldPolicyWasForceProgrammed && !newPolicyForceProgrammed {
				log.Debugf("Policy %v no longer force-programmed.", key)
				arc.onMatchStopped(key, forceProgrammedDummyKey)
			}

			if arc.policyIDToEndpointKeys.ContainsKey(key) {
				// If we get here, the selector still matches something,
				// update the rules.
				log.Debug("Policy updated while active, telling listener")
				arc.sendPolicyUpdate(key, policy)
			}

			// update ALP policies set.
			if arc.isALPPolicy(policy) {
				arc.allALPPolicies.Add(key)
			} else if arc.allALPPolicies.Contains(key) {
				arc.allALPPolicies.Discard(key)
			}
		} else {
			log.Debugf("Removing policy %v from ARC", key)
			arc.allPolicies.Delete(key)
			if oldPolicyWasForceProgrammed {
				log.Debugf("Policy %v being deleted, was force-programmed.", key)
				arc.onMatchStopped(key, forceProgrammedDummyKey)
			}
			arc.labelIndex.DeleteSelector(key)
			// No need to call updatePolicy() because we'll have got a matchStopped
			// callback.

			// update ALP policies set.
			if arc.allALPPolicies.Contains(key) {
				arc.allALPPolicies.Discard(key)
			}
		}
		// Update the tier/policy/profile counts.
		arc.updateStats()
	case model.TierKey:
		if update.Value != nil {
			log.Debugf("Updating ARC for tier %v", key)
			tier := update.Value.(*model.Tier)
			arc.allTiers[key.Name] = tier
		} else {
			log.Debugf("Removing tier %v from ARC", key)
			delete(arc.allTiers, key.Name)
		}
		// Update the tier/policy/profile counts.
		arc.updateStats()
	default:
		log.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return
}

// AddExtraComputedSelector adds an extra non-policy selector to the label index and gives OnComputedSelectorMatch
// and OnComputedSelectorMatchStopped callbacks when that selector matches/stops matching local endpoints.  Allows for
// sharing the expensive selector index.
func (arc *ActiveRulesCalculator) AddExtraComputedSelector(cs string) {
	sel, err := selector.Parse(cs)
	if err != nil {
		log.WithError(err).Panicf("Failed to parse computed selector %#v", cs)
	}
	arc.labelIndex.UpdateSelector(computedSelector(cs), sel)
}

func (arc *ActiveRulesCalculator) RemoveExtraComputedSelector(cs string) {
	arc.labelIndex.DeleteSelector(computedSelector(cs))
}

func policyForceProgrammed(policy *model.Policy) bool {
	if policy == nil {
		return false
	}
	return slices.Contains(policy.PerformanceHints, v3.PerfHintAssumeNeededOnEveryNode)
}

func (arc *ActiveRulesCalculator) updateStats() {
	if arc.OnPolicyCountsChanged == nil {
		return
	}
	arc.OnPolicyCountsChanged(len(arc.allTiers), arc.allPolicies.Len(), arc.allProfileRules.Len(), arc.allALPPolicies.Len())
}

func (arc *ActiveRulesCalculator) OnStatusUpdate(status api.SyncStatus) {
	if status == api.InSync && !arc.datastoreInSync {
		arc.datastoreInSync = true
		if arc.missingProfiles.Len() > 0 {
			// Log out any profiles that were missing during the resync.  We defer
			// this until now because we may hear about profiles or endpoints first.
			for profileID := range arc.missingProfiles.All() {
				log.WithField("profileID", profileID).Warning(
					"End of resync: local endpoints refer to missing " +
						"or invalid profile, profile's rules replaced " +
						"with drop rules.")
				arc.missingProfiles.Discard(profileID)
			}
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
			profile, _ := arc.allProfileRules.Get(id)
			arc.sendProfileUpdate(id, profile)
		}
	}

	// Update the index for no-longer required profile IDs, triggering
	// events for profiles that just became inactive.
	for id := range removedIDs {
		arc.profileIDToEndpointKeys.Discard(id, key)
		if !arc.profileIDToEndpointKeys.ContainsKey(id) {
			// No endpoint refers to this ID anymore.  Clean it
			// up.
			profile, _ := arc.allProfileRules.Get(id)
			arc.sendProfileUpdate(id, profile)
		}
	}
}

func (arc *ActiveRulesCalculator) onMatchStarted(selID, labelId any) {
	if cs, ok := selID.(computedSelector); ok {
		for _, l := range arc.PolicyMatchListeners {
			if labelId, ok := labelId.(model.EndpointKey); ok {
				l.OnComputedSelectorMatch(string(cs), labelId)
			}
		}
		return
	}
	polKey := selID.(model.PolicyKey)
	policyWasActive := arc.policyIDToEndpointKeys.ContainsKey(polKey)
	arc.policyIDToEndpointKeys.Put(selID, labelId)

	if !policyWasActive {
		// Policy wasn't active before, tell the listener.  The policy
		// must be in allPolicies because we can only match on a policy
		// that we've seen.
		log.Debugf("Policy %v now active", polKey)
		policy, known := arc.allPolicies.Get(polKey)
		if !known {
			log.WithField("policy", polKey).Panic("Policy active but missing from allPolicies.")
		}
		arc.sendPolicyUpdate(polKey, policy)
	}

	if labelId, ok := labelId.(model.EndpointKey); ok {
		for _, l := range arc.PolicyMatchListeners {
			l.OnPolicyMatch(polKey, labelId)
		}
	}
}

func (arc *ActiveRulesCalculator) onMatchStopped(selID, labelId any) {
	if cs, ok := selID.(computedSelector); ok {
		for _, l := range arc.PolicyMatchListeners {
			if labelId, ok := labelId.(model.EndpointKey); ok {
				l.OnComputedSelectorMatchStopped(string(cs), labelId)
			}
		}
		return
	}
	polKey := selID.(model.PolicyKey)
	arc.policyIDToEndpointKeys.Discard(selID, labelId)
	if !arc.policyIDToEndpointKeys.ContainsKey(selID) {
		// Policy no longer active.
		polKey := selID.(model.PolicyKey)
		log.Debugf("Policy %v no longer active", polKey)
		policy, _ := arc.allPolicies.Get(polKey)
		arc.sendPolicyUpdate(polKey, policy)
	}
	if labelId, ok := labelId.(model.EndpointKey); ok {
		for _, l := range arc.PolicyMatchListeners {
			l.OnPolicyMatchStopped(polKey, labelId)
		}
	}
}

var DummyDropRules = model.ProfileRules{
	InboundRules:  []model.Rule{{Action: "deny"}},
	OutboundRules: []model.Rule{{Action: "deny"}},
}

func (arc *ActiveRulesCalculator) sendProfileUpdate(profileID string, rules *model.ProfileRules) {
	active := arc.profileIDToEndpointKeys.ContainsKey(profileID)
	known := rules != nil
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
				log.WithField("profileID", profileID).Info(
					"One or more endpoints uses a profile that doesn't exist; generating " +
						"default-drop profile. (This can happen transiently when a Kubernetes " +
						"namespace is deleted.)")
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
		if arc.PolicyLookupCache != nil {
			arc.PolicyLookupCache.OnProfileActive(key, rules)
		}
	} else {
		arc.RuleScanner.OnProfileInactive(key)
		if arc.PolicyLookupCache != nil {
			arc.PolicyLookupCache.OnProfileInactive(key)
		}
	}
}

func (arc *ActiveRulesCalculator) sendPolicyUpdate(policyKey model.PolicyKey, policy *model.Policy) {
	known := policy != nil
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
		if arc.PolicyLookupCache != nil {
			arc.PolicyLookupCache.OnPolicyActive(policyKey, policy)
		} else {
			log.Debug("PolicyLookup OnPolicyActive : cache nil on windows platform")
		}
	} else {
		arc.RuleScanner.OnPolicyInactive(policyKey)
		if arc.PolicyLookupCache != nil {
			arc.PolicyLookupCache.OnPolicyInactive(policyKey)
		} else {
			log.Debug("PolicyLookup OnPolicyInactive : cache nil on windows platform")
		}
	}
}

func (arc *ActiveRulesCalculator) isALPPolicy(policy *model.Policy) bool {
	// Policy is a ALP policy if HTTPMatch rule or service account selector exists.
	checkRules := func(rules []model.Rule) bool {
		for _, rule := range rules {
			if rule.HTTPMatch != nil || rule.OriginalSrcServiceAccountSelector != "" || rule.OriginalDstServiceAccountSelector != "" {
				return true
			}
		}
		return false
	}
	return checkRules(policy.InboundRules) || checkRules(policy.OutboundRules)
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
