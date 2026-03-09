// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const EPCompDataKindLiveMigration = EndpointComputedDataKind("LiveMigration")

type sourceOrTarget int

const (
	source sourceOrTarget = iota
	target
	numSourceOrTarget
)

// LiveMigrationCalculator tracks local workload endpoints and LiveMigration resources and
// correlates between them, in order to correctly set the live_migration_role field in
// proto.WorkloadEndpoints that are sent to the dataplane.
type LiveMigrationCalculator struct {
	activeRulesCalc        *ActiveRulesCalculator
	onEndpointComputedData EndpointComputedDataUpdater
	weps                   map[types.NamespacedName]*wepData
	liveMigrations         map[model.ResourceKey]internalapi.LiveMigration
	directNameKeys         [numSourceOrTarget]map[types.NamespacedName]set.Set[model.ResourceKey]
	selectorKeys           map[string]set.Set[model.ResourceKey]

	// pendingSelectorMatches tracks WEPs that were matched by a computed selector callback
	// before the LMC had processed the WEP update.  This can happen because the ARC's
	// handler runs before the LMC's handler in the dispatcher chain.
	pendingSelectorMatches set.Set[types.NamespacedName]
}

type wepData struct {
	// The full WEP key.
	key model.WorkloadEndpointKey

	// Keys of LiveMigration resources that directly say this WEP is a live migration source or
	// target.  Normally there should only be one LiveMigration resource mentioning a given WEP,
	// i.e. in the union of both these sets.  But we've coded to allow for transient overlaps.
	directNameKeys [numSourceOrTarget]set.Set[model.ResourceKey]

	// Whether there is a current LiveMigration resource with destination selector matching this
	// WEP (as determined by the active rules calculator).
	targetSelectorMatching bool
}

func (wepData *wepData) liveMigrationRole() proto.LiveMigrationRole {
	if wepData.targetSelectorMatching {
		return proto.LiveMigrationRole_TARGET
	}
	if wepData.directNameKeys[target].Len() > 0 {
		return proto.LiveMigrationRole_TARGET
	}
	if wepData.directNameKeys[source].Len() > 0 {
		return proto.LiveMigrationRole_SOURCE
	}
	return proto.LiveMigrationRole_NO_ROLE
}

func NewLiveMigrationCalculator(
	activeRulesCalc *ActiveRulesCalculator,
	onEndpointComputedDataUpdater EndpointComputedDataUpdater,
) *LiveMigrationCalculator {
	lmc := &LiveMigrationCalculator{
		activeRulesCalc:        activeRulesCalc,
		onEndpointComputedData: onEndpointComputedDataUpdater,
		weps:                   map[types.NamespacedName]*wepData{},
		liveMigrations:         map[model.ResourceKey]internalapi.LiveMigration{},
		directNameKeys: [numSourceOrTarget]map[types.NamespacedName]set.Set[model.ResourceKey]{
			map[types.NamespacedName]set.Set[model.ResourceKey]{},
			map[types.NamespacedName]set.Set[model.ResourceKey]{},
		},
		selectorKeys:           map[string]set.Set[model.ResourceKey]{},
		pendingSelectorMatches: set.New[types.NamespacedName](),
	}
	activeRulesCalc.RegisterPolicyMatchListener(lmc)
	return lmc
}

func (lmc *LiveMigrationCalculator) refDirectName(
	namespacedName types.NamespacedName,
	lmKey model.ResourceKey,
	sourceOrTarget sourceOrTarget,
) {
	// Emit role change if there is an existing and affected known WEP.
	if wepData := lmc.weps[namespacedName]; wepData != nil {
		lmc.withRoleUpdateIfNeeded(wepData, func() {
			wepData.directNameKeys[sourceOrTarget].Add(lmKey)
		})
	}

	// Update tracking for WEPs that we might hear about later.
	directNameKeysForName := lmc.directNameKeys[sourceOrTarget][namespacedName]
	if directNameKeysForName == nil {
		directNameKeysForName = set.New[model.ResourceKey]()
		lmc.directNameKeys[sourceOrTarget][namespacedName] = directNameKeysForName
	}
	directNameKeysForName.Add(lmKey)
}

func (lmc *LiveMigrationCalculator) unrefDirectName(
	namespacedName types.NamespacedName,
	lmKey model.ResourceKey,
	sourceOrTarget sourceOrTarget,
) {
	// Emit role change if there is an existing and affected known WEP.
	if wepData := lmc.weps[namespacedName]; wepData != nil {
		lmc.withRoleUpdateIfNeeded(wepData, func() {
			wepData.directNameKeys[sourceOrTarget].Discard(lmKey)
		})
	}

	// Update tracking for WEPs that we might hear about later.
	directNameKeysForName := lmc.directNameKeys[sourceOrTarget][namespacedName]
	if directNameKeysForName != nil {
		directNameKeysForName.Discard(lmKey)
		if directNameKeysForName.Len() == 0 {
			delete(lmc.directNameKeys[sourceOrTarget], namespacedName)
		}
	}
}

func (lmc *LiveMigrationCalculator) refSelector(
	selector string,
	lmKey model.ResourceKey,
) {
	keys := lmc.selectorKeys[selector]
	if keys == nil {
		keys = set.New[model.ResourceKey]()
		lmc.selectorKeys[selector] = keys
	}
	keys.Add(lmKey)
	if keys.Len() == 1 {
		lmc.activeRulesCalc.AddExtraComputedSelector(selector)
	}
}

func (lmc *LiveMigrationCalculator) unrefSelector(
	selector string,
	lmKey model.ResourceKey,
) {
	keys := lmc.selectorKeys[selector]
	if keys != nil {
		keys.Discard(lmKey)
		if keys.Len() == 0 {
			lmc.activeRulesCalc.RemoveExtraComputedSelector(selector)
			delete(lmc.selectorKeys, selector)
		}
	}
}

func (lmc *LiveMigrationCalculator) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		// Only the WEP name and namespace are relevant in this component; we don't care
		// about details within the WEP Spec.
		name, ns := key.GetNameAndNamespace()
		namespacedName := types.NamespacedName{Namespace: ns, Name: name}
		if update.Value != nil {
			// WEP being created or updated.
			if lmc.weps[namespacedName] != nil {
				// We already know this WEP and have done whatever is needed for it.
				return
			}

			// First time we're seeing this WEP.
			wepData := &wepData{
				key: key,
				directNameKeys: [numSourceOrTarget]set.Set[model.ResourceKey]{
					set.New[model.ResourceKey](),
					set.New[model.ResourceKey](),
				},
			}
			if lmc.directNameKeys[source][namespacedName] != nil {
				wepData.directNameKeys[source].AddSet(lmc.directNameKeys[source][namespacedName])
			}
			if lmc.directNameKeys[target][namespacedName] != nil {
				wepData.directNameKeys[target].AddSet(lmc.directNameKeys[target][namespacedName])
			}
			if lmc.pendingSelectorMatches.Contains(namespacedName) {
				wepData.targetSelectorMatching = true
				lmc.pendingSelectorMatches.Discard(namespacedName)
			}
			lmc.weps[namespacedName] = wepData
			lmc.indicateRole(key, wepData.liveMigrationRole())
		} else {
			// Don't need anything here to "reset the role that we previously said"
			// because the WEP is being deleted anyway.
			delete(lmc.weps, namespacedName)
		}
	case model.ResourceKey:
		if key.Kind != internalapi.KindLiveMigration {
			return
		}

		// If we already had a LiveMigration with this key, get the names it indicated.
		old := [numSourceOrTarget]types.NamespacedName{}
		oldSelector := ""
		if existing, ok := lmc.liveMigrations[key]; ok {
			if existing.Spec.Source != nil {
				old[source] = *existing.Spec.Source
			}
			if existing.Spec.Destination != nil && existing.Spec.Destination.NamespacedName != nil {
				old[target] = *existing.Spec.Destination.NamespacedName
			}
			if existing.Spec.Destination != nil && existing.Spec.Destination.Selector != nil {
				oldSelector = *existing.Spec.Destination.Selector
			}
		}

		// Now check the new LiveMigration state.
		new := [numSourceOrTarget]types.NamespacedName{}
		newSelector := ""
		if update.Value != nil {
			lm := update.Value.(*internalapi.LiveMigration)
			lmc.liveMigrations[key] = *lm
			if lm.Spec.Source != nil {
				new[source] = *lm.Spec.Source
			}
			if lm.Spec.Destination != nil && lm.Spec.Destination.NamespacedName != nil {
				new[target] = *lm.Spec.Destination.NamespacedName
			}
			if lm.Spec.Destination != nil && lm.Spec.Destination.Selector != nil {
				newSelector = *lm.Spec.Destination.Selector
			}
		} else {
			delete(lmc.liveMigrations, key)
		}

		// Process the effects of this update on the roles of existing known endpoints, and
		// on tracking for WEPs that we might hear about later.
		//
		// Note, even though we allow for multiple LiveMigration resources
		// referencing the same WEP in transient overlapping situations, a single
		// given LiveMigration will never reference the same WEP as both its source
		// and its target; and will never transition from referencing a WEP as
		// source to referencing that same WEP as target, or vice versa.  Hence it's
		// correct to process the source and target fields independently here.
		for sourceOrTarget := range numSourceOrTarget {
			if new[sourceOrTarget] != old[sourceOrTarget] {
				if old[sourceOrTarget].Name != "" {
					lmc.unrefDirectName(old[sourceOrTarget], key, sourceOrTarget)
				}
				if new[sourceOrTarget].Name != "" {
					lmc.refDirectName(new[sourceOrTarget], key, sourceOrTarget)
				}
			}
		}

		if newSelector != oldSelector {
			if oldSelector != "" {
				lmc.unrefSelector(oldSelector, key)
			}
			if newSelector != "" {
				lmc.refSelector(newSelector, key)
			}
		}
	default:
		logrus.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return
}

func (lmc *LiveMigrationCalculator) withRoleUpdateIfNeeded(wepData *wepData, updateFunc func()) {
	oldRole := wepData.liveMigrationRole()
	updateFunc()
	newRole := wepData.liveMigrationRole()
	if newRole != oldRole {
		lmc.indicateRole(wepData.key, newRole)
	}
}

func (lmc *LiveMigrationCalculator) indicateRole(key model.WorkloadEndpointKey, role proto.LiveMigrationRole) {
	lmc.onEndpointComputedData(key, EPCompDataKindLiveMigration, &liveMigrationRole{role: role})
}

func (lmc *LiveMigrationCalculator) OnPolicyMatch(_ model.PolicyKey, _ model.EndpointKey)        {}
func (lmc *LiveMigrationCalculator) OnPolicyMatchStopped(_ model.PolicyKey, _ model.EndpointKey) {}

func (lmc *LiveMigrationCalculator) OnComputedSelectorMatch(cs string, epKey model.EndpointKey) {
	if _, ok := lmc.selectorKeys[cs]; !ok {
		return
	}
	if wepKey, ok := epKey.(model.WorkloadEndpointKey); ok {
		name, ns := wepKey.GetNameAndNamespace()
		namespacedName := types.NamespacedName{Namespace: ns, Name: name}
		if wepData := lmc.weps[namespacedName]; wepData != nil {
			lmc.withRoleUpdateIfNeeded(wepData, func() {
				wepData.targetSelectorMatching = true
			})
		} else {
			// WEP not yet tracked; the ARC handler runs before ours in the
			// dispatcher chain, so we may receive selector match callbacks
			// before our OnUpdate has processed the WEP.  Record it so we can
			// pick it up when the WEP is processed.
			lmc.pendingSelectorMatches.Add(namespacedName)
		}
	}
}

func (lmc *LiveMigrationCalculator) OnComputedSelectorMatchStopped(cs string, epKey model.EndpointKey) {
	if _, ok := lmc.selectorKeys[cs]; !ok {
		return
	}
	if wepKey, ok := epKey.(model.WorkloadEndpointKey); ok {
		name, ns := wepKey.GetNameAndNamespace()
		namespacedName := types.NamespacedName{Namespace: ns, Name: name}
		if wepData := lmc.weps[namespacedName]; wepData != nil {
			lmc.withRoleUpdateIfNeeded(wepData, func() {
				wepData.targetSelectorMatching = false
			})
		} else {
			// Undo a pending match if there was one.
			lmc.pendingSelectorMatches.Discard(namespacedName)
		}
	}
}

type liveMigrationRole struct {
	role proto.LiveMigrationRole
}

func (lmr *liveMigrationRole) ApplyTo(wep *proto.WorkloadEndpoint) {
	wep.LiveMigrationRole = lmr.role
}
