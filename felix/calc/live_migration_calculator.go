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

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// LiveMigrationCalculator tracks local workload endpoints and LiveMigration resources and
// correlates between them, in order to correctly set the live_migration_role field in
// proto.WorkloadEndpoints that are sent to the dataplane.
type LiveMigrationCalculator struct {
	activeRulesCalc        *ActiveRulesCalculator
	OnEndpointComputedData EndpointComputedDataUpdater
	weps                   map[wepOwnerID]*wepData
	liveMigrations         map[model.ResourceKey]internalapi.LiveMigration
	// endpointKeys tracks LiveMigration resources that reference a specific endpoint
	// (all four fields of wepOwnerID set).
	endpointKeys [numSourceOrTarget]map[wepOwnerID]set.Set[model.ResourceKey]
	// workloadKeys tracks LiveMigration resources that reference an entire workload
	// (endpointID empty, matching all endpoints for that workload).
	workloadKeys [numSourceOrTarget]map[wepOwnerID]set.Set[model.ResourceKey]
	selectorKeys map[string]set.Set[model.ResourceKey]
}

type sourceOrTarget int

const (
	source sourceOrTarget = iota
	target
	numSourceOrTarget
)

// wepOwnerID identifies either a single WorkloadEndpoint (all fields set) or an entire workload
// (endpointID empty, matching all endpoints for that workload).
type wepOwnerID struct {
	hostname       string
	orchestratorID string
	workloadID     string
	endpointID     string // empty = matches all endpoints for this workload
}

type wepData struct {
	// The full WEP key.
	key model.WorkloadEndpointKey

	// Keys of LiveMigration resources that directly say this WEP is a live migration source or
	// target.  Normally there should only be one LiveMigration resource mentioning a given WEP,
	// i.e. in the union of both these sets.  But we've coded to allow for transient overlaps.
	directNameKeys [numSourceOrTarget]set.Set[model.ResourceKey]

	// The computed selector string that matched this WEP as a live migration target, or "" if
	// no selector is currently matching.  Set by the active rules calculator's match callbacks.
	targetSelectorMatched string
}

func NewLiveMigrationCalculator(activeRulesCalc *ActiveRulesCalculator) *LiveMigrationCalculator {
	lmc := &LiveMigrationCalculator{
		activeRulesCalc: activeRulesCalc,
		weps:            map[wepOwnerID]*wepData{},
		liveMigrations:  map[model.ResourceKey]internalapi.LiveMigration{},
		endpointKeys: [numSourceOrTarget]map[wepOwnerID]set.Set[model.ResourceKey]{
			map[wepOwnerID]set.Set[model.ResourceKey]{},
			map[wepOwnerID]set.Set[model.ResourceKey]{},
		},
		workloadKeys: [numSourceOrTarget]map[wepOwnerID]set.Set[model.ResourceKey]{
			map[wepOwnerID]set.Set[model.ResourceKey]{},
			map[wepOwnerID]set.Set[model.ResourceKey]{},
		},
		selectorKeys: map[string]set.Set[model.ResourceKey]{},
	}
	activeRulesCalc.RegisterPolicyMatchListener(lmc)
	return lmc
}
func (lmc *LiveMigrationCalculator) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		// Only the WEP key is relevant in this component; we don't care about details
		// within the WEP Spec.
		exactID := wepOwnerIDFromKey(key)
		if update.Value != nil {
			// WEP being created or updated.
			if lmc.weps[exactID] != nil {
				// We already know this WEP and have done whatever is needed for it.
				return
			}

			logrus.WithField("wep", exactID).Debug("LiveMigrationCalculator: new WEP")

			// First time we're seeing this WEP.
			wd := &wepData{
				key: key,
				directNameKeys: [numSourceOrTarget]set.Set[model.ResourceKey]{
					set.New[model.ResourceKey](),
					set.New[model.ResourceKey](),
				},
			}

			// Check for direct-name matches: both exact endpoint-level and workload-level.
			workloadID := exactID.workloadLevel()
			for _, sot := range []sourceOrTarget{source, target} {
				if lmc.endpointKeys[sot][exactID] != nil {
					wd.directNameKeys[sot].AddSet(lmc.endpointKeys[sot][exactID])
				}
				if lmc.workloadKeys[sot][workloadID] != nil {
					wd.directNameKeys[sot].AddSet(lmc.workloadKeys[sot][workloadID])
				}
			}

			lmc.weps[exactID] = wd
			role, uid := lmc.liveMigrationRoleAndUID(wd)
			lmc.indicateRole(key, role, uid)
		} else {
			logrus.WithField("wep", exactID).Debug("LiveMigrationCalculator: WEP deleted")
			// Don't need anything here to "reset the role that we previously said"
			// because the WEP is being deleted anyway.
			delete(lmc.weps, exactID)
		}
	case model.ResourceKey:
		if key.Kind != internalapi.KindLiveMigration {
			return
		}

		// If we already had a LiveMigration with this key, get the IDs it indicated.
		var oldSourceID, oldTargetID wepOwnerID
		oldSelector := ""
		if existing, ok := lmc.liveMigrations[key]; ok {
			oldSourceID = extractSourceOwnerID(existing.Spec.Source)
			oldTargetID = extractTargetOwnerID(existing.Spec.Target)
			oldSelector = extractTargetSelector(existing.Spec.Target)
		}

		// Now check the new LiveMigration state.
		var newSourceID, newTargetID wepOwnerID
		newSelector := ""
		if update.Value != nil {
			lm := update.Value.(*internalapi.LiveMigration)
			lmc.liveMigrations[key] = *lm
			newSourceID = extractSourceOwnerID(lm.Spec.Source)
			newTargetID = extractTargetOwnerID(lm.Spec.Target)
			newSelector = extractTargetSelector(lm.Spec.Target)
			logrus.WithFields(logrus.Fields{
				"lm":       key,
				"uid":      lm.UID,
				"source":   newSourceID,
				"target":   newTargetID,
				"selector": newSelector,
			}).Debug("LiveMigrationCalculator: LiveMigration created/updated")
		} else {
			logrus.WithField("lm", key).Debug("LiveMigrationCalculator: LiveMigration deleted")
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
		type ownerIDTuple struct {
			oldID wepOwnerID
			newID wepOwnerID
			sot   sourceOrTarget
		}
		for _, pair := range []ownerIDTuple{
			{oldSourceID, newSourceID, source},
			{oldTargetID, newTargetID, target},
		} {
			if pair.newID != pair.oldID {
				empty := wepOwnerID{}
				if pair.oldID != empty {
					lmc.unrefDirectName(pair.oldID, key, pair.sot)
				}
				if pair.newID != empty {
					lmc.refDirectName(pair.newID, key, pair.sot)
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

func (lmc *LiveMigrationCalculator) OnPolicyMatch(_ model.PolicyKey, _ model.EndpointKey)        {}
func (lmc *LiveMigrationCalculator) OnPolicyMatchStopped(_ model.PolicyKey, _ model.EndpointKey) {}

func (lmc *LiveMigrationCalculator) OnComputedSelectorMatch(cs string, epKey model.EndpointKey) {
	if _, ok := lmc.selectorKeys[cs]; !ok {
		return
	}
	if wepKey, ok := epKey.(model.WorkloadEndpointKey); ok {
		exactID := wepOwnerIDFromKey(wepKey)
		if wd := lmc.weps[exactID]; wd != nil {
			logrus.WithFields(logrus.Fields{
				"wep":      exactID,
				"selector": cs,
			}).Debug("LiveMigrationCalculator: selector matched WEP")
			lmc.withRoleUpdateIfNeeded(wd, func() {
				wd.targetSelectorMatched = cs
			})
		}
		// If the WEP isn't tracked yet, we can ignore this callback.  The LMC is registered
		// on localEndpointDispatcher before the ARC, so it always sees WEP updates first.
		// The unknown WEP case here (wd == nil) shouldn't occur because
		// LiveMigrationCalculator sees the same set of local WEPs as ActiveRulesCalculator,
		// but it's harmless to be defensive here.
	}
}

func (lmc *LiveMigrationCalculator) OnComputedSelectorMatchStopped(cs string, epKey model.EndpointKey) {
	if _, ok := lmc.selectorKeys[cs]; !ok {
		return
	}
	if wepKey, ok := epKey.(model.WorkloadEndpointKey); ok {
		exactID := wepOwnerIDFromKey(wepKey)
		if wd := lmc.weps[exactID]; wd != nil {
			logrus.WithFields(logrus.Fields{
				"wep":      exactID,
				"selector": cs,
			}).Debug("LiveMigrationCalculator: selector match stopped for WEP")
			lmc.withRoleUpdateIfNeeded(wd, func() {
				wd.targetSelectorMatched = ""
			})
		}
	}
}

// isWorkloadLevel returns true if this ID matches all endpoints for a workload
// rather than a single endpoint.
func (w wepOwnerID) isWorkloadLevel() bool {
	return w.endpointID == ""
}

// workloadLevel returns a copy with endpointID cleared, so it matches all endpoints
// for the same workload.
func (w wepOwnerID) workloadLevel() wepOwnerID {
	w.endpointID = ""
	return w
}

// hostnameForOwnerID returns the hostname to use in a wepOwnerID.  For the
// "k8s" orchestrator, the WorkloadID (namespace/pod) is already unique,
// so hostname is unnecessary for matching and is normalized to "" so that
// WEP-derived and LM-derived keys match without needing the source node.
func hostnameForOwnerID(orchestratorID, hostname string) string {
	if orchestratorID == "k8s" {
		return ""
	}
	return hostname
}

func wepOwnerIDFromWorkload(w *internalapi.WorkloadIdentifier) wepOwnerID {
	return wepOwnerID{
		hostname:       hostnameForOwnerID(w.OrchestratorID, w.Hostname),
		orchestratorID: w.OrchestratorID,
		workloadID:     w.WorkloadID,
	}
}

func wepOwnerIDFromEndpoint(e *internalapi.WorkloadEndpointIdentifier) wepOwnerID {
	return wepOwnerID{
		hostname:       hostnameForOwnerID(e.OrchestratorID, e.Hostname),
		orchestratorID: e.OrchestratorID,
		workloadID:     e.WorkloadID,
		endpointID:     e.EndpointID,
	}
}

func wepOwnerIDFromKey(k model.WorkloadEndpointKey) wepOwnerID {
	return wepOwnerID{
		hostname:       hostnameForOwnerID(k.OrchestratorID, k.Hostname),
		orchestratorID: k.OrchestratorID,
		workloadID:     k.WorkloadID,
		endpointID:     k.EndpointID,
	}
}

// liveMigrationRoleAndUID returns the live migration role and UID for the given
// WEP.  The UID is always taken from the same LiveMigration resource that
// determines the role, so they are consistent even during transient overlaps.
func (lmc *LiveMigrationCalculator) liveMigrationRoleAndUID(wd *wepData) (proto.LiveMigrationRole, string) {
	// Selector-based target match takes priority.
	if wd.targetSelectorMatched != "" {
		return proto.LiveMigrationRole_TARGET, lmc.uidFromLMKeys(lmc.selectorKeys[wd.targetSelectorMatched])
	}
	if wd.directNameKeys[target].Len() > 0 {
		return proto.LiveMigrationRole_TARGET, lmc.uidFromLMKeys(wd.directNameKeys[target])
	}
	if wd.directNameKeys[source].Len() > 0 {
		return proto.LiveMigrationRole_SOURCE, lmc.uidFromLMKeys(wd.directNameKeys[source])
	}
	return proto.LiveMigrationRole_NO_ROLE, ""
}

// uidFromLMKeys returns the greatest UID from the LiveMigration resources
// referenced by the given set of keys, or "" if none has a UID.  Taking the
// greatest ensures a deterministic result when multiple LMs reference the same WEP.
func (lmc *LiveMigrationCalculator) uidFromLMKeys(keys set.Set[model.ResourceKey]) string {
	if keys == nil {
		return ""
	}
	best := ""
	for lmKey := range keys.All() {
		if lm, ok := lmc.liveMigrations[lmKey]; ok && string(lm.UID) > best {
			best = string(lm.UID)
		}
	}
	return best
}

func (lmc *LiveMigrationCalculator) refDirectName(
	ownerID wepOwnerID,
	lmKey model.ResourceKey,
	sourceOrTarget sourceOrTarget,
) {
	// Emit role change for existing known WEPs that match this ownerID.
	if ownerID.isWorkloadLevel() {
		// Workload-level: iterate all known WEPs to find matching ones.
		for wepID, wd := range lmc.weps {
			if wepID.workloadLevel() == ownerID {
				lmc.withRoleUpdateIfNeeded(wd, func() {
					wd.directNameKeys[sourceOrTarget].Add(lmKey)
				})
			}
		}
	} else {
		// Endpoint-level: direct lookup.
		if wd := lmc.weps[ownerID]; wd != nil {
			lmc.withRoleUpdateIfNeeded(wd, func() {
				wd.directNameKeys[sourceOrTarget].Add(lmKey)
			})
		}
	}

	// Update tracking for WEPs that we might hear about later.
	keysMap := lmc.endpointKeys[sourceOrTarget]
	if ownerID.isWorkloadLevel() {
		keysMap = lmc.workloadKeys[sourceOrTarget]
	}
	keysForOwner := keysMap[ownerID]
	if keysForOwner == nil {
		keysForOwner = set.New[model.ResourceKey]()
		keysMap[ownerID] = keysForOwner
	}
	keysForOwner.Add(lmKey)
}

func (lmc *LiveMigrationCalculator) unrefDirectName(
	ownerID wepOwnerID,
	lmKey model.ResourceKey,
	sourceOrTarget sourceOrTarget,
) {
	// Emit role change for existing known WEPs that match this ownerID.
	if ownerID.isWorkloadLevel() {
		// Workload-level: iterate all known WEPs to find matching ones.
		for wepID, wd := range lmc.weps {
			if wepID.workloadLevel() == ownerID {
				lmc.withRoleUpdateIfNeeded(wd, func() {
					wd.directNameKeys[sourceOrTarget].Discard(lmKey)
				})
			}
		}
	} else {
		// Endpoint-level: direct lookup.
		if wd := lmc.weps[ownerID]; wd != nil {
			lmc.withRoleUpdateIfNeeded(wd, func() {
				wd.directNameKeys[sourceOrTarget].Discard(lmKey)
			})
		}
	}

	// Update tracking for WEPs that we might hear about later.
	keysMap := lmc.endpointKeys[sourceOrTarget]
	if ownerID.isWorkloadLevel() {
		keysMap = lmc.workloadKeys[sourceOrTarget]
	}
	keysForOwner := keysMap[ownerID]
	if keysForOwner != nil {
		keysForOwner.Discard(lmKey)
		if keysForOwner.Len() == 0 {
			delete(keysMap, ownerID)
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

// extractSourceOwnerID extracts the wepOwnerID from a LiveMigrationSource.
// Returns the zero value if the source is nil or has no identifying fields set.
func extractSourceOwnerID(src *internalapi.LiveMigrationSource) wepOwnerID {
	if src != nil {
		if src.Workload != nil {
			return wepOwnerIDFromWorkload(src.Workload)
		}
		if src.WorkloadEndpoint != nil {
			return wepOwnerIDFromEndpoint(src.WorkloadEndpoint)
		}
	}
	return wepOwnerID{}
}

// extractTargetOwnerID extracts the wepOwnerID from a LiveMigrationTarget's
// WorkloadEndpoint field (used for direct-name target matching).
// Returns the zero value if the target is nil or uses selector-based matching.
func extractTargetOwnerID(tgt *internalapi.LiveMigrationTarget) wepOwnerID {
	if tgt != nil {
		if tgt.WorkloadEndpoint != nil {
			return wepOwnerIDFromEndpoint(tgt.WorkloadEndpoint)
		}
	}
	return wepOwnerID{}
}

// extractTargetSelector extracts the selector string from a LiveMigrationTarget.
func extractTargetSelector(tgt *internalapi.LiveMigrationTarget) string {
	if tgt != nil && tgt.Selector != nil {
		return *tgt.Selector
	}
	return ""
}

func (lmc *LiveMigrationCalculator) withRoleUpdateIfNeeded(wepData *wepData, updateFunc func()) {
	oldRole, _ := lmc.liveMigrationRoleAndUID(wepData)
	updateFunc()
	newRole, newUID := lmc.liveMigrationRoleAndUID(wepData)
	if newRole != oldRole {
		lmc.indicateRole(wepData.key, newRole, newUID)
	}
}

const EPCompDataKindLiveMigration = EndpointComputedDataKind("LiveMigration")

func (lmc *LiveMigrationCalculator) indicateRole(key model.WorkloadEndpointKey, role proto.LiveMigrationRole, uid string) {
	logrus.WithFields(logrus.Fields{
		"wep":  key,
		"role": role,
		"uid":  uid,
	}).Debug("LiveMigrationCalculator: emitting role for WEP")
	lmc.OnEndpointComputedData(key, EPCompDataKindLiveMigration, &liveMigrationRole{role: role, uid: uid})
}

type liveMigrationRole struct {
	role proto.LiveMigrationRole
	uid  string
}

func (lmr *liveMigrationRole) ApplyTo(wep *proto.WorkloadEndpoint) {
	wep.LiveMigrationRole = lmr.role
	wep.LiveMigrationUid = lmr.uid
}
