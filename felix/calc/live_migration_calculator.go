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

	// Keys of LiveMigration resources whose target selector matches this WEP.
	selectorKeys set.Set[model.ResourceKey]
}

// lmSelectorListener receives the matches for one LiveMigration's target selector.  There is one
// per LiveMigration, rather than one per distinct selector, so that each match identifies the
// LiveMigration that it is for.
type lmSelectorListener struct {
	lmc   *LiveMigrationCalculator
	lmKey model.ResourceKey
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
				selectorKeys: set.New[model.ResourceKey](),
			}

			lmc.withRoleUpdateIfNeeded(wd, func() {
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
			})

			lmc.weps[exactID] = wd
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

		var lm *internalapi.LiveMigration
		if update.Value != nil {
			lm = update.Value.(*internalapi.LiveMigration)
			logrus.WithFields(logrus.Fields{
				"lm":       key,
				"uid":      lm.UID,
				"source":   extractSourceOwnerID(lm.Spec.Source),
				"target":   extractTargetOwnerID(lm.Spec.Target),
				"selector": extractTargetSelector(lm.Spec.Target),
			}).Info("LiveMigrationCalculator: LiveMigration created/updated")
		} else {
			logrus.WithField("lm", key).Info("LiveMigrationCalculator: LiveMigration deleted")
		}

		old, hadOld := lmc.liveMigrations[key]
		if hadOld && lm != nil && sameUIDAndReferences(&old, lm) {
			// Nothing that affects any WEP's role or UID has changed.
			lmc.liveMigrations[key] = *lm
			return
		}

		// A WEP's role and UID depend on which LiveMigrations reference it, and on their UIDs.
		// Changes are detected per WEP, by comparing before and after a LiveMigration starts or
		// stops referencing it, so the stored LiveMigration, and hence its UID, must only change
		// while it references no WEPs.  Hence an update is handled as removing all of the old
		// version's references, then replacing the stored LiveMigration, then adding the new
		// version's references.  A WEP can pass through an intermediate role in between, but
		// only the final one reaches the dataplane.
		if hadOld {
			lmc.removeReferences(key, &old)
			delete(lmc.liveMigrations, key)
		}
		if lm != nil {
			lmc.liveMigrations[key] = *lm
			lmc.addReferences(key, lm)
		}
	default:
		logrus.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return
}

func (lmc *LiveMigrationCalculator) OnPolicyMatch(_ model.PolicyKey, _ model.EndpointKey)        {}
func (lmc *LiveMigrationCalculator) OnPolicyMatchStopped(_ model.PolicyKey, _ model.EndpointKey) {}

func (l lmSelectorListener) OnComputedSelectorMatch(_ string, epKey model.EndpointKey) {
	l.lmc.updateSelectorMatch(l.lmKey, epKey, true)
}

func (l lmSelectorListener) OnComputedSelectorMatchStopped(_ string, epKey model.EndpointKey) {
	l.lmc.updateSelectorMatch(l.lmKey, epKey, false)
}

func (lmc *LiveMigrationCalculator) updateSelectorMatch(
	lmKey model.ResourceKey,
	epKey model.EndpointKey,
	matching bool,
) {
	wepKey, ok := epKey.(model.WorkloadEndpointKey)
	if !ok {
		return
	}
	exactID := wepOwnerIDFromKey(wepKey)
	wd := lmc.weps[exactID]
	if wd == nil {
		// Shouldn't happen, because this calculator sees each local WEP before the active rules
		// calculator does, but harmless.
		return
	}
	logrus.WithFields(logrus.Fields{
		"wep":      exactID,
		"lm":       lmKey,
		"matching": matching,
	}).Debug("LiveMigrationCalculator: target selector match changed")
	lmc.withRoleUpdateIfNeeded(wd, func() {
		if matching {
			wd.selectorKeys.Add(lmKey)
		} else {
			wd.selectorKeys.Discard(lmKey)
		}
	})
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
	if wd.selectorKeys.Len() > 0 {
		return proto.LiveMigrationRole_TARGET, lmc.uidFromLMKeys(wd.selectorKeys)
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

func (lmc *LiveMigrationCalculator) addReferences(key model.ResourceKey, lm *internalapi.LiveMigration) {
	if sourceID := extractSourceOwnerID(lm.Spec.Source); sourceID != (wepOwnerID{}) {
		lmc.refDirectName(sourceID, key, source)
	}
	if targetID := extractTargetOwnerID(lm.Spec.Target); targetID != (wepOwnerID{}) {
		lmc.refDirectName(targetID, key, target)
	}
	if selector := extractTargetSelector(lm.Spec.Target); selector != "" {
		lmc.activeRulesCalc.AddExtraComputedSelector(selector, lmSelectorListener{lmc, key})
	}
}

func (lmc *LiveMigrationCalculator) removeReferences(key model.ResourceKey, lm *internalapi.LiveMigration) {
	if sourceID := extractSourceOwnerID(lm.Spec.Source); sourceID != (wepOwnerID{}) {
		lmc.unrefDirectName(sourceID, key, source)
	}
	if targetID := extractTargetOwnerID(lm.Spec.Target); targetID != (wepOwnerID{}) {
		lmc.unrefDirectName(targetID, key, target)
	}
	if selector := extractTargetSelector(lm.Spec.Target); selector != "" {
		lmc.activeRulesCalc.RemoveExtraComputedSelector(selector, lmSelectorListener{lmc, key})
	}
}

// sameUIDAndReferences returns true if two versions of a LiveMigration have the same UID and
// reference the same WEPs.
func sameUIDAndReferences(a, b *internalapi.LiveMigration) bool {
	return a.UID == b.UID &&
		extractSourceOwnerID(a.Spec.Source) == extractSourceOwnerID(b.Spec.Source) &&
		extractTargetOwnerID(a.Spec.Target) == extractTargetOwnerID(b.Spec.Target) &&
		extractTargetSelector(a.Spec.Target) == extractTargetSelector(b.Spec.Target)
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
	oldRole, oldUID := lmc.liveMigrationRoleAndUID(wepData)
	updateFunc()
	newRole, newUID := lmc.liveMigrationRoleAndUID(wepData)

	// The UID must be emitted when it changes, even if the role doesn't, so that what we emit
	// depends only on the current datastore state, not on the order of the updates that led to
	// it.
	if newRole != oldRole || newUID != oldUID {
		logrus.WithFields(logrus.Fields{
			"wep":  wepData.key,
			"role": newRole,
			"uid":  newUID,
		}).Info("LiveMigrationCalculator: emitting role for WEP")
		lmc.OnEndpointComputedData(wepData.key, EPCompDataKindLiveMigration, &liveMigrationRole{role: newRole, uid: newUID})
	}
}

const EPCompDataKindLiveMigration = EndpointComputedDataKind("LiveMigration")

type liveMigrationRole struct {
	role proto.LiveMigrationRole
	uid  string
}

func (lmr *liveMigrationRole) ApplyTo(wep *proto.WorkloadEndpoint) {
	wep.LiveMigrationRole = lmr.role
	wep.LiveMigrationUid = lmr.uid
}
