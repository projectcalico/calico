// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.

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

package policystore

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// ProcessUpdate -  Update the PolicyStore with the information passed over the Sync API.
func (store *PolicyStore) ProcessUpdate(subscriptionType string, update *proto.ToDataplane, storeStaged bool) {
	// TODO: maybe coalesce-ing updater fits here
	switch payload := update.Payload.(type) {
	case *proto.ToDataplane_InSync:
		store.processInSync(payload.InSync)
	case *proto.ToDataplane_IpsetUpdate:
		store.processIPSetUpdate(payload.IpsetUpdate)
	case *proto.ToDataplane_IpsetDeltaUpdate:
		store.processIPSetDeltaUpdate(payload.IpsetDeltaUpdate)
	case *proto.ToDataplane_IpsetRemove:
		store.processIPSetRemove(payload.IpsetRemove)
	case *proto.ToDataplane_ActiveProfileUpdate:
		store.processActiveProfileUpdate(payload.ActiveProfileUpdate)
	case *proto.ToDataplane_ActiveProfileRemove:
		store.processActiveProfileRemove(payload.ActiveProfileRemove)
	case *proto.ToDataplane_ActivePolicyUpdate:
		if !storeStaged && model.KindIsStaged(payload.ActivePolicyUpdate.Id.Name) {
			log.WithFields(log.Fields{
				"id": payload.ActivePolicyUpdate.Id,
			}).Debug("Skipping StagedPolicy ActivePolicyUpdate")

			return
		}

		store.processActivePolicyUpdate(payload.ActivePolicyUpdate)
	case *proto.ToDataplane_ActivePolicyRemove:
		if !storeStaged && model.KindIsStaged(payload.ActivePolicyRemove.Id.Name) {
			log.WithFields(log.Fields{
				"id": payload.ActivePolicyRemove.Id,
			}).Debug("Skipping StagedPolicy ActivePolicyRemove")

			return
		}

		store.processActivePolicyRemove(payload.ActivePolicyRemove)
	case *proto.ToDataplane_WorkloadEndpointUpdate:
		store.processWorkloadEndpointUpdate(subscriptionType, payload.WorkloadEndpointUpdate)
	case *proto.ToDataplane_WorkloadEndpointRemove:
		store.processWorkloadEndpointRemove(subscriptionType, payload.WorkloadEndpointRemove)
	case *proto.ToDataplane_ServiceAccountUpdate:
		store.processServiceAccountUpdate(payload.ServiceAccountUpdate)
	case *proto.ToDataplane_ServiceAccountRemove:
		store.processServiceAccountRemove(payload.ServiceAccountRemove)
	case *proto.ToDataplane_NamespaceUpdate:
		store.processNamespaceUpdate(payload.NamespaceUpdate)
	case *proto.ToDataplane_NamespaceRemove:
		store.processNamespaceRemove(payload.NamespaceRemove)
	default:
		log.Debugf("unknown payload %v", update.String())
	}
}

func (store *PolicyStore) processInSync(inSync *proto.InSync) {
	log.Debug("Processing InSync")
}

func (store *PolicyStore) processIPSetUpdate(update *proto.IPSetUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id":      update.Id,
			"type":    update.Type.String(),
			"members": update.Members,
		}).Debug("Processing IPSetUpdate")
	}

	// IPSetUpdate replaces the existing set.
	if s := NewIPSet(update.Type); s != nil {
		for _, addr := range update.Members {
			s.AddString(addr)
		}
		store.IPSetByID[update.Id] = s
	}
}

func (store *PolicyStore) processIPSetDeltaUpdate(update *proto.IPSetDeltaUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id":      update.Id,
			"added":   update.AddedMembers,
			"removed": update.RemovedMembers,
		}).Debug("Processing IPSetDeltaUpdate")
	}
	s, ok := store.IPSetByID[update.Id]
	if !ok {
		log.Errorf("Unknown IPSet id: %v, skipping update", update.Id)
		return // we shouldn't be getting a delta update before we've seen the IPSet
	}

	for _, addr := range update.AddedMembers {
		s.AddString(addr)
	}
	for _, addr := range update.RemovedMembers {
		s.RemoveString(addr)
	}
}

func (store *PolicyStore) processIPSetRemove(update *proto.IPSetRemove) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing IPSetRemove")
	}
	delete(store.IPSetByID, update.Id)
}

func (store *PolicyStore) processActiveProfileUpdate(update *proto.ActiveProfileUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing ActiveProfileUpdate")
	}
	if update.Id == nil {
		log.Error("got ActiveProfileUpdate with nil ProfileID")
		return
	}
	id := types.ProtoToProfileID(update.GetId())
	store.ProfileByID[id] = update.Profile
}

func (store *PolicyStore) processActiveProfileRemove(update *proto.ActiveProfileRemove) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing ActiveProfileRemove")
	}
	if update.Id == nil {
		log.Error("got ActiveProfileRemove with nil ProfileID")
		return
	}
	id := types.ProtoToProfileID(update.GetId())
	delete(store.ProfileByID, id)
}

func (store *PolicyStore) processActivePolicyUpdate(update *proto.ActivePolicyUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing ActivePolicyUpdate")
	}
	if update.Id == nil {
		log.Error("got ActivePolicyUpdate with nil PolicyID")
		return
	}
	id := types.ProtoToPolicyID(update.GetId())
	store.PolicyByID[id] = update.Policy
}

func (store *PolicyStore) processActivePolicyRemove(update *proto.ActivePolicyRemove) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing ActivePolicyRemove")
	}
	if update.Id == nil {
		log.Error("got ActivePolicyRemove with nil PolicyID")
		return
	}
	id := types.ProtoToPolicyID(update.GetId())
	delete(store.PolicyByID, id)
}

func (store *PolicyStore) processWorkloadEndpointUpdate(subscriptionType string, update *proto.WorkloadEndpointUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"orchestratorID": update.GetId().GetOrchestratorId(),
			"workloadID":     update.GetId().GetWorkloadId(),
			"endpointID":     update.GetId().GetEndpointId(),
		}).Debug("Processing WorkloadEndpointUpdate")
	}
	switch subscriptionType {
	case "per-pod-policies", "":
		store.Endpoint = update.Endpoint
	case "per-host-policies":
		store.Endpoints[types.ProtoToWorkloadEndpointID(update.Id)] = update.Endpoint
		log.Debugf("%d endpoints received so far", len(store.Endpoints))
	}
}

func (store *PolicyStore) processWorkloadEndpointRemove(subscriptionType string, update *proto.WorkloadEndpointRemove) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"orchestratorID": update.GetId().GetOrchestratorId(),
			"workloadID":     update.GetId().GetWorkloadId(),
			"endpointID":     update.GetId().GetEndpointId(),
		}).Debug("Processing WorkloadEndpointRemove")
	}

	switch subscriptionType {
	case "per-pod-policies", "":
		store.Endpoint = nil
	case "per-host-policies":
		delete(store.Endpoints, types.ProtoToWorkloadEndpointID(update.Id))
	}
}

func (store *PolicyStore) processServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	log.WithField("id", update.Id).Debug("Processing ServiceAccountUpdate")
	if update.Id == nil {
		log.Error("got ServiceAccountUpdate with nil ServiceAccountID")
		return
	}
	id := types.ProtoToServiceAccountID(update.GetId())
	store.ServiceAccountByID[id] = update
}

func (store *PolicyStore) processServiceAccountRemove(update *proto.ServiceAccountRemove) {
	log.WithField("id", update.Id).Debug("Processing ServiceAccountRemove")
	if update.Id == nil {
		log.Error("got ServiceAccountRemove with nil ServiceAccountID")
		return
	}
	id := types.ProtoToServiceAccountID(update.GetId())
	delete(store.ServiceAccountByID, id)
}

func (store *PolicyStore) processNamespaceUpdate(update *proto.NamespaceUpdate) {
	log.WithField("id", update.Id).Debug("Processing NamespaceUpdate")
	if update.Id == nil {
		log.Error("got NamespaceUpdate with nil NamespaceID")
		return
	}
	id := types.ProtoToNamespaceID(update.GetId())
	store.NamespaceByID[id] = update
}

func (store *PolicyStore) processNamespaceRemove(update *proto.NamespaceRemove) {
	log.WithField("id", update.Id).Debug("Processing NamespaceRemove")
	if update.Id == nil {
		log.Error("got NamespaceRemove with nil NamespaceID")
		return
	}
	id := types.ProtoToNamespaceID(update.GetId())
	delete(store.NamespaceByID, id)
}
