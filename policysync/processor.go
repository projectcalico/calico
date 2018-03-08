// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package policysync

import (
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/proto"
)

type Processor struct {
	Updates            <-chan interface{}
	JoinUpdates        chan interface{}
	endpointsByID      map[proto.WorkloadEndpointID]*EndpointInfo
	policyByID         map[proto.PolicyID]*proto.Policy
	profileByID        map[proto.ProfileID]*proto.Profile
	serviceAccountByID map[proto.ServiceAccountID]*proto.ServiceAccountUpdate
	namespaceByID      map[proto.NamespaceID]*proto.NamespaceUpdate
	receivedInSync     bool
}

type EndpointInfo struct {
	// The channel to send updates for this workload to.
	output         chan<- proto.ToDataplane
	currentJoinUID uint64
	endpointUpd    *proto.WorkloadEndpointUpdate
	syncedPolicies map[proto.PolicyID]bool
	syncedProfiles map[proto.ProfileID]bool
}

type JoinMetadata struct {
	EndpointID proto.WorkloadEndpointID
	// JoinUID is a correlator, used to match stop requests with join requests.
	JoinUID uint64
}

// JoinRequest is sent to the Processor when a new socket connection is accepted by the GRPC server,
// it provides the channel used to send sync messages back to the server goroutine.
type JoinRequest struct {
	JoinMetadata
	// C is the channel to send updates to the policy sync client.  Processor closes the channel when the
	// workload endpoint is removed, or when a new JoinRequest is received for the same endpoint.  If nil, indicates
	// the client wants to stop receiving updates.
	C chan<- proto.ToDataplane
}

type LeaveRequest struct {
	JoinMetadata
}

func NewProcessor(updates <-chan interface{}) *Processor {
	return &Processor{
		// Updates from the calculation graph.
		Updates: updates,
		// JoinUpdates from the new servers that have started.
		JoinUpdates:        make(chan interface{}, 10),
		endpointsByID:      make(map[proto.WorkloadEndpointID]*EndpointInfo),
		policyByID:         make(map[proto.PolicyID]*proto.Policy),
		profileByID:        make(map[proto.ProfileID]*proto.Profile),
		serviceAccountByID: make(map[proto.ServiceAccountID]*proto.ServiceAccountUpdate),
		namespaceByID:      make(map[proto.NamespaceID]*proto.NamespaceUpdate),
	}
}

func (p *Processor) Start() {
	go p.loop()
}

func (p *Processor) loop() {
	for {
		select {
		case update := <-p.Updates:
			p.handleDataplane(update)
		case joinReq := <-p.JoinUpdates:
			log.WithField("update", joinReq).Info("Request received on the join updates channel")
			switch r := joinReq.(type) {
			case JoinRequest:
				p.handleJoin(r)
			case LeaveRequest:
				p.handleLeave(r)
			default:
				log.WithField("message", joinReq).Panic("Unexpected message")
			}
		}
	}
}

func (p *Processor) handleJoin(joinReq JoinRequest) {
	epID := joinReq.EndpointID
	logCxt := log.WithField("joinReq", joinReq).WithField("epID", epID)
	ei, ok := p.endpointsByID[epID]

	if !ok {
		logCxt.Info("Join request for unknown endpoint, pre-creating EndpointInfo")
		ei = &EndpointInfo{}
		p.endpointsByID[epID] = ei
	}

	if ei.output != nil {
		logCxt.Info("Join request for already-active connection, closing old channel.")
		close(ei.output)
	} else {
		logCxt.Info("Join request with no previously active connection.")
	}

	ei.currentJoinUID = joinReq.JoinUID
	ei.output = joinReq.C
	ei.syncedPolicies = map[proto.PolicyID]bool{}
	ei.syncedProfiles = map[proto.ProfileID]bool{}

	p.maybeSyncEndpoint(ei)

	// Any updates to service accounts will be synced, but the endpoint needs to know about any existing service
	// accounts that were updated before it joined.
	p.sendServiceAccounts(ei)
	p.sendNamespaces(ei)
	logCxt.Debug("Done with join")
}

func (p *Processor) handleLeave(leaveReq LeaveRequest) {
	epID := leaveReq.EndpointID
	logCxt := log.WithField("leaveReq", leaveReq).WithField("epID", epID)
	ei, ok := p.endpointsByID[epID]

	if !ok {
		logCxt.Info("Leave request for unknown endpoint, ignoring")
		return
	}

	// Make sure we clean up endpointsByID if needed.
	defer func() {
		if ei.output == nil && ei.currentJoinUID == 0 && ei.endpointUpd == nil {
			logCxt.Info("Cleaning up empty EndpointInfo")
			delete(p.endpointsByID, epID)
		}
	}()
	if ei.currentJoinUID != leaveReq.JoinUID {
		logCxt.Info("Leave request doesn't match active connection, ignoring")
		return
	}
	logCxt.Info("Leave request for active connection, closing channel.")
	close(ei.output)
	ei.output = nil
	ei.currentJoinUID = 0
	return
}

func (p *Processor) handleDataplane(update interface{}) {
	log.WithFields(log.Fields{"update": update, "type": reflect.TypeOf(update)}).Info("Dataplane update")
	switch update := update.(type) {
	case *proto.InSync:
		p.handleInSync(update)
	case *proto.WorkloadEndpointUpdate:
		p.handleWorkloadEndpointUpdate(update)
	case *proto.WorkloadEndpointRemove:
		p.handleWorkloadEndpointRemove(update)
	case *proto.ActiveProfileUpdate:
		p.handleActiveProfileUpdate(update)
	case *proto.ActiveProfileRemove:
		p.handleActiveProfileRemove(update)
	case *proto.ActivePolicyUpdate:
		p.handleActivePolicyUpdate(update)
	case *proto.ActivePolicyRemove:
		p.handleActivePolicyRemove(update)
	case *proto.ServiceAccountUpdate:
		p.handleServiceAccountUpdate(update)
	case *proto.ServiceAccountRemove:
		p.handleServiceAccountRemove(update)
	case *proto.NamespaceUpdate:
		p.handleNamespaceUpdate(update)
	case *proto.NamespaceRemove:
		p.handleNamespaceRemove(update)
	default:
		log.WithFields(log.Fields{
			"update": update,
			"type":   reflect.TypeOf(update),
		}).Warn("Unhandled update")
	}
}

func (p *Processor) handleInSync(update *proto.InSync) {
	if p.receivedInSync {
		log.Debug("Ignoring duplicate InSync message from the calculation graph")
		return
	}
	log.Info("Now in sync with the calculation graph")
	p.receivedInSync = true
	for _, ei := range p.endpointsByID {
		if ei.output != nil {
			ei.output <- proto.ToDataplane{
				Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}}}
		}
	}
	return
}

func (p *Processor) handleWorkloadEndpointUpdate(update *proto.WorkloadEndpointUpdate) {
	epID := *update.Id
	log.WithField("epID", epID).Info("Endpoint update")
	ei, ok := p.endpointsByID[epID]
	if !ok {
		// Add this endpoint
		ei = &EndpointInfo{
			endpointUpd:    update,
			syncedPolicies: map[proto.PolicyID]bool{},
			syncedProfiles: map[proto.ProfileID]bool{},
		}
		p.endpointsByID[epID] = ei
	} else {
		ei.endpointUpd = update
	}
	p.maybeSyncEndpoint(ei)
}

func (p *Processor) maybeSyncEndpoint(ei *EndpointInfo) {
	if ei.endpointUpd == nil {
		log.Debug("Skipping sync: endpoint has no update")
		return
	}
	if ei.output == nil {
		log.Debug("Skipping sync: endpoint has no listening client")
		return
	}

	// The calc graph sends us policies and profiles before endpoint updates, but the Processor doesn't know
	// which endpoints need them until now.  Send any unsynced profiles & policies referenced
	p.syncAddedPolicies(ei)
	p.syncAddedProfiles(ei)
	ei.output <- proto.ToDataplane{
		Payload: &proto.ToDataplane_WorkloadEndpointUpdate{ei.endpointUpd}}
	p.syncRemovedPolicies(ei)
	p.syncRemovedProfiles(ei)
	if p.receivedInSync {
		log.WithField("channel", ei.output).Debug("Already in sync with the datastore, sending in-sync message to client")
		ei.output <- proto.ToDataplane{
			Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}}}
	}
}

func (p *Processor) handleWorkloadEndpointRemove(update *proto.WorkloadEndpointRemove) {
	// we trust the Calc graph never to send us a remove for an endpoint it didn't tell us about
	ei := p.endpointsByID[*update.Id]
	if ei.output != nil {
		// Send update and close down.
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointRemove{update}}
		close(ei.output)
	}
	delete(p.endpointsByID, *update.Id)
}

func (p *Processor) handleActiveProfileUpdate(update *proto.ActiveProfileUpdate) {
	pId := *update.Id
	profile := update.GetProfile()
	p.profileByID[pId] = profile

	// Update any endpoints that reference this profile
	for _, ei := range p.updateableEndpoints() {
		action := func(other proto.ProfileID) bool {
			if other == pId {
				ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{update}}
				ei.syncedProfiles[pId] = true
				return true
			}
			return false
		}
		ei.iterateProfiles(action)
	}
}

func (p *Processor) handleActiveProfileRemove(update *proto.ActiveProfileRemove) {
	pId := *update.Id
	log.WithFields(log.Fields{"ProfileID": pId}).Debug("Processing ActiveProfileRemove")

	// Push the update to any endpoints it was synced to
	for _, ei := range p.updateableEndpoints() {
		if ei.syncedProfiles[pId] {
			ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileRemove{update}}
			delete(ei.syncedProfiles, pId)
		}
	}
	delete(p.profileByID, pId)
}

func (p *Processor) handleActivePolicyUpdate(update *proto.ActivePolicyUpdate) {
	pId := *update.Id
	log.WithFields(log.Fields{"PolicyID": pId}).Debug("Processing ActivePolicyUpdate")
	policy := update.GetPolicy()
	p.policyByID[pId] = policy

	// Update any endpoints that reference this policy
	for _, ei := range p.updateableEndpoints() {
		// Closure of the action to take on each policy on the endpoint.
		action := func(other proto.PolicyID) bool {
			if other == pId {
				ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{update}}
				ei.syncedPolicies[pId] = true
				return true
			}
			return false
		}
		ei.iteratePolicies(action)
	}
}

func (p *Processor) handleActivePolicyRemove(update *proto.ActivePolicyRemove) {
	pId := *update.Id
	log.WithFields(log.Fields{"PolicyID": pId}).Debug("Processing ActivePolicyRemove")

	// Push the update to any endpoints it was synced to
	for _, ei := range p.updateableEndpoints() {
		if ei.syncedPolicies[pId] {
			ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyRemove{update}}
			delete(ei.syncedPolicies, pId)
		}
	}
	delete(p.policyByID, pId)
}

func (p *Processor) handleServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	id := *update.Id
	log.WithField("ServiceAccountID", id).Debug("Processing ServiceAccountUpdate")

	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountUpdate{update}}
	}
	p.serviceAccountByID[id] = update
	return
}

func (p *Processor) handleServiceAccountRemove(update *proto.ServiceAccountRemove) {
	id := *update.Id
	log.WithField("ServiceAccountID", id).Debug("Processing ServiceAccountRemove")

	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountRemove{update}}
	}
	delete(p.serviceAccountByID, id)
}

func (p *Processor) handleNamespaceUpdate(update *proto.NamespaceUpdate) {
	id := *update.Id
	log.WithField("NamespaceID", id).Debug("Processing NamespaceUpdate")

	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceUpdate{update}}
	}
	p.namespaceByID[id] = update
	return
}

func (p *Processor) handleNamespaceRemove(update *proto.NamespaceRemove) {
	id := *update.Id
	log.WithField("NamespaceID", id).Debug("Processing NamespaceRemove")

	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceRemove{update}}
	}
	delete(p.namespaceByID, id)
}

func (p *Processor) syncAddedPolicies(ei *EndpointInfo) {
	ei.iteratePolicies(func(pId proto.PolicyID) bool {
		if !ei.syncedPolicies[pId] {
			policy := p.policyByID[pId]
			ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
				&proto.ActivePolicyUpdate{
					Id:     &pId,
					Policy: policy,
				},
			}}
			ei.syncedPolicies[pId] = true
		}
		return false
	})
}

// syncRemovedPolicies sends ActivePolicyRemove messages for any previously active, but now unused
// policies.
func (p *Processor) syncRemovedPolicies(ei *EndpointInfo) {
	oldSyncedPolicies := ei.syncedPolicies
	ei.syncedPolicies = map[proto.PolicyID]bool{}

	ei.iteratePolicies(func(pId proto.PolicyID) bool {
		if !oldSyncedPolicies[pId] {
			// We've never sent this policy?
			return false
		}

		// Still an active policy, remove it from the old set.
		delete(oldSyncedPolicies, pId)
		ei.syncedPolicies[pId] = true
		return false
	})

	// oldSyncedPolicies now contains only policies that are no longer needed by this endpoint.
	for polID := range oldSyncedPolicies {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyRemove{
			&proto.ActivePolicyRemove{Id: &polID},
		}}
	}
}

func (p *Processor) syncAddedProfiles(ei *EndpointInfo) {
	ei.iterateProfiles(func(pId proto.ProfileID) bool {
		if !ei.syncedProfiles[pId] {
			profile := p.profileByID[pId]
			ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{
				&proto.ActiveProfileUpdate{
					Id:      &pId,
					Profile: profile,
				},
			}}
			ei.syncedProfiles[pId] = true
		}
		return false
	})
}

// syncRemovedProfiles sends ActiveProfileRemove messages for any previously active, but now unused
// profiles.
func (p *Processor) syncRemovedProfiles(ei *EndpointInfo) {
	oldSyncedProfiles := ei.syncedProfiles
	ei.syncedProfiles = map[proto.ProfileID]bool{}

	ei.iterateProfiles(func(pId proto.ProfileID) bool {
		if !oldSyncedProfiles[pId] {
			// We've never sent this profile?
			return false
		}

		// Still an active profile, remove it from the old set.
		delete(oldSyncedProfiles, pId)
		ei.syncedProfiles[pId] = true
		return false
	})

	// oldSyncedProfiles now contains only policies that are no longer needed by this endpoint.
	for polID := range oldSyncedProfiles {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileRemove{
			&proto.ActiveProfileRemove{Id: &polID},
		}}
	}
}

// sendServiceAccounts sends all known ServiceAccounts to the endpoint
func (p *Processor) sendServiceAccounts(ei *EndpointInfo) {
	for _, update := range p.serviceAccountByID {
		log.WithFields(log.Fields{
			"serviceAccount": update.Id,
			"endpoint":       ei.endpointUpd.GetEndpoint(),
		}).Debug("sending ServiceAccountUpdate")
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountUpdate{update}}
	}
}

// sendNamespaces sends all known Namespaces to the endpoint
func (p *Processor) sendNamespaces(ei *EndpointInfo) {
	for _, update := range p.namespaceByID {
		log.WithFields(log.Fields{
			"namespace": update.Id,
			"endpoint":  ei.endpointUpd.GetEndpoint(),
		}).Debug("sending NamespaceUpdate")
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceUpdate{update}}
	}
}

// A slice of all the Endpoints that can currently be sent updates.
func (p *Processor) updateableEndpoints() []*EndpointInfo {
	out := make([]*EndpointInfo, 0)
	for _, ei := range p.endpointsByID {
		if ei.output != nil {
			out = append(out, ei)
		}
	}
	return out
}

// Perform the action on every policy on the Endpoint, breaking if the action returns true.
func (ei *EndpointInfo) iteratePolicies(action func(id proto.PolicyID) (stop bool)) {
	var pId proto.PolicyID
	for _, tier := range ei.endpointUpd.GetEndpoint().GetTiers() {
		pId.Tier = tier.Name
		for _, name := range tier.GetIngressPolicies() {
			pId.Name = name
			if action(pId) {
				return
			}
		}
		for _, name := range tier.GetEgressPolicies() {
			pId.Name = name
			if action(pId) {
				return
			}
		}
	}
}

// Perform the action on every profile on the Endpoint, breaking if the action returns true.
func (ei *EndpointInfo) iterateProfiles(action func(id proto.ProfileID) (stop bool)) {
	var pId proto.ProfileID
	for _, name := range ei.endpointUpd.GetEndpoint().GetProfileIds() {
		pId.Name = name
		if action(pId) {
			return
		}
	}
}
