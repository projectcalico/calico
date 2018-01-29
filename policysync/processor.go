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
	Updates       <-chan interface{}
	Joins         chan JoinRequest
	endpointsByID map[proto.WorkloadEndpointID]*EndpointInfo
	policyByID    map[proto.PolicyID]*proto.Policy
	profileByID   map[proto.ProfileID]*proto.Profile
}

type EndpointInfo struct {
	// The channel to send updates for this workload to.
	output         chan<- proto.ToDataplane
	currentJoinUID uint64
	endpointUpd    *proto.WorkloadEndpointUpdate
	syncedPolicies map[proto.PolicyID]bool
	syncedProfiles map[proto.ProfileID]bool
}

// JoinRequest is sent to the Processor when a new socket connection is accepted by the GRPC server,
// it provides the channel used to send sync messages back to the server goroutine.
type JoinRequest struct {
	EndpointID proto.WorkloadEndpointID
	// C is the channel to send updates to the policy sync client.  Processor closes the channel when the
	// workload endpoint is removed, or when a new JoinRequest is received for the same endpoint.  If nil, indicates
	// the client wants to stop receiving updates.
	C       chan<- proto.ToDataplane
	JoinUID uint64
}

func NewProcessor(updates <-chan interface{}) *Processor {
	return &Processor{
		// Updates from the calculation graph.
		Updates: updates,
		// Joins from the new servers that have started.
		Joins:         make(chan JoinRequest, 10),
		endpointsByID: make(map[proto.WorkloadEndpointID]*EndpointInfo),
		policyByID:    make(map[proto.PolicyID]*proto.Policy),
		profileByID:   make(map[proto.ProfileID]*proto.Profile),
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
		case joinReq := <-p.Joins:
			p.handleJoin(joinReq)
		}
	}
}

func (p *Processor) handleJoin(joinReq JoinRequest) {
	logCxt := log.WithField("joinReq", joinReq)
	ei, ok := p.endpointsByID[joinReq.EndpointID]

	if !ok {
		logCxt.Info("Request for unknown endpoint, pre-creating EndpointInfo")
		ei = &EndpointInfo{}
		p.endpointsByID[joinReq.EndpointID] = ei
	}

	if joinReq.C == nil {
		// This is a leave request, make sure we clean up endpointsByID if needed.
		defer func() {
			if reflect.DeepEqual(*ei, EndpointInfo{}) {
				logCxt.Info("Cleaning up empty EndpointInfo")
				delete(p.endpointsByID, joinReq.EndpointID)
			}
		}()
		if ei.currentJoinUID != joinReq.JoinUID {
			logCxt.Info("Leave request doesn't match active connection, ignoring")
			return
		}
		logCxt.Info("Leave request for active connection, closing channel.")
		close(ei.output)
		ei.output = nil
		ei.currentJoinUID = 0
		return
	}

	// If we get here, we've got a join request.
	if ei.output != nil {
		logCxt.Info("Join request for already-active connection, closing old channel.")
		close(ei.output)
	}

	ei.currentJoinUID = joinReq.JoinUID
	ei.output = joinReq.C

	p.maybeSyncEndpoint(ei)
}

func (p *Processor) handleDataplane(update interface{}) {
	switch update := update.(type) {
	case proto.InSync:
		p.handleInSync(update)
	case proto.WorkloadEndpointUpdate:
		p.handleWorkloadEndpointUpdate(update)
	case proto.WorkloadEndpointRemove:
		p.handleWorkloadEndpointRemove(update)
	case proto.ActiveProfileUpdate:
		p.handleActiveProfileUpdate(update)
	case proto.ActiveProfileRemove:
		p.handleActiveProfileRemove(update)
	case proto.ActivePolicyUpdate:
		p.handleActivePolicyUpdate(update)
	case proto.ActivePolicyRemove:
		p.handleActivePolicyRemove(update)
	default:
		log.WithFields(log.Fields{"update": update}).Debug("Unhandled update")
	}
}

func (p *Processor) handleInSync(update proto.InSync) {
	return
}

func (p *Processor) handleWorkloadEndpointUpdate(update proto.WorkloadEndpointUpdate) {
	ei, ok := p.endpointsByID[*update.Id]
	if !ok {
		// Add this endpoint
		ei = &EndpointInfo{
			endpointUpd: &update,
		}
		p.endpointsByID[*update.Id] = ei
	} else {
		ei.endpointUpd = &update
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
	p.syncPolicies(ei)
	p.syncProfiles(ei)
	ei.output <- proto.ToDataplane{
		Payload: &proto.ToDataplane_WorkloadEndpointUpdate{ei.endpointUpd}}
}

func (p *Processor) handleWorkloadEndpointRemove(update proto.WorkloadEndpointRemove) {
	// we trust the Calc graph never to send us a remove for an endpoint it didn't tell us about
	ei := p.endpointsByID[*update.Id]
	if ei.output != nil {
		// Send update and close down.
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointRemove{&update}}
		close(ei.output)
	}
	delete(p.endpointsByID, *update.Id)
}

func (p *Processor) handleActiveProfileUpdate(update proto.ActiveProfileUpdate) {
	pId := *update.Id
	profile := update.GetProfile()
	p.profileByID[pId] = profile

	// Update any endpoints that reference this profile
	for _, ei := range p.updateableEndpoints() {
		action := func(other proto.ProfileID) bool {
			if other == pId {
				ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{&update}}
				ei.syncedProfiles[pId] = true
				return true
			}
			return false
		}
		ei.iterateProfiles(action)
	}
}

func (p *Processor) handleActiveProfileRemove(update proto.ActiveProfileRemove) {
	pId := *update.Id
	log.WithFields(log.Fields{"ProfileID": pId.String()}).Debug("Processing ActiveProfileRemove")

	// Push the update to any endpoints it was synced to
	for _, ei := range p.updateableEndpoints() {
		if ei.syncedProfiles[pId] {
			ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileRemove{&update}}
			delete(ei.syncedProfiles, pId)
		}
	}
	delete(p.profileByID, pId)
}

func (p *Processor) handleActivePolicyUpdate(update proto.ActivePolicyUpdate) {
	pId := *update.Id
	log.WithFields(log.Fields{"PolicyID": pId.String()}).Debug("Processing ActivePolicyUpdate")
	policy := update.GetPolicy()
	p.policyByID[pId] = policy

	// Update any endpoints that reference this policy
	for _, ei := range p.updateableEndpoints() {
		// Closure of the action to take on each policy on the endpoint.
		action := func(other proto.PolicyID) bool {
			if other == pId {
				ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{&update}}
				ei.syncedPolicies[pId] = true
				return true
			}
			return false
		}
		ei.iteratePolicies(action)
	}
}

func (p *Processor) handleActivePolicyRemove(update proto.ActivePolicyRemove) {
	pId := *update.Id
	log.WithFields(log.Fields{"PolicyID": pId.String()}).Debug("Processing ActivePolicyRemove")

	// Push the update to any endpoints it was synced to
	for _, ei := range p.updateableEndpoints() {
		if ei.syncedPolicies[pId] {
			ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyRemove{&update}}
			delete(ei.syncedPolicies, pId)
		}
	}
	delete(p.policyByID, pId)
}

func (p *Processor) syncPolicies(ei *EndpointInfo) {
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

func (p *Processor) syncProfiles(ei *EndpointInfo) {
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
