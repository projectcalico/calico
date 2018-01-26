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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/proto"
)

type Processor struct {
	Updates       <-chan interface{}
	Joins         chan JoinRequest
	joinCount     uint64
	endpointsById map[proto.WorkloadEndpointID]*EndpointInfo
	policyById    map[proto.PolicyID]*proto.Policy
	profileById   map[proto.ProfileID]*proto.Profile
}

type EndpointInfo struct {
	// The channel to send updates for this workload to.
	output            chan<- proto.ToDataplane
	expectedJoinCount uint64
	endpointUpd       *proto.WorkloadEndpointUpdate
	syncedPolicies    map[proto.PolicyID]bool
	syncedProfiles    map[proto.ProfileID]bool
}

// JoinRequest is sent to the Processor when a new socket connection is accepted by the GRPC server,
// it provides the channel used to send sync messages back to the server goroutine.
type JoinRequest struct {
	EndpointID proto.WorkloadEndpointID
	// C is the channel to send updates to the policy sync client.  Processor closes the channel when the
	// workload endpoint is removed, or when a new JoinRequest is received for the same endpoint.  If nil, indicates
	// the client wants to stop receiving updates.
	C         chan<- proto.ToDataplane
	JoinCount uint64
}

func NewProcessor(updates <-chan interface{}) *Processor {
	return &Processor{
		// Updates from the calculation graph.
		Updates: updates,
		// Joins from the new servers that have started.
		Joins:         make(chan JoinRequest, 10),
		endpointsById: make(map[proto.WorkloadEndpointID]*EndpointInfo),
		policyById:    make(map[proto.PolicyID]*proto.Policy),
		profileById:   make(map[proto.ProfileID]*proto.Profile),
	}
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
	ei, ok := p.endpointsById[joinReq.EndpointID]
	if !ok {
		if joinReq.C == nil {
			logCxt.Info("Leave request for already-deleted endpoint, ignoring")
			return
		}
		logCxt.Info("Join for deleted endpoint, closing new channel immediately")
		close(joinReq.C)
		return
	}
	if ei.expectedJoinCount != joinReq.JoinCount {
		if joinReq.C != nil {
			logCxt.Info("Out of date join request, closing its channel immediately")
			close(joinReq.C)
			return
		}
		logCxt.Info("Out of date leave request, ignoring")
		return
	}
	if ei.output != nil {
		logCxt.Info("Join/Leave for endpoint that already has an active connection. Closing the old connection.")
		close(ei.output)
	}
	ei.output = joinReq.C
	if ei.output == nil {
		return // Nothing more to do after a leave.
	}
	logCxt.Info("Join: have new channel for (known) endpoint, syncing it")
	p.syncEndpoint(ei)
}

func (p *Processor) handleDataplane(update interface{}) {
	switch update := update.(type) {
	case proto.InSync:
		p.handleInSync(update)
	case proto.WorkloadEndpointUpdate:
		p.handleWorkloadEndpointUpdate(update)
	case proto.WorkloadEndpointRemove:
		p.handleWorkloadEndpointRemove(update)
	}
}

func (p *Processor) handleInSync(update proto.InSync) {
	panic("not implemented")
}

func (p *Processor) handleWorkloadEndpointUpdate(update proto.WorkloadEndpointUpdate) {
	ei, ok := p.endpointsById[*update.Id]
	if !ok {
		// Add this endpoint
		ei = &EndpointInfo{
			endpointUpd:       &update,
			expectedJoinCount: p.joinCount,
		}
		p.joinCount++
		p.endpointsById[*update.Id] = ei
		p.startListener(*update.Id, ei.expectedJoinCount)
	} else {
		ei.endpointUpd = &update
	}
	if ei.output != nil {
		// There is a channel waiting for updates on this endpoint, send them now.
		p.syncEndpoint(ei)
	}
}

func (p *Processor) startListener(epID proto.WorkloadEndpointID, joinCount uint64) {
	go func() {
		for {
			// TODO Accept a connection.

			// Then start a per-connection goroutine...
			go func() {
				updates := make(chan proto.ToDataplane)
				p.Joins <- JoinRequest{
					EndpointID: epID,
					C:          updates,
					JoinCount:  joinCount,
				}
				for update := range updates {
					// TODO send update to client
					_ := update

					// TODO Then on connection failure....
					joins := p.Joins
					leave := JoinRequest{EndpointID: epID, JoinCount: joinCount}
					select {
					case joins <- leave:
						log.Info("Sent leave request, draining the updates until channel is closed...")
						joins = nil
					case <-updates:
					}
				}
			}()
		}
	}()
}

func (p *Processor) syncEndpoint(ei *EndpointInfo) {
	// The calc graph sends us policies and profiles before endpoint updates, but the Processor doesn't know
	// which endpoints need them until now.  Send any unsynced profiles & policies referenced
	p.syncPolicies(ei)
	p.syncProfiles(ei)
	ei.output <- proto.ToDataplane{
		Payload: &proto.ToDataplane_WorkloadEndpointUpdate{ei.endpointUpd}}
}

func (p *Processor) handleWorkloadEndpointRemove(update proto.WorkloadEndpointRemove) {
	// we trust the Calc graph never to send us a remove for an endpoint it didn't tell us about
	ei := p.endpointsById[*update.Id]
	if ei.output != nil {
		// Send update and close down.
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointRemove{&update}}
		close(ei.output)
	}
	delete(p.endpointsById, *update.Id)
}

func (p *Processor) syncPolicies(ei *EndpointInfo) {
	for _, tier := range ei.endpointUpd.Endpoint.GetTiers() {
		for _, name := range tier.GetIngressPolicies() {
			pId := proto.PolicyID{Tier: tier.GetName(), Name: name}
			p.syncPolicy(ei, pId)
		}
		for _, name := range tier.GetEgressPolicies() {
			pId := proto.PolicyID{Tier: tier.GetName(), Name: name}
			p.syncPolicy(ei, pId)
		}
	}
}

func (p *Processor) syncPolicy(ei *EndpointInfo, pId proto.PolicyID) {
	if !ei.syncedPolicies[pId] {
		policy := p.policyById[pId]
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
			&proto.ActivePolicyUpdate{
				Id:     &pId,
				Policy: policy,
			},
		}}
		ei.syncedPolicies[pId] = true
	}
}

func (p *Processor) syncProfiles(ei *EndpointInfo) {
	for _, name := range ei.endpointUpd.Endpoint.GetProfileIds() {
		pId := proto.ProfileID{Name: name}
		p.syncProfile(ei, pId)
	}
}

func (p *Processor) syncProfile(ei *EndpointInfo, pId proto.ProfileID) {
	if !ei.syncedProfiles[pId] {
		profile := p.profileById[pId]
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{
			&proto.ActiveProfileUpdate{
				Id:      &pId,
				Profile: profile,
			},
		}}
		ei.syncedProfiles[pId] = true
	}
}
