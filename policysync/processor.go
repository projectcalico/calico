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
	"github.com/projectcalico/felix/proto"
)

type Processor struct {
	Updates       <-chan interface{}
	endpointsById map[proto.WorkloadEndpointID]*EndpointInfo
	policyById    map[proto.PolicyID]*proto.Policy
	profileById   map[proto.ProfileID]*proto.Profile
}

type EndpointInfo struct {
	// The channel to send updates for this workload to.
	output         chan<- proto.ToDataplane
	endpoint       *proto.WorkloadEndpoint
	syncedPolicies map[proto.PolicyID]bool
	syncedProfiles map[proto.ProfileID]bool
}

func NewProcessor() *Processor {
	return &Processor{
		Updates:       make(chan interface{}),
		endpointsById: make(map[proto.WorkloadEndpointID]*EndpointInfo),
	}
}

func (p *Processor) loop() {
	for {
		update := <-p.Updates
		p.handleDataplane(update)
	}
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
		ei = &EndpointInfo{endpoint: update.GetEndpoint()}
		p.endpointsById[*update.Id] = ei
	} else {
		ei.endpoint = update.GetEndpoint()
	}
	if ei.output != nil {
		// There is a channel waiting for updates on this endpoint
		// The calc graph sends us policies and profiles before endpoint updates, but the Processor doesn't know
		// which endpoints need them until now.  Send any unsynced profiles & policies referenced
		p.syncPolicies(ei)
		p.syncProfiles(ei)
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointUpdate{&update}}
	}
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
	for _, tier := range ei.endpoint.GetTiers() {
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
	for _, name := range ei.endpoint.GetProfileIds() {
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
