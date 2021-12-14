// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/felix/proto"
)

// MaxMembersPerMessage sets the limit on how many IP Set members to include in an outgoing gRPC message, which has a
// size limit of 4MB (4194304 bytes).  Worst case, an IP Set member would be an IPv6 address including a port and
// protocol.
// 2001:0db8:0000:0000:0000:ff00:0042:8329,tcp:65535 = 49 characters
// Protobuf strings have 2 extra bytes of key/length (for lengths < 128), which gives 51 bytes per member, worst case.
// 4194304 / 51 = 82241, which we round down to 82200, giving about 2kB for the rest of the message.
const MaxMembersPerMessage = 82200

type Processor struct {
	Updates            <-chan interface{}
	JoinUpdates        chan interface{}
	endpointsByID      map[proto.WorkloadEndpointID]*EndpointInfo
	policyByID         map[proto.PolicyID]*policyInfo
	profileByID        map[proto.ProfileID]*profileInfo
	serviceAccountByID map[proto.ServiceAccountID]*proto.ServiceAccountUpdate
	namespaceByID      map[proto.NamespaceID]*proto.NamespaceUpdate
	ipSetsByID         map[string]*ipSetInfo
	receivedInSync     bool
}

type EndpointInfo struct {
	// The channel to send updates for this workload to.
	output         chan<- proto.ToDataplane
	currentJoinUID uint64
	endpointUpd    *proto.WorkloadEndpointUpdate
	syncedPolicies map[proto.PolicyID]bool
	syncedProfiles map[proto.ProfileID]bool
	syncedIPSets   map[string]bool
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
		policyByID:         make(map[proto.PolicyID]*policyInfo),
		profileByID:        make(map[proto.ProfileID]*profileInfo),
		serviceAccountByID: make(map[proto.ServiceAccountID]*proto.ServiceAccountUpdate),
		namespaceByID:      make(map[proto.NamespaceID]*proto.NamespaceUpdate),
		ipSetsByID:         make(map[string]*ipSetInfo),
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
	ei.syncedIPSets = map[string]bool{}

	p.maybeSyncEndpoint(ei)

	// Any updates to service accounts will be synced, but the endpoint needs to know about any existing service
	// accounts that were updated before it joined.
	p.sendServiceAccounts(ei)
	p.sendNamespaces(ei)

	if p.receivedInSync {
		log.WithField("channel", ei.output).Debug("Already in sync with the datastore, sending in-sync message to client")
		ei.output <- proto.ToDataplane{
			Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}}}
	}
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
}

func (p *Processor) handleDataplane(update interface{}) {
	log.WithFields(log.Fields{"update": update, "type": reflect.TypeOf(update)}).Debug("Dataplane update")
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
	case *proto.IPSetUpdate:
		p.handleIPSetUpdate(update)
	case *proto.IPSetDeltaUpdate:
		p.handleIPSetDeltaUpdate(update)
	case *proto.IPSetRemove:
		p.handleIPSetRemove(update)
	default:
		log.WithFields(log.Fields{
			"type": reflect.TypeOf(update),
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
	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{
			Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}}}
	}
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

	// The calc graph sends us IP sets, policies and profiles before endpoint updates, but the Processor doesn't know
	// which endpoints need them until now.  Send any unsynced, IP sets, profiles & policies referenced
	doAdd, doDel := p.getIPSetsSync(ei)
	doAdd()
	p.syncAddedPolicies(ei)
	p.syncAddedProfiles(ei)
	ei.output <- proto.ToDataplane{
		Payload: &proto.ToDataplane_WorkloadEndpointUpdate{WorkloadEndpointUpdate: ei.endpointUpd}}
	p.syncRemovedPolicies(ei)
	p.syncRemovedProfiles(ei)
	doDel()
}

func (p *Processor) handleWorkloadEndpointRemove(update *proto.WorkloadEndpointRemove) {
	// we trust the Calc graph never to send us a remove for an endpoint it didn't tell us about
	ei := p.endpointsByID[*update.Id]
	if ei.output != nil {
		// Send update and close down.
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointRemove{WorkloadEndpointRemove: update}}
		close(ei.output)
	}
	delete(p.endpointsByID, *update.Id)
}

func (p *Processor) handleActiveProfileUpdate(update *proto.ActiveProfileUpdate) {
	pId := *update.Id
	profile := update.GetProfile()
	p.profileByID[pId] = newProfileInfo(profile)

	// Update any endpoints that reference this profile
	for _, ei := range p.updateableEndpoints() {
		action := func(other proto.ProfileID) bool {
			if other == pId {
				doAdd, doDel := p.getIPSetsSync(ei)
				doAdd()
				ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{ActiveProfileUpdate: update}}
				ei.syncedProfiles[pId] = true
				doDel()
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

	// We trust the Calc graph to remove all references to the Profile before sending the Remove, thus we will have
	// already sent the ActiveProfileRemove to any connected endpoints that are affected.
	delete(p.profileByID, pId)
}

func (p *Processor) handleActivePolicyUpdate(update *proto.ActivePolicyUpdate) {
	pId := *update.Id
	log.WithFields(log.Fields{"PolicyID": pId}).Debug("Processing ActivePolicyUpdate")
	policy := update.GetPolicy()
	p.policyByID[pId] = newPolicyInfo(policy)

	// Update any endpoints that reference this policy
	for _, ei := range p.updateableEndpoints() {
		// Closure of the action to take on each policy on the endpoint.
		action := func(other proto.PolicyID) bool {
			if other == pId {
				doAdd, doDel := p.getIPSetsSync(ei)
				doAdd()
				ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{ActivePolicyUpdate: update}}
				ei.syncedPolicies[pId] = true
				doDel()
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

	// We trust the Calc graph to remove all references to the Policy before sending the Remove, thus we will have
	// already sent the ActivePolicyRemove to any connected endpoints that are affected.
	delete(p.policyByID, pId)
}

func (p *Processor) handleServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	id := *update.Id
	log.WithField("ServiceAccountID", id).Debug("Processing ServiceAccountUpdate")

	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountUpdate{ServiceAccountUpdate: update}}
	}
	p.serviceAccountByID[id] = update
}

func (p *Processor) handleServiceAccountRemove(update *proto.ServiceAccountRemove) {
	id := *update.Id
	log.WithField("ServiceAccountID", id).Debug("Processing ServiceAccountRemove")

	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountRemove{ServiceAccountRemove: update}}
	}
	delete(p.serviceAccountByID, id)
}

func (p *Processor) handleNamespaceUpdate(update *proto.NamespaceUpdate) {
	id := *update.Id
	log.WithField("NamespaceID", id).Debug("Processing NamespaceUpdate")

	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceUpdate{NamespaceUpdate: update}}
	}
	p.namespaceByID[id] = update
}

func (p *Processor) handleNamespaceRemove(update *proto.NamespaceRemove) {
	id := *update.Id
	log.WithField("NamespaceID", id).Debug("Processing NamespaceRemove")

	for _, ei := range p.updateableEndpoints() {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceRemove{NamespaceRemove: update}}
	}
	delete(p.namespaceByID, id)
}

func (p *Processor) handleIPSetUpdate(update *proto.IPSetUpdate) {
	id := update.Id
	logCxt := log.WithField("ID", id)
	logCxt.Debug("Processing IPSetUpdate")
	s, ok := p.ipSetsByID[id]
	if !ok {
		logCxt.Info("Adding new IP Set")
		s = newIPSet(update)
		p.ipSetsByID[id] = s

		// Since the calc graph will always send IPSets before any policies/profiles
		// that reference them, we don't know which endpoints will need this IPSet yet,
		// so we can stop processing here.
		return
	}
	logCxt.Info("Updating existing IPSet")
	s.replaceMembers(update)

	// gRPC has limits on message size, so break up large update if necessary.
	updates := splitIPSetUpdate(update)
	for _, ei := range p.updateableEndpoints() {
		if p.referencesIPSet(ei, id) {
			ei.syncedIPSets[id] = true
			for _, u := range updates {
				ei.output <- u
			}
		}
	}
}

func (p *Processor) handleIPSetDeltaUpdate(update *proto.IPSetDeltaUpdate) {
	id := update.Id
	log.WithField("ID", id).Debug("Processing IPSetDeltaUpdate")

	// We trust the calc graph to never send us Delta updates for non-existent sets.
	s := p.ipSetsByID[id]
	s.deltaUpdate(update)

	// gRPC has limits on message size, so break up large update if necessary.
	updates := splitIPSetDeltaUpdate(update)
	for _, ei := range p.updateableEndpoints() {
		if p.referencesIPSet(ei, id) {
			for _, u := range updates {
				ei.output <- u
			}
		}
	}
}

func (p *Processor) handleIPSetRemove(update *proto.IPSetRemove) {
	id := update.Id
	log.WithField("ID", id).Debug("Processing IPSetRemove")
	delete(p.ipSetsByID, id)

	// No need to send the update to any endpoints, since that will happen
	// as soon as the endpoint no longer has a reference to the IPSet.
}

func (p *Processor) syncAddedPolicies(ei *EndpointInfo) {
	ei.iteratePolicies(func(pId proto.PolicyID) bool {
		if !ei.syncedPolicies[pId] {
			policy := p.policyByID[pId].p
			ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
				ActivePolicyUpdate: &proto.ActivePolicyUpdate{
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
			log.WithFields(log.Fields{
				"PolicyID": pId,
				"endpoint": ei.endpointUpd.GetId(),
			}).Panic("syncing removed policies before all policies are added")
		}

		// Still an active policy, remove it from the old set.
		delete(oldSyncedPolicies, pId)
		ei.syncedPolicies[pId] = true
		return false
	})

	// oldSyncedPolicies now contains only policies that are no longer needed by this endpoint.
	for polID := range oldSyncedPolicies {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyRemove{
			ActivePolicyRemove: &proto.ActivePolicyRemove{Id: &polID},
		}}
	}
}

func (p *Processor) syncAddedProfiles(ei *EndpointInfo) {
	ei.iterateProfiles(func(pId proto.ProfileID) bool {
		if !ei.syncedProfiles[pId] {
			profile := p.profileByID[pId].p
			ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{
				ActiveProfileUpdate: &proto.ActiveProfileUpdate{
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
			log.WithField("profileID", pId).Panic("syncing removed profiles before all profiles are added")
		}

		// Still an active profile, remove it from the old set.
		delete(oldSyncedProfiles, pId)
		ei.syncedProfiles[pId] = true
		return false
	})

	// oldSyncedProfiles now contains only policies that are no longer needed by this endpoint.
	for polID := range oldSyncedProfiles {
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileRemove{
			ActiveProfileRemove: &proto.ActiveProfileRemove{Id: &polID},
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
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountUpdate{ServiceAccountUpdate: update}}
	}
}

// sendNamespaces sends all known Namespaces to the endpoint
func (p *Processor) sendNamespaces(ei *EndpointInfo) {
	for _, update := range p.namespaceByID {
		log.WithFields(log.Fields{
			"namespace": update.Id,
			"endpoint":  ei.endpointUpd.GetEndpoint(),
		}).Debug("sending NamespaceUpdate")
		ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceUpdate{NamespaceUpdate: update}}
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

// referencesIPSet determines whether the endpoint's policies or profiles reference a given IPSet
func (p *Processor) referencesIPSet(ei *EndpointInfo, id string) bool {
	var found = false
	ei.iterateProfiles(func(pid proto.ProfileID) bool {
		pi := p.profileByID[pid]
		if pi.referencesIPSet(id) {
			found = true
			return true
		}
		return false
	})
	// bail out here if we found a ref
	if found {
		return true
	}
	// otherwise, check policies
	ei.iteratePolicies(func(pid proto.PolicyID) bool {
		pi := p.policyByID[pid]
		if pi.referencesIPSet(id) {
			found = true
			return true
		}
		return false
	})
	return found
}

// syncIPSets computes IPSets to be added and removed for an endpoint. Returns closures that do the
// add and remove since we often want to sequence these around other operations.
func (p *Processor) getIPSetsSync(ei *EndpointInfo) (func(), func()) {
	// Compute all the IPSets that should be synced.
	newS := map[string]bool{}
	ei.iterateProfiles(func(id proto.ProfileID) bool {
		pi := p.profileByID[id]
		for ipset := range pi.refs {
			newS[ipset] = true
		}
		return false
	})
	ei.iteratePolicies(func(id proto.PolicyID) bool {
		pi := p.policyByID[id]
		for ipset := range pi.refs {
			newS[ipset] = true
		}
		return false
	})

	oldS := ei.syncedIPSets
	var toAdd []string
	for ipset := range newS {
		if !oldS[ipset] {
			toAdd = append(toAdd, ipset)
		}
		delete(oldS, ipset)
	}
	// oldS now only contains items to be deleted
	ei.syncedIPSets = newS

	doAdd := func() {
		for _, ipset := range toAdd {
			p.sendIPSetUpdate(ei, ipset)
		}
	}

	doDel := func() {
		for ipset := range oldS {
			p.sendIPSetRemove(ei, ipset)
		}
	}
	return doAdd, doDel
}

func (p *Processor) sendIPSetUpdate(ei *EndpointInfo, id string) {
	si := p.ipSetsByID[id]
	updates := splitIPSetUpdate(si.getIPSetUpdate())
	for _, u := range updates {
		ei.output <- u
	}
}

func (p *Processor) sendIPSetRemove(ei *EndpointInfo, id string) {
	ei.output <- proto.ToDataplane{Payload: &proto.ToDataplane_IpsetRemove{IpsetRemove: &proto.IPSetRemove{Id: id}}}
}

// Perform the action on every policy on the Endpoint, breaking if the action returns true.
func (ei *EndpointInfo) iteratePolicies(action func(id proto.PolicyID) (stop bool)) {
	var pId proto.PolicyID
	seen := make(map[proto.PolicyID]bool)
	for _, tier := range ei.endpointUpd.GetEndpoint().GetTiers() {
		pId.Tier = tier.Name
		for _, name := range tier.GetIngressPolicies() {
			pId.Name = name
			// No need to check seen since we trust Calc graph to only list a policy once per tier.
			seen[pId] = true
			if action(pId) {
				return
			}
		}
		for _, name := range tier.GetEgressPolicies() {
			pId.Name = name
			if !seen[pId] {
				seen[pId] = true
				if action(pId) {
					return
				}
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

// splitIPSetUpdate splits updates that would not fit into a single gRPC message into several smaller ones.
func splitIPSetUpdate(update *proto.IPSetUpdate) []proto.ToDataplane {
	mPerMsg := splitMembers(update.GetMembers())
	numMsg := len(mPerMsg)
	out := make([]proto.ToDataplane, numMsg)

	// First message is always IPSetUpdate, and always is included.
	out[0].Payload = &proto.ToDataplane_IpsetUpdate{IpsetUpdate: &proto.IPSetUpdate{
		Id:      update.Id,
		Type:    update.Type,
		Members: mPerMsg[0],
	}}

	// If there are additional messages, they are IPSetDeltaUpdates
	for i := 1; i < numMsg; i++ {
		out[i].Payload = &proto.ToDataplane_IpsetDeltaUpdate{IpsetDeltaUpdate: &proto.IPSetDeltaUpdate{
			Id:           update.Id,
			AddedMembers: mPerMsg[i],
		}}
	}
	return out
}

// splitIPSetDeltaUpdate splits updates that would not fit into a single gRPC message into smaller ones.
func splitIPSetDeltaUpdate(update *proto.IPSetDeltaUpdate) []proto.ToDataplane {
	adds := splitMembers(update.GetAddedMembers())
	dels := splitMembers(update.GetRemovedMembers())

	var out []proto.ToDataplane
	for len(adds)+len(dels) > 0 {
		msg := proto.ToDataplane{Payload: &proto.ToDataplane_IpsetDeltaUpdate{
			IpsetDeltaUpdate: &proto.IPSetDeltaUpdate{Id: update.GetId()}}}
		out = append(out, msg)
		update := msg.GetIpsetDeltaUpdate()
		if len(adds) > 0 {
			update.AddedMembers = adds[0]
			adds = adds[1:]
		}

		// Put removes on the message if they fit, but work from end end of the list since that is where
		// partial slices will be.
		end := len(dels) - 1
		log.Debugf("end %d", end)
		if len(dels) > 0 && (len(update.AddedMembers)+len(dels[end])) <= MaxMembersPerMessage {
			update.RemovedMembers = dels[end]
			dels = dels[0:end]
		}
	}
	return out
}

func splitMembers(members []string) [][]string {
	// We handle this very simply with a conservative maximum number of members. We could spin through and add up the
	// actual member lengths, which could mean fewer messages, since few members will have the max length (IPv6 + port
	// + protocol).  However, that would make this code more complex and slow message generation down, which would
	// offset gains we might get with fewer messages.
	out := make([][]string, 0)
	first := 0
	remains := len(members)

	if remains == 0 {
		// Special case handling an empty slice as input because we always want to return at least one element in the
		// output (a slice containing and empty slice). This simplifies calling code that has to send a different
		// initial message.
		return [][]string{{}}
	}

	for remains > 0 {
		numThis := MaxMembersPerMessage
		if remains < numThis {
			numThis = remains
		}
		end := first + numThis
		sliceThis := members[first:end]
		out = append(out, sliceThis)
		first = end
		remains = remains - numThis
	}
	return out
}
