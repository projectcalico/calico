// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policystore

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

const (
	addr1Ip = "3.4.6.8"
	addr2Ip = "23.8.58.1"
	addr3Ip = "2.2.2.2"
)

var profile1 = &proto.Profile{
	InboundRules: []*proto.Rule{
		{
			Action:      "allow",
			SrcIpSetIds: []string{"ipset1", "ipset6"},
		},
	},
}

var profile2 = &proto.Profile{
	OutboundRules: []*proto.Rule{
		{
			Action:      "allow",
			DstIpSetIds: []string{"ipset1", "ipset6"},
		},
	},
}

var policy1 = &proto.Policy{
	Tier: "test_tier",
	InboundRules: []*proto.Rule{
		{
			Action:      "allow",
			SrcIpSetIds: []string{"ipset1", "ipset6"},
		},
	},
}

var policy2 = &proto.Policy{
	Tier: "test_tier",
	OutboundRules: []*proto.Rule{
		{
			Action:      "allow",
			DstIpSetIds: []string{"ipset1", "ipset6"},
		},
	},
}

var endpoint1 = &proto.WorkloadEndpoint{
	Name:       "wep",
	ProfileIds: []string{"profile1", "profile2"},
}

var serviceAccount1 = &proto.ServiceAccountUpdate{
	Id:     &proto.ServiceAccountID{Name: "serviceAccount1", Namespace: "test"},
	Labels: map[string]string{"k1": "v1", "k2": "v2"},
}

var namespace1 = &proto.NamespaceUpdate{
	Id:     &proto.NamespaceID{Name: "namespace1"},
	Labels: map[string]string{"k1": "v1", "k2": "v2"},
}

// IPSetUpdate with a new ID
func TestIPSetUpdateNew(t *testing.T) {
	RegisterTestingT(t)
	id := "test_id"
	store := NewPolicyStore()
	update := &proto.IPSetUpdate{
		Id:   id,
		Type: proto.IPSetUpdate_IP,
		Members: []string{
			addr1Ip,
			addr2Ip,
		},
	}
	store.processIPSetUpdate(update)
	ipset := store.IPSetByID[id]
	Expect(ipset).ToNot(BeNil())
	Expect(ipset.Contains(addr1Ip)).To(BeTrue())
	Expect(ipset.Contains(addr2Ip)).To(BeTrue())
}

// IPSetUpdate with existing ID
func TestIPSetUpdateExists(t *testing.T) {
	RegisterTestingT(t)
	id := "test_id"
	store := NewPolicyStore()
	ipset := NewIPSet(proto.IPSetUpdate_IP)
	store.IPSetByID[id] = ipset
	ipset.AddString(addr1Ip)
	ipset.AddString(addr3Ip)
	update := &proto.IPSetUpdate{
		Id:   id,
		Type: proto.IPSetUpdate_IP,
		Members: []string{
			addr1Ip,
			addr2Ip,
		},
	}
	store.processIPSetUpdate(update)
	ipset = store.IPSetByID[id]

	// The update should replace existing set, so we don't expect 2.2.2.2 (addr3) to still be
	Expect(ipset.Contains(addr1Ip)).To(BeTrue())
	Expect(ipset.Contains(addr2Ip)).To(BeTrue())
	Expect(ipset.Contains(addr3Ip)).To(BeFalse())
}

// processUpdate handles IPSetUpdate without a crash.
func TestIPSetUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	id := "test_id"
	store := NewPolicyStore()
	update := &proto.ToDataplane{
		Payload: &proto.ToDataplane_IpsetUpdate{IpsetUpdate: &proto.IPSetUpdate{
			Id:   id,
			Type: proto.IPSetUpdate_IP,
			Members: []string{
				addr1Ip,
				addr2Ip,
			},
		}},
	}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

// IPSetDeltaUpdate with existing ID.
func TestIPSetDeltaUpdateExists(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := NewPolicyStore()
	ipset := NewIPSet(proto.IPSetUpdate_IP)
	store.IPSetByID[id] = ipset
	ipset.AddString(addr1Ip)
	ipset.AddString(addr3Ip)
	update := &proto.IPSetDeltaUpdate{
		Id: id,
		AddedMembers: []string{
			addr2Ip,
		},
		RemovedMembers: []string{addr3Ip},
	}
	store.processIPSetDeltaUpdate(update)
	ipset = store.IPSetByID[id] // don't assume set pointer doesn't change
	Expect(ipset.Contains(addr1Ip)).To(BeTrue())
	Expect(ipset.Contains(addr2Ip)).To(BeTrue())
	Expect(ipset.Contains(addr3Ip)).To(BeFalse())
}

// processUpdate handles a valid IPSetDeltaUpdate without a panic
func TestIPSetDeltaUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	id := "test_id"
	store := NewPolicyStore()
	ipset := NewIPSet(proto.IPSetUpdate_IP)
	store.IPSetByID[id] = ipset
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetDeltaUpdate{
		IpsetDeltaUpdate: &proto.IPSetDeltaUpdate{
			Id: id,
			AddedMembers: []string{
				addr2Ip,
			},
			RemovedMembers: []string{addr3Ip},
		},
	}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

// IPSetRemove with an existing ID.
func TestIPSetRemoveExist(t *testing.T) {
	RegisterTestingT(t)
	id := "test_id"
	store := NewPolicyStore()
	ipset := NewIPSet(proto.IPSetUpdate_IP)
	store.IPSetByID[id] = ipset
	update := &proto.IPSetRemove{Id: id}
	store.processIPSetRemove(update)
	Expect(store.IPSetByID[id]).To(BeNil())
}

// IPSetRemove with an unknown ID is handled
func TestIPSetRemoveNonExist(t *testing.T) {
	RegisterTestingT(t)
	id := "test_id"
	store := NewPolicyStore()
	update := &proto.IPSetRemove{Id: id}
	store.processIPSetRemove(update)
	Expect(store.IPSetByID[id]).To(BeNil())
}

// processUpdate with IPSetRemove
func TestIPSetRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)
	id := "test_id"
	store := NewPolicyStore()
	ipset := NewIPSet(proto.IPSetUpdate_IP)
	store.IPSetByID[id] = ipset
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetRemove{
		IpsetRemove: &proto.IPSetRemove{Id: id},
	}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

// ActiveProfileUpdate with a new id
func TestActiveProfileUpdateNonExist(t *testing.T) {
	RegisterTestingT(t)
	id := proto.ProfileID{Name: "test_id"}
	store := NewPolicyStore()
	update := &proto.ActiveProfileUpdate{
		Id:      &id,
		Profile: profile1,
	}
	store.processActiveProfileUpdate(update)
	tid := types.ProtoToProfileID(&id)
	Expect(store.ProfileByID[tid]).To(BeIdenticalTo(profile1))
}

// ActiveProfileUpdate with an existing ID
func TestActiveProfileUpdateExist(t *testing.T) {
	RegisterTestingT(t)
	id := types.ProfileID{Name: "test_id"}
	store := NewPolicyStore()
	store.ProfileByID[id] = profile2
	protoID := types.ProfileIDToProto(id)
	update := &proto.ActiveProfileUpdate{
		Id:      protoID,
		Profile: profile1,
	}
	store.processActiveProfileUpdate(update)
	Expect(store.ProfileByID[id]).To(BeIdenticalTo(profile1))
}

// processUpdate with ActiveProfileUpdate
func TestActiveProfileUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	id := proto.ProfileID{Name: "test_id"}
	store := NewPolicyStore()
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{
		ActiveProfileUpdate: &proto.ActiveProfileUpdate{
			Id:      &id,
			Profile: profile1,
		},
	}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

// ActiveProfileRemove with an unknown id is handled without panic.
func TestActiveProfileRemoveNonExist(t *testing.T) {
	RegisterTestingT(t)
	id := proto.ProfileID{Name: "test_id"}
	store := NewPolicyStore()
	update := &proto.ActiveProfileRemove{Id: &id}
	store.processActiveProfileRemove(update)
	tid := types.ProtoToProfileID(&id)
	Expect(store.ProfileByID[tid]).To(BeNil())
}

// ActiveProfileRemove with existing id
func TestActiveProfileRemoveExist(t *testing.T) {
	RegisterTestingT(t)
	id := types.ProfileID{Name: "test_id"}
	store := NewPolicyStore()
	store.ProfileByID[id] = profile1
	protoID := types.ProfileIDToProto(id)
	update := &proto.ActiveProfileRemove{Id: protoID}
	store.processActiveProfileRemove(update)
	Expect(store.ProfileByID[id]).To(BeNil())
}

// processUpdate handles ActiveProfileRemove
func TestActiveProfileRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)
	id := proto.ProfileID{Name: "test_id"}
	store := NewPolicyStore()
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileRemove{
		ActiveProfileRemove: &proto.ActiveProfileRemove{Id: &id},
	}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

// ActivePolicyUpdate for a new id
func TestActivePolicyUpdateNonExist(t *testing.T) {
	RegisterTestingT(t)
	id := proto.PolicyID{Name: "test_id"}
	store := NewPolicyStore()
	update := &proto.ActivePolicyUpdate{
		Id:     &id,
		Policy: policy1,
	}
	store.processActivePolicyUpdate(update)
	tid := types.ProtoToPolicyID(&id)
	Expect(store.PolicyByID[tid]).To(BeIdenticalTo(policy1))
}

// ActivePolicyUpdate for an existing id
func TestActivePolicyUpdateExist(t *testing.T) {
	RegisterTestingT(t)
	id := types.PolicyID{Name: "test_id"}
	store := NewPolicyStore()
	store.PolicyByID[id] = policy2
	protoID := types.PolicyIDToProto(id)
	update := &proto.ActivePolicyUpdate{
		Id:     protoID,
		Policy: policy1,
	}
	store.processActivePolicyUpdate(update)
	Expect(store.PolicyByID[id]).To(BeIdenticalTo(policy1))
}

// processUpdate handles ActivePolicyDispatch
func TestActivePolicyUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	id := proto.PolicyID{Name: "test_id"}
	store := NewPolicyStore()
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
		ActivePolicyUpdate: &proto.ActivePolicyUpdate{
			Id:     &id,
			Policy: policy1,
		},
	}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

// ActivePolicyRemove with unknown id is handled
func TestActivePolicyRemoveNonExist(t *testing.T) {
	RegisterTestingT(t)
	id := proto.PolicyID{Name: "test_id"}
	store := NewPolicyStore()
	update := &proto.ActivePolicyRemove{Id: &id}
	store.processActivePolicyRemove(update)
	tid := types.ProtoToPolicyID(&id)
	Expect(store.PolicyByID[tid]).To(BeNil())
}

// ActivePolicyRemove with existing id
func TestActivePolicyRemoveExist(t *testing.T) {
	RegisterTestingT(t)

	id := types.PolicyID{Name: "test_id"}
	store := NewPolicyStore()
	store.PolicyByID[id] = policy1

	protoID := types.PolicyIDToProto(id)
	update := &proto.ActivePolicyRemove{Id: protoID}
	store.processActivePolicyRemove(update)
	Expect(store.PolicyByID[id]).To(BeNil())
}

// processUpdate handles ActivePolicyRemove
func TestActivePolicyRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)
	id := proto.PolicyID{Name: "test_id"}
	store := NewPolicyStore()
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyRemove{
		ActivePolicyRemove: &proto.ActivePolicyRemove{Id: &id},
	}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

// WorkloadEndpointUpdate sets the endpoint
func TestWorkloadEndpointUpdate(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	update := &proto.WorkloadEndpointUpdate{Endpoint: endpoint1}
	store.processWorkloadEndpointUpdate("per-pod-policies", update)
	Expect(store.Endpoint).To(BeIdenticalTo(endpoint1))
}

// processUpdate handles WorkloadEndpointUpdate
func TestWorkloadEndpointUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
		WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{Endpoint: endpoint1},
	}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

// WorkloadEndpointRemove removes the endpoint
func TestWorkloadEndpointRemove(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	store.Endpoint = endpoint1
	update := &proto.WorkloadEndpointRemove{}
	store.processWorkloadEndpointRemove("per-pod-policies", update)
	Expect(store.Endpoint).To(BeNil())
}

// processUpdate handles WorkloadEndpointRemove
func TestWorkloadEndpointRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	store.Endpoint = endpoint1
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointRemove{
		WorkloadEndpointRemove: &proto.WorkloadEndpointRemove{},
	}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}

func TestServiceAccountUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountUpdate{ServiceAccountUpdate: serviceAccount1}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
	Expect(store.ServiceAccountByID).To(Equal(map[types.ServiceAccountID]*proto.ServiceAccountUpdate{
		types.ProtoToServiceAccountID(serviceAccount1.GetId()): serviceAccount1,
	}))
}

func TestServiceAccountRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	id := types.ProtoToServiceAccountID(serviceAccount1.GetId())
	store.ServiceAccountByID[id] = serviceAccount1
	remove := &proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountRemove{
		ServiceAccountRemove: &proto.ServiceAccountRemove{Id: serviceAccount1.Id},
	}}
	Expect(func() { store.ProcessUpdate("", remove, false) }).ToNot(Panic())
	Expect(store.ServiceAccountByID).To(Equal(map[types.ServiceAccountID]*proto.ServiceAccountUpdate{}))
}

func TestNamespaceUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceUpdate{NamespaceUpdate: namespace1}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
	Expect(store.NamespaceByID).To(Equal(map[types.NamespaceID]*proto.NamespaceUpdate{
		types.ProtoToNamespaceID(namespace1.GetId()): namespace1,
	}))
}

func TestNamespaceRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	id := types.ProtoToNamespaceID(namespace1.GetId())
	store.NamespaceByID[id] = namespace1
	remove := &proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceRemove{
		NamespaceRemove: &proto.NamespaceRemove{Id: namespace1.Id},
	}}
	Expect(func() { store.ProcessUpdate("", remove, false) }).ToNot(Panic())
	Expect(store.NamespaceByID).To(Equal(map[types.NamespaceID]*proto.NamespaceUpdate{}))
}

// processUpdate handles InSync
func TestInSyncDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := NewPolicyStore()
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_InSync{}}
	Expect(func() { store.ProcessUpdate("", update, false) }).ToNot(Panic())
}
