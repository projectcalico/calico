// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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
package syncher

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/proto"
	"github.com/projectcalico/calico/app-policy/uds"

	envoyapi "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
)

const addr1Ip = "3.4.6.8"
const addr2Ip = "23.8.58.1"
const addr3Ip = "2.2.2.2"

var addr1 = &envoyapi.Address{
	Address: &envoyapi.Address_SocketAddress{SocketAddress: &envoyapi.SocketAddress{
		Address:  addr1Ip,
		Protocol: envoyapi.SocketAddress_TCP,
		PortSpecifier: &envoyapi.SocketAddress_PortValue{
			PortValue: 5429,
		},
	}},
}
var addr2 = &envoyapi.Address{
	Address: &envoyapi.Address_SocketAddress{SocketAddress: &envoyapi.SocketAddress{
		Address:  addr2Ip,
		Protocol: envoyapi.SocketAddress_TCP,
		PortSpecifier: &envoyapi.SocketAddress_PortValue{
			PortValue: 6632,
		},
	}},
}
var addr3 = &envoyapi.Address{
	Address: &envoyapi.Address_SocketAddress{SocketAddress: &envoyapi.SocketAddress{
		Address:  addr3Ip,
		Protocol: envoyapi.SocketAddress_TCP,
		PortSpecifier: &envoyapi.SocketAddress_PortValue{
			PortValue: 2222,
		},
	}},
}
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
	InboundRules: []*proto.Rule{
		{
			Action:      "allow",
			SrcIpSetIds: []string{"ipset1", "ipset6"},
		},
	},
}
var policy2 = &proto.Policy{
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
	store := policystore.NewPolicyStore()
	update := &proto.IPSetUpdate{
		Id:   id,
		Type: proto.IPSetUpdate_IP,
		Members: []string{
			addr1Ip,
			addr2Ip,
		},
	}
	processIPSetUpdate(store, update)
	ipset := store.IPSetByID[id]
	Expect(ipset).ToNot(BeNil())
	Expect(ipset.ContainsAddress(addr1)).To(BeTrue())
	Expect(ipset.ContainsAddress(addr2)).To(BeTrue())
}

// IPSetUpdate with existing ID
func TestIPSetUpdateExists(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := policystore.NewPolicyStore()
	ipset := policystore.NewIPSet(proto.IPSetUpdate_IP)
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
	processIPSetUpdate(store, update)
	ipset = store.IPSetByID[id]

	// The update should replace existing set, so we don't expect 2.2.2.2 (addr3) to still be
	Expect(ipset.ContainsAddress(addr1)).To(BeTrue())
	Expect(ipset.ContainsAddress(addr2)).To(BeTrue())
	Expect(ipset.ContainsAddress(addr3)).To(BeFalse())
}

// processUpdate handles IPSetUpdate without a crash.
func TestIPSetUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})
	update := &proto.ToDataplane{
		Payload: &proto.ToDataplane_IpsetUpdate{IpsetUpdate: &proto.IPSetUpdate{
			Id:   id,
			Type: proto.IPSetUpdate_IP,
			Members: []string{
				addr1Ip,
				addr2Ip,
			}}}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

// IPSetDeltaUpdate with existing ID.
func TestIPSetDeltaUpdateExists(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := policystore.NewPolicyStore()
	ipset := policystore.NewIPSet(proto.IPSetUpdate_IP)
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
	processIPSetDeltaUpdate(store, update)
	ipset = store.IPSetByID[id] // don't assume set pointer doesn't change

	Expect(ipset.ContainsAddress(addr1)).To(BeTrue())
	Expect(ipset.ContainsAddress(addr2)).To(BeTrue())
	Expect(ipset.ContainsAddress(addr3)).To(BeFalse())
}

// IPSetDeltaUpdate with an unknown ID results in a panic.
func TestIPSetDeltaUpdateNonExist(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := policystore.NewPolicyStore()

	update := &proto.IPSetDeltaUpdate{
		Id: id,
		AddedMembers: []string{
			addr2Ip,
		},
		RemovedMembers: []string{addr3Ip},
	}
	Expect(func() { processIPSetDeltaUpdate(store, update) }).To(Panic())
}

// processUpdate handles a valid IPSetDeltaUpdate without a panic
func TestIPSetDeltaUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := policystore.NewPolicyStore()
	ipset := policystore.NewIPSet(proto.IPSetUpdate_IP)
	store.IPSetByID[id] = ipset
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetDeltaUpdate{
		IpsetDeltaUpdate: &proto.IPSetDeltaUpdate{
			Id: id,
			AddedMembers: []string{
				addr2Ip,
			},
			RemovedMembers: []string{addr3Ip},
		},
	}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

// IPSetRemove with an existing ID.
func TestIPSetRemoveExist(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := policystore.NewPolicyStore()
	ipset := policystore.NewIPSet(proto.IPSetUpdate_IP)
	store.IPSetByID[id] = ipset

	update := &proto.IPSetRemove{Id: id}
	processIPSetRemove(store, update)
	Expect(store.IPSetByID[id]).To(BeNil())
}

// IPSetRemove with an unknown ID is handled
func TestIPSetRemoveNonExist(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := policystore.NewPolicyStore()

	update := &proto.IPSetRemove{Id: id}
	processIPSetRemove(store, update)
	Expect(store.IPSetByID[id]).To(BeNil())
}

// processUpdate with IPSetRemove
func TestIPSetRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)

	id := "test_id"
	store := policystore.NewPolicyStore()
	ipset := policystore.NewIPSet(proto.IPSetUpdate_IP)
	store.IPSetByID[id] = ipset
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetRemove{
		IpsetRemove: &proto.IPSetRemove{Id: id},
	}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

// ActiveProfileUpdate with a new id
func TestActiveProfileUpdateNonExist(t *testing.T) {
	RegisterTestingT(t)

	id := proto.ProfileID{Name: "test_id"}
	store := policystore.NewPolicyStore()

	update := &proto.ActiveProfileUpdate{
		Id:      &id,
		Profile: profile1,
	}
	processActiveProfileUpdate(store, update)
	Expect(store.ProfileByID[id]).To(BeIdenticalTo(profile1))
}

// ActiveProfileUpdate with an existing ID
func TestActiveProfileUpdateExist(t *testing.T) {
	RegisterTestingT(t)

	id := proto.ProfileID{Name: "test_id"}
	store := policystore.NewPolicyStore()
	store.ProfileByID[id] = profile2

	update := &proto.ActiveProfileUpdate{
		Id:      &id,
		Profile: profile1,
	}
	processActiveProfileUpdate(store, update)
	Expect(store.ProfileByID[id]).To(BeIdenticalTo(profile1))
}

// ActiveProfileUpdate without an ID results in panic
func TestActiveProfileUpdateNilId(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	update := &proto.ActiveProfileUpdate{
		Profile: profile1,
	}
	Expect(func() { processActiveProfileUpdate(store, update) }).To(Panic())
}

// processUpdate with ActiveProfileUpdate
func TestActiveProfileUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)

	id := proto.ProfileID{Name: "test_id"}
	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{
		ActiveProfileUpdate: &proto.ActiveProfileUpdate{
			Id:      &id,
			Profile: profile1,
		},
	}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

// ActiveProfileRemove with an unknown id is handled without panic.
func TestActiveProfileRemoveNonExist(t *testing.T) {
	RegisterTestingT(t)

	id := proto.ProfileID{Name: "test_id"}
	store := policystore.NewPolicyStore()

	update := &proto.ActiveProfileRemove{Id: &id}
	processActiveProfileRemove(store, update)
	Expect(store.ProfileByID[id]).To(BeNil())
}

// ActiveProfileRemove with existing id
func TestActiveProfileRemoveExist(t *testing.T) {
	RegisterTestingT(t)

	id := proto.ProfileID{Name: "test_id"}
	store := policystore.NewPolicyStore()
	store.ProfileByID[id] = profile1

	update := &proto.ActiveProfileRemove{Id: &id}
	processActiveProfileRemove(store, update)
	Expect(store.ProfileByID[id]).To(BeNil())
}

// ActiveProfileRemove without an ID results in panic.
func TestActiveProfileRemoveNilId(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	update := &proto.ActiveProfileRemove{}
	Expect(func() { processActiveProfileRemove(store, update) }).To(Panic())
}

// processUpdate handles ActiveProfileRemove
func TestActiveProfileRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)

	id := proto.ProfileID{Name: "test_id"}
	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileRemove{
		ActiveProfileRemove: &proto.ActiveProfileRemove{Id: &id},
	}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

// ActivePolicyUpdate for a new id
func TestActivePolicyUpdateNonExist(t *testing.T) {
	RegisterTestingT(t)

	id := proto.PolicyID{Tier: "test_tier", Name: "test_id"}
	store := policystore.NewPolicyStore()

	update := &proto.ActivePolicyUpdate{
		Id:     &id,
		Policy: policy1,
	}
	processActivePolicyUpdate(store, update)
	Expect(store.PolicyByID[id]).To(BeIdenticalTo(policy1))
}

// ActivePolicyUpdate for an existing id
func TestActivePolicyUpdateExist(t *testing.T) {
	RegisterTestingT(t)

	id := proto.PolicyID{Tier: "test_tier", Name: "test_id"}
	store := policystore.NewPolicyStore()
	store.PolicyByID[id] = policy2

	update := &proto.ActivePolicyUpdate{
		Id:     &id,
		Policy: policy1,
	}
	processActivePolicyUpdate(store, update)
	Expect(store.PolicyByID[id]).To(BeIdenticalTo(policy1))
}

// ActivePolicyUpdate without an id causes a panic
func TestActivePolicyUpdateNilId(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	update := &proto.ActivePolicyUpdate{
		Policy: policy1,
	}
	Expect(func() { processActivePolicyUpdate(store, update) }).To(Panic())
}

// processUpdate handles ActivePolicyDispatch
func TestActivePolicyUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)

	id := proto.PolicyID{Tier: "test_tier", Name: "test_id"}
	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
		ActivePolicyUpdate: &proto.ActivePolicyUpdate{
			Id:     &id,
			Policy: policy1,
		},
	}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

// ActivePolicyRemove with unknown id is handled
func TestActivePolicyRemoveNonExist(t *testing.T) {
	RegisterTestingT(t)

	id := proto.PolicyID{Tier: "test_tier", Name: "test_id"}
	store := policystore.NewPolicyStore()

	update := &proto.ActivePolicyRemove{Id: &id}
	processActivePolicyRemove(store, update)
	Expect(store.PolicyByID[id]).To(BeNil())
}

// ActivePolicyRemove with existing id
func TestActivePolicyRemoveExist(t *testing.T) {
	RegisterTestingT(t)

	id := proto.PolicyID{Tier: "test_tier", Name: "test_id"}
	store := policystore.NewPolicyStore()
	store.PolicyByID[id] = policy1

	update := &proto.ActivePolicyRemove{Id: &id}
	processActivePolicyRemove(store, update)
	Expect(store.PolicyByID[id]).To(BeNil())
}

// ActivePolicyRemove without an id causes a panic
func TestActivePolicyRemoveNilId(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	update := &proto.ActivePolicyRemove{}
	Expect(func() { processActivePolicyRemove(store, update) }).To(Panic())
}

// processUpdate handles ActivePolicyRemove
func TestActivePolicyRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)

	id := proto.PolicyID{Tier: "test_tier", Name: "test_id"}
	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyRemove{
		ActivePolicyRemove: &proto.ActivePolicyRemove{Id: &id},
	}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

// WorkloadEndpointUpdate sets the endpoint
func TestWorkloadEndpointUpdate(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	update := &proto.WorkloadEndpointUpdate{Endpoint: endpoint1}
	processWorkloadEndpointUpdate(store, update)
	Expect(store.Endpoint).To(BeIdenticalTo(endpoint1))
}

// processUpdate handles WorkloadEndpointUpdate
func TestWorkloadEndpointUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
		WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{Endpoint: endpoint1},
	}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

// WorkloadEndpointRemove removes the endpoint
func TestWorkloadEndpointRemove(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = endpoint1

	update := &proto.WorkloadEndpointRemove{}
	processWorkloadEndpointRemove(store, update)
	Expect(store.Endpoint).To(BeNil())
}

// processUpdate handles WorkloadEndpointRemove
func TestWorkloadEndpointRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = endpoint1
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointRemove{
		WorkloadEndpointRemove: &proto.WorkloadEndpointRemove{},
	}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
}

func TestServiceAccountUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountUpdate{ServiceAccountUpdate: serviceAccount1}}

	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
	Expect(store.ServiceAccountByID).To(Equal(map[proto.ServiceAccountID]*proto.ServiceAccountUpdate{
		*serviceAccount1.Id: serviceAccount1,
	}))
}

func TestServiceAccountUpdateNilId(t *testing.T) {
	RegisterTestingT(t)
	store := policystore.NewPolicyStore()

	Expect(func() { processServiceAccountUpdate(store, &proto.ServiceAccountUpdate{}) }).To(Panic())
}

func TestServiceAccountRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := policystore.NewPolicyStore()
	store.ServiceAccountByID[*serviceAccount1.Id] = serviceAccount1
	inSync := make(chan struct{})

	remove := &proto.ToDataplane{Payload: &proto.ToDataplane_ServiceAccountRemove{
		ServiceAccountRemove: &proto.ServiceAccountRemove{Id: serviceAccount1.Id}}}
	Expect(func() { processUpdate(store, inSync, remove) }).ToNot(Panic())
	Expect(store.ServiceAccountByID).To(Equal(map[proto.ServiceAccountID]*proto.ServiceAccountUpdate{}))
}

func TestServiceAccountRemoveNilId(t *testing.T) {
	RegisterTestingT(t)
	store := policystore.NewPolicyStore()

	Expect(func() { processServiceAccountRemove(store, &proto.ServiceAccountRemove{}) }).To(Panic())
}

func TestNamespaceUpdateDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})

	update := &proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceUpdate{NamespaceUpdate: namespace1}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
	Expect(store.NamespaceByID).To(Equal(map[proto.NamespaceID]*proto.NamespaceUpdate{
		*namespace1.Id: namespace1,
	}))
}

func TestNamespaceUpdateNilId(t *testing.T) {
	RegisterTestingT(t)
	store := policystore.NewPolicyStore()

	Expect(func() { processNamespaceUpdate(store, &proto.NamespaceUpdate{}) }).To(Panic())
}

func TestNamespaceRemoveDispatch(t *testing.T) {
	RegisterTestingT(t)
	store := policystore.NewPolicyStore()
	store.NamespaceByID[*namespace1.Id] = namespace1
	inSync := make(chan struct{})

	remove := &proto.ToDataplane{Payload: &proto.ToDataplane_NamespaceRemove{
		NamespaceRemove: &proto.NamespaceRemove{Id: namespace1.Id}}}
	Expect(func() { processUpdate(store, inSync, remove) }).ToNot(Panic())
	Expect(store.NamespaceByID).To(Equal(map[proto.NamespaceID]*proto.NamespaceUpdate{}))
}

func TestNamespaceRemoveNilId(t *testing.T) {
	RegisterTestingT(t)
	store := policystore.NewPolicyStore()

	Expect(func() { processNamespaceRemove(store, &proto.NamespaceRemove{}) }).To(Panic())
}

// processUpdate handles InSync
func TestInSyncDispatch(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_InSync{}}
	Expect(func() { processUpdate(store, inSync, update) }).ToNot(Panic())
	Expect(inSync).To(BeClosed())
}

// processUpdate for an unhandled Payload causes a panic
func TestProcessUpdateUnknown(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	inSync := make(chan struct{})
	update := &proto.ToDataplane{Payload: &proto.ToDataplane_ConfigUpdate{}}
	Expect(func() { processUpdate(store, inSync, update) }).To(Panic())
}

func TestSyncRestart(t *testing.T) {
	RegisterTestingT(t)

	sCtx, sCancel := context.WithCancel(context.Background())
	defer sCancel()

	server := newTestSyncServer(sCtx)

	uut := NewClient(server.GetTarget(), []SyncClientOption{
		WithDialOption(uds.GetDialOptions()),
	}...)
	stores := make(chan *policystore.PolicyStore)

	cCtx, cCancel := context.WithCancel(context.Background())
	defer cCancel()
	go uut.Sync(cCtx, stores)

	if uut.Readiness() {
		t.Error("Expected syncClient not to be ready before receiving inSync")
	}

	server.SendInSync()
	select {
	case <-time.After(1 * time.Second):
		t.Error("Failed to get sync'd PolicyStore")
	case <-stores:
		// pass
	}

	server.Restart()
	select {
	case <-stores:
		t.Error("New PolicyStore should wait for inSync")
	case <-time.After(100 * time.Millisecond):
		// pass
	}

	server.SendInSync()
	select {
	case <-time.After(1 * time.Second):
		t.Error("Failed to get sync'd PolicyStore")
	case <-stores:
		// pass
	}

	if !uut.Readiness() {
		t.Error("Expected syncClient to be ready after receiving inSync")
	}
}

func TestSyncCancelBeforeInSync(t *testing.T) {
	RegisterTestingT(t)

	sCtx, sCancel := context.WithCancel(context.Background())
	defer sCancel()

	server := newTestSyncServer(sCtx)

	uut := NewClient(server.GetTarget(), []SyncClientOption{
		WithDialOption(uds.GetDialOptions()),
	}...)
	stores := make(chan *policystore.PolicyStore)

	cCtx, cCancel := context.WithCancel(context.Background())
	syncDone := make(chan struct{})
	go func() {
		uut.Sync(cCtx, stores)
		close(syncDone)
	}()

	time.Sleep(10 * time.Millisecond)
	cCancel()
	Eventually(syncDone).Should(BeClosed())
}

func TestSyncCancelAfterInSync(t *testing.T) {
	RegisterTestingT(t)

	sCtx, sCancel := context.WithCancel(context.Background())
	defer sCancel()

	server := newTestSyncServer(sCtx)

	uut := NewClient(server.GetTarget(), []SyncClientOption{
		WithDialOption(uds.GetDialOptions()),
	}...)
	stores := make(chan *policystore.PolicyStore)

	cCtx, cCancel := context.WithCancel(context.Background())
	syncDone := make(chan struct{})
	go func() {
		uut.Sync(cCtx, stores)
		close(syncDone)
	}()

	server.SendInSync()
	select {
	case <-time.After(1 * time.Second):
		t.Error("Failed to get sync'd PolicyStore")
	case <-stores:
		// pass
	}
	cCancel()
	Eventually(syncDone).Should(BeClosed())
}

func TestSyncServerCancelBeforeInSync(t *testing.T) {
	RegisterTestingT(t)

	sCtx, sCancel := context.WithCancel(context.Background())

	server := newTestSyncServer(sCtx)

	uut := NewClient(server.GetTarget(), []SyncClientOption{
		WithDialOption(uds.GetDialOptions()),
	}...)
	stores := make(chan *policystore.PolicyStore)

	cCtx, cCancel := context.WithCancel(context.Background())
	syncDone := make(chan struct{})
	go func() {
		uut.Sync(cCtx, stores)
		close(syncDone)
	}()

	sCancel()
	time.Sleep(10 * time.Millisecond)
	cCancel()
	Eventually(syncDone).Should(BeClosed())
}

type testSyncServer struct {
	context    context.Context
	updates    chan proto.ToDataplane
	path       string
	gRPCServer *grpc.Server
	listener   net.Listener
	cLock      sync.Mutex
	cancelFns  []func()
}

func newTestSyncServer(ctx context.Context) *testSyncServer {
	socketDir := makeTmpListenerDir()
	socketPath := path.Join(socketDir, ListenerSocket)
	ss := &testSyncServer{context: ctx, updates: make(chan proto.ToDataplane), path: socketPath, gRPCServer: grpc.NewServer()}
	proto.RegisterPolicySyncServer(ss.gRPCServer, ss)
	ss.listen()
	return ss
}

func (s *testSyncServer) Sync(_ *proto.SyncRequest, stream proto.PolicySync_SyncServer) error {
	ctx, cancel := context.WithCancel(s.context)
	s.cLock.Lock()
	s.cancelFns = append(s.cancelFns, cancel)
	s.cLock.Unlock()
	var update proto.ToDataplane
	for {
		select {
		case <-ctx.Done():
			return nil
		case update = <-s.updates:
			err := stream.Send(&update)
			if err != nil {
				return err
			}
		}
	}
}

func (s *testSyncServer) SendInSync() {
	s.updates <- proto.ToDataplane{Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}}}
}

func (s *testSyncServer) Restart() {
	s.cLock.Lock()
	for _, c := range s.cancelFns {
		c()
	}
	s.cancelFns = make([]func(), 0)
	s.cLock.Unlock()

	err := os.Remove(s.path)
	Expect(err).ToNot(HaveOccurred())

	s.listen()
}

func (s *testSyncServer) GetTarget() string {
	return s.path
}

func (s *testSyncServer) listen() {
	var err error

	s.listener = openListener(s.path)
	go func() {
		err = s.gRPCServer.Serve(s.listener)
	}()
	Expect(err).ToNot(HaveOccurred())
}

const ListenerSocket = "policysync.sock"

func makeTmpListenerDir() string {
	dirPath, err := ioutil.TempDir("/tmp", "felixut")
	Expect(err).ToNot(HaveOccurred())
	return dirPath
}

func openListener(socketPath string) net.Listener {
	lis, err := net.Listen("unix", socketPath)
	Expect(err).ToNot(HaveOccurred())
	return lis
}
