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

package syncher

import (
	"context"
	"fmt"

	"github.com/projectcalico/app-policy/policystore"
	"github.com/projectcalico/app-policy/proto"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type syncClient struct {
	target   string
	dialOpts []grpc.DialOption
}

type SyncClient interface {

	// Sync connects to the Policy Sync API server and processes updates from it.  It modifies the provided store with
	// the updates.  Sync blocks until the connection to the API server is terminated.
	Sync(ctx context.Context, store *policystore.PolicyStore)
}

// NewClient creates a new syncClient.
func NewClient(target string, opts []grpc.DialOption) SyncClient {
	return &syncClient{target: target, dialOpts: opts}
}

func (s *syncClient) Sync(cxt context.Context, store *policystore.PolicyStore) {
	// TODO: Handle connection errors more gracefully than Fatal.
	conn, err := grpc.Dial(s.target, s.dialOpts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := proto.NewPolicySyncClient(conn)
	stream, err := client.Sync(cxt, &proto.SyncRequest{})
	if err != nil {
		log.Fatalf("failed to Sync with server: %v", err)
	}
	for {
		update, err := stream.Recv()
		if err != nil {
			log.Fatalf("connection to Policy Sync server broken: %v", err)
		}
		log.WithFields(log.Fields{"proto": update.String()}).Debug("Received sync API Update")
		store.Write(func(ps *policystore.PolicyStore) { processUpdate(ps, update) })
	}
	// Note that as written, this function will never return. It only ends when the connection is torn down, which
	// terminates the entire program.
}

// Update the PolicyStore with the information passed over the Sync API.
func processUpdate(store *policystore.PolicyStore, update *proto.ToDataplane) {
	switch payload := update.Payload.(type) {
	case *proto.ToDataplane_InSync:
		processInSync(store, payload.InSync)
	case *proto.ToDataplane_IpsetUpdate:
		processIPSetUpdate(store, payload.IpsetUpdate)
	case *proto.ToDataplane_IpsetDeltaUpdate:
		processIPSetDeltaUpdate(store, payload.IpsetDeltaUpdate)
	case *proto.ToDataplane_IpsetRemove:
		processIPSetRemove(store, payload.IpsetRemove)
	case *proto.ToDataplane_ActiveProfileUpdate:
		processActiveProfileUpdate(store, payload.ActiveProfileUpdate)
	case *proto.ToDataplane_ActiveProfileRemove:
		processActiveProfileRemove(store, payload.ActiveProfileRemove)
	case *proto.ToDataplane_ActivePolicyUpdate:
		processActivePolicyUpdate(store, payload.ActivePolicyUpdate)
	case *proto.ToDataplane_ActivePolicyRemove:
		processActivePolicyRemove(store, payload.ActivePolicyRemove)
	case *proto.ToDataplane_WorkloadEndpointUpdate:
		processWorkloadEndpointUpdate(store, payload.WorkloadEndpointUpdate)
	case *proto.ToDataplane_WorkloadEndpointRemove:
		processWorkloadEndpointRemove(store, payload.WorkloadEndpointRemove)
	case *proto.ToDataplane_ServiceAccountUpdate:
		processServiceAccountUpdate(store, payload.ServiceAccountUpdate)
	case *proto.ToDataplane_ServiceAccountRemove:
		processServiceAccountRemove(store, payload.ServiceAccountRemove)
	case *proto.ToDataplane_NamespaceUpdate:
		processNamespaceUpdate(store, payload.NamespaceUpdate)
	case *proto.ToDataplane_NamespaceRemove:
		processNamespaceRemove(store, payload.NamespaceRemove)
	default:
		panic(fmt.Sprintf("unknown payload %v", update.String()))
	}
}

func processInSync(store *policystore.PolicyStore, inSync *proto.InSync) {
	// TODO (spikecurtis): disallow requests until policy is synced
	log.Debug("Processing InSync")
	return
}

func processIPSetUpdate(store *policystore.PolicyStore, update *proto.IPSetUpdate) {
	log.WithFields(log.Fields{
		"id": update.Id,
	}).Debug("Processing IPSetUpdate")

	// IPSetUpdate replaces the existing set.
	s := policystore.NewIPSet(update.Type)
	for _, addr := range update.Members {
		s.AddString(addr)
	}
	store.IPSetByID[update.Id] = s
}

func processIPSetDeltaUpdate(store *policystore.PolicyStore, update *proto.IPSetDeltaUpdate) {
	log.WithFields(log.Fields{
		"id": update.Id,
	}).Debug("Processing IPSetDeltaUpdate")
	s := store.IPSetByID[update.Id]
	if s == nil {
		log.Errorf("Unknown IPSet id: %v", update.Id)
		panic("unknown IPSet id")
	}
	for _, addr := range update.AddedMembers {
		s.AddString(addr)
	}
	for _, addr := range update.RemovedMembers {
		s.RemoveString(addr)
	}
}

func processIPSetRemove(store *policystore.PolicyStore, update *proto.IPSetRemove) {
	log.WithFields(log.Fields{
		"id": update.Id,
	}).Debug("Processing IPSetRemove")
	delete(store.IPSetByID, update.Id)
}

func processActiveProfileUpdate(store *policystore.PolicyStore, update *proto.ActiveProfileUpdate) {
	log.WithFields(log.Fields{
		"id": update.Id,
	}).Debug("Processing ActiveProfileUpdate")
	if update.Id == nil {
		log.Error("got ActiveProfileUpdate with nil ProfileID")
		panic("got ActiveProfileUpdate with nil ProfileID")
	}
	store.ProfileByID[*update.Id] = update.Profile
}

func processActiveProfileRemove(store *policystore.PolicyStore, update *proto.ActiveProfileRemove) {
	log.WithFields(log.Fields{
		"id": update.Id,
	}).Debug("Processing ActiveProfileRemove")
	if update.Id == nil {
		log.Error("got ActiveProfileRemove with nil ProfileID")
		panic("got ActiveProfileRemove with nil ProfileID")
	}
	delete(store.ProfileByID, *update.Id)
}

func processActivePolicyUpdate(store *policystore.PolicyStore, update *proto.ActivePolicyUpdate) {
	log.WithFields(log.Fields{
		"id": update.Id,
	}).Debug("Processing ActivePolicyUpdate")
	if update.Id == nil {
		log.Error("got ActivePolicyUpdate with nil PolicyID")
		panic("got ActivePolicyUpdate with nil PolicyID")
	}
	store.PolicyByID[*update.Id] = update.Policy
}

func processActivePolicyRemove(store *policystore.PolicyStore, update *proto.ActivePolicyRemove) {
	log.WithFields(log.Fields{
		"id": update.Id,
	}).Debug("Processing ActivePolicyRemove")
	if update.Id == nil {
		log.Error("got ActivePolicyRemove with nil PolicyID")
		panic("got ActivePolicyRemove with nil PolicyID")
	}
	delete(store.PolicyByID, *update.Id)
}

func processWorkloadEndpointUpdate(store *policystore.PolicyStore, update *proto.WorkloadEndpointUpdate) {
	// TODO: check the WorkloadEndpointID?
	log.WithFields(log.Fields{
		"orchestratorID": update.GetId().GetOrchestratorId(),
		"workloadID":     update.GetId().GetWorkloadId(),
		"endpointID":     update.GetId().GetEndpointId(),
	}).Info("Processing WorkloadEndpointUpdate")
	store.Endpoint = update.Endpoint
}

func processWorkloadEndpointRemove(store *policystore.PolicyStore, update *proto.WorkloadEndpointRemove) {
	// TODO: maybe this isn't required, because removing the endpoint means shutting down the pod?
	log.WithFields(log.Fields{
		"orchestratorID": update.GetId().GetOrchestratorId(),
		"workloadID":     update.GetId().GetWorkloadId(),
		"endpointID":     update.GetId().GetEndpointId(),
	}).Warning("Processing WorkloadEndpointRemove")
	store.Endpoint = nil
}

func processServiceAccountUpdate(store *policystore.PolicyStore, update *proto.ServiceAccountUpdate) {
	log.WithField("id", update.Id).Debug("Processing ServiceAccountUpdate")
	if update.Id == nil {
		log.Error("got ServiceAccountUpdate with nil ServiceAccountID")
		panic("got ServiceAccountUpdate with nil ServiceAccountID")
	}
	store.ServiceAccountByID[*update.Id] = update
}

func processServiceAccountRemove(store *policystore.PolicyStore, update *proto.ServiceAccountRemove) {
	log.WithField("id", update.Id).Debug("Processing ServiceAccountRemove")
	if update.Id == nil {
		log.Error("got ServiceAccountRemove with nil ServiceAccountID")
		panic("got ServiceAccountRemove with nil ServiceAccountID")
	}
	delete(store.ServiceAccountByID, *update.Id)
}

func processNamespaceUpdate(store *policystore.PolicyStore, update *proto.NamespaceUpdate) {
	log.WithField("id", update.Id).Debug("Processing NamespaceUpdate")
	if update.Id == nil {
		log.Error("got NamespaceUpdate with nil NamespaceID")
		panic("got NamespaceUpdate with nil NamespaceID")
	}
	store.NamespaceByID[*update.Id] = update
}

func processNamespaceRemove(store *policystore.PolicyStore, update *proto.NamespaceRemove) {
	log.WithField("id", update.Id).Debug("Processing NamespaceRemove")
	if update.Id == nil {
		log.Error("got NamespaceRemove with nil NamespaceID")
		panic("got NamespaceRemove with nil NamespaceID")
	}
	delete(store.NamespaceByID, *update.Id)
}
