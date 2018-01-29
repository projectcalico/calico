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
	"errors"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/proto"

	mwi "github.com/colabsaumoh/proto-udsuspver/mgmtwlhintf"
	nam "github.com/colabsaumoh/proto-udsuspver/nodeagentmgmt"
	wlh "github.com/colabsaumoh/proto-udsuspver/workloadhandler"
	"google.golang.org/grpc"
)

const (
	SockName       = "/policysync.sock"
	OrchestratorId = "k8s"
	EndpointId     = "eth0"
	PathPrefix     = "/tmp/"
)

// WorkloadAPIServer implements the API that each policy-sync agent connects to in order to get policy information.
// There is a single instance of the WorkloadAPIServer, it disambiguates connections from different clients by the
// credentials present in the gRPC request.
type WorkloadAPIServer struct {
	Joins       chan<- JoinRequest
	nextJoinUID func() uint64
}

func NewWorkloadAPIServer(joins chan<- JoinRequest, allocUID func() uint64) *WorkloadAPIServer {
	return &WorkloadAPIServer{
		Joins: joins,
	}
}

// NewMgmtAPIServer creates a new server to listen for workload lifecycle events (i.e. workloads being created and
// removed).  It opens and closes the per-workload socket accordingly, registering the workload API server with each
// new socket.
func NewMgmtAPIServer(joins chan<- JoinRequest, allocUID func() uint64) *nam.Server {
	// Initialize the workload API server.
	s := NewWorkloadAPIServer(joins, allocUID)
	// The WlServer sets up/tears down the sockets, deferring the API implementation to the WorkloadAPIServer.
	wls := &mwi.WlServer{
		SockFile: SockName,
		RegAPI:   s.RegisterGrpc,
	}
	// The workloadHandler handles the lifecycle events, invoking the WlServer's methods.
	workloadHandler := mwi.NewWlHandler(
		wls,
		wlh.NewServer,
	)
	// The management API server will listen on the socket for lifecycle messages.
	mgmtAPIServer := nam.NewServer(
		PathPrefix,
		workloadHandler,
	)
	return mgmtAPIServer
}

func (s *WorkloadAPIServer) RegisterGrpc(g *grpc.Server) {
	proto.RegisterPolicySyncServer(g, s)
}

func (s *WorkloadAPIServer) Sync(_ *proto.SyncRequest, stream proto.PolicySync_SyncServer) error {
	log.Info("New policy sync connection")

	// Extract the workload ID form the request.
	cxt := stream.Context()
	creds, ok := wlh.CallerFromContext(cxt)
	if !ok {
		return errors.New("Unable to authenticate client.")
	}
	workloadID := creds.Uid

	// Allocate a new unique join ID, this allows the processor to disambiguate if there are multiple connections
	// for the same workload, which can happen transiently over client restart.  In particular, if our "leave"
	// request races with the "join" request of the new connection.
	myJoinUID := s.nextJoinUID()
	logCxt := log.WithFields(log.Fields{
		"workload": workloadID,
		"joinID":   myJoinUID,
	})
	logCxt.Info("New policy sync connection identified")

	// Send a join request to the processor to ask it to start sending us updates.
	updates := make(chan proto.ToDataplane)
	epID := proto.WorkloadEndpointID{
		OrchestratorId: OrchestratorId,
		EndpointId:     EndpointId,
		WorkloadId:     workloadID,
	}
	s.Joins <- JoinRequest{
		EndpointID: epID,
		C:          updates,
		JoinUID:    myJoinUID,
	}

	// Defer the cleanup of the join and the updates channel.
	defer func() {
		logCxt.Info("Shutting down policy sync connection")
		joinsCopy := s.Joins
		leaveRequest := JoinRequest{
			EndpointID: epID,
			JoinUID:    myJoinUID,
		}
		// Since the processor closes the update channel, we need to keep draining the updates channel to avoid
		// blocking the processor.
		//
		// We also need to send the processor a leave request to ask it to stop sending updates.
		//
		// Make sure we don't block on either operation, or we could deadlock with the processor.
		for updates != nil && joinsCopy != nil {
			select {
			case _, ok := <-updates:
				if !ok {
					logCxt.Info("Updates channel was closed by processor.")
					updates = nil
				}
			case joinsCopy <- leaveRequest:
				logCxt.Info("Leave request sent to processor")
				joinsCopy = nil
			}
		}
	}()

	for update := range updates {
		err := stream.Send(&update)
		if err != nil {
			logCxt.WithError(err).Warn("Failed to send update to policy sync client")
			// TODO: maybe don't just blindly send errors?
			return err
		}
	}
	return nil
}

type UIDAllocator struct {
	l       sync.Mutex
	nextUID uint64
}

func NewUIDAllocator() *UIDAllocator {
	return &UIDAllocator{}
}

func (a *UIDAllocator) NextUID() uint64 {
	a.l.Lock()
	a.nextUID++ // Increment first so that we don't use the 0 value.
	uid := a.nextUID
	a.l.Unlock()
	return uid
}
