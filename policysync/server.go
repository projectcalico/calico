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

	"github.com/projectcalico/felix/proto"

	mwi "github.com/colabsaumoh/proto-udsuspver/mgmtwlhintf"
	wlh "github.com/colabsaumoh/proto-udsuspver/workloadhandler"
	"google.golang.org/grpc"
)

const SockName = "/policysync.sock"
const OrchestratorId = "k8s"
const EndpointId = "eth0"

type Server struct {
	Joins chan<- JoinRequest
}

func NewServer(joins chan<- JoinRequest) *Server {
	return &Server{Joins: joins}
}

func NewWlServer(joins chan<- JoinRequest) *mwi.WlServer {
	s := NewServer(joins)
	return &mwi.WlServer{SockFile: SockName, RegAPI: s.RegisterGrpc}
}

func (s *Server) RegisterGrpc(g *grpc.Server) {
	proto.RegisterPolicySyncServer(g, s)
}

func (s *Server) Sync(_ *proto.SyncRequest, stream proto.PolicySync_SyncServer) error {
	cxt := stream.Context()
	creds, ok := wlh.CallerFromContext(cxt)
	if !ok {
		return errors.New("Unable to authenticate client.")
	}
	updates := make(chan proto.ToDataplane)
	s.Joins <- JoinRequest{
		EndpointID: proto.WorkloadEndpointID{
			OrchestratorId: OrchestratorId,
			EndpointId:     EndpointId,
			WorkloadId:     creds.Uid,
		},
		C: updates,
		//TODO: JoinCount?
	}
	for update := range updates {
		err := stream.Send(&update)
		if err != nil {
			// TODO: maybe don't just blindly send errors?
			return err
		}
	}
	return nil
}
