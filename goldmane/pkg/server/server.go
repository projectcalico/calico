// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package server

import (
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/proto"
)

func NewServer(aggr *aggregator.LogAggregator) *FlowServer {
	return &FlowServer{
		aggr: aggr,
	}
}

type FlowServer struct {
	proto.UnimplementedFlowAPIServer

	aggr *aggregator.LogAggregator
}

func (s *FlowServer) RegisterWith(srv *grpc.Server) {
	// Register the server with the gRPC server.
	proto.RegisterFlowAPIServer(srv, s)
	logrus.Info("Registered FlowAPI Server")
}

func (s *FlowServer) List(req *proto.FlowRequest, server proto.FlowAPI_ListServer) error {
	// Get flows.
	flows, err := s.aggr.GetFlows(req)
	if err != nil {
		return err
	}

	// Send flows.
	for _, flow := range flows {
		if err := server.Send(flow); err != nil {
			return err
		}
	}
	return nil
}

func (s *FlowServer) Stream(req *proto.FlowRequest, server proto.FlowAPI_StreamServer) error {
	// Get a new Stream from the aggregator.
	stream, err := s.aggr.Stream()
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		select {
		case flow := <-stream.Flows():
			if err := server.Send(flow); err != nil {
				return err
			}
		case <-server.Context().Done():
			return server.Context().Err()
		}
	}
}
