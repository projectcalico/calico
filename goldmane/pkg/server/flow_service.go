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
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/proto"
)

func NewFlowsServer(aggr *aggregator.LogAggregator) *FlowsServer {
	return &FlowsServer{
		aggr: aggr,
	}
}

type FlowsServer struct {
	proto.UnimplementedFlowsServer

	aggr *aggregator.LogAggregator
}

func (s *FlowsServer) RegisterWith(srv *grpc.Server) {
	// Register the server with the gRPC server.
	proto.RegisterFlowsServer(srv, s)
	logrus.Info("Registered FlowAPI Server")
}

func (s *FlowsServer) List(ctx context.Context, req *proto.FlowListRequest) (*proto.FlowListResult, error) {
	return s.aggr.List(req)
}

func (s *FlowsServer) Stream(req *proto.FlowStreamRequest, server proto.Flows_StreamServer) error {
	// Get a new Stream from the aggregator.
	stream, err := s.aggr.Stream(req)
	if err != nil {
		return err
	}
	defer stream.Close()

	// Share memory for each flow result.
	result := &proto.FlowResult{Flow: &proto.Flow{}}

	for {
		select {
		case flow := <-stream.Flows():
			if flow.BuildInto(req.Filter, result) {
				if err := server.Send(result); err != nil {
					return err
				}
			}
		case <-server.Context().Done():
			return server.Context().Err()
		}
	}
}

func (s *FlowsServer) FilterHints(ctx context.Context, req *proto.FilterHintsRequest) (*proto.FilterHintsResult, error) {
	return s.aggr.Hints(req)
}
