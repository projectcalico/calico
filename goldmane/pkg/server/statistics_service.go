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

func NewStatisticsServiceServer(aggr *aggregator.LogAggregator) *StatisticsServiceServer {
	return &StatisticsServiceServer{
		aggr: aggr,
	}
}

type StatisticsServiceServer struct {
	proto.UnimplementedStatisticsServiceServer

	aggr *aggregator.LogAggregator
}

func (s *StatisticsServiceServer) RegisterWith(srv *grpc.Server) {
	// Register the server with the gRPC server.
	proto.RegisterStatisticsServiceServer(srv, s)
	logrus.Info("Registered flow statistics server")
}

func (s *StatisticsServiceServer) List(req *proto.StatisticsRequest, server proto.StatisticsService_ListServer) error {
	responses, err := s.aggr.Statistics(req)
	if err != nil {
		return err
	}
	for _, resp := range responses {
		if err := server.Send(resp); err != nil {
			return err
		}
	}
	return nil
}
