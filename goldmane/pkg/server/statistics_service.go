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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/proto"
)

func NewStatisticsServer(aggr *goldmane.Goldmane) *Statistics {
	return &Statistics{
		gm: aggr,
	}
}

type Statistics struct {
	proto.UnimplementedStatisticsServer

	gm *goldmane.Goldmane
}

func (s *Statistics) RegisterWith(srv *grpc.Server) {
	// Register the server with the gRPC server.
	proto.RegisterStatisticsServer(srv, s)
	logrus.Info("Registered flow statistics server")
}

func (s *Statistics) List(req *proto.StatisticsRequest, server proto.Statistics_ListServer) error {
	responses, err := s.gm.Statistics(req)
	if err != nil {
		logrus.WithError(err).Error("Failed to get statistics")
		return err
	}

	if len(responses) == 0 {
		// Send an explicit NotFound error. We also send an empty statistics object - this is to workaround a behavior we have seen
		// with some Go proxies where trailers are not properly proxied in the case of a "trailers-only" gRPC response with
		// no body.
		if err := server.Send(&proto.StatisticsResult{}); err != nil {
			logrus.WithError(err).Error("failed to send empty result")
		}
		return status.Error(codes.NotFound, "No statistics matching request")
	}

	for _, resp := range responses {
		if err := server.Send(resp); err != nil {
			logrus.WithError(err).Error("Failed to send statistics response")
			return err
		}
	}
	return nil
}
