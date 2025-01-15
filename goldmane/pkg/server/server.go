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
	aggr *aggregator.LogAggregator
}

func (s *FlowServer) RegisterWith(srv *grpc.Server) {
	// Register the server with the gRPC server.
	proto.RegisterFlowAPIServer(srv, s)
	logrus.Info("Registered FlowAPI Server")
}

func (s *FlowServer) List(req *proto.FlowRequest, server proto.FlowAPI_ListServer) error {
	// Get flows.
	flows := s.aggr.GetFlows(req)

	// Send flows.
	for _, flow := range flows {
		if err := server.Send(&flow); err != nil {
			return err
		}
	}
	return nil
}
