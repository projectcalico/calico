// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
	"io"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

var (
	labels = []string{"source"}

	receivedFlowCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "goldmane_collector_received_flows",
		Help: "Total number of flows received by Goldmane aggregator.",
	}, labels)

	flowProcessLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "goldmane_collector_flow_process_latency",
		Help: "Histogram measuring the time taken to ingest a flow.",
	}, labels)

	numClients = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "goldmane_collector_num_clients",
		Help: "Number of clients connected to the flow collector.",
	})
)

func init() {
	prometheus.MustRegister(receivedFlowCounter)
	prometheus.MustRegister(flowProcessLatency)
	prometheus.MustRegister(numClients)
}

type Sink interface {
	Receive(flow *types.Flow, node string)
}

type FlowCollectorService interface {
	RegisterWith(*grpc.Server)
}

// NewFlowCollector returns a new push collector, which handles incoming flow streams from nodes in the cluster.
func NewFlowCollector(sink Sink) *flowCollectorService {
	logrus.Info("Starting flow collector")
	return &flowCollectorService{sink: sink}
}

type flowCollectorService struct {
	proto.UnimplementedFlowCollectorServer

	// sink is where we will send flows upon receipt.
	sink Sink
}

func (p *flowCollectorService) RegisterWith(srv *grpc.Server) {
	// Register the collector with the gRPC server.
	proto.RegisterFlowCollectorServer(srv, p)
	logrus.Info("Registered FlowCollector Server")
}

// nodeScope returns a scope that survives a reconnect. The peer's ephemeral port changes
// on every reconnect, so including it would give each connection its own scope.
func nodeScope(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return addr.String()
}

func (p *flowCollectorService) Connect(srv proto.FlowCollector_ConnectServer) error {
	return p.handleClient(srv)
}

func (p *flowCollectorService) handleClient(srv proto.FlowCollector_ConnectServer) error {
	// Track the number of clients connected to the collector.
	numClients.Inc()
	defer numClients.Dec()

	who := "unknown"
	scope := "unknown"
	if pr, ok := peer.FromContext(srv.Context()); ok {
		who = pr.Addr.String()
		scope = nodeScope(pr.Addr)
	}
	logCtx := logrus.WithField("who", who)
	logCtx.Info("Connection from client")

	num := 0
	defer func() {
		logCtx.WithField("numFlows", num).Info("Connection from client completed.")
	}()

	for {
		logCtx.Debug("Waiting for flows from client")
		upd, err := srv.Recv()
		if err == io.EOF {
			logCtx.Info("Client closed connection")
			return nil
		}
		if err != nil {
			logCtx.WithError(err).Error("Failed to receive flow")
			return err
		}
		receivedFlowCounter.WithLabelValues(scope).Inc()
		start := time.Now()

		// Convert to minified types.Flow object. The sink deduplicates per node and bucket,
		// which is what covers a client replaying its cache after a connection reset.
		logCtx.Debug("Sending Flow to sink")
		p.sink.Receive(types.ProtoToFlow(upd.Flow), scope)
		num++

		// Tell the client we have received the flow.
		if err = srv.Send(&proto.FlowReceipt{}); err != nil {
			logCtx.WithError(err).Error("Failed to send receipt")
			return err
		}

		flowProcessLatency.WithLabelValues(scope).Observe(time.Since(start).Seconds())
	}
}
