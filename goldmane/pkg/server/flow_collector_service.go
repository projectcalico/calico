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
	"io"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/pkg/internal/flowcache"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/log"
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
}

type Sink interface {
	Receive(*types.Flow)
}

type FlowCollectorService interface {
	RegisterWith(*grpc.Server)
}

// NewFlowCollector returns a new push collector, which handles incoming flow streams from nodes in the cluster.
func NewFlowCollector(sink Sink) *flowCollectorService {
	return &flowCollectorService{
		sink:         sink,
		deduplicator: flowcache.NewExpiringFlowCache(client.FlowCacheExpiry),
	}
}

type flowCollectorService struct {
	proto.UnimplementedFlowCollectorServer

	// sink is where we will send flows upon receipt.
	sink Sink

	// deduplicator is used to deduplicate flows received from clients upon connection resets.
	deduplicator *flowcache.ExpiringFlowCache
}

func (p *flowCollectorService) Run() {
	log.Info("Starting flow collector")
	p.deduplicator.Run(client.FlowCacheCleanup)
}

func (p *flowCollectorService) RegisterWith(srv *grpc.Server) {
	// Register the collector with the gRPC server.
	proto.RegisterFlowCollectorServer(srv, p)
	log.Info("Registered FlowCollector Server")
}

func (p *flowCollectorService) Connect(srv proto.FlowCollector_ConnectServer) error {
	return p.handleClient(srv)
}

func (p *flowCollectorService) handleClient(srv proto.FlowCollector_ConnectServer) error {
	// Track the number of clients connected to the collector.
	numClients.Inc()
	defer numClients.Dec()

	scope := "unknown"
	pr, ok := peer.FromContext(srv.Context())
	if ok {
		scope = pr.Addr.String()
	}
	logCtx := log.WithField("who", scope)
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

		// Convert to minified types.Flow object.
		flow := types.ProtoToFlow(upd.Flow)

		// Skip flows that we have already received from this node. This is a simple deduplication
		// mechanism to avoid processing the same flow if the connection is reset for some reason.
		// Should this happen, the client will resend all its flows and we must ensure we don't process
		// the same flow twice.
		if !p.deduplicator.Has(flow, scope) {

			// Add it to the deduplicator, scoped to the client's address (i.e., per-node).
			// The cache will automatically time out this flow in the background when it is no longer
			// relevant.
			p.deduplicator.Add(flow, scope)

			// Send the flow to the configured Sink.
			logCtx.Debug("Sending Flow to sink")
			p.sink.Receive(flow)
		} else {
			logCtx.Debug("Skipping already learned flow")
		}
		num++

		// Tell the client we have received the flow.
		if err = srv.Send(&proto.FlowReceipt{}); err != nil {
			logCtx.WithError(err).Error("Failed to send receipt")
			return err
		}

		flowProcessLatency.WithLabelValues(scope).Observe(time.Since(start).Seconds())
	}
}
