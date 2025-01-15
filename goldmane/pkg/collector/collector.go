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

package collector

import (
	"io"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/projectcalico/calico/goldmane/proto"
)

type Sink interface {
	Receive(*proto.FlowUpdate)
}

// NewFlowCollector returns a new push collector, which handles incoming flow streams from nodes in the cluster.
func NewFlowCollector(sink Sink) *collector {
	return &collector{
		sink: sink,
	}
}

type collector struct {
	sink      Sink
	connected bool
}

func (p *collector) RegisterWith(srv *grpc.Server) {
	// Register the collector with the gRPC server.
	proto.RegisterFlowCollectorServer(srv, p)
	logrus.Info("Registered FlowCollector Server")
}

func (p *collector) Connect(srv proto.FlowCollector_ConnectServer) error {
	return p.handleClient(srv)
}

func (p *collector) handleClient(srv proto.FlowCollector_ConnectServer) error {
	pr, _ := peer.FromContext(srv.Context())
	logCtx := logrus.WithField("who", pr.Addr.String())
	logCtx.Info("Connection from client")

	num := 0
	defer func() {
		logCtx.WithField("numFlows", num).Info("Connection from client completed.")
	}()

	for {
		flow, err := srv.Recv()
		if err == io.EOF {
			logCtx.Info("Client closed connection")
			return nil
		}
		if err != nil {
			logCtx.WithError(err).Error("Failed to receive flow")
			return err
		}

		// Send the flow to the output channel.
		num++
		p.sink.Receive(flow)
		srv.Send(&proto.FlowReceipt{})
	}
}
