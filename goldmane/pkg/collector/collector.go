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
