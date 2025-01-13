package client

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/goldmane/proto"
)

func NewFlowClient(server string) *FlowClient {
	cc, err := grpc.NewClient(server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to dial server")
	}
	return &FlowClient{
		grpcClient: cc,
		inChan:     make(chan *proto.Flow, 5000),
	}
}

// FlowClient pushes flow updates to the flow server.
type FlowClient struct {
	grpcClient *grpc.ClientConn
	inChan     chan *proto.Flow
}

func (c *FlowClient) Run(ctx context.Context) {
	logrus.Info("Starting flow client")
	defer func() {
		logrus.Info("Stopping flow client")
	}()

	// Create a new client to push flows to the server.
	cli := proto.NewFlowCollectorClient(c.grpcClient)

	for {
		// Check if the parent context has been canceled.
		if err := ctx.Err(); err != nil {
			logrus.WithError(err).Warn("Parent context canceled")
			return
		}

		// Connect to the flow server. This establishes a streaming connection over which
		// we can send flow updates.
		rc, err := cli.Connect(ctx)
		if err != nil {
			logrus.WithError(err).Warn("Failed to connect to flow server")
			time.Sleep(5 * time.Second)
			continue
		}
		logrus.Info("Connected to flow server")

		// Send new Flows as they are received.
		for flog := range c.inChan {
			if err := rc.Send(&proto.FlowUpdate{Flow: flog}); err != nil {
				logrus.WithError(err).Warn("Failed to send flow")
				break
			}

			// Receive a receipt.
			if _, err := rc.Recv(); err != nil {
				logrus.WithError(err).Warn("Failed to receive receipt")
				break
			}
		}

		if err := rc.CloseSend(); err != nil {
			logrus.WithError(err).Warn("Failed to close connection")
		}
		// TODO: Exponential backoff.
		time.Sleep(1 * time.Second)
	}
}

func (c *FlowClient) Push(f *proto.Flow) {
	// Make a copy of the flow to decouple the caller from the client.
	cp := f
	select {
	case c.inChan <- cp:
	default:
		logrus.Warn("Flow client buffer full, dropping flow")
	}
}
