package main

import (
	"context"
	"os"
	"time"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// Create a new health client, connected to localhost.
	server := "localhost:9999"
	cc, err := grpc.NewClient(server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.WithError(err).Error("Failed to dial server")
		os.Exit(1)
	}
	healthClient := proto.NewHealthClient(cc)

	// Call the Ready method on the server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := healthClient.Ready(ctx, &proto.ReadyRequest{})
	if err != nil {
		logrus.WithError(err).Error("Failed to check health")
		os.Exit(1)
	}
	if !resp.Ready {
		logrus.Error("Server is not ready")
		os.Exit(1)
	}
	logrus.Info("Server is ready")
	os.Exit(0)
}
