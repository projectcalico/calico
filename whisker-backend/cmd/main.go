package main

import (
	"context"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/server"
	gorillaadpt "github.com/projectcalico/calico/lib/httpapimachinery/pkg/server/adaptors/gorilla"
	"github.com/projectcalico/calico/whisker-backend/pkg/config"
	"github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to parse configuration.")
	}
	logrus.WithField("cfg", cfg.String()).Info("Applying configuration...")

	// TODO not sure if we're going to require TLS communication since these will be part of the same pod, at least
	// TODO to start.
	gmCli, err := client.NewFlowsAPIClient(cfg.GoldmaneHost, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create goldmane client.")
	}

	opts := []server.Option{
		server.WithAddr(cfg.HostAddr()),
	}

	// TODO maybe we can push getting tls files to the common http utilities package?
	if cfg.TlsKeyPath != "" && cfg.TlsCertPath != "" {
		opts = append(opts, server.WithTLSFiles(cfg.TlsCertPath, cfg.TlsKeyPath))
	}

	flowsAPI := v1.NewFlows(gmCli)
	srv, err := server.NewHTTPServer(
		gorillaadpt.NewRouter(),
		flowsAPI.APIs(),
		opts...,
	)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create server.")
	}

	// TODO Should we require that this is TLS? It will be in the same pod as nginx.
	logrus.Infof("Listening on %s.", cfg.HostAddr())
	if err := srv.ListenAndServe(context.Background()); err != nil {
		logrus.WithError(err).Fatal("Failed to start server.")
	}

	if err := srv.WaitForShutdown(); err != nil {
		logrus.WithError(err).Fatal("An unexpected error occurred while waiting for shutdown.")
	}
}
