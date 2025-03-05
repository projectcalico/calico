// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
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

package main

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/server"
	gorillaadpt "github.com/projectcalico/calico/lib/httpmachinery/pkg/server/adaptors/gorilla"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/whisker-backend/pkg/config"
	v1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func configureLogging(logLevel string) {
	// Install a hook that adds file/line number information.
	logutils.ConfigureFormatter("whisker-backend")
	logrus.SetOutput(os.Stdout)

	// Override with desired log level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.Error("Invalid logging level passed in. Will use default level set to WARN")
		// Setting default to WARN
		level = logrus.WarnLevel
	}

	logrus.SetLevel(level)
}

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to parse configuration.")
	}
	configureLogging(cfg.LogLevel)

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

	var kubeRestConfig *rest.Config
	if cfg.Kubeconfig == "" {
		// Creates the in-cluster restConfig.
		kubeRestConfig, err = rest.InClusterConfig()
		if err != nil {
			logrus.WithError(err).Fatal("Failed to build kubernetes rest config.")
		}
	} else {
		// Creates a restConfig from supplied kubeconfig.
		kubeRestConfig, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to build kubernetes rest config.")
		}
	}

	scheme := runtime.NewScheme()
	if err = v3.AddToScheme(scheme); err != nil {
		logrus.WithError(err).Fatal("Failed to configure controller runtime client.")
	}
	client, err := ctrlclient.New(kubeRestConfig, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		logrus.WithError(err).Fatal("Failed to configure controller runtime client.")
	}

	flowsAPI := v1.NewFlows(gmCli)
	usageTrackerAPI := v1.NewClusterInfoHandler(client)
	apis := append(flowsAPI.APIs(), usageTrackerAPI.APIs()...)

	srv, err := server.NewHTTPServer(
		gorillaadpt.NewRouter(),
		apis,
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
