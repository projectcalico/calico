// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package whiskerbackend

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/server"
	gorillaadpt "github.com/projectcalico/calico/lib/httpmachinery/pkg/server/adaptors/gorilla"
	"github.com/projectcalico/calico/lib/logrusr"
	"github.com/projectcalico/calico/lib/std/log"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	"github.com/projectcalico/calico/whisker-backend/pkg/config"
	v1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
	goldmaneupstream "github.com/projectcalico/calico/whisker-backend/pkg/upstream/goldmane"
)

// Option customizes Run. Production wiring needs none; options exist for tests.
type Option func(*runOptions)

type runOptions struct {
	newBackend func(cfg *config.Config) (whiskerv1.FlowsBackend, []apiutil.Middleware, []v1.FlowsOption)
}

// WithFlowsBackend serves flows from the given backend instead of the one
// newFlowsBackend builds, bypassing that wiring entirely — including its
// endpoint middleware and flow handler options. For tests that exercise the
// HTTP surface against a bespoke upstream.
func WithFlowsBackend(backend whiskerv1.FlowsBackend) Option {
	return func(o *runOptions) {
		o.newBackend = func(*config.Config) (whiskerv1.FlowsBackend, []apiutil.Middleware, []v1.FlowsOption) {
			return backend, nil, nil
		}
	}
}

func Run(ctx context.Context, cfg *config.Config, options ...Option) {
	log.SetDefaultLogger(logrusr.New(logrus.StandardLogger()))

	// Config fields are file paths and host:port only — no inline credentials or key material.
	logrus.WithField("cfg", cfg.String()).Info("Applying configuration...")

	// newFlowsBackend is defined per repo (backend_oss.go / backend_enterprise.go):
	// each repo's file wires its flow upstream together with the endpoint
	// middleware and flow handler options that upstream requires.
	runOpts := runOptions{newBackend: newFlowsBackend}
	for _, o := range options {
		o(&runOpts)
	}
	backend, endpointMiddleware, flowsOpts := runOpts.newBackend(cfg)

	opts := []server.Option{
		server.WithAddr(cfg.HostAddr()),
	}

	if cfg.ServerTLSCertPath == "" || cfg.ServerTLSKeyPath == "" {
		logrus.Fatal("SERVER_TLS_CERT_PATH and SERVER_TLS_KEY_PATH must be set.")
	}
	opts = append(opts, server.WithTLSFiles(cfg.ServerTLSCertPath, cfg.ServerTLSKeyPath))

	flowsAPI := v1.NewFlows(backend, flowsOpts...)

	// Apply the endpoint middleware (auth + cluster-ID on the enterprise path) to
	// every endpoint. Wiring it per-endpoint here ensures nothing added later is
	// accidentally served unauthenticated.
	var endpoints []apiutil.Endpoint
	for _, ep := range flowsAPI.APIs() {
		ep.Middleware = append(ep.Middleware, endpointMiddleware...)
		endpoints = append(endpoints, ep)
	}

	srv, err := server.NewHTTPServer(
		gorillaadpt.NewRouter(),
		endpoints,
		opts...,
	)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create server.")
	}

	// TODO Should we require that this is TLS? It will be in the same pod as nginx.
	logrus.Infof("Listening on %s.", cfg.HostAddr())
	if err := srv.ListenAndServeTLS(ctx); err != nil {
		logrus.WithError(err).Fatal("Failed to start server.")
	}

	if err := srv.WaitForShutdown(); err != nil {
		logrus.WithError(err).Fatal("An unexpected error occurred while waiting for shutdown.")
	}
}

// newGoldmaneBackend builds the Goldmane flow backend: the only upstream in OSS
// builds and the fallback for enterprise ones.
func newGoldmaneBackend(cfg *config.Config) whiskerv1.FlowsBackend {
	logrus.Info("Using Goldmane upstream for flow data.")
	creds, err := client.ClientCredentials(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.CACertPath)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create goldmane TLS credentials.")
	}

	gmCli, err := client.NewFlowsAPIClient(cfg.GoldmaneHost, grpc.WithTransportCredentials(creds))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create goldmane client.")
	}
	return goldmaneupstream.NewBackend(gmCli)
}
