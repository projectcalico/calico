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

package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/kelseyhightower/envconfig"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/goldmane/pkg/emitter"
	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/libcalico-go/lib/debugserver"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

type Config struct {
	// LogLevel is the log level to use.
	LogLevel string `json:"log_level" envconfig:"LOG_LEVEL" default:"info"`

	// PushURL is the URL to push logs to, if set. Logs will be pushed
	// periodically in a bulk format.
	PushURL string `json:"push_url" envconfig:"PUSH_URL"`

	// FileConfigPath is the path to the goldmane configuration file, used for a subset of goldmane
	// configuration that does not require a process restart.
	// If set, Goldmane will watch this file for changes and reload its configuration when it changes.
	FileConfigPath string `json:"file_config_path" envconfig:"FILE_CONFIG_PATH"`

	// Port is the port to listen on for gRPC connections.
	Port int `json:"port" envconfig:"PORT" default:"443"`

	// Configuration for health checking.
	HealthEnabled bool `json:"health_enabled" envconfig:"HEALTH_ENABLED" default:"true"`
	HealthPort    int  `json:"health_port" envconfig:"HEALTH_PORT" default:"8080"`

	// ClientKeyPath, ClientCertPath, and CACertPath are paths to the client key, client cert, and CA cert
	// used when publishing logs to an HTTPS endpoint.
	ClientCertPath string `json:"ca_client_cert_path" envconfig:"CLIENT_CERT_PATH"`
	ClientKeyPath  string `json:"client_key_path" envconfig:"CLIENT_KEY_PATH"`
	CACertPath     string `json:"ca_cert_path" envconfig:"CA_CERT_PATH"`
	ServerName     string `json:"server_name" envconfig:"SERVER_NAME" default:"tigera-linseed.tigera-elasticsearch.svc"`

	// ServerCertPath and ServerKeyPath are paths to the server cert and key used when serving gRPC.
	ServerCertPath string `json:"server_cert_path" envconfig:"SERVER_CERT_PATH"`
	ServerKeyPath  string `json:"server_key_path" envconfig:"SERVER_KEY_PATH"`

	// AggregationWindow is the size in seconds of each bucket used when aggregating flows received
	// from each node in the cluster.
	AggregationWindow time.Duration `json:"aggregation_window" envconfig:"AGGREGATION_WINDOW" default:"15s"`

	// EmitAfterSeconds is the number of seconds from flow receipt to wait before a flow becomes eligible to be
	// pushed to the emitter. Increasing this value will increase the latency of emitted flows, while a smaller
	// value will cause the emitter to emit potentially incomplete flows.
	//
	// This must be a multiple of the aggregation window.
	EmitAfterSeconds int `json:"emit_after_seconds" envconfig:"EMIT_AFTER_SECONDS" default:"30"`

	// EmitterAggregationWindow is the duration of time across which flows are aggregated before being pushed to the emitter.
	// This must be a multiple of the aggregation window.
	// Emitted flows will be aggregated from "now-EmitAfterSeconds-EmitterAggregationWindow" to "now-EmitAfterSeconds"
	EmitterAggregationWindow time.Duration `json:"emitter_aggregation_window" envconfig:"EMITTER_AGGREGATION_WINDOW" default:"5m"`

	// ProfilePort is the port to listen on for serving pprof profiles. By default, this is disabled.
	ProfilePort int `json:"profile_port" envconfig:"PROFILE_PORT" default:"0"`

	// PrometheusPort is the port to listen on for serving Prometheus metrics.
	PrometheusPort int `json:"prometheus_port" envconfig:"PROMETHEUS_PORT" default:"0"`
}

func ConfigFromEnv() Config {
	// Load configuration from environment variables.
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration from environment")
	}

	utils.ConfigureLogging(cfg.LogLevel)

	return cfg
}

func newGRPCServer(cfg *Config) (*grpc.Server, error) {
	opts := []grpc.ServerOption{}
	if cfg.ServerCertPath != "" && cfg.ServerKeyPath != "" {
		tlsCfg, err := calicotls.NewMutualTLSConfig(cfg.ServerCertPath, cfg.ServerKeyPath, cfg.CACertPath)
		if err != nil {
			return nil, err
		}
		creds := credentials.NewTLS(tlsCfg)
		opts = append(opts, grpc.Creds(creds))
	}
	return grpc.NewServer(opts...), nil
}

func Run(ctx context.Context, cfg Config) {
	logrus.WithField("cfg", cfg).Info("Loaded configuration")
	defer logrus.Warn("Shutting down")

	// Make an initial report that says we're live but not yet ready.
	healthAggregator := health.NewHealthAggregator()
	healthAggregator.ServeHTTP(cfg.HealthEnabled, "localhost", cfg.HealthPort)
	healthAggregator.RegisterReporter("startup", &health.HealthReport{Live: true, Ready: true}, 0)
	healthAggregator.Report("startup", &health.HealthReport{Live: true, Ready: false})

	// Create a Kubenetes client. If we fail to create the client, we will log a warning and continue,
	// but we will not be able to use the client to e.g., cache emitter progress.
	var kclient client.Client
	cliCfg, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		logrus.WithError(err).Warn("Failed to load Kubernetes client configuration")
	} else {
		kclient, err = client.New(cliCfg, client.Options{})
		if err != nil {
			logrus.WithError(err).Warn("Failed to create Kubernetes client")
		}
	}

	// Create the shared gRPC server with TLS enabled.
	grpcServer, err := newGRPCServer(&cfg)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create gRPC server")
	}

	// Track options for Goldmane.
	opts := []goldmane.Option{
		goldmane.WithRolloverTime(cfg.AggregationWindow),
		goldmane.WithBucketsToCombine(int(cfg.EmitterAggregationWindow.Seconds()) / int(cfg.AggregationWindow.Seconds())),
		goldmane.WithPushIndex(cfg.EmitAfterSeconds / int(cfg.AggregationWindow.Seconds())),
		goldmane.WithHealthAggregator(healthAggregator),
	}
	gm := goldmane.NewGoldmane(opts...)

	if cfg.PushURL != "" {
		// Create an emitter, which forwards flows to an upstream HTTP endpoint.
		logEmitter := emitter.NewEmitter(
			emitter.WithKubeClient(kclient),
			emitter.WithURL(cfg.PushURL),
			emitter.WithCACertPath(cfg.CACertPath),
			emitter.WithClientKeyPath(cfg.ClientKeyPath),
			emitter.WithClientCertPath(cfg.ClientCertPath),
			emitter.WithServerName(cfg.ServerName),
			emitter.WithHealthAggregator(healthAggregator),
		)
		go logEmitter.Run(ctx)

		if cfg.FileConfigPath != "" {
			// Start a goroutine to manage sink enablement. This will monitor a file on disk to determine if
			// the sink should be enabled or disabled, and update the aggregator configuration accordingly. This
			// allows the sink to be enabled or disabled without a process restart.
			mgr, err := newSinkManager(gm, logEmitter, cfg.FileConfigPath)
			if err != nil {
				logrus.WithError(err).Fatal("Failed to create sink manager")
			}
			go mgr.run(ctx)
		} else {
			// Just set the sink directly.
			gm.SetSink(logEmitter)
		}
	}

	// Create a flow collector to receive flows from clients, connected goldmane.
	collector := server.NewFlowCollector(gm)
	collector.RegisterWith(grpcServer)
	go collector.Run()

	// Start Goldmane, waiting for it to be ready to receive requests before continuing.
	<-gm.Run(storage.GetStartTime(int(cfg.AggregationWindow.Seconds())))

	// Start a flow server, serving from Goldmane.
	flowServer := server.NewFlowsServer(gm)
	flowServer.RegisterWith(grpcServer)

	// Start a statistics server, serving from Goldmane.
	statsServer := server.NewStatisticsServer(gm)
	statsServer.RegisterWith(grpcServer)

	// Start the gRPC server.
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	logrus.Info("Listening on ", cfg.Port)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
	defer grpcServer.GracefulStop()

	if cfg.ProfilePort != 0 {
		// Start a profile server.
		debugserver.StartDebugPprofServer("0.0.0.0", cfg.ProfilePort)
	}

	if cfg.PrometheusPort != 0 {
		// Serve prometheus metrics.
		logrus.Infof("Starting Prometheus metrics server on port %d", cfg.PrometheusPort)
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.PrometheusPort), mux)
			if err != nil {
				logrus.WithError(err).Fatal("Failed to serve prometheus metrics")
			}
		}()
	}

	healthAggregator.Report("startup", &health.HealthReport{Live: true, Ready: true})
	<-ctx.Done()
}
