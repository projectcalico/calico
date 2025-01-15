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

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/pkg/collector"
	"github.com/projectcalico/calico/goldmane/pkg/emitter"
	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

// configureLogging configures the logging framework. The logging level that will
// be used is passed in as a parameter. Otherwise, it will default to WARN
// The output will be set to STDOUT and the format is TextFormat
func configureLogging(logLevel string) {
	// Install a hook that adds file/line number information.
	logutils.ConfigureFormatter("goldmane")
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

type Config struct {
	// LogLevel is the log level to use.
	LogLevel string `json:"log_level" envconfig:"LOG_LEVEL" default:"info"`

	// PushURL is the URL to push logs to, if set. Logs will be pushed
	// periodically in a bulk format.
	PushURL string `json:"push_url" envconfig:"PUSH_URL"`

	// Port is the port to listen on for gRPC connections.
	Port int `json:"port" envconfig:"PORT" default:"443"`

	// ClientKeyPath, ClientCertPath, and CACertPath are paths to the client key, client cert, and CA cert
	// used when publishing logs to an HTTPS endpoint.
	ClientCertPath string `json:"ca_client_cert_path" envconfig:"CLIENT_CERT_PATH"`
	ClientKeyPath  string `json:"client_key_path" envconfig:"CLIENT_KEY_PATH"`
	CACertPath     string `json:"ca_cert_path" envconfig:"CA_CERT_PATH"`
	ServerName     string `json:"server_name" envconfig:"SERVER_NAME" default:"tigera-linseed.tigera-elasticsearch.svc"`

	// AggregationWindow is the size in seconds of each bucket used when aggregating flows received
	// from each node in the cluster.
	AggregationWindow time.Duration `json:"rollover_time" envconfig:"ROLLOVER_TIME" default:"15s"`

	// The number of buckets to combine when pushing flows to the sink. This can be used to reduce the number
	// buckets combined into time-aggregated flows that are sent to the sink.
	NumBucketsToCombine int `json:"num_buckets_to_combine" envconfig:"NUM_BUCKETS_TO_COMBINE" default:"20"`

	// PushIndex is the index of the bucket which triggers pushing to the emitter. A larger value
	// will increase the latency of emitted flows, while a smaller value will cause the emitter to emit
	// potentially incomplete flows.
	PushIndex int `json:"push_index" envconfig:"PUSH_INDEX" default:"30"`

	// NoCache disables caching of emitted flow state, allowing the emitter
	// to run without need for a k8s API server.
	NoCache bool `json:"no_cache" envconfig:"NO_CACHE"`
}

func main() {
	// Load configuration from environment variables.
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration from environment")
	}

	configureLogging(cfg.LogLevel)
	logrus.WithField("cfg", cfg).Info("Loaded configuration")

	// Create a stop channel.
	stopCh := make(chan struct{})

	// Create a Kubenetes client.
	var kclient client.Client
	if !cfg.NoCache {
		cliCfg, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			panic(err.Error())
		}
		kclient, err = client.New(cliCfg, client.Options{})
		if err != nil {
			logrus.WithError(err).Fatal("Failed to create Kubernetes client")
		}
	}

	// Create the shared gRPC server.
	grpcServer := grpc.NewServer()

	// Track options for log aggregator.
	aggOpts := []aggregator.Option{
		aggregator.WithRolloverTime(cfg.AggregationWindow),
		aggregator.WithBucketsToCombine(cfg.NumBucketsToCombine),
		aggregator.WithPushIndex(cfg.PushIndex),
	}

	if cfg.PushURL != "" {
		// Create an emitter, which forwards flows to an upstream HTTP endpoint.
		logEmitter := emitter.NewEmitter(
			emitter.WithKubeClient(kclient),
			emitter.WithURL(cfg.PushURL),
			emitter.WithCACertPath(cfg.CACertPath),
			emitter.WithClientKeyPath(cfg.ClientKeyPath),
			emitter.WithClientCertPath(cfg.ClientCertPath),
			emitter.WithServerName(cfg.ServerName),
		)
		aggOpts = append(aggOpts, aggregator.WithSink(logEmitter))
		go logEmitter.Run(stopCh)
	}

	// Create an aggregator and collector, and connected the collector to the aggregator.
	agg := aggregator.NewLogAggregator(aggOpts...)
	collector := collector.NewFlowCollector(agg)
	collector.RegisterWith(grpcServer)

	// Start the aggregator.
	go agg.Run(aggregator.GetStartTime(int(cfg.AggregationWindow.Seconds())))

	// Start a flow server, serving from the aggregator.
	flowServer := server.NewServer(agg)
	flowServer.RegisterWith(grpcServer)

	// Start the gRPC server.
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	logrus.Info("Listening on ", cfg.Port)

	grpcServer.Serve(lis)
	<-stopCh
}
