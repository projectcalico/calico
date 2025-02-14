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
	"flag"
	"fmt"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/cmd/guardian/apply"
	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/server"
	"github.com/projectcalico/calico/guardian/pkg/version"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "GUARDIAN"
)

var (
	versionFlag = flag.Bool("version", false, "Print version information")
)

func main() {
	flag.Parse()

	// For --version use case
	if *versionFlag {
		version.Version()
		os.Exit(0)
	}

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatal(err)
	}

	cfg.ConfigureLogging()

	log.Infof("Starting %s with %s", EnvConfigPrefix, cfg)

	targets, err := server.ParseTargets(apply.Targets(cfg))
	if err != nil {
		log.Fatalf("Failed to parse default proxy targets: %s", err)
	}

	tunnelDialOpts := []tunnel.DialerOption{
		tunnel.WithDialerTimeout(cfg.TunnelDialTimeout),
		tunnel.WithDialerRetryInterval(cfg.TunnelDialRetryInterval),
		tunnel.WithDialerTimeout(cfg.TunnelDialTimeout),
		tunnel.WithDialerKeepAliveSettings(cfg.KeepAliveEnable, time.Duration(cfg.KeepAliveInterval)*time.Millisecond),
	}

	proxyURL, err := cfg.GetHTTPProxyURL()
	if err != nil {
		log.Fatalf("Failed to resolve proxy URL: %s", err)
	} else if proxyURL != nil {
		tunnelDialOpts = append(tunnelDialOpts, tunnel.WithDialerHTTPProxyURL(proxyURL))
	}

	opts := []server.Option{
		server.WithProxyTargets(targets),
		server.WithConnectionRetryAttempts(cfg.ConnectionRetryAttempts),
		server.WithConnectionRetryInterval(cfg.ConnectionRetryInterval),
		server.WithTunnelDialerOptions(tunnelDialOpts...),
	}

	cert := fmt.Sprintf("%s/managed-cluster.crt", cfg.CertPath)
	key := fmt.Sprintf("%s/managed-cluster.key", cfg.CertPath)
	opt, err := server.WithTunnelCertificatesFromFile(cert, key)
	if err != nil {
		log.Fatalf("Failed to load tunnel cert: %s", err)
	} else if opt != nil {
		opts = append(opts, opt)
	}

	if strings.ToLower(cfg.VoltronCAType) != "public" {
		opt, err := server.WithTunnelRootCAFromFile(fmt.Sprintf("%s/management-cluster.crt", cfg.CertPath))
		if err != nil {
			log.Fatalf("Failed to load tunnel root CA: %s", err)
		} else if opt != nil {
			opts = append(opts, opt)
		}
	}

	srv, err := server.New(cfg.VoltronURL, opts...)
	if err != nil {
		log.Fatalf("Failed to create server: %s", err)
	}

	health, err := server.NewHealth()
	if err != nil {
		log.Fatalf("Failed to create health server: %s.", err)
	}

	ctx := GetShutdownContext()
	go func() {
		// Health checks start, meaning everything before has worked.
		if err = health.ListenAndServeHTTP(); err != nil {
			log.Fatalf("Health exited with error: %s", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Allow requests to come down from the management cluster.
		if err := srv.ListenAndServeManagementCluster(ctx); err != nil {
			log.WithError(err).Fatal("Serving the tunnel exited.")
		}
	}()

	// Allow requests from the cluster to be sent up to the management cluster.
	if cfg.Listen {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := srv.ListenAndServeCluster(ctx); err != nil {
				log.WithError(err).Fatal("proxy tunnel exited with an error")
			}
		}()
	}

	wg.Wait()
}

// GetShutdownContext creates a context that's done when either syscall.SIGINT or syscall.SIGTERM notified.
func GetShutdownContext() context.Context {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signalChan
		cancel()
	}()

	return ctx
}
