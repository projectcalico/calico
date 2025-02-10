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
	"flag"
	"fmt"
	"os"
	"sync"

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

	cert := fmt.Sprintf("%s/managed-cluster.crt", cfg.CertPath)
	key := fmt.Sprintf("%s/managed-cluster.key", cfg.CertPath)
	log.Infof("Voltron Address: %s", cfg.VoltronURL)

	pemCert, err := os.ReadFile(cert)
	if err != nil {
		log.Fatalf("Failed to load cert: %s", err)
	}
	pemKey, err := os.ReadFile(key)
	if err != nil {
		log.Fatalf("Failed to load key: %s", err)
	}

	serverName, ca, err := cfg.Cert()
	if err != nil {
		log.Fatalf("Failed to load cert: %s", err)
	}

	health, err := server.NewHealth()
	if err != nil {
		log.Fatalf("Failed to create health server: %s.", err)
	}

	targets, err := server.ParseTargets(apply.Targets(cfg))
	if err != nil {
		log.Fatalf("Failed to parse default proxy targets: %s", err)
	}

	proxyURL, err := cfg.GetHTTPProxyURL()
	if err != nil {
		log.Fatalf("Failed to resolve proxy URL: %s", err)
	}

	srv, err := server.New(
		cfg.VoltronURL,
		serverName,
		server.WithKeepAliveSettings(cfg.KeepAliveEnable, cfg.KeepAliveInterval),
		server.WithProxyTargets(targets),
		server.WithTunnelCreds(pemCert, pemKey),
		server.WithTunnelRootCA(ca),
		server.WithTunnelDialRetryAttempts(cfg.TunnelDialRetryAttempts),
		server.WithTunnelDialRetryInterval(cfg.TunnelDialRetryInterval),
		server.WithTunnelDialTimeout(cfg.TunnelDialTimeout),
		server.WithConnectionRetryAttempts(cfg.ConnectionRetryAttempts),
		server.WithConnectionRetryInterval(cfg.ConnectionRetryInterval),
		server.WithHTTPProxyURL(proxyURL),
	)

	if err != nil {
		log.Fatalf("Failed to create server: %s", err)
	}

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
		if err := srv.ListenAndServeManagementCluster(); err != nil {
			log.WithError(err).Fatal("Serving the tunnel exited")
		}
	}()

	// Allow requests from the cluster to be sent up to the management cluster.
	if cfg.Listen {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := srv.ListenAndServeCluster(); err != nil {
				log.WithError(err).Fatal("proxy tunnel exited with an error")
			}
		}()
	}

	wg.Wait()
}
