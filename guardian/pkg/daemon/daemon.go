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

package daemon

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/server"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
)

// Run starts the daemon, which configures and starts the services needed for guardian to run.
func Run(cfg config.Config, proxyTargets []server.Target) {
	tunnelDialOpts := []tunnel.DialerOption{
		tunnel.WithDialerRetryInterval(cfg.TunnelDialRetryInterval),
		tunnel.WithDialerTimeout(cfg.TunnelDialTimeout),
		tunnel.WithDialerKeepAliveSettings(cfg.KeepAliveEnable, time.Duration(cfg.KeepAliveInterval)*time.Millisecond),
	}

	proxyURL, err := cfg.GetHTTPProxyURL()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to resolve proxy URL.")
	} else if proxyURL != nil {
		tunnelDialOpts = append(tunnelDialOpts, tunnel.WithDialerHTTPProxyURL(proxyURL))
	}

	srvOpts := []server.Option{
		server.WithProxyTargets(proxyTargets),
		server.WithConnectionRetryAttempts(cfg.ConnectionRetryAttempts),
		server.WithConnectionRetryInterval(cfg.ConnectionRetryInterval),
	}

	tlsConfig, cert, err := cfg.TLSConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create tls config")
	}

	logrus.Infof("Using server name %s", tlsConfig.ServerName)

	ctx := GetShutdownContext()

	dialer, err := tunnel.NewTLSSessionDialer(cfg.VoltronURL, tlsConfig, tunnelDialOpts...)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create session dialer.")
	}

	srv, err := server.New(ctx, cert, dialer, srvOpts...)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create server")
	}

	health, err := server.NewHealth()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create health server")
	}

	go func() {
		// Health checks start, meaning everything before has worked.
		if err = health.ListenAndServeHTTP(); err != nil {
			logrus.WithError(err).Fatal("Health exited with error")
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Allow requests to come down from the management cluster.
		if err := srv.ListenAndServeManagementCluster(); err != nil {
			logrus.WithError(err).Fatal("Serving the tunnel exited.")
		}
	}()

	// Allow requests from the cluster to be sent up to the management cluster.
	if cfg.Listen {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := srv.ListenAndServeCluster(); err != nil {
				logrus.WithError(err).Fatal("proxy tunnel exited with an error")
			}
		}()
	}

	if err := srv.WaitForShutdown(); err != nil {
		logrus.WithError(err).Fatal("proxy tunnel exited with an error")
	}
}

// GetShutdownContext creates a context that's done when either syscall.SIGINT or syscall.SIGTERM notified.
func GetShutdownContext() context.Context {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signalChan
		logrus.Debug("Shutdown signal received, shutting down.")
		cancel()
	}()

	return ctx
}
