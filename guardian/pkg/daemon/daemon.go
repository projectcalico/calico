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
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/bimux"
	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/server"
)

// Run starts the daemon, which configures and starts the services needed for guardian to run.
func Run(ctx context.Context, cfg config.Config, proxyTargets []server.Target) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	dialOpts := []bimux.DialerOption{
		bimux.WithDialerRetryInterval(cfg.TunnelDialRetryInterval),
		bimux.WithDialerTimeout(cfg.TunnelDialTimeout),
		bimux.WithDialerRetryAttempts(cfg.TunnelDialRetryAttempts),
		bimux.WithDialerKeepAliveSettings(cfg.KeepAliveEnable, time.Duration(cfg.KeepAliveInterval)*time.Millisecond),
	}

	if cfg.ProxyURL != nil {
		dialOpts = append(dialOpts, bimux.WithDialerHTTPProxyURL(cfg.ProxyURL))
		if cfg.ProxyTLSConfig != nil {
			dialOpts = append(dialOpts, bimux.WithDialerHTTPProxyTLSConfig(cfg.ProxyTLSConfig))
		}
	}

	tlsConfig, cert, err := cfg.TLSConfigProvider().TLSConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create tls config")
	}

	logrus.Infof("Using server name %s", tlsConfig.ServerName)

	sessionDialer, err := bimux.NewSessionDialer(
		cfg.VoltronURL,
		tlsConfig,
		dialOpts...,
	)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create session dialer.")
	}

	sessionPool := bimux.NewSessionPool(sessionDialer)
	sessionPool.Start(ctx)

	inboundProxyServer, err := server.NewInboundProxyServer(
		sessionPool,
		server.WithProxyTargets(proxyTargets),
	)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create inbound proxy server.")
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		// If the inboundProxyServer exits, then we need to shut down the daemon. Cancelling the context ensures the
		// other services exit and that the daemon isn't stuck waiting for the other services to exit.
		defer cancel()

		// Allow requests to come down from the management cluster.
		if err := inboundProxyServer.ListenAndProxy(ctx, *cert); err != nil {
			logrus.WithError(err).Warn("Inbound proxy server exited.")
		}
	}()

	// Allow for proxying requests from the cluster to outside it.
	if cfg.Listen {
		outboundProxyServer, err := server.NewOutboundProxyServer(
			sessionPool,
			server.WithListenPort(cfg.ListenPort),
		)
		if err != nil {
			logrus.WithError(err).Warn("Failed to create outbound proxy server.")
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			// If the outboundProxyServer exits, then we need to shut down the daemon. Cancelling the context ensures the
			// other services exit and that the daemon isn't stuck waiting for the other services to exit.
			defer cancel()

			if err := outboundProxyServer.ListenAndProxy(ctx); err != nil {
				logrus.WithError(err).Warn("proxy tunnel exited with an error")
			}
		}()
	}

	health, err := server.NewHealth()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create health server")
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// If the outboundProxyServer exits, then we need to shut down the daemon. Cancelling the context ensures the
		// other services exit and that the daemon isn't stuck waiting for the other services to exit.
		defer cancel()

		// Health checks start, meaning everything before has worked.
		if err = health.Start(ctx); err != nil {
			logrus.WithError(err).Warn("Health exited with error")
		}
	}()

	wg.Wait()

	// Wait for the session pool to close before exiting.
	<-sessionPool.WaitForClose()

	logrus.Info("Daemon exiting.")
}
