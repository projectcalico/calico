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

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/guardian/pkg/conn"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/lib/std/log"
)

// Server represents a server interface with methods for cluster and management cluster operations and graceful shutdown.
type Server interface {
	ListenAndServeCluster() error
	ListenAndServeManagementCluster() error
	WaitForShutdown() error
}

type server struct {
	http     *http.Server
	proxyMux *http.ServeMux
	targets  []Target

	tunnelCert *tls.Certificate

	tunnel tunnel.Tunnel

	connRetryAttempts int
	connRetryInterval time.Duration

	listenPort string
	listenHost string

	shutdownCtx context.Context
	// function to run if there is an internal issue that warrants a shutdown.
	shutdownFunc func()
}

func New(shutdownCtx context.Context, tunnelCert *tls.Certificate, dialer tunnel.SessionDialer, opts ...Option) (Server, error) {
	shutdownCtx, cancel := context.WithCancel(shutdownCtx)
	srv := &server{
		http:              new(http.Server),
		connRetryAttempts: 5,
		connRetryInterval: 2 * time.Second,
		listenPort:        "8080",
		tunnelCert:        tunnelCert,
		shutdownCtx:       shutdownCtx,
		shutdownFunc:      cancel,
	}

	for _, o := range opts {
		if err := o(srv); err != nil {
			return nil, fmt.Errorf("applying option failed: %w", err)
		}
	}

	for _, target := range srv.targets {
		log.Infof("Will route traffic to %s for requests matching %s", target.Dest, target.Path)
	}

	srv.proxyMux = http.NewServeMux()
	srv.http.Handler = srv.proxyMux

	handler, err := NewProxy(srv.targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy: %w", err)
	}
	srv.proxyMux.Handle("/", handler)

	srv.tunnel, err = tunnel.NewTunnel(dialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	return srv, nil
}

func (srv *server) ListenAndServeManagementCluster() error {
	defer srv.shutdownFunc()
	if err := srv.tunnel.Connect(srv.shutdownCtx); err != nil {
		return fmt.Errorf("failed to connect to tunnel: %w", err)
	}

	log.Debug("Getting listener for tunnel.")
	listener, err := srv.tunnel.Listener()
	if err != nil {
		return err
	}

	// we need to upgrade the tunnel to a TLS listener to support HTTP2 on this side.
	tlsConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to create TLS Config: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{*srv.tunnelCert}
	tlsConfig.NextProtos = []string{"h2"}

	listener = tls.NewListener(listener, tlsConfig)
	log.Infof("serving HTTP/2 enabled")

	log.Infof("Starting to serve tunneled HTTP.")

	return srv.http.Serve(listener)
}

func (srv *server) ListenAndServeCluster() error {
	defer srv.shutdownFunc()
	log.Infof("Listening on %s:%s for connections to proxy to voltron", srv.listenHost, srv.listenPort)
	if err := srv.tunnel.Connect(srv.shutdownCtx); err != nil {
		return fmt.Errorf("failed to connect to tunnel: %w", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", srv.listenHost, srv.listenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%s: %w", srv.listenHost, srv.listenPort, err)
	}

	defer wrapErrFunc(listener.Close, "Failed to close listener.")

	for {
		// TODO Consider throttling the number of connections this accepts.
		srcConn, err := listener.Accept()
		if err != nil {
			return err
		}

		log.Debugf("Accepted connection from %s", srcConn.RemoteAddr())

		dstConn, err := srv.tunnel.Open()
		if err != nil {
			if err := srcConn.Close(); err != nil {
				log.WithError(err).Error("failed to close source connection")
			}

			log.WithError(err).Error("failed to open connection to the tunnel")
			return err
		}

		go conn.Forward(srcConn, dstConn)
	}
}

func (srv *server) WaitForShutdown() error {
	<-srv.shutdownCtx.Done()
	log.Info("Received shutdown signal, shutting server down.")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Info("Waiting for tunnel to close...")
	_, err := chanutil.Read(ctx, srv.tunnel.WaitForClose())
	if !errors.Is(err, chanutil.ErrChannelClosed) {
		log.WithError(err).Warn("failed to wait for tunnel to close")
	}
	log.Info("Tunnel is closed.")

	err = srv.http.Shutdown(ctx)
	log.Info("Server shutdown complete.")
	return err
}

func wrapErrFunc(f func() error, errMessage string) {
	if err := f(); err != nil {
		log.WithError(err).Error(errMessage)
	}
}
