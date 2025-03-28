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

// Package server provides utilities for creating http servers and registering APIs.
package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
)

// HTTPServer is the interface that most, if not all, our http servers need to implement. It allows for starting tls /
// non tls servers, and waiting for the server to shut down.
type HTTPServer interface {
	ListenAndServeTLS(context.Context) error
	ListenAndServe(context.Context) error
	WaitForShutdown() error
}

type httpServer struct {
	srv         *http.Server
	tlsConfig   *tls.Config
	addr        string
	shutdownCtx context.Context
	serverErrs  chan error
}

type Router interface {
	RegisterAPIs([]apiutil.Endpoint, ...apiutil.MiddlewareFunc) http.Handler
}

func NewHTTPServer(router Router, apis []apiutil.Endpoint, options ...Option) (HTTPServer, error) {
	srv := &httpServer{
		srv:        &http.Server{},
		serverErrs: make(chan error, 1),
	}

	for _, option := range options {
		if err := option(srv); err != nil {
			return nil, err
		}
	}

	srv.srv.Addr = srv.addr
	srv.srv.TLSConfig = srv.tlsConfig
	srv.srv.Handler = router.RegisterAPIs(apis)

	return srv, nil
}

func (s *httpServer) ListenAndServeTLS(ctx context.Context) error {
	s.shutdownCtx = ctx

	addr := s.srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		defer ln.Close()
		defer close(s.serverErrs)

		s.serverErrs <- s.srv.ServeTLS(ln, "", "")
	}()

	return nil
}

func (s *httpServer) ListenAndServe(ctx context.Context) error {
	addr := s.srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.shutdownCtx = ctx
	go func() {
		defer ln.Close()
		defer close(s.serverErrs)

		s.serverErrs <- s.srv.Serve(ln)
	}()

	return nil
}

func (s *httpServer) WaitForShutdown() error {
	var err error
	select {
	case <-s.shutdownCtx.Done():
		logrus.Info("Received shutdown signal, shutting server down.")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = s.srv.Shutdown(ctx)
	case err = <-s.serverErrs:
	}
	return err
}
