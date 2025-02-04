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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
)

// Option is a common format for New() options
type Option func(*httpServer) error

func WithInternalServer(internalSrv *http.Server) Option {
	return func(srv *httpServer) error {
		srv.srv = internalSrv
		return nil
	}
}

// WithAddr changes the address where the server accepts
// connections when Listener is not provided.
func WithAddr(addr string) Option {
	return func(srv *httpServer) error {
		srv.addr = addr
		return nil
	}
}

// WithTLSFiles sets the cert and key to be used for the TLS
// connections for internal traffic (this includes in-cluster requests or
// ones coming from Voltron tunnel).
func WithTLSFiles(certFile, keyFile string) Option {
	return func(srv *httpServer) error {
		var err error

		certPEMBlock, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		keyPEMBlock, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}

		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return err
		}

		if srv.tlsConfig == nil {
			srv.tlsConfig = new(tls.Config)
		}

		srv.tlsConfig.Certificates = append(srv.tlsConfig.Certificates, cert)
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			return err
		}

		srv.tlsConfig.ClientCAs = rootCAs
		return err
	}
}
