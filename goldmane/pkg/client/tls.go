// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package client

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"google.golang.org/grpc/credentials"
)

// ClientCredentials returns the transport credentials for a Goldmane gRPC client, configured to
// authenticate with mTLS using the provided client certificate, key, and CA certificate.
func ClientCredentials(cert, key, ca string) (credentials.TransportCredentials, error) {
	tlsCfg, err := tlsConfig(cert, key, ca)
	if err != nil {
		return nil, err
	}
	creds := credentials.NewTLS(tlsCfg)
	return creds, nil
}

func tlsConfig(cert, key, caFile string) (*tls.Config, error) {
	// Load client cert.
	certificate, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	// Load CA cert.
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config.
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	}, nil
}
