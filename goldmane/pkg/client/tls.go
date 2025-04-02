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
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
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
	logrus.WithFields(logrus.Fields{
		"cert": cert,
		"key":  key,
	}).Debug("Loading client cert and key")
	certificate, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("failed to load keypair: %s", err)
	}

	// Load CA cert.
	logrus.WithField("ca", caFile).Debug("Loading CA cert")
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config.
	cfg := calicotls.NewTLSConfig()
	cfg.Certificates = []tls.Certificate{certificate}
	cfg.RootCAs = caCertPool
	return cfg, nil
}
