// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

// Ciphers supported by TLS 1.2
var tls12Ciphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
}

// Ciphers supported by TLS 1.3
var tls13Ciphers = []uint16{
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_128_GCM_SHA256,
}

// NewTLSConfig returns a tls.Config with the recommended default settings for Calico components. Based on build flags,
// boringCrypto may be used and fips strict mode may be enforced, which can override the parameters defined in this func.
func NewTLSConfig() *tls.Config {
	log.WithField("BuiltWithBoringCrypto", BuiltWithBoringCrypto).Debug("creating a TLS config")
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: append(tls12Ciphers, tls13Ciphers...),
	}
}

// NewMutualTLSConfig generates a tls.Config configured to enable mTLS with clients using the provided cert, key, and CA file paths.
// If any of the files cannot be read, an error is returned.
func NewMutualTLSConfig(cert, key, ca string) (*tls.Config, error) {
	// Configure use of mTLS.
	tlsCfg := NewTLSConfig()
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

	// Load Server cert and key and add to the TLS config.
	c, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("failed to load x509 key pair: %s", err)
	}
	tlsCfg.Certificates = []tls.Certificate{c}

	// Load the CA cert and add it to the cert pool for verifying client certs.
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("failed to open CA file %s: %s", ca, err)
	}
	certPool.AppendCertsFromPEM(caCert)
	tlsCfg.ClientCAs = certPool

	return tlsCfg, nil
}
