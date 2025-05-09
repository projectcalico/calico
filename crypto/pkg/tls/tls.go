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
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

type CipherInfo struct {
	ID      uint16
	Default bool
	Order   int
}

var supportedCiphers = map[string]CipherInfo{
	// TLS 1.3 (Strongest)
	"TLS_AES_256_GCM_SHA384":       {ID: tls.TLS_AES_256_GCM_SHA384, Default: true, Order: 1},
	"TLS_CHACHA20_POLY1305_SHA256": {ID: tls.TLS_CHACHA20_POLY1305_SHA256, Default: true, Order: 2},
	"TLS_AES_128_GCM_SHA256":       {ID: tls.TLS_AES_128_GCM_SHA256, Default: true, Order: 3},

	// TLS 1.2 (PFS with ECDHE)
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       {ID: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, Default: true, Order: 4},
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         {ID: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, Default: true, Order: 5},
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   {ID: tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, Default: true, Order: 6},
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": {ID: tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, Default: true, Order: 7},
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         {ID: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, Default: true, Order: 8},
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       {ID: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, Default: true, Order: 9},

	// TLS 1.2 (CBC mode, weaker than GCM)
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": {ID: tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, Default: true, Order: 10},
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":   {ID: tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, Default: true, Order: 11},
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":   {ID: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, Default: true, Order: 12},

	// TLS 1.2 (Non-PFS, Legacy/Weak)
	"TLS_RSA_WITH_AES_256_GCM_SHA384": {ID: tls.TLS_RSA_WITH_AES_256_GCM_SHA384, Default: false, Order: 13},
	"TLS_RSA_WITH_AES_128_GCM_SHA256": {ID: tls.TLS_RSA_WITH_AES_128_GCM_SHA256, Default: false, Order: 14},
}

// DefaultCiphers returns the ciphers supported by TLS 1.3 and the PFS ciphers supported by TLS 1.2, ordered by the the cipher strength.
func DefaultCiphers() []uint16 {
	type kv struct {
		Name  string
		Value CipherInfo
	}
	var ordered []kv
	for name, info := range supportedCiphers {
		if info.Default {
			ordered = append(ordered, kv{Name: name, Value: info})
		}
	}

	// Sort by Order
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Value.Order < ordered[j].Value.Order
	})

	// Collect sorted IDs
	result := make([]uint16, len(ordered))
	for i, entry := range ordered {
		result[i] = entry.Value.ID
	}
	return result
}

// ParseTLSCiphers takes a comma-separated string of cipher names and returns a slice of uint16 representing the ciphers.
// It returns an error if any of the cipher names are not supported.
func ParseTLSCiphers(ciphers string) ([]uint16, error) {
	var result []uint16
	cipherNames := strings.Split(ciphers, ",")
	for _, name := range cipherNames {
		name = strings.TrimSpace(name)
		cipherValue, ok := supportedCiphers[name]
		if !ok {
			return nil, fmt.Errorf("unsupported cipher: %s", name)
		}
		result = append(result, cipherValue.ID)
	}

	return result, nil
}

// NewTLSConfig returns a tls.Config with the recommended default settings for Calico components. Based on build flags,
// boringCrypto may be used and fips strict mode may be enforced, which can override the parameters defined in this func.
func NewTLSConfig() *tls.Config {
	log.WithField("BuiltWithBoringCrypto", BuiltWithBoringCrypto).Debug("creating a TLS config")
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: DefaultCiphers(),
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
