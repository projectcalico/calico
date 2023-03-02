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

	log "github.com/sirupsen/logrus"
)

// NewTLSConfig returns a tls.Config with the recommended default settings for Calico Enterprise components.
// Read more recommendations here in Chapter 3:
// https://www.gsa.gov/cdnstatic/SSL_TLS_Implementation_%5BCIO_IT_Security_14-69_Rev_6%5D_04-06-2021docx.pdf
// When built with GOEXPERIMENT and tag boringcrypto, the TLS settings in the config will automatically
// be overwritten and set to strict mode, due to the fipsonly import in fipstls.go.
func NewTLSConfig(fipsMode bool) *tls.Config {
	log.WithField("BuiltWithBoringCrypto", BuiltWithBoringCrypto).
		WithField("fipsMode", fipsMode).
		Debug("creating a TLS config")

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	if fipsMode {
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		}
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP384, tls.CurveP256}
		// Our certificate for FIPS validation not mention validation for v1.3.
		cfg.MaxVersion = tls.VersionTLS12
		cfg.Renegotiation = tls.RenegotiateNever
	}
	return cfg
}
