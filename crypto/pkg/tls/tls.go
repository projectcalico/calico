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
)

// NewTLSConfig returns a tls.Config with the recommended default settings for Calico.
// Read more recommendations here:
// https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4095
func NewTLSConfig(fipsMode bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
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
		// Our certificate for FIPS does not mention validation for v1.3.
		cfg.MaxVersion = tls.VersionTLS12
		cfg.Renegotiation = tls.RenegotiateNever
	}
	return cfg
}
