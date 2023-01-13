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
// Read more here:
// https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4095
func NewTLSConfig(_ bool) *tls.Config {
	log.WithField("BuiltWithBoringCrypto", BuiltWithBoringCrypto).Debug("creating a TLS config")
	// When we build with GOEXPERIMENT and tag boringcrypto, the tls settings in the config will automatically
	// be overwritten and set to strict mode, due to the fipsonly import in fipstls.go.
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
}
