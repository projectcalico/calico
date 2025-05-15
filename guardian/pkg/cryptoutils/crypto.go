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

// Package cryptoutils has a set of utility function to be used across components
package cryptoutils

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// GenerateFingerprint returns the sha256 hash for a x509 certificate printed as a hex number
func GenerateFingerprint(certificate *x509.Certificate) string {
	// NewManagedClusterStorage() call in managedCluster_storage.go generates the certificate fingerprint
	// using sha256. This checksum is saved as one of the annotations for this ManagedCluster resource.
	// When voltron accepts the tunnel connection from guardian in voltron server.go, this internal active
	// fingerprint is checked. If we want to upgrade to a better hash algorithm in the future, we need to
	// change both places and properly update the annotation for any existing ManagedCluster resources.
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(certificate.Raw))
	log.Debugf("Created fingerprint for cert with common name: %s and fingerprint: %s", certificate.Subject.CommonName, fingerprint)
	return fingerprint
}
