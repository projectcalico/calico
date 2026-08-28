// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

// tls package contains tls related helper functions related to generating and modifying certificates and private keys
// used for tls.

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
)

const DefaultCertificateDuration = 825 * 24 * time.Hour

func SetClientAuth(x *x509.Certificate) error {
	if x.ExtKeyUsage == nil {
		x.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	x.ExtKeyUsage = append(x.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	return nil
}
func SetServerAuth(x *x509.Certificate) error {
	if x.ExtKeyUsage == nil {
		x.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	x.ExtKeyUsage = append(x.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	return nil
}

// ParseTLSVersion parses a TLS version string and returns the corresponding tls version constant.
// Accepts: "1.2", "1.3", or empty string (defaults to "1.2").
func ParseTLSVersion(version string) (uint16, error) {
	switch version {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s (supported versions: 1.2, 1.3)", version)
	}
}

// ParseClientAuthType parses a client auth type string and returns the corresponding tls.ClientAuthType.
// Accepts: RequireAndVerifyClientCert (default), RequireAnyClientCert, VerifyClientCertIfGiven, NoClientCert.
func ParseClientAuthType(value string) (tls.ClientAuthType, error) {
	switch strings.ToLower(value) {
	case "", "requireandverifyclientcert":
		return tls.RequireAndVerifyClientCert, nil
	case "requireanyclientcert":
		return tls.RequireAnyClientCert, nil
	case "verifyclientcertifgiven":
		return tls.VerifyClientCertIfGiven, nil
	case "noclientcert":
		return tls.NoClientCert, nil
	default:
		return 0, fmt.Errorf("unsupported client auth type: %s (supported: RequireAndVerifyClientCert, RequireAnyClientCert, VerifyClientCertIfGiven, NoClientCert)", value)
	}
}

func MakeCA(signerName string) (*crypto.CA, error) {
	caConfig, err := crypto.MakeSelfSignedCAConfigForDuration(
		signerName,
		100*365*24*time.Hour, //100years*365days*24hours
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA: %s", err)
	}
	return &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          caConfig,
	}, nil
}
