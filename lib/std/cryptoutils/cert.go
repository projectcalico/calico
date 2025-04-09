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

package cryptoutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type CertificateOptions func(*x509.Certificate) error

func WithDNSNames(dnsNames ...string) CertificateOptions {
	return func(c *x509.Certificate) error {
		c.DNSNames = dnsNames
		return nil
	}
}

func WithExtKeyUsages(keyUsages ...x509.ExtKeyUsage) CertificateOptions {
	return func(c *x509.Certificate) error {
		c.ExtKeyUsage = keyUsages
		return nil
	}
}

func GenerateSelfSignedCert(opts ...CertificateOptions) ([]byte, []byte, error) {
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Certificate valid for 24 hours
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, opt := range opts {
		if err := opt(&template); err != nil {
			return nil, nil, fmt.Errorf("failed to apply certificate options: %w", err)
		}
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode the certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode the private key to PEM format
	keyDER := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// ExtractServerNameFromCertBytes decodes the cert bytes as a certificate and pulls out
func ExtractServerNameFromCertBytes(certBytes []byte) (string, error) {
	certDERBlock, _ := pem.Decode(certBytes)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		return "", errors.New("cannot decode pem block for server certificate")
	}

	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("cannot decode pem block for server certificate: %w", err)
	}
	if len(cert.DNSNames) != 1 {
		return "", fmt.Errorf("expected a single DNS name registered on the certificate: %w", err)
	}
	return cert.DNSNames[0], nil
}

func ParseCertificateBytes(certBytes []byte) (*x509.Certificate, error) {
	certDERBlock, _ := pem.Decode(certBytes)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		return nil, errors.New("cannot decode pem block for server certificate")
	}

	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot decode pem block for server certificate: %w", err)
	}

	return cert, nil
}
