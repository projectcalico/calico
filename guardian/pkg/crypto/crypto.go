// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

// Package utils has a set of utility function to be used across components
package utils

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// LoadX509Key reads private keys from file and returns the key as a crypto.Signer
func LoadX509Key(keyFile string) (crypto.Signer, error) {
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Could not read key %s", keyFile))
	}

	key, err := ssh.ParseRawPrivateKey(keyPEMBlock)
	if err != nil {
		return nil, errors.WithMessage(err, "Could not parse key")
	}

	return key.(crypto.Signer), nil
}

// LoadX509Cert reads a certificate from file and returns the cert (as a crypto.Signer)
func LoadX509Cert(certFile string) (*x509.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Could not read cert %s", certFile))
	}

	block, _ := pem.Decode(certPEMBlock)
	if block == nil {
		return nil, errors.WithMessage(err, "Could not decode cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Could not parse cert")
	}

	return cert, nil
}

// KeyPEMEncode encodes a crypto.Signer as a PEM block
func KeyPEMEncode(key crypto.Signer) ([]byte, error) {
	var block *pem.Block

	switch k := key.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	default:
		return nil, errors.New("unsupported key type")
	}

	return pem.EncodeToMemory(block), nil
}

// CertPEMEncode encodes a x509.Certificate as a PEM block
func CertPEMEncode(cert *x509.Certificate) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	return pem.EncodeToMemory(block)
}

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
