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
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/projectcalico/calico/lib/std/clock"
	"time"
)

type CertificateChainWithPrivateKey struct {
	certs []*x509.Certificate
	key   crypto.PrivateKey
}

type certificateTemplate struct {
	*x509.Certificate
	ca *certificateAuthority
}

func CreateSelfSignedCertificate(name string, opts ...CertificateOption) (*x509.Certificate, crypto.PrivateKey, error) {
	publicKey, privateKey, publicKeyHash, err := newKeyPairWithHash()
	if err != nil {
		return nil, nil, err
	}

	subject := pkix.Name{CommonName: name}

	// AuthorityKeyId and SubjectKeyId need to match for a self-signed CA
	authorityKeyId := publicKeyHash
	subjectKeyId := publicKeyHash

	template := &certificateTemplate{
		Certificate: &x509.Certificate{
			Subject: subject,

			SignatureAlgorithm: x509.SHA256WithRSA,

			NotBefore: clock.Now().Add(-1 * time.Second),
			NotAfter:  clock.Now().Add(DefaultCertificateLifetime),

			SerialNumber: randomSerialNumber(),

			BasicConstraintsValid: true,

			AuthorityKeyId: authorityKeyId,
			SubjectKeyId:   subjectKeyId,
		},
	}

	for _, opt := range opts {
		if err := opt(template); err != nil {
			return nil, nil, err
		}
	}

	parent := template.Certificate
	signerPrivateKey := privateKey
	if template.ca != nil {
		parent = template.ca.cert
		signerPrivateKey = template.ca.key
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template.Certificate, parent, publicKey, signerPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}

	if len(certs) != 1 {
		return nil, nil, errors.New("expected a single certificate")
	}

	return certs[0], privateKey, err
}

func (chain *CertificateChainWithPrivateKey) EncodeCertificates() ([]byte, error) {
	return encodeCertificates(chain.certs...)
}

func (chain *CertificateChainWithPrivateKey) GetCertificates() []*x509.Certificate {
	return chain.certs
}

func (chain *CertificateChainWithPrivateKey) EncodePrivateKey() ([]byte, error) {
	return encodeKey(chain.key)
}

func (chain *CertificateChainWithPrivateKey) GenerateTLSCertificate() (tls.Certificate, error) {
	certPem, err := chain.EncodeCertificates()
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPem, err := chain.EncodePrivateKey()
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPem, keyPem)
}
