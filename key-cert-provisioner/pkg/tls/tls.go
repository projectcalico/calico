// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/projectcalico/calico/key-cert-provisioner/pkg/cfg"
)

type X509CSR struct {
	PrivateKey    interface{}
	PrivateKeyPEM []byte
	CSR           []byte
}

// CreateX509CSR creates a certificate signing request based on a configuration.
func CreateX509CSR(config *cfg.Config) (*X509CSR, error) {
	subj := pkix.Name{
		CommonName:         config.CommonName,
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"Tigera"},
		OrganizationalUnit: []string{"Engineering"},
	}

	if config.EmailAddress != "" {
		subj.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(config.EmailAddress),
				},
			},
		}
	}

	// Cert does not need to function as a CA.
	basicVal, err := asn1.Marshal(basicConstraints{false, -1})
	if err != nil {
		return nil, err
	}

	usageVal, err := marshalKeyUsage(x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement)
	if err != nil {
		return nil, err
	}

	extKeyUsages := []asn1.ObjectIdentifier{
		// ExtKeyUsageServerAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		// ExtKeyUsageClientAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	}

	extKeyUsagesVal, err := asn1.Marshal(extKeyUsages)
	if err != nil {
		return nil, err
	}

	// step: generate a csr template
	csrTemplate := x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           config.DNSNames,
		IPAddresses:        config.IPAddresses,
		SignatureAlgorithm: SignatureAlgorithm(config.SignatureAlgorithm),
		ExtraExtensions: []pkix.Extension{
			{
				// ExtensionBasicConstraints
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Value:    basicVal,
				Critical: true,
			},
			// KeyUsage will be set to KeyEncipherment and DigitalSignature.
			usageVal,
			{
				// ExtKeyUsage will be set to ServerAuth and ClientAuth.
				Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
				Value: extKeyUsagesVal,
			},
		},
	}
	privateKey, privateKeyPem, err := GeneratePrivateKey(config.PrivateKeyAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("unable to create private key: %w", err)
	}
	// step: generate the csr request
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create an x509 csr: %w", err)
	}
	return &X509CSR{
		PrivateKey:    privateKey,
		PrivateKeyPEM: privateKeyPem,
		CSR: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
		}),
	}, nil
}

// basicConstraints is a struct needed for creating a template.
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// Create a private key based on the env variables.
// Default: 2048 bit.
func GeneratePrivateKey(algorithm string) (interface{}, []byte, error) {
	switch algorithm {
	case "RSAWithSize2048":
		return genRSA(2048)
	case "RSAWithSize4096":
		return genRSA(4096)
	case "RSAWithSize8192":
		return genRSA(8192)
	case "ECDSAWithCurve256":
		return genECDSA(elliptic.P256())
	case "ECDSAWithCurve384":
		return genECDSA(elliptic.P384())
	case "ECDSAWithCurve521":
		return genECDSA(elliptic.P521())
	default:
		return genRSA(2048)
	}
}

// genECDSA generates a private key.
func genECDSA(curve elliptic.Curve) (interface{}, []byte, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	byteArr, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: byteArr})
	return key, buf.Bytes(), err

}

// genRSA generates a private key.
func genRSA(size int) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, buf.Bytes(), err

}

// SignatureAlgorithm returns a x506 signature algorithm based on the env variables.
// Default: SHA256WithRSA
func SignatureAlgorithm(algorithm string) x509.SignatureAlgorithm {
	switch algorithm {
	case "SHA256WithRSA":
		return x509.SHA256WithRSA
	case "SHA384WithRSA":
		return x509.SHA384WithRSA
	case "SHA512WithRSA":
		return x509.SHA512WithRSA
	case "ECDSAWithSHA256":
		return x509.ECDSAWithSHA256
	case "ECDSAWithSHA384":
		return x509.ECDSAWithSHA384
	case "ECDSAWithSHA512":
		return x509.ECDSAWithSHA512
	default:
		return x509.SHA256WithRSA
	}
}

// marshalKeyUsage has been copied from the golang package crypto/x509/x509.go in order to marshal keyUsage.
func marshalKeyUsage(ku x509.KeyUsage) (pkix.Extension, error) {
	ext := pkix.Extension{Id: []int{2, 5, 29, 15}, Critical: true}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return ext, err
	}
	return ext, nil
}

// reverseBitsInAByte has been copied from the golang package crypto/x509/x509.go in order to marshal keyUsage.
func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength has been copied from the golang package crypto/x509/x509.go in order to marshal keyUsage.
// asn1BitLength returns the bit-length of bitString by considering the most-significant bit in a byte to be the "first"
// bit. This convention matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}
