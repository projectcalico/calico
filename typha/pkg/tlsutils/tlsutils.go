// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package tlsutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// Common code for verifying whether a peer certificate has a required Common Name and/or a required
// URI SAN.
func CertificateVerifier(logCxt *log.Entry, roots *x509.CertPool, requiredCN, requiredURISAN string) func([][]byte, [][]*x509.Certificate) error {
	log.WithFields(log.Fields{
		"roots":          roots,
		"requiredCN":     requiredCN,
		"requiredURISAN": requiredURISAN,
	}).Info("Make certificate verifier")
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			// We haven't yet verified that the peer certificate is signed by a trusted
			// CA.  (Because the client-side TLS config sets InsecureSkipVerify true, in
			// order to skip verifying against the server hostname or IP address.)  Do
			// certificate chain verification now.
			logCxt.Info("Verify certificate chain signing")
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1Data := range rawCerts {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("Failed to parse certificate: " + err.Error())
				}
				certs[i] = cert
			}

			opts := x509.VerifyOptions{
				Roots:         roots,
				Intermediates: x509.NewCertPool(),
			}

			for i, cert := range certs {
				if i == 0 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}
			var err error
			verifiedChains, err = certs[0].Verify(opts)
			if err != nil {
				return err
			}
		}

		// When successful, Verify returns one or more chains, with the leaf certificate
		// being the first in each chain.
		leafCert := verifiedChains[0][0]

		requiredCNFound := false
		if requiredCN != "" {
			requiredCNFound = (leafCert.Subject.CommonName == requiredCN)
		}

		requiredURIFound := false
		if requiredURISAN != "" {
			for _, uri := range leafCert.URIs {
				logCxt.WithField("uri", uri).Info("Checking URI")
				if uri.String() == requiredURISAN {
					requiredURIFound = true
					break
				}
			}
		}

		if requiredCN != "" && requiredURISAN != "" {
			if !(requiredCNFound || requiredURIFound) {
				return errors.New("Peer certificate does not have required CN or URI SAN")
			}
		} else if requiredCN != "" {
			if !requiredCNFound {
				return errors.New("Peer certificate does not have required CN")
			}
		} else if requiredURISAN != "" {
			if !requiredURIFound {
				return errors.New("Peer certificate does not have required URI SAN")
			}
		}

		// Reaching here means that the certificate was valid and had required CN and/or URI
		// SAN.
		return nil
	}
}

// The following certificate generators panic if they hit any error.  This is a bit poor, but OK in
// practice because they are only used by test code.
func PanicIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

var serialNumber int = 0
var RSAKeySize int = 2048

func MakeCACert(name string) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	PanicIfErr(err)

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)
	serialNumber++

	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(serialNumber)),
		Subject: pkix.Name{
			Organization: []string{name},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		// Must contain all key usages any child certs will contain. c.f. "nesting" comment on
		// https://golang.org/pkg/crypto/x509/#VerifyOptions
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	PanicIfErr(err)
	caCert, err := x509.ParseCertificate(derBytes)
	PanicIfErr(err)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)
	_, err = caCert.Verify(x509.VerifyOptions{Roots: rootPool})
	PanicIfErr(err)
	return caCert, key
}

func MakePeerCert(cn, uriSAN string, extKeyUsage x509.ExtKeyUsage, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, *rsa.PrivateKey) {
	log.WithFields(log.Fields{
		"cn":          cn,
		"uriSAN":      uriSAN,
		"extKeyUsage": extKeyUsage,
	}).Info("Make peer cert")
	key, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	PanicIfErr(err)

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)
	serialNumber++

	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(serialNumber)),
		Subject: pkix.Name{
			Organization: []string{"Widgits"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{extKeyUsage},
		BasicConstraintsValid: true,
	}

	if cn != "" {
		template.Subject.CommonName = cn
	}
	if uriSAN != "" {
		uri, err := url.Parse(uriSAN)
		PanicIfErr(err)
		template.URIs = []*url.URL{uri}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	PanicIfErr(err)
	if caCert != nil {
		log.Info("Verifying peer certificate")
		peerCert, err := x509.ParseCertificate(derBytes)
		PanicIfErr(err)
		rootPool := x509.NewCertPool()
		rootPool.AddCert(caCert)
		_, err = peerCert.Verify(x509.VerifyOptions{
			Roots:     rootPool,
			KeyUsages: []x509.ExtKeyUsage{extKeyUsage},
		})
		PanicIfErr(err)
	}
	return derBytes, key
}

func WriteCert(data []byte, fileName string) {
	certOut, err := os.Create(fileName)
	PanicIfErr(err)
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: data})
	PanicIfErr(err)
	err = certOut.Close()
	PanicIfErr(err)
	log.Printf("written %v", fileName)
}

func WriteKey(key *rsa.PrivateKey, fileName string) {
	keyOut, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	PanicIfErr(err)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	PanicIfErr(err)
	err = keyOut.Close()
	PanicIfErr(err)
	log.Printf("written %v", fileName)
}
