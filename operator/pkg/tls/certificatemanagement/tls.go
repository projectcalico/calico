// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package certificatemanagement

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	VoltronKeySizeBits  = 2048
	blockTypePrivateKey = "RSA PRIVATE KEY"
	blockTypeCert       = "CERTIFICATE"
)

// CreateSelfSignedSecret creates a self signed TLS secret.
func CreateSelfSignedSecret(secretName, namespace, cn string, altNames []string) (*corev1.Secret, error) {
	template := template(cn, altNames)
	privateKey, err := rsa.GenerateKey(rand.Reader, VoltronKeySizeBits)
	if err != nil {
		panic(err)
	}
	// Passing in template as parent, creates a self-signed cert.
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}
	// This will create a pem string for the privateKey and the cert
	var keyPem bytes.Buffer
	err = pem.Encode(&keyPem, &pem.Block{
		Type:  blockTypePrivateKey,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, err
	}
	var certPem bytes.Buffer
	if err := pem.Encode(&certPem, &pem.Block{Type: blockTypeCert, Bytes: cert}); err != nil {
		panic(err)
	}
	labels, annotations := tlsSecretMetadata(certPem.Bytes())

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPem.Bytes(),
			corev1.TLSPrivateKeyKey: keyPem.Bytes(),
		},
	}, nil
}

func template(cn string, altNames []string) *x509.Certificate {
	return &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1),
		DNSNames:              altNames,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		// For now use the same lifetime as the other certs we generate. This will change when we implement rotation.
		NotAfter: time.Now().Add(crypto.DefaultCACertificateLifetimeDuration),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
	}
}
