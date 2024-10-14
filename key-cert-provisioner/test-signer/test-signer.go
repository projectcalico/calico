// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	masterURL  string
	kubeconfig string
	signerName string
	caCert     string
	caKey      string
	approve    bool
	sign       bool
)

// WARNING: DO NOT USE THIS IN PRODUCTION CLUSTERS.
// This is a watcher that automatically signs all CSRs in your cluster for dev/test purposes.
func main() {
	flag.Parse()

	log.WithField("masterURL", masterURL).
		WithField("kubeconfig", kubeconfig).
		WithField("signerName", signerName).
		WithField("caCert", caCert).
		WithField("caKey", caKey).
		WithField("sign", sign).
		WithField("approve", approve).
		Infof("Starting with the following settings.")

	if caCert == "" || caKey == "" {
		log.Fatal("caCert and caKey must be set")
	}
	ctx := context.Background()
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// Read private key in order to sign the csrs.
	keyPEM, err := os.ReadFile(caKey)
	if err != nil {
		log.Fatal(err)
	}

	keyDER, _ := pem.Decode(keyPEM)
	if keyDER == nil {
		log.Fatal("No key found")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(keyDER.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(keyDER.Bytes); err != nil {
			log.Fatal(err)
		}
	}

	privateKey, _ := parsedKey.(*rsa.PrivateKey)

	certPEM, err := os.ReadFile(caCert)
	if err != nil {
		log.Fatal(err)
	}
	certDER, _ := pem.Decode(certPEM)
	if certDER == nil {
		log.Fatal("No certificate found")
	}

	crt, err := x509.ParseCertificate(certDER.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	certV1Client := clientset.CertificatesV1()

	watchers, err := certV1Client.CertificateSigningRequests().Watch(ctx, metaV1.ListOptions{})

	if err != nil {
		log.Fatal(err)
	}
	ch := watchers.ResultChan()

	for event := range ch {
		csr, ok := event.Object.(*certv1.CertificateSigningRequest)
		if !ok {
			log.Fatal("unexpected type in cert channel")
		}

		cert := csr.DeepCopy()
		if csr.Spec.SignerName != signerName {
			log.Infof("Skipping CSR %s with signerName %s. We only sign signerName: %s", csr.Name, csr.Spec.SignerName, signerName)
			continue
		}
		if csr.Status.Certificate == nil && sign {
			log.Infof("CSR: %v", csr.Name)

			block, _ := pem.Decode(cert.Spec.Request)
			if block == nil {
				log.Fatal("failed to decode csr")
			}

			cr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			// todo: Don't do this in prod. This code does not check the signature!
			bigint, _ := rand.Int(rand.Reader, big.NewInt(10e6))
			certIssued := &x509.Certificate{
				Version:               cr.Version,
				BasicConstraintsValid: true,
				SerialNumber:          bigint,
				PublicKeyAlgorithm:    cr.PublicKeyAlgorithm,
				PublicKey:             cr.PublicKey,
				IsCA:                  false,
				Subject:               cr.Subject,
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(10e4 * time.Hour),
				// see http://golang.org/pkg/crypto/x509/#KeyUsage
				KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
				ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				DNSNames:       cr.DNSNames,
				IPAddresses:    cr.IPAddresses,
				EmailAddresses: cr.EmailAddresses,
				URIs:           cr.URIs,
			}

			derBytes, err := x509.CreateCertificate(rand.Reader, certIssued, crt, cr.PublicKey, privateKey)
			if err != nil {
				log.Fatalf("error creating x509 certificate: %s", err.Error())
			}
			pemBytes := bytes.NewBuffer([]byte{})
			err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
			if err != nil {
				log.Panicf("error encoding certificate PEM: %s", err.Error())
			}

			cert.Status.Certificate = pemBytes.Bytes()
			r, err := certV1Client.CertificateSigningRequests().UpdateStatus(ctx, cert, metaV1.UpdateOptions{})
			if err != nil {
				log.Fatalf("unexpected err when updating csr: %v", err)
			}
			log.Infof("CSR Signed: %v", r.ObjectMeta.Name)
		} else if len(csr.Status.Conditions) == 0 && approve {
			cert.Status.Conditions = []certv1.CertificateSigningRequestCondition{
				{
					Type:    certv1.CertificateApproved,
					Message: "Approved",
					Reason:  "Approved",
					Status:  corev1.ConditionTrue,
				},
			}
			if _, err := certV1Client.CertificateSigningRequests().UpdateApproval(ctx, cert.Name, cert, metaV1.UpdateOptions{}); err != nil {
				log.Fatalf("Unable to update approval")
			}
			log.Infof("CSR Approved: %v", cert.Spec.Username)
		}
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "127.0.0.1:8001", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.BoolVar(&sign, "sign", true, "Set to false if you do not want to sign.")
	flag.BoolVar(&approve, "approve", true, "Set to false if you do not want to approve.")
	flag.StringVar(&signerName, "signerName", os.Getenv("SIGNER_NAME"), "The signerName for this application.")
	flag.StringVar(&caCert, "caCert", os.Getenv("CA_CRT"), "The CA certificate file path.")
	flag.StringVar(&caKey, "caKey", os.Getenv("CA_KEY"), "The CA private key file path.")
}
