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

package k8s_test

import (
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	certV1 "k8s.io/api/certificates/v1"
	certV1beta1 "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/key-cert-provisioner/pkg/cfg"
	"github.com/projectcalico/calico/key-cert-provisioner/pkg/k8s"
	"github.com/projectcalico/calico/key-cert-provisioner/pkg/tls"
)

var _ = Describe("Test Certificates", func() {
	ctx := context.Background()

	var (
		// Clients and configurations that will be initialized.
		config    *cfg.Config
		clientset kubernetes.Interface
		tlsCsr    *tls.X509CSR

		// Variables that are set and tested.
		csrName = "calico-node:calico-node:12345"
		csrPem  = []byte("<this is a csr>")
		signer  = "example.com/signer"
	)

	BeforeEach(func() {
		clientset = fake.NewSimpleClientset()
		config = &cfg.Config{
			Signer:    signer,
			CSRName:   csrName,
			CSRLabels: map[string]string{"label-key": "label-value"},
		}
		tlsCsr = &tls.X509CSR{
			CSR: csrPem,
		}
	})
	Context("Test submitting a CSR", func() {
		It("should list no CSRs when the suite starts", func() {
			By("verifying no v1 CSRs are present yet")
			resp, err := clientset.CertificatesV1().CertificateSigningRequests().List(ctx, v1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Items).To(HaveLen(0))

			By("creating the v1 CSRs are present yet")
			Expect(k8s.SubmitCSR(ctx, config, clientset, tlsCsr)).ToNot(HaveOccurred())

			By("Verifying the object exists with the right settings")
			csrs, err := clientset.CertificatesV1().CertificateSigningRequests().List(ctx, v1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(csrs.Items).To(HaveLen(1))
			csr := csrs.Items[0]

			Expect(csr.Name).To(Equal(csrName))
			Expect(csr.Labels).To(HaveKeyWithValue("label-key", "label-value"))
			Expect(csr.Spec.Request).To(Equal(csrPem))
			Expect(csr.Spec.SignerName).To(Equal(signer))
			Expect(csr.Spec.Usages).To(ConsistOf(certV1.UsageServerAuth, certV1.UsageClientAuth,
				certV1.UsageDigitalSignature, certV1.UsageKeyAgreement, certV1.UsageKeyEncipherment))
			Expect(csr.Spec.Usages).NotTo(ConsistOf(certV1beta1.UsageServerAuth, certV1beta1.UsageClientAuth,
				certV1beta1.UsageDigitalSignature, certV1beta1.UsageKeyAgreement))
		})
	})
})

var _ = Describe("Test writing TLS secrets to disk", func() {
	const (
		caCert     = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
		key        = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----"
		cert       = "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
		certName   = "tls.crt"
		keyName    = "tls.key"
		caCertName = "ca.crt"
	)
	var (
		dir     string
		config  *cfg.Config
		x509CSR = &tls.X509CSR{
			PrivateKeyPEM: []byte(key),
		}
	)

	BeforeEach(func() {
		var err error
		dir, err = os.MkdirTemp("", "certificate_test.go")
		Expect(err).NotTo(HaveOccurred())
		config = &cfg.Config{
			CACertPEM:  []byte(caCert),
			CertPath:   filepath.Join(dir, certName),
			KeyPath:    filepath.Join(dir, keyName),
			CACertPath: filepath.Join(dir, caCertName),
		}
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dir)).NotTo(HaveOccurred())
	})

	It("should write the TLS secrets to file", func() {
		Expect(k8s.WriteCertificateToFile(config, []byte(cert), x509CSR)).NotTo(HaveOccurred())
		files, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(files).To(HaveLen(3))

		bytes, err := os.ReadFile(filepath.Join(dir, keyName))
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes).To(Equal([]byte(key)))

		bytes, err = os.ReadFile(filepath.Join(dir, certName))
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes).To(Equal([]byte(cert)))

		bytes, err = os.ReadFile(filepath.Join(dir, caCertName))
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes).To(Equal([]byte(caCert)))
	})

	It("should write the TLS secrets to file even if no ca.crt is provided", func() {
		config.CACertPath = ""
		Expect(k8s.WriteCertificateToFile(config, []byte(cert), x509CSR)).NotTo(HaveOccurred())
		files, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(files).To(HaveLen(2))

		bytes, err := os.ReadFile(filepath.Join(dir, keyName))
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes).To(Equal([]byte(key)))

		bytes, err = os.ReadFile(filepath.Join(dir, certName))
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes).To(Equal([]byte(cert)))

		bytes, err = os.ReadFile(filepath.Join(dir, caCertName))
		Expect(err).To(HaveOccurred())
		Expect(bytes).To(BeNil())
	})

	It("should write the TLS secrets to file even if no ca.crt is provided", func() {
		config.CACertPEM = []byte("")
		Expect(k8s.WriteCertificateToFile(config, []byte(cert), x509CSR)).NotTo(HaveOccurred())
		files, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(files).To(HaveLen(2))

		bytes, err := os.ReadFile(filepath.Join(dir, keyName))
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes).To(Equal([]byte(key)))

		bytes, err = os.ReadFile(filepath.Join(dir, certName))
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes).To(Equal([]byte(cert)))

		bytes, err = os.ReadFile(filepath.Join(dir, caCertName))
		Expect(err).To(HaveOccurred())
		Expect(bytes).To(BeNil())
	})
})
