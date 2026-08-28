// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package certificatemanagement_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"

	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("TLS secret metadata", func() {
	Describe("KeyPair.Secret()", func() {
		It("should add labels and annotations to the secret from a valid cert", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("test-secret", "test-ns", "test-cn", []string{"foo.example.com", "bar.example.com"})
			Expect(err).NotTo(HaveOccurred())

			kp := certificatemanagement.NewKeyPair(secret, []string{"foo.example.com"}, "cluster.local")
			s := kp.Secret("test-ns")

			By("verifying labels are present")
			Expect(s.Labels).To(HaveKey("certificates.operator.tigera.io/signer"))

			By("verifying annotations are present")
			Expect(s.Annotations).To(HaveKey("certificates.operator.tigera.io/issuer"))
			Expect(s.Annotations).To(HaveKey("certificates.operator.tigera.io/signer"))
			Expect(s.Annotations).To(HaveKey("certificates.operator.tigera.io/expiry"))
			Expect(s.Annotations).To(HaveKey("certificates.operator.tigera.io/dns-names"))

			By("verifying the issuer matches the CN we used")
			Expect(s.Annotations["certificates.operator.tigera.io/issuer"]).To(Equal("test-cn"))
			Expect(s.Annotations["certificates.operator.tigera.io/signer"]).To(Equal("test-cn"))

			By("verifying the DNS names annotation contains our DNS names")
			dnsNames := s.Annotations["certificates.operator.tigera.io/dns-names"]
			Expect(dnsNames).To(ContainSubstring("foo.example.com"))
			Expect(dnsNames).To(ContainSubstring("bar.example.com"))

			By("verifying cert-expiry is in RFC3339 format")
			Expect(s.Annotations["certificates.operator.tigera.io/expiry"]).To(MatchRegexp(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`))

			By("verifying the hash annotation is present")
			Expect(s.Annotations).To(HaveKey(kp.HashAnnotationKey()))
			Expect(s.Annotations[kp.HashAnnotationKey()]).To(Equal(kp.HashAnnotationValue()))
		})

		It("should omit cert-ip-sans when there are no IP SANs", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("test-secret", "test-ns", "test-cn", []string{"foo.example.com"})
			Expect(err).NotTo(HaveOccurred())

			kp := certificatemanagement.NewKeyPair(secret, []string{"foo.example.com"}, "cluster.local")
			s := kp.Secret("test-ns")

			Expect(s.Annotations).NotTo(HaveKey("certificates.operator.tigera.io/ip-sans"))
		})

		It("should only have hash annotation when cert PEM is empty", func() {
			kp := &certificatemanagement.KeyPair{
				Name:           "empty-cert",
				PrivateKeyPEM:  []byte("fake-key"),
				CertificatePEM: []byte{},
			}
			s := kp.Secret("test-ns")

			Expect(s.Labels).To(BeEmpty())
			Expect(s.Annotations).To(HaveLen(1))
			Expect(s.Annotations).To(HaveKey(kp.HashAnnotationKey()))
		})
	})

	Describe("KeyPair.Warnings()", func() {
		createCertPEM := func(notAfter time.Time) []byte {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "test"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     notAfter,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			Expect(err).NotTo(HaveOccurred())
			var buf bytes.Buffer
			Expect(pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})).NotTo(HaveOccurred())
			return buf.Bytes()
		}

		It("should return a warning for a BYO cert expiring within 30 days", func() {
			kp := &certificatemanagement.KeyPair{
				Name:           "my-tls-secret",
				CertificatePEM: createCertPEM(time.Now().Add(10 * 24 * time.Hour)),
			}
			Expect(kp.BYO()).To(BeTrue())
			warning := kp.Warnings()
			Expect(warning).To(ContainSubstring("user provided certificate"))
			Expect(warning).To(ContainSubstring("my-tls-secret"))
			Expect(warning).To(ContainSubstring("expires in"))
		})

		It("should return empty for a BYO cert expiring in more than 30 days", func() {
			kp := &certificatemanagement.KeyPair{
				Name:           "my-tls-secret",
				CertificatePEM: createCertPEM(time.Now().Add(60 * 24 * time.Hour)),
			}
			Expect(kp.BYO()).To(BeTrue())
			Expect(kp.Warnings()).To(BeEmpty())
		})

		It("should return empty for a non-BYO cert even if expiring soon", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("test-secret", "test-ns", "test-cn", nil)
			Expect(err).NotTo(HaveOccurred())
			// NewKeyPair creates a BYO keypair (no issuer, no cert management)
			// but a KeyPair with an Issuer is not BYO.
			issuer := certificatemanagement.NewKeyPair(secret, nil, "cluster.local")
			kp := &certificatemanagement.KeyPair{
				Name:           "managed-secret",
				CertificatePEM: createCertPEM(time.Now().Add(10 * 24 * time.Hour)),
				Issuer:         issuer,
			}
			Expect(kp.BYO()).To(BeFalse())
			Expect(kp.Warnings()).To(BeEmpty())
		})
	})

	Describe("CreateSelfSignedSecret()", func() {
		It("should include labels and annotations on the created secret", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", "my-issuer@1234567890", []string{"dns1.example.com"})
			Expect(err).NotTo(HaveOccurred())

			By("verifying labels")
			Expect(secret.Labels).To(HaveKeyWithValue("certificates.operator.tigera.io/signer", "my-issuer-1234567890"))

			By("verifying annotations")
			Expect(secret.Annotations["certificates.operator.tigera.io/issuer"]).To(Equal("my-issuer@1234567890"))
			Expect(secret.Annotations["certificates.operator.tigera.io/signer"]).To(Equal("my-issuer@1234567890"))
			Expect(secret.Annotations).To(HaveKey("certificates.operator.tigera.io/expiry"))
			Expect(secret.Annotations["certificates.operator.tigera.io/dns-names"]).To(Equal("dns1.example.com"))
		})

		It("should handle the signer label with no @ in the CN", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", "simple-signer", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(secret.Labels["certificates.operator.tigera.io/signer"]).To(Equal("simple-signer"))
		})

		It("should truncate the signer label to 63 characters", func() {
			longCN := strings.Repeat("a", 100)
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", longCN, nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(secret.Labels["certificates.operator.tigera.io/signer"])).To(Equal(63))
		})

		It("should sanitize spaces in the signer label", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", "My Company Root CA", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(secret.Labels["certificates.operator.tigera.io/signer"]).To(Equal("My-Company-Root-CA"))
		})

		It("should sanitize commas and equals in the signer label", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", "O=Foo, CN=Bar", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(secret.Labels["certificates.operator.tigera.io/signer"]).To(Equal("O-Foo--CN-Bar"))
		})

		It("should trim leading/trailing special chars after sanitization", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", "...leading-and-trailing---", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(secret.Labels["certificates.operator.tigera.io/signer"]).To(Equal("leading-and-trailing"))
		})

		It("should return unknown when CN becomes empty after sanitization", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("my-secret", "my-ns", "   ", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(secret.Labels["certificates.operator.tigera.io/signer"]).To(Equal("unknown"))
		})
	})

	Describe("GetKeyCertPEM()", func() {
		It("should read the standard tls.crt/tls.key pair", func() {
			secret := &corev1.Secret{Data: map[string][]byte{
				"tls.key": []byte("standard-key"),
				"tls.crt": []byte("standard-cert"),
			}}
			key, cert := certificatemanagement.GetKeyCertPEM(secret)
			Expect(string(key)).To(Equal("standard-key"))
			Expect(string(cert)).To(Equal("standard-cert"))
		})

		It("should fall back to legacy cert/key names when the standard pair is absent", func() {
			secret := &corev1.Secret{Data: map[string][]byte{
				"key":  []byte("legacy-key"),
				"cert": []byte("legacy-cert"),
			}}
			key, cert := certificatemanagement.GetKeyCertPEM(secret)
			Expect(string(key)).To(Equal("legacy-key"))
			Expect(string(cert)).To(Equal("legacy-cert"))
		})

		// Regression test: a secret may legitimately hold both the standard tls.crt/tls.key pair
		// and a legacy cert/key pair at the same time (e.g. an expired legacy cert kept during a
		// rotation overlap). Selection must be deterministic and always prefer the standard pair;
		// otherwise the KeyPair hash annotation flaps and rolls consumers like tigera-manager.
		It("should deterministically prefer tls.crt/tls.key when both standard and legacy pairs exist", func() {
			secret := &corev1.Secret{Data: map[string][]byte{
				"tls.key": []byte("standard-key"),
				"tls.crt": []byte("standard-cert"),
				"key":     []byte("legacy-key"),
				"cert":    []byte("legacy-cert"),
			}}
			// Run many times to defeat Go's randomized map iteration order.
			for i := 0; i < 100; i++ {
				key, cert := certificatemanagement.GetKeyCertPEM(secret)
				Expect(string(key)).To(Equal("standard-key"))
				Expect(string(cert)).To(Equal("standard-cert"))
			}
		})

		It("should return nil when no recognised pair is present", func() {
			secret := &corev1.Secret{Data: map[string][]byte{"unrelated": []byte("x")}}
			key, cert := certificatemanagement.GetKeyCertPEM(secret)
			Expect(key).To(BeNil())
			Expect(cert).To(BeNil())
		})
	})
})
