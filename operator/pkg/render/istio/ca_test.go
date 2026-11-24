// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package istio_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/operator/pkg/render/istio"
)

// testCert is a certificate made for a test, with the PEM forms a Secret holds.
type testCert struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// newTestCert signs a certificate for cn with parent, or self-signs it when
// parent is nil.
func newTestCert(cn string, parent *testCert, isCA bool) *testCert {
	return newTestCertWithUsage(cn, parent, isCA, x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature)
}

func newTestCertWithUsage(cn string, parent *testCert, isCA bool, usage x509.KeyUsage, ext ...x509.ExtKeyUsage) *testCert {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	Expect(err).NotTo(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              usage,
		ExtKeyUsage:           ext,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return &testCert{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// reissue signs another certificate for tc's subject and key under parent.
func reissue(tc *testCert, parent *testCert) *testCert {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	Expect(err).NotTo(HaveOccurred())
	template := *tc.cert
	template.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, &template, parent.cert, &tc.key.PublicKey, parent.key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return &testCert{cert: cert, key: tc.key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM: tc.keyPEM}
}

func concatPEM(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func pemBlockCount(data []byte) int {
	n := 0
	for rest := data; ; n++ {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return n
		}
	}
}

var _ = Describe("Istio CA", func() {
	Describe("GenerateCA", func() {
		It("makes a self-signed RSA 2048 root valid for ten years, like istiod's own self-signed CA", func() {
			ca, err := istio.GenerateCA("mesh.example")
			Expect(err).NotTo(HaveOccurred())

			certs, err := istio.ParseCertificates(ca.CertPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).To(HaveLen(1))
			cert := certs[0]
			Expect(cert.IsCA).To(BeTrue())
			Expect(cert.KeyUsage).To(Equal(x509.KeyUsageCertSign))
			Expect(cert.Subject.Organization).To(Equal([]string{"mesh.example"}))
			Expect(cert.Subject.CommonName).To(HavePrefix("tigera-operator-istio-ca@"))
			Expect(cert.CheckSignatureFrom(cert)).To(Succeed())
			Expect(cert.PublicKey.(*rsa.PublicKey).N.BitLen()).To(Equal(2048))
			Expect(cert.NotAfter.Sub(cert.NotBefore)).To(Equal(3650 * 24 * time.Hour))

			Expect(ca.Chain).To(Equal([]*x509.Certificate{cert}))
			Expect(ca.Roots).To(Equal([]*x509.Certificate{cert}))

			// A root CA is its own chain and its own trust anchor.
			data := ca.SecretData()
			Expect(data).To(HaveLen(4))
			Expect(data[istio.CACertKey]).To(Equal(ca.CertPEM))
			Expect(data[istio.CertChainKey]).To(Equal(ca.CertPEM))
			Expect(data[istio.RootCertKey]).To(Equal(ca.CertPEM))
			Expect(data[istio.CAKeyKey]).To(Equal(ca.KeyPEM))
		})

		It("round-trips through LoadCA", func() {
			ca, err := istio.GenerateCA("cluster.local")
			Expect(err).NotTo(HaveOccurred())
			loaded, err := istio.LoadCA(ca.SecretData())
			Expect(err).NotTo(HaveOccurred())
			Expect(loaded.CertPEM).To(Equal(ca.CertPEM))
			Expect(loaded.KeyPEM).To(Equal(ca.KeyPEM))
			Expect(loaded.Roots).To(HaveLen(1))
			Expect(loaded.Roots[0].Raw).To(Equal(ca.Roots[0].Raw))
		})
	})

	Describe("LoadCA", func() {
		var root, other, intermediate *testCert

		BeforeEach(func() {
			root = newTestCert("root", nil, true)
			other = newTestCert("other-root", nil, true)
			intermediate = newTestCert("intermediate", root, true)
		})

		It("accepts the plug-in layout and chains the CA up to its root", func() {
			ca, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:    intermediate.certPEM,
				istio.CAKeyKey:     intermediate.keyPEM,
				istio.CertChainKey: append(append([]byte{}, intermediate.certPEM...), root.certPEM...),
				istio.RootCertKey:  root.certPEM,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.CertPEM).To(Equal(intermediate.certPEM))
			Expect(ca.KeyPEM).To(Equal(intermediate.keyPEM))
			Expect(ca.Chain).To(HaveLen(2))
			Expect(ca.Chain[0].Raw).To(Equal(intermediate.cert.Raw))
			Expect(ca.Chain[1].Raw).To(Equal(root.cert.Raw))
			Expect(ca.Roots).To(HaveLen(1))
			Expect(ca.Roots[0].Raw).To(Equal(root.cert.Raw))
		})

		It("takes as its roots only those the CA chains to", func() {
			ca, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:   root.certPEM,
				istio.CAKeyKey:    root.keyPEM,
				istio.RootCertKey: append(append([]byte{}, other.certPEM...), root.certPEM...),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.Roots).To(HaveLen(1))
			Expect(ca.Roots[0].Raw).To(Equal(root.cert.Raw))
		})

		It("accepts a PKCS#8 private key", func() {
			keyDER, err := x509.MarshalPKCS8PrivateKey(root.key)
			Expect(err).NotTo(HaveOccurred())
			_, err = istio.LoadCA(map[string][]byte{
				istio.CACertKey:   root.certPEM,
				istio.CAKeyKey:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
				istio.RootCertKey: root.certPEM,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("rejects a private key that does not match the certificate", func() {
			_, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:   root.certPEM,
				istio.CAKeyKey:    other.keyPEM,
				istio.RootCertKey: root.certPEM,
			})
			Expect(err).To(MatchError(ContainSubstring("ca-key.pem does not match the certificate in ca-cert.pem")))
		})

		It("rejects a certificate that is not a CA", func() {
			leaf := newTestCert("leaf", root, false)
			_, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:   leaf.certPEM,
				istio.CAKeyKey:    leaf.keyPEM,
				istio.RootCertKey: root.certPEM,
			})
			Expect(err).To(MatchError(ContainSubstring("ca-cert.pem: the certificate is not a CA")))
		})

		It("rejects a CA whose key usage does not allow certificate signing", func() {
			restricted := newTestCertWithUsage("restricted", nil, true, x509.KeyUsageDigitalSignature)
			_, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:   restricted.certPEM,
				istio.CAKeyKey:    restricted.keyPEM,
				istio.RootCertKey: restricted.certPEM,
			})
			Expect(err).To(MatchError(ContainSubstring("ca-cert.pem: the key usage does not allow certificate signing")))
		})

		It("rejects a CA, or an issuer of it, whose extended key usage leaves out TLS client or server authentication", func() {
			usage := x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
			serverOnly := newTestCertWithUsage("server-only", nil, true, usage, x509.ExtKeyUsageServerAuth)
			_, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:   serverOnly.certPEM,
				istio.CAKeyKey:    serverOnly.keyPEM,
				istio.RootCertKey: serverOnly.certPEM,
			})
			Expect(err).To(MatchError(ContainSubstring("ca-cert.pem: the extended key usage of the chain does not allow TLS client and server authentication")))

			clientOnlyRoot := newTestCertWithUsage("client-only-root", nil, true, usage, x509.ExtKeyUsageClientAuth)
			under := newTestCert("under-client-only", clientOnlyRoot, true)
			_, err = istio.LoadCA(map[string][]byte{
				istio.CACertKey:   under.certPEM,
				istio.CAKeyKey:    under.keyPEM,
				istio.RootCertKey: clientOnlyRoot.certPEM,
			})
			Expect(err).To(MatchError(ContainSubstring("the extended key usage of the chain does not allow")))

			both := newTestCertWithUsage("both", nil, true, usage, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
			_, err = istio.LoadCA(map[string][]byte{
				istio.CACertKey:   both.certPEM,
				istio.CAKeyKey:    both.keyPEM,
				istio.RootCertKey: both.certPEM,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("rejects a CA whose only server and client paths are different chains", func() {
			usage := x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
			serverRoot := newTestCertWithUsage("server-root", nil, true, usage, x509.ExtKeyUsageServerAuth)
			clientRoot := newTestCertWithUsage("client-root", nil, true, usage, x509.ExtKeyUsageClientAuth)
			// One intermediate key, cross-signed under both roots.
			viaServer := newTestCertWithUsage("intermediate", serverRoot, true, usage)
			viaClient := reissue(viaServer, clientRoot)
			ca := newTestCert("ca", viaServer, true)
			_, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:    ca.certPEM,
				istio.CAKeyKey:     ca.keyPEM,
				istio.CertChainKey: concatPEM(viaServer.certPEM, viaClient.certPEM),
				istio.RootCertKey:  concatPEM(serverRoot.certPEM, clientRoot.certPEM),
			})
			Expect(err).To(MatchError(ContainSubstring("the extended key usage of the chain does not allow")))
		})

		It("rejects a certificate that does not chain to a root in root-cert.pem", func() {
			_, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:   intermediate.certPEM,
				istio.CAKeyKey:    intermediate.keyPEM,
				istio.RootCertKey: other.certPEM,
			})
			Expect(err).To(MatchError(ContainSubstring("ca-cert.pem does not chain to a root in root-cert.pem")))
		})

		It("rejects a root-cert.pem entry that is not a CA", func() {
			leaf := newTestCert("leaf", root, false)
			_, err := istio.LoadCA(map[string][]byte{
				istio.CACertKey:   root.certPEM,
				istio.CAKeyKey:    root.keyPEM,
				istio.RootCertKey: leaf.certPEM,
			})
			Expect(err).To(MatchError(ContainSubstring("root-cert.pem: certificate 1 is not a CA")))
		})

		It("names the keys it expects when they are missing", func() {
			_, err := istio.LoadCA(map[string][]byte{})
			Expect(err).To(MatchError(ContainSubstring("expected keys ca-cert.pem, ca-key.pem and root-cert.pem")))
			_, err = istio.LoadCA(map[string][]byte{istio.CACertKey: root.certPEM, istio.CAKeyKey: root.keyPEM})
			Expect(err).To(MatchError(ContainSubstring("expected keys")))
		})
	})

	Describe("ParseCACertificates", func() {
		It("parses every certificate in a bundle", func() {
			a, b := newTestCert("a", nil, true), newTestCert("b", nil, true)
			certs, err := istio.ParseCACertificates(append(append([]byte{}, a.certPEM...), b.certPEM...))
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).To(HaveLen(2))
		})

		It("rejects a certificate that is not a CA", func() {
			root := newTestCert("root", nil, true)
			leaf := newTestCert("leaf", root, false)
			_, err := istio.ParseCACertificates(append(append([]byte{}, root.certPEM...), leaf.certPEM...))
			Expect(err).To(MatchError("certificate 2 is not a CA"))
		})

		It("rejects a PEM block that is not a certificate", func() {
			root := newTestCert("root", nil, true)
			_, err := istio.ParseCACertificates(append(append([]byte{}, root.certPEM...), root.keyPEM...))
			Expect(err).To(MatchError("PEM block 2 is a EC PRIVATE KEY, not a CERTIFICATE"))
		})

		It("rejects data with no certificate", func() {
			_, err := istio.ParseCACertificates([]byte("not a certificate"))
			Expect(err).To(MatchError("no PEM certificate found"))
			_, err = istio.ParseCACertificates(nil)
			Expect(err).To(MatchError("no PEM certificate found"))
		})

		It("rejects a certificate that does not parse", func() {
			_, err := istio.ParseCACertificates(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
			Expect(err).To(MatchError(ContainSubstring("certificate 1:")))
		})
	})

	Describe("ComposeRootBundle", func() {
		It("deduplicates by DER bytes and sorts for a stable byte sequence", func() {
			a, b, c := newTestCert("a", nil, true), newTestCert("b", nil, true), newTestCert("c", nil, true)
			bundle := istio.ComposeRootBundle([]*x509.Certificate{c.cert, a.cert}, []*x509.Certificate{b.cert, a.cert, c.cert})
			Expect(pemBlockCount(bundle)).To(Equal(3))
			Expect(bundle).To(Equal(istio.ComposeRootBundle([]*x509.Certificate{a.cert, b.cert, c.cert})))
			Expect(bundle).To(Equal(istio.ComposeRootBundle([]*x509.Certificate{b.cert}, []*x509.Certificate{c.cert}, []*x509.Certificate{a.cert})))

			certs, err := istio.ParseCertificates(bundle)
			Expect(err).NotTo(HaveOccurred())
			for i := 1; i < len(certs); i++ {
				Expect(bytes.Compare(certs[i-1].Raw, certs[i].Raw)).To(BeNumerically("<", 0))
			}
		})

		It("is empty for no roots", func() {
			Expect(istio.ComposeRootBundle()).To(BeEmpty())
			Expect(istio.ComposeRootBundle(nil)).To(BeEmpty())
		})
	})
})
