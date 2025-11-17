package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
)

var RSAKeySize int = 2048

func CreateKeyCertPair(dir string) (*os.File, *os.File) {
	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	Expect(err).ShouldNot(HaveOccurred())

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Valid for 1 day
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")}, // Add 127.0.0.1 as an IP SAN - needed for httptest package
		DNSNames:              []string{"localhost"},              // Add localhost as a DNS SAN
	}

	// Create a self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	Expect(err).ShouldNot(HaveOccurred())

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := x509.MarshalPKCS1PrivateKey(priv)
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyPEM})

	// Write the certificate and key to temporary files
	certFile, err := os.CreateTemp(dir, "cert.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer func() { _ = certFile.Close() }()

	keyFile, err := os.CreateTemp(dir, "key.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer func() { _ = keyFile.Close() }()

	_, err = certFile.Write(certPEM)
	Expect(err).ShouldNot(HaveOccurred())
	_, err = keyFile.Write(keyPEMBlock)
	Expect(err).ShouldNot(HaveOccurred())

	return certFile, keyFile
}
