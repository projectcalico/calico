package fv_test

import (
	"crypto/x509"
	"os"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/std/cryptoutils"
)

func createKeyCertPair(dir, certFileName, keyFileName string) (string, string) {
	certPEM, keyPEM, err := cryptoutils.GenerateSelfSignedCert(
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny))
	Expect(err).ShouldNot(HaveOccurred())

	certFile, err := os.Create(dir + "/" + certFileName)
	Expect(err).ShouldNot(HaveOccurred())
	defer certFile.Close()

	keyFile, err := os.Create(dir + "/" + keyFileName)
	Expect(err).ShouldNot(HaveOccurred())
	defer keyFile.Close()

	_, err = certFile.Write(certPEM)
	Expect(err).ShouldNot(HaveOccurred())
	_, err = keyFile.Write(keyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	return certFile.Name(), keyFile.Name()
}
