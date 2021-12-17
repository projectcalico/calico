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

package tlsutils_test

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/tlsutils"
)

const (
	goodCN     = "typha-peer"
	badCN      = "impostor"
	goodURISAN = "spiffe://k8s.example.com/typha-peer"
	badURISAN  = "spiffe://k8s.example.com/impostor"
)

type certConfig struct {
	Signature string
	CN        string
	URISAN    string
}

type typhaConfig struct {
	CAs    string
	CN     string
	URISAN string
}

func genTestCases() []TableEntry {
	// Prepare certificate cases: all possible combinations of whether and how it's signed, what
	// CN it has, and what URI SAN it has.
	signatureConfigs := []string{
		"SignedCA1",
		"SignedCA2",
		"SignedByUntrusted",
	}
	cnConfigs := []string{
		"", // No CN.
		goodCN,
		badCN,
	}
	uriSANConfigs := []string{
		"", // No URI SAN.
		goodURISAN,
		badURISAN,
	}
	var certConfigs []*certConfig
	for _, signature := range signatureConfigs {
		for _, cn := range cnConfigs {
			for _, uri := range uriSANConfigs {
				certConfigs = append(certConfigs, &certConfig{
					Signature: signature,
					CN:        cn,
					URISAN:    uri,
				})
			}
		}
	}

	// Prepare Typha config cases: all possible combinations of CA cert(s), required CN and
	// required SAN.
	caConfigs := []string{
		"NoTrustedCAs",
		"TrustCA1Only",
		"TrustCA2Only",
		"TrustCA1AndCA2",
	}
	cnConfigs = []string{
		"", // No CN.
		goodCN,
	}
	uriSANConfigs = []string{
		"", // No URI SAN.
		goodURISAN,
	}
	var typhaConfigs []*typhaConfig
	for _, ca := range caConfigs {
		for _, cn := range cnConfigs {
			for _, uri := range uriSANConfigs {
				typhaConfigs = append(typhaConfigs, &typhaConfig{
					CAs:    ca,
					CN:     cn,
					URISAN: uri,
				})
			}
		}
	}

	// Prepare an Entry for each combination of cert config and Typha config.
	var entries []TableEntry
	for _, certConfig := range certConfigs {
		peerCertBytes := makePeerCert(certConfig)
		for _, typhaConfig := range typhaConfigs {
			entries = append(entries, Entry(
				fmt.Sprintf("%#v %#v", certConfig, typhaConfig),
				peerCertBytes,
				typhaConfig,
				errChecker(certConfig, typhaConfig),
			))
		}
	}
	return entries
}

var (
	certCA1, keyCA1                 = tlsutils.MakeCACert("CA1")
	certCA2, keyCA2                 = tlsutils.MakeCACert("CA2")
	certCAUntrusted, keyCAUntrusted = tlsutils.MakeCACert("CAUntrusted")
)

func expectOK(actualError error) {
	Expect(actualError).NotTo(HaveOccurred())
}

func expectUntrustedCAError(actualError error) {
	Expect(actualError).To(BeAssignableToTypeOf(x509.UnknownAuthorityError{}))
}

func expectErrorMessage(errorMessage string) func(error) {
	return func(actualError error) {
		Expect(actualError).To(MatchError(errorMessage))
	}
}

func errChecker(certConfig *certConfig, typhaConfig *typhaConfig) func(error) {
	// Possible errors based on certificate signature.
	switch certConfig.Signature {
	case "SignedCA1":
		if typhaConfig.CAs != "TrustCA1Only" && typhaConfig.CAs != "TrustCA1AndCA2" {
			return expectUntrustedCAError
		}
	case "SignedCA2":
		if typhaConfig.CAs != "TrustCA2Only" && typhaConfig.CAs != "TrustCA1AndCA2" {
			return expectUntrustedCAError
		}
	case "SignedByUntrusted":
		return expectUntrustedCAError
	}

	// Possible errors based on certificate content.
	if typhaConfig.CN != "" && certConfig.CN == typhaConfig.CN {
		// Good.
		return expectOK
	}
	if typhaConfig.URISAN != "" && certConfig.URISAN == typhaConfig.URISAN {
		// Good.
		return expectOK
	}
	if typhaConfig.CN != "" && typhaConfig.URISAN != "" {
		// Required CN and URISAN both specified.
		return expectErrorMessage("Peer certificate does not have required CN or URI SAN")
	} else if typhaConfig.CN != "" {
		return expectErrorMessage("Peer certificate does not have required CN")
	} else if typhaConfig.URISAN != "" {
		return expectErrorMessage("Peer certificate does not have required URI SAN")
	}
	return expectOK
}

var _ = DescribeTable("CertificateVerifier",
	func(peerCertBytes []byte, typhaConfig *typhaConfig, errChecker func(err error)) {
		roots := x509.NewCertPool()
		switch typhaConfig.CAs {
		case "NoTrustedCAs":
			// No root certs.
		case "TrustCA1Only":
			roots.AddCert(certCA1)
		case "TrustCA2Only":
			roots.AddCert(certCA2)
		case "TrustCA1AndCA2":
			roots.AddCert(certCA1)
			roots.AddCert(certCA2)
		}
		verifier := tlsutils.CertificateVerifier(
			log.WithFields(log.Fields{
				"typhaConfig": typhaConfig,
			}),
			roots,
			typhaConfig.CN,
			typhaConfig.URISAN,
		)
		err := verifier([][]byte{peerCertBytes}, nil)
		errChecker(err)
	},
	genTestCases()...)

func makePeerCert(cfg *certConfig) []byte {
	log.WithField("cfg", cfg).Info("Make peer cert")
	var (
		caCert *x509.Certificate
		caKey  *rsa.PrivateKey
	)
	switch cfg.Signature {
	case "SignedCA1":
		caCert = certCA1
		caKey = keyCA1
	case "SignedCA2":
		caCert = certCA2
		caKey = keyCA2
	case "SignedByUntrusted":
		caCert = certCAUntrusted
		caKey = keyCAUntrusted
	}
	certBytes, _ := tlsutils.MakePeerCert(cfg.CN, cfg.URISAN, x509.ExtKeyUsageServerAuth, caCert, caKey)
	return certBytes
}
