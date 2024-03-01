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

package cfg_test

import (
	"crypto/x509"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	certv1 "k8s.io/api/certificates/v1"

	"github.com/projectcalico/calico/key-cert-provisioner/pkg/cfg"
)

var _ = DescribeTable("Test configuration related to private key algorithm",
	func(privateKeyAlgorithm,
		expectedKeyAlgorithm string,
		expectedX509Usage x509.KeyUsage,
		expectedCertv1Usage []certv1.KeyUsage) {
		keyAlg, x509Usage, certv1Usage := cfg.GetPrivateKeyInfo(privateKeyAlgorithm)
		Expect(keyAlg).To(Equal(expectedKeyAlgorithm))
		Expect(x509Usage).To(Equal(expectedX509Usage))
		Expect(certv1Usage).To(Equal(expectedCertv1Usage))
	},
	Entry("Algorithm: RSAWithSize2048", "RSAWithSize2048", "RSAWithSize2048",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]certv1.KeyUsage{certv1.UsageServerAuth, certv1.UsageClientAuth, certv1.UsageDigitalSignature, certv1.UsageKeyEncipherment}),

	Entry("Algorithm: RSAWithSize4096", "RSAWithSize4096", "RSAWithSize4096",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]certv1.KeyUsage{certv1.UsageServerAuth, certv1.UsageClientAuth, certv1.UsageDigitalSignature, certv1.UsageKeyEncipherment}),

	Entry("Algorithm: RSAWithSize8192", "RSAWithSize8192", "RSAWithSize8192",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]certv1.KeyUsage{certv1.UsageServerAuth, certv1.UsageClientAuth, certv1.UsageDigitalSignature, certv1.UsageKeyEncipherment}),

	Entry("Algorithm: ECDSAWithCurve256", "ECDSAWithCurve256", "ECDSAWithCurve256",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement,
		[]certv1.KeyUsage{certv1.UsageServerAuth, certv1.UsageClientAuth, certv1.UsageDigitalSignature, certv1.UsageKeyAgreement}),

	Entry("Algorithm: ECDSAWithCurve384", "ECDSAWithCurve384", "ECDSAWithCurve384",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement,
		[]certv1.KeyUsage{certv1.UsageServerAuth, certv1.UsageClientAuth, certv1.UsageDigitalSignature, certv1.UsageKeyAgreement}),

	Entry("Algorithm: ECDSAWithCurve521", "ECDSAWithCurve521", "ECDSAWithCurve521",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement,
		[]certv1.KeyUsage{certv1.UsageServerAuth, certv1.UsageClientAuth, certv1.UsageDigitalSignature, certv1.UsageKeyAgreement}),

	Entry("Empty string should default to RSAWithSize2048", "", "RSAWithSize2048",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]certv1.KeyUsage{certv1.UsageServerAuth, certv1.UsageClientAuth, certv1.UsageDigitalSignature, certv1.UsageKeyEncipherment}),

	Entry("Weird value should default to RSAWithSize2048", "weird value", "RSAWithSize2048",
		x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature,
		[]certv1.KeyUsage{certv1.UsageServerAuth, certv1.UsageClientAuth, certv1.UsageDigitalSignature, certv1.UsageKeyEncipherment}),
)
