// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package tls

import (
	"crypto/tls"
	"testing"

	. "github.com/onsi/gomega"
)

func TestTLSCipherParsing(t *testing.T) {
	RegisterTestingT(t)
	testCases := []struct {
		ciphersName       string
		expectedCiphersID []uint16
		errorExpected     bool
	}{
		{"", DefaultCiphers(), false},
		{
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384",
			[]uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
			false,
		},
		{"madeup-cipher", nil, true},
	}

	for _, testCase := range testCases {
		ciphersID, err := ParseTLSCiphers(testCase.ciphersName)
		Expect(err != nil).To(Equal(testCase.errorExpected))
		Expect(ciphersID).To(Equal(testCase.expectedCiphersID))
	}
}
