// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package yaml

import (
	"bytes"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Copyright 2014 The Kubernetes Authors.
// The test cases were originally written in:
// https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apimachinery/pkg/util/yaml/decoder_test.go
// and modified to use the Ginkgo testing framework
var _ = Describe("Test splitYAMLDocument", func() {
	It("should not split up full documents without separators", func() {
		ValidateSplitYAMLDocument("foo", true, "foo", 3)
	})

	It("should not return anything without a separator and not at the EOF", func() {
		ValidateSplitYAMLDocument("fo", false, "", 0)
	})

	It("should return part of YAML separator at EOF", func() {
		ValidateSplitYAMLDocument("---", true, "---", 3)
	})

	It("should return something similar to YAML separator with newline at EOF", func() {
		ValidateSplitYAMLDocument("---\n", true, "---\n", 4)
	})

	It("should not return something similar to YAML separator if not at EOF", func() {
		ValidateSplitYAMLDocument("---\n", false, "", 0)
	})

	It("should not return yaml separator before EOF but advance the bytes read", func() {
		ValidateSplitYAMLDocument("\n---\n", false, "", 5)
	})

	It("should not return yaml separator at EOF but advance the bytes read", func() {
		ValidateSplitYAMLDocument("\n---\n", true, "", 5)
	})

	It("should split out and read the first document in multiple documents", func() {
		ValidateSplitYAMLDocument("abc\n---\ndef", true, "abc", 8)
	})

	It("should split out and read the first document in a large doc without separators", func() {
		// Just shy of 10MB, which is the limit:
		doc := strings.Repeat("0123456789abcdef", 65535)
		ValidateSplitYAMLDocument(doc, true, doc, len(doc))
	})

	It("should split out and read the first document in a compound large doc", func() {
		// Just shy of 10MB, which is the limit:
		firstDoc := strings.Repeat("0123456789abcdef", 65535)
		docs := firstDoc + "\n---\ndef"
		ValidateSplitYAMLDocument(docs, true, firstDoc, len(firstDoc)+5)
	})

	It("should read the rest of the multiple documents at the EOF", func() {
		ValidateSplitYAMLDocument("def", true, "def", 3)
	})

	It("should read nothing from an empty file", func() {
		ValidateSplitYAMLDocument("", true, "", 0)
	})
})

func ValidateSplitYAMLDocument(input string, atEOF bool, expect string, advAmt int) {
	adv, token, err := splitYAMLDocument([]byte(input), atEOF)
	Expect(err).NotTo(HaveOccurred())
	Expect(expect).To(Equal(string(token)))
	Expect(advAmt).To(Equal(adv))
}

var _ = Describe("Test YAML Separator Next", func() {
	Context("with 2 YAML documents in one file", func() {
		reader := bytes.NewReader([]byte(testYAMLDocFull))
		separator := NewYAMLDocumentSeparator(reader)

		var doc []byte
		var err error
		BeforeEach(func() {
			doc, err = separator.Next()
		})

		It("should correctly separate the first document and return it", func() {
			Expect(err).NotTo(HaveOccurred())
			Expect(bytes.Equal([]byte(testYAMLDoc1), doc)).To(Equal(true))
		})

		It("should correctly separate the second document and return it", func() {
			Expect(err).NotTo(HaveOccurred())
			Expect(bytes.Equal([]byte(testYAMLDoc2), doc)).To(Equal(true))
		})

		It("should return an EOF error when there is nothing left", func() {
			Expect(err).To(HaveOccurred())
			Expect(len(doc)).To(Equal(0))
		})
	})
})

const testYAMLDoc1 = `
a: TestFieldA
b: TestFieldB
c:
  c1: TestFieldC1
  c2: TestFieldC2`

const testYAMLDoc2 = `
d: TestFieldD
e: TestFieldE
f:
  - name: TestFieldFListItem1
  - name: TestFieldFListItem2`

const testYAMLDocFull = testYAMLDoc1 + `
---
` + testYAMLDoc2
