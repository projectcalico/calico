// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package hash_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/libcalico-go/lib/hash"
)

func TestHash(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Hash Suite")
}

var _ = Describe("MakeUniqueID", func() {
	It("should include prefix in output", func() {
		result := MakeUniqueID("test", "content")
		Expect(result).To(HavePrefix("test:"))
	})

	It("should produce deterministic output", func() {
		result1 := MakeUniqueID("prefix", "content")
		result2 := MakeUniqueID("prefix", "content")
		Expect(result1).To(Equal(result2))
	})

	It("should produce different outputs for different content", func() {
		result1 := MakeUniqueID("prefix", "content1")
		result2 := MakeUniqueID("prefix", "content2")
		Expect(result1).NotTo(Equal(result2))
	})

	It("should produce different outputs for different prefixes", func() {
		result1 := MakeUniqueID("prefix1", "content")
		result2 := MakeUniqueID("prefix2", "content")
		Expect(result1).NotTo(Equal(result2))
	})

	It("should handle empty content", func() {
		result := MakeUniqueID("prefix", "")
		Expect(result).To(HavePrefix("prefix:"))
		Expect(len(result)).To(BeNumerically(">", len("prefix:")))
	})

	It("should handle empty prefix", func() {
		result := MakeUniqueID("", "content")
		Expect(result).To(HavePrefix(":"))
		Expect(len(result)).To(BeNumerically(">", 1))
	})

	It("should produce base64-encoded hash", func() {
		result := MakeUniqueID("test", "content")
		hashPart := result[len("test:"):]
		// SHA224 produces 28 bytes, base64.RawURLEncoding produces 38 characters
		Expect(len(hashPart)).To(Equal(38))
	})
})

var _ = Describe("GetLengthLimitedID", func() {
	It("should return the suffix if short enough", func() {
		Expect(GetLengthLimitedID("felix", "1234", 10)).To(Equal("felix1234"))
	})
	It("should return the suffix if exact length without _ prefix", func() {
		Expect(GetLengthLimitedID("felix", "123456", 11)).To(Equal("felix123456"))
	})
	It("should return the hash if exact length with _ prefix", func() {
		Expect(GetLengthLimitedID("felix", "_2345", 10)).To(Equal("felix_kMQI"))
	})
	It("should return the hash if too long prefix", func() {
		Expect(GetLengthLimitedID("felix", "12345678910", 13)).To(Equal("felix_Y2QCZIS"))
	})
	It("should treat empty suffix as shortenedPrefix", func() {
		Expect(GetLengthLimitedID("felix", "", 10)).To(Equal("felix_"))
	})
	It("should panic when maxLength is too small to hold prefix + shortened hash", func() {
		Expect(func() {
			GetLengthLimitedID("felix", "toolong", 6)
		}).To(Panic())
	})
})
