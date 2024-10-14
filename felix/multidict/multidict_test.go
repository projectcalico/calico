// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package multidict_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/multidict"
)

var _ = Describe("StringToString", func() {
	var s2s Multidict[string, string]
	BeforeEach(func() {
		s2s = New[string, string]()
		s2s.Put("a", "b")
		s2s.Put("a", "c")
		s2s.Put("b", "d")
	})
	It("should contain items that are added", func() {
		Expect(s2s.Contains("a", "b")).To(BeTrue())
		Expect(s2s.Contains("a", "c")).To(BeTrue())
		Expect(s2s.Contains("b", "d")).To(BeTrue())
		Expect(s2s.ContainsKey("a")).To(BeTrue())
		Expect(s2s.ContainsKey("b")).To(BeTrue())
	})
	It("should not contain items with different key", func() {
		Expect(s2s.Contains("b", "b")).To(BeFalse())
		Expect(s2s.ContainsKey("c")).To(BeFalse())
	})
	It("should not contain items with different value", func() {
		Expect(s2s.Contains("a", "a")).To(BeFalse())
	})
	It("should not contain discarded item", func() {
		s2s.Discard("a", "b")
		Expect(s2s.Contains("a", "b")).To(BeFalse())
		Expect(s2s.ContainsKey("a")).To(BeTrue())
		s2s.Discard("a", "c")
		Expect(s2s.ContainsKey("a")).To(BeFalse())
	})
	It("should ignore discard of unknown item", func() {
		s2s.Discard("a", "c")
		s2s.Discard("e", "f")
		Expect(s2s.Contains("a", "b")).To(BeTrue())
	})
	It("should have idempotent insert", func() {
		s2s.Put("a", "b")
		Expect(s2s.Contains("a", "b")).To(BeTrue())
	})
	It("should have idempotent discard", func() {
		s2s.Discard("a", "b")
		s2s.Discard("a", "b")
		Expect(s2s.Contains("a", "b")).To(BeFalse())
	})
})
