// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ipsets

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ipsets"
)

var _ = Describe("MockIPSets interval semantics", func() {
	var ipSets *MockIPSets

	addSet := func(setType ipsets.IPSetType, members ...string) {
		ipSets.AddOrReplaceIPSet(ipsets.IPSetMetadata{
			MaxSize: 1024,
			SetID:   "pools",
			Type:    setType,
		}, members)
	}

	BeforeEach(func() {
		ipSets = NewMockIPSets()
	})

	It("should reject a hash:net member covered by an existing member", func() {
		addSet(ipsets.IPSetTypeHashNet, "10.0.0.0/16")
		Expect(InterceptGomegaFailure(func() {
			ipSets.AddMembers("pools", []string{"10.0.1.0/24"})
		})).To(HaveOccurred())
	})

	It("should reject a hash:net member covering an existing member", func() {
		addSet(ipsets.IPSetTypeHashNet, "10.0.0.0/16")
		Expect(InterceptGomegaFailure(func() {
			ipSets.AddMembers("pools", []string{"10.0.0.0/8"})
		})).To(HaveOccurred())
	})

	It("should reject overlapping members in the initial contents", func() {
		Expect(InterceptGomegaFailure(func() {
			addSet(ipsets.IPSetTypeHashNet, "10.0.0.0/16", "10.0.1.0/24")
		})).To(HaveOccurred())
	})

	It("should tolerate an exact duplicate in the initial contents", func() {
		Expect(InterceptGomegaFailure(func() {
			addSet(ipsets.IPSetTypeHashNet, "10.0.0.0/16", "10.0.0.0/16")
		})).NotTo(HaveOccurred())
	})

	It("should accept a disjoint hash:net member", func() {
		addSet(ipsets.IPSetTypeHashNet, "10.0.0.0/16")
		Expect(InterceptGomegaFailure(func() {
			ipSets.AddMembers("pools", []string{"10.1.0.0/16", "feed:beef::/96"})
		})).NotTo(HaveOccurred())
	})

	It("should not apply interval semantics to a hash:net,net set", func() {
		addSet(ipsets.IPSetTypeHashNetNet, "10.0.0.0/16,10.1.0.0/16")
		Expect(InterceptGomegaFailure(func() {
			ipSets.AddMembers("pools", []string{"10.0.1.0/24,10.1.0.0/16"})
		})).NotTo(HaveOccurred())
	})
})
