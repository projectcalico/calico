// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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


package iptables_test

import (
	. "github.com/projectcalico/felix/go/felix/iptables"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	rulesFragments1 = []string{
		"-m foobar --foobar baz --jump biff",
	}
	rulesFragments2 = []string{
		"-m foobar --foobar baz --jump boff",
	}
	rulesFragments3 = []string{
		"-m foobar --foobar baz --jump biff",
		"-m foobar --foobar baz --jump boff",
	}
)

var _ = Describe("Rule hashing tests", func() {
	It("should generate different hashes for different rules", func() {
		hashes1 := RuleHashes("chain", rulesFragments1)
		hashes2 := RuleHashes("chain", rulesFragments2)
		Expect(hashes1).NotTo(Equal(hashes2))
	})
	It("should generate same hash for prefix to same chain", func() {
		hashes1 := RuleHashes("chain", rulesFragments1)
		hashes2 := RuleHashes("chain", rulesFragments3)
		Expect(hashes1[0]).To(Equal(hashes2[0]))
	})
	It("should generate different hashes for different chains with same rules", func() {
		hashes1 := RuleHashes("chain", rulesFragments1)
		hashes2 := RuleHashes("chain2", rulesFragments1)
		Expect(hashes1).NotTo(Equal(hashes2))
	})
	It("should generate different hashes for same rule at different position", func() {
		hashes2 := RuleHashes("chain", rulesFragments2)
		hashes3 := RuleHashes("chain", rulesFragments3)
		Expect(hashes2[0]).NotTo(Equal(hashes3[1]))
	})
	It("should generate a slice of same length as input", func() {
		Expect(len(RuleHashes("foo", rulesFragments1))).To(Equal(len(rulesFragments1)))
		Expect(len(RuleHashes("foo", rulesFragments2))).To(Equal(len(rulesFragments2)))
		Expect(len(RuleHashes("foo", rulesFragments3))).To(Equal(len(rulesFragments3)))
	})
})
