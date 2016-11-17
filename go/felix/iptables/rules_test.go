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
	rules1 = []Rule{
		{"-m foobar --foobar baz", "--jump biff"},
	}
	rules2 = []Rule{
		{"-m foobar --foobar baz", "--jump boff"},
	}
	rules3 = []Rule{
		{"-m foobar --foobar baz", "--jump biff"},
		{"-m foobar --foobar baz", "--jump biff"},
	}
)

var _ = Describe("Rule hashing tests", func() {
	It("should generate different hashes for different rules", func() {
		hashes1 := calculateHashes("chain", rules1)
		hashes2 := calculateHashes("chain", rules2)
		Expect(hashes1).NotTo(Equal(hashes2))
	})
	It("should generate same hash for prefix to same chain", func() {
		hashes1 := calculateHashes("chain", rules1)
		hashes2 := calculateHashes("chain", rules3)
		Expect(hashes1[0]).To(Equal(hashes2[0]))
	})
	It("should generate different hashes for different chains with same rules", func() {
		hashes1 := calculateHashes("chain", rules1)
		hashes2 := calculateHashes("chain2", rules1)
		Expect(hashes1).NotTo(Equal(hashes2))
	})
	It("should generate different hashes for same rule at different position", func() {
		hashes2 := calculateHashes("chain", rules2)
		hashes3 := calculateHashes("chain", rules3)
		Expect(hashes2[0]).NotTo(Equal(hashes3[1]))
	})
	It("should generate a slice of same length as input", func() {
		Expect(len(calculateHashes("foo", rules1))).To(Equal(len(rules1)))
		Expect(len(calculateHashes("foo", rules2))).To(Equal(len(rules2)))
		Expect(len(calculateHashes("foo", rules3))).To(Equal(len(rules3)))
	})
})

func calculateHashes(chainName string, rules []Rule) []string {
	chain := &Chain{
		Name:  chainName,
		Rules: rules,
	}
	return chain.RuleHashes()
}
