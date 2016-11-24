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

package iptables

import (
	"bytes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	rules1 = []Rule{
		{Match: MatchCriteria{"-m foobar --foobar baz"}, Action: JumpAction{"biff"}},
	}
	rules2 = []Rule{
		{Match: MatchCriteria{"-m foobar --foobar baz"}, Action: JumpAction{"boff"}},
	}
	rules3 = []Rule{
		{Match: MatchCriteria{"-m foobar --foobar baz"}, Action: JumpAction{"biff"}},
		{Match: MatchCriteria{"-m foobar --foobar baz"}, Action: JumpAction{"boff"}},
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

var _ = Describe("Hash extraction tests", func() {
	var table *Table

	BeforeEach(func() {
		table = NewTable("filter", 4, []string{"felix-", "cali"}, "cali:")
	})

	It("should extract an old felix rule with no hash", func() {
		hashes := table.getHashesFromBuffer(bytes.NewBufferString("-A FORWARD -j felix-FORWARD\n"))
		Expect(hashes).To(Equal(map[string][]string{
			"FORWARD": []string{"OLD INSERT RULE"},
		}))
	})
	It("should extract a hash", func() {
		hashes := table.getHashesFromBuffer(bytes.NewBufferString(
			"-A FORWARD -m comment --comment \"cali:wUHhoiAYhphO9Mso\" -j cali-FORWARD\n"))
		Expect(hashes).To(Equal(map[string][]string{
			"FORWARD": []string{"wUHhoiAYhphO9Mso"},
		}))
	})
})

func calculateHashes(chainName string, rules []Rule) []string {
	chain := &Chain{
		Name:  chainName,
		Rules: rules,
	}
	return chain.RuleHashes()
}
