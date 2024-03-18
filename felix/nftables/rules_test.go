// Copyright (c) 2016-2022 Tigera, Inc. All rights reserved.
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

package nftables

import (
	"bytes"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
)

var (
	rules1 = []generictables.Rule{
		{Match: nftMatch{"-m foobar --foobar baz"}, Action: JumpAction{Target: "biff"}},
	}
	rules2 = []generictables.Rule{
		{Match: nftMatch{"-m foobar --foobar baz"}, Action: JumpAction{Target: "boff"}},
	}
	rules3 = []generictables.Rule{
		{Match: nftMatch{"-m foobar --foobar baz"}, Action: JumpAction{Target: "biff"}},
		{Match: nftMatch{"-m foobar --foobar baz"}, Action: JumpAction{Target: "boff"}},
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

var _ = Describe("rule comments", func() {
	Context("Rule with multiple comments", func() {
		rule := generictables.Rule{
			Match:   nftMatch{"-m foobar --foobar baz"},
			Action:  JumpAction{Target: "biff"},
			Comment: []string{"boz", "fizz"},
		}

		It("should render rule including multiple comments", func() {
			render := rule.RenderAppend("test", "TEST", renderInner, &environment.Features{})
			Expect(render).To(ContainSubstring("-m comment --comment \"boz\""))
			Expect(render).To(ContainSubstring("-m comment --comment \"fizz\""))
		})
	})

	Context("Rule with comment with newlines", func() {
		rule := generictables.Rule{
			Match:  nftMatch{"-m foobar --foobar baz"},
			Action: JumpAction{Target: "biff"},
			Comment: []string{`boz
fizz`},
		}

		It("should render rule with newline escaped", func() {
			render := rule.RenderAppend("test", "TEST", renderInner, &environment.Features{})
			Expect(render).To(ContainSubstring("-m comment --comment \"boz_fizz\""))
		})
	})

	Context("Rule with comment longer than 256 characters", func() {
		rule := generictables.Rule{
			Match:   nftMatch{"-m foobar --foobar baz"},
			Action:  JumpAction{Target: "biff"},
			Comment: []string{strings.Repeat("a", 257)},
		}

		It("should render rule with comment truncated", func() {
			render := rule.RenderAppend("test", "TEST", renderInner, &environment.Features{})
			Expect(render).To(ContainSubstring("-m comment --comment \"" + strings.Repeat("a", 256) + "\""))
		})
	})
})

func newClosableBuf(s string) *withDummyClose {
	return (*withDummyClose)(bytes.NewBufferString(s))
}

type withDummyClose bytes.Buffer

func (b *withDummyClose) Read(p []byte) (n int, err error) {
	return (*bytes.Buffer)(b).Read(p)
}

func (b *withDummyClose) Close() error {
	return nil
}

func calculateHashes(chainName string, rules []generictables.Rule) []string {
	chain := &generictables.Chain{
		Name:  chainName,
		Rules: rules,
	}
	return chain.RuleHashes(renderInner, &environment.Features{})
}
