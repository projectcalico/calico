// Copyright (c) 2016, 2019 Tigera, Inc. All rights reserved.

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

package tokenizer_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/tokenizer"
)

var tokenTests = []struct {
	input    string
	expected []tokenizer.Token
}{
	{`a=="b"`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokEq, ""},
		{tokenizer.TokStringLiteral, "b"},
		{tokenizer.TokEOF, ""},
	}},

	{`a=="b"`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokEq, ""},
		{tokenizer.TokStringLiteral, "b"},
		{tokenizer.TokEOF, ""},
	}},
	{`label == "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokEq, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`label contains "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokContains, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`contains contains "contains"`, []tokenizer.Token{
		{tokenizer.TokLabel, "contains"},
		{tokenizer.TokContains, ""},
		{tokenizer.TokStringLiteral, "contains"},
		{tokenizer.TokEOF, ""},
	}},
	{`contains contains 'contains'`, []tokenizer.Token{
		{tokenizer.TokLabel, "contains"},
		{tokenizer.TokContains, ""},
		{tokenizer.TokStringLiteral, "contains"},
		{tokenizer.TokEOF, ""},
	}},
	{`label contains"value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokContains, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`label startswith "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokStartsWith, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`label endswith "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokEndsWith, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`label starts with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokStartsWith, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`startswith starts with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "startswith"},
		{tokenizer.TokStartsWith, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`label ends with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokEndsWith, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`endswith ends with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "endswith"},
		{tokenizer.TokEndsWith, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`label starts  with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokStartsWith, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`label ends  with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokEndsWith, ""},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, ""},
	}},
	{`label starts foo "value"`, nil},
	{`label ends foo "value"`, nil},
	{`label squiggles "value"`, nil},
	{`a not in "bar" && !has(foo) || b in c`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, ""},
		{tokenizer.TokStringLiteral, "bar"},
		{tokenizer.TokAnd, ""},
		{tokenizer.TokNot, ""},
		{tokenizer.TokHas, "foo"},
		{tokenizer.TokOr, ""},
		{tokenizer.TokLabel, "b"},
		{tokenizer.TokIn, ""},
		{tokenizer.TokLabel, "c"},
		{tokenizer.TokEOF, ""},
	}},
	{`has(calico/k8s_ns)`, []tokenizer.Token{
		{tokenizer.TokHas, "calico/k8s_ns"},
		{tokenizer.TokEOF, ""},
	}},
	{`has(calico/k8s_ns/role)`, []tokenizer.Token{
		{tokenizer.TokHas, "calico/k8s_ns/role"},
		{tokenizer.TokEOF, ""},
	}},
	{`has(calico/k8s_NS-.1/role)`, []tokenizer.Token{
		{tokenizer.TokHas, "calico/k8s_NS-.1/role"},
		{tokenizer.TokEOF, ""},
	}},
	{`calico/k8s_ns == "kube-system" && k8s-app == "kube-dns"`, []tokenizer.Token{
		{tokenizer.TokLabel, "calico/k8s_ns"},
		{tokenizer.TokEq, ""},
		{tokenizer.TokStringLiteral, "kube-system"},
		{tokenizer.TokAnd, ""},
		{tokenizer.TokLabel, "k8s-app"},
		{tokenizer.TokEq, ""},
		{tokenizer.TokStringLiteral, "kube-dns"},
		{tokenizer.TokEOF, ""},
	}},
	{`a  not  in  "bar"  &&  ! has( foo )  ||  b  in  c `, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, ""},
		{tokenizer.TokStringLiteral, "bar"},
		{tokenizer.TokAnd, ""},
		{tokenizer.TokNot, ""},
		{tokenizer.TokHas, "foo"},
		{tokenizer.TokOr, ""},
		{tokenizer.TokLabel, "b"},
		{tokenizer.TokIn, ""},
		{tokenizer.TokLabel, "c"},
		{tokenizer.TokEOF, ""},
	}},
	{`a notin"bar"&&!has(foo)||b in"c"`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, ""},
		{tokenizer.TokStringLiteral, "bar"},
		{tokenizer.TokAnd, ""},
		{tokenizer.TokNot, ""},
		{tokenizer.TokHas, "foo"},
		{tokenizer.TokOr, ""},
		{tokenizer.TokLabel, "b"},
		{tokenizer.TokIn, ""},
		{tokenizer.TokStringLiteral, "c"},
		{tokenizer.TokEOF, ""},
	}},
	{`a not in {}`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, ""},
		{tokenizer.TokLBrace, ""},
		{tokenizer.TokRBrace, ""},
		{tokenizer.TokEOF, ""},
	}},
	{`a not in {"a"}`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, ""},
		{tokenizer.TokLBrace, ""},
		{tokenizer.TokStringLiteral, "a"},
		{tokenizer.TokRBrace, ""},
		{tokenizer.TokEOF, ""},
	}},
	{`a not in {"a","B"}`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, ""},
		{tokenizer.TokLBrace, ""},
		{tokenizer.TokStringLiteral, "a"},
		{tokenizer.TokComma, ""},
		{tokenizer.TokStringLiteral, "B"},
		{tokenizer.TokRBrace, ""},
		{tokenizer.TokEOF, ""},
	}},
	{`global()`, []tokenizer.Token{
		{tokenizer.TokGlobal, ""},
		{tokenizer.TokEOF, ""},
	}},
	{`all()`, []tokenizer.Token{
		{tokenizer.TokAll, ""},
		{tokenizer.TokEOF, ""},
	}},
}

var _ = Describe("Token", func() {
	for _, test := range tokenTests {
		test := test // Take copy for closure
		if test.expected == nil {
			It(fmt.Sprintf("should return error for input %#v", test.input), func() {
				_, err := tokenizer.Tokenize(test.input)
				Expect(err).To(HaveOccurred())
			})
		} else {
			It(fmt.Sprintf("should tokenize %s as %v", test.input, test.expected), func() {
				tokens, err := tokenizer.Tokenize(test.input)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokens).To(Equal(test.expected), fmt.Sprintf("Got: %s", tokens))
			})
		}
	}
})
