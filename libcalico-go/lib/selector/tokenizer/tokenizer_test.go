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
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/tokenizer"
)

var tokenTests = []struct {
	input    string
	expected []tokenizer.Token
}{
	{`a=="b"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a!="b"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNe},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a != "b"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNe},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokEOF},
	}},
	{`(a=="b")`, []tokenizer.Token{
		{Kind: tokenizer.TokLParen},
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokRParen},
		{Kind: tokenizer.TokEOF},
	}},

	{`a=="b"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label == "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label contains "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokContains},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`contains contains "contains"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "contains"},
		{Kind: tokenizer.TokContains},
		{Kind: tokenizer.TokStringLiteral, Value: "contains"},
		{Kind: tokenizer.TokEOF},
	}},
	{`contains contains 'contains'`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "contains"},
		{Kind: tokenizer.TokContains},
		{Kind: tokenizer.TokStringLiteral, Value: "contains"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label contains"value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokContains},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label startswith "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokStartsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label endswith "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokEndsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label starts with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokStartsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`startswith starts with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "startswith"},
		{Kind: tokenizer.TokStartsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label ends with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokEndsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`endswith ends with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "endswith"},
		{Kind: tokenizer.TokEndsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label starts  with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokStartsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label ends  with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokEndsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{strings.Repeat("a", 512) + ` == "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: strings.Repeat("a", 512)},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{strings.Repeat("a", 513) + ` == "value"`, nil},
	{`label == "value`, nil},
	{`label == 'value`, nil},
	{`label = "value"`, nil},
	{`all(`, nil},
	{`global(`, nil},
	{`has()`, nil},
	{`has(foo`, nil},
	{`has( foo `, nil},
	{`a == "b" & has(foo)`, nil},
	{`a == "b" | has(foo)`, nil},
	{`label starts foo "value"`, nil},
	{`label inf "value"`, nil},
	{`label ends foo "value"`, nil},
	{`label ends withs "value"`, nil},
	{`label squiggles "value"`, nil},
	{`a not in "bar" && !has(foo) || b in c`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokStringLiteral, Value: "bar"},
		{Kind: tokenizer.TokAnd},
		{Kind: tokenizer.TokNot},
		{Kind: tokenizer.TokHas, Value: "foo"},
		{Kind: tokenizer.TokOr},
		{Kind: tokenizer.TokLabel, Value: "b"},
		{Kind: tokenizer.TokIn},
		{Kind: tokenizer.TokLabel, Value: "c"},
		{Kind: tokenizer.TokEOF},
	}},
	{`has(calico/k8s_ns)`, []tokenizer.Token{
		{Kind: tokenizer.TokHas, Value: "calico/k8s_ns"},
		{Kind: tokenizer.TokEOF},
	}},
	{`has(calico/k8s_ns/role)`, []tokenizer.Token{
		{Kind: tokenizer.TokHas, Value: "calico/k8s_ns/role"},
		{Kind: tokenizer.TokEOF},
	}},
	{`has(calico/k8s_NS-.1/role)`, []tokenizer.Token{
		{Kind: tokenizer.TokHas, Value: "calico/k8s_NS-.1/role"},
		{Kind: tokenizer.TokEOF},
	}},
	{`calico/k8s_ns == "kube-system" && k8s-app == "kube-dns"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "calico/k8s_ns"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "kube-system"},
		{Kind: tokenizer.TokAnd},
		{Kind: tokenizer.TokLabel, Value: "k8s-app"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "kube-dns"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a  not  in  "bar"  &&  ! has( foo )  ||  b  in  c `, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokStringLiteral, Value: "bar"},
		{Kind: tokenizer.TokAnd},
		{Kind: tokenizer.TokNot},
		{Kind: tokenizer.TokHas, Value: "foo"},
		{Kind: tokenizer.TokOr},
		{Kind: tokenizer.TokLabel, Value: "b"},
		{Kind: tokenizer.TokIn},
		{Kind: tokenizer.TokLabel, Value: "c"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a notin"bar"&&!has(foo)||b in"c"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokStringLiteral, Value: "bar"},
		{Kind: tokenizer.TokAnd},
		{Kind: tokenizer.TokNot},
		{Kind: tokenizer.TokHas, Value: "foo"},
		{Kind: tokenizer.TokOr},
		{Kind: tokenizer.TokLabel, Value: "b"},
		{Kind: tokenizer.TokIn},
		{Kind: tokenizer.TokStringLiteral, Value: "c"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a not in {}`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokLBrace},
		{Kind: tokenizer.TokRBrace},
		{Kind: tokenizer.TokEOF},
	}},
	{`a not in {"a"}`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokLBrace},
		{Kind: tokenizer.TokStringLiteral, Value: "a"},
		{Kind: tokenizer.TokRBrace},
		{Kind: tokenizer.TokEOF},
	}},
	{`a not in {"a","B"}`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokLBrace},
		{Kind: tokenizer.TokStringLiteral, Value: "a"},
		{Kind: tokenizer.TokComma},
		{Kind: tokenizer.TokStringLiteral, Value: "B"},
		{Kind: tokenizer.TokRBrace},
		{Kind: tokenizer.TokEOF},
	}},
	{`global()`, []tokenizer.Token{
		{Kind: tokenizer.TokGlobal},
		{Kind: tokenizer.TokEOF},
	}},
	{`global( )`, []tokenizer.Token{
		{Kind: tokenizer.TokGlobal},
		{Kind: tokenizer.TokEOF},
	}},
	{`all()`, []tokenizer.Token{
		{Kind: tokenizer.TokAll},
		{Kind: tokenizer.TokEOF},
	}},
	{`all( )`, []tokenizer.Token{
		{Kind: tokenizer.TokAll},
		{Kind: tokenizer.TokEOF},
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
			It(fmt.Sprintf("should tokenize <%s> as %v", test.input, test.expected), func() {
				tokens, err := tokenizer.Tokenize(test.input)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokens).To(Equal(test.expected), fmt.Sprintf("Expected: %s\nGot: %s", test.expected, tokens))
			})
		}
	}
})
