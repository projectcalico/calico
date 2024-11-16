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
		{tokenizer.TokEq, nil},
		{tokenizer.TokStringLiteral, "b"},
		{tokenizer.TokEOF, nil},
	}},

	{`a=="b"`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokEq, nil},
		{tokenizer.TokStringLiteral, "b"},
		{tokenizer.TokEOF, nil},
	}},
	{`label == "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokEq, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`label contains "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokContains, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`contains contains "contains"`, []tokenizer.Token{
		{tokenizer.TokLabel, "contains"},
		{tokenizer.TokContains, nil},
		{tokenizer.TokStringLiteral, "contains"},
		{tokenizer.TokEOF, nil},
	}},
	{`contains contains 'contains'`, []tokenizer.Token{
		{tokenizer.TokLabel, "contains"},
		{tokenizer.TokContains, nil},
		{tokenizer.TokStringLiteral, "contains"},
		{tokenizer.TokEOF, nil},
	}},
	{`label contains"value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokContains, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`label startswith "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokStartsWith, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`label endswith "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokEndsWith, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`label starts with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokStartsWith, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`startswith starts with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "startswith"},
		{tokenizer.TokStartsWith, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`label ends with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokEndsWith, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`endswith ends with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "endswith"},
		{tokenizer.TokEndsWith, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`label starts  with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokStartsWith, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`label ends  with "value"`, []tokenizer.Token{
		{tokenizer.TokLabel, "label"},
		{tokenizer.TokEndsWith, nil},
		{tokenizer.TokStringLiteral, "value"},
		{tokenizer.TokEOF, nil},
	}},
	{`label starts foo "value"`, nil},
	{`label ends foo "value"`, nil},
	{`label squiggles "value"`, nil},
	{`a not in "bar" && !has(foo) || b in c`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, nil},
		{tokenizer.TokStringLiteral, "bar"},
		{tokenizer.TokAnd, nil},
		{tokenizer.TokNot, nil},
		{tokenizer.TokHas, "foo"},
		{tokenizer.TokOr, nil},
		{tokenizer.TokLabel, "b"},
		{tokenizer.TokIn, nil},
		{tokenizer.TokLabel, "c"},
		{tokenizer.TokEOF, nil},
	}},
	{`has(calico/k8s_ns)`, []tokenizer.Token{
		{tokenizer.TokHas, "calico/k8s_ns"},
		{tokenizer.TokEOF, nil},
	}},
	{`has(calico/k8s_ns/role)`, []tokenizer.Token{
		{tokenizer.TokHas, "calico/k8s_ns/role"},
		{tokenizer.TokEOF, nil},
	}},
	{`has(calico/k8s_NS-.1/role)`, []tokenizer.Token{
		{tokenizer.TokHas, "calico/k8s_NS-.1/role"},
		{tokenizer.TokEOF, nil},
	}},
	{`calico/k8s_ns == "kube-system" && k8s-app == "kube-dns"`, []tokenizer.Token{
		{tokenizer.TokLabel, "calico/k8s_ns"},
		{tokenizer.TokEq, nil},
		{tokenizer.TokStringLiteral, "kube-system"},
		{tokenizer.TokAnd, nil},
		{tokenizer.TokLabel, "k8s-app"},
		{tokenizer.TokEq, nil},
		{tokenizer.TokStringLiteral, "kube-dns"},
		{tokenizer.TokEOF, nil},
	}},
	{`a  not  in  "bar"  &&  ! has( foo )  ||  b  in  c `, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, nil},
		{tokenizer.TokStringLiteral, "bar"},
		{tokenizer.TokAnd, nil},
		{tokenizer.TokNot, nil},
		{tokenizer.TokHas, "foo"},
		{tokenizer.TokOr, nil},
		{tokenizer.TokLabel, "b"},
		{tokenizer.TokIn, nil},
		{tokenizer.TokLabel, "c"},
		{tokenizer.TokEOF, nil},
	}},
	{`a notin"bar"&&!has(foo)||b in"c"`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, nil},
		{tokenizer.TokStringLiteral, "bar"},
		{tokenizer.TokAnd, nil},
		{tokenizer.TokNot, nil},
		{tokenizer.TokHas, "foo"},
		{tokenizer.TokOr, nil},
		{tokenizer.TokLabel, "b"},
		{tokenizer.TokIn, nil},
		{tokenizer.TokStringLiteral, "c"},
		{tokenizer.TokEOF, nil},
	}},
	{`a not in {}`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, nil},
		{tokenizer.TokLBrace, nil},
		{tokenizer.TokRBrace, nil},
		{tokenizer.TokEOF, nil},
	}},
	{`a not in {"a"}`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, nil},
		{tokenizer.TokLBrace, nil},
		{tokenizer.TokStringLiteral, "a"},
		{tokenizer.TokRBrace, nil},
		{tokenizer.TokEOF, nil},
	}},
	{`a not in {"a","B"}`, []tokenizer.Token{
		{tokenizer.TokLabel, "a"},
		{tokenizer.TokNotIn, nil},
		{tokenizer.TokLBrace, nil},
		{tokenizer.TokStringLiteral, "a"},
		{tokenizer.TokComma, nil},
		{tokenizer.TokStringLiteral, "B"},
		{tokenizer.TokRBrace, nil},
		{tokenizer.TokEOF, nil},
	}},
	{`global()`, []tokenizer.Token{
		{tokenizer.TokGlobal, nil},
		{tokenizer.TokEOF, nil},
	}},
	{`all()`, []tokenizer.Token{
		{tokenizer.TokAll, nil},
		{tokenizer.TokEOF, nil},
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
			It(fmt.Sprintf("should tokenize %#v as %v", test.input, test.expected), func() {
				Expect(tokenizer.Tokenize(test.input)).To(Equal(test.expected))
			})
		}
	}
})
