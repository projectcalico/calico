// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	. "github.com/tigera/libcalico-go/lib/selector/tokenizer"

	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var tokenTests = []struct {
	input    string
	expected []Token
}{
	{`a=="b"`, []Token{
		{TokLabel, "a"},
		{TokEq, nil},
		{TokStringLiteral, "b"},
		{TokEof, nil},
	}},

	{`a=="b"`, []Token{
		{TokLabel, "a"},
		{TokEq, nil},
		{TokStringLiteral, "b"},
		{TokEof, nil},
	}},
	{`label == "value"`, []Token{
		{TokLabel, "label"},
		{TokEq, nil},
		{TokStringLiteral, "value"},
		{TokEof, nil},
	}},
	{`a not in "bar" && !has(foo) || b in c`, []Token{
		{TokLabel, "a"},
		{TokNotIn, nil},
		{TokStringLiteral, "bar"},
		{TokAnd, nil},
		{TokNot, nil},
		{TokHas, "foo"},
		{TokOr, nil},
		{TokLabel, "b"},
		{TokIn, nil},
		{TokLabel, "c"},
		{TokEof, nil},
	}},
	{`a  not  in  "bar"  &&  ! has( foo )  ||  b  in  c `, []Token{
		{TokLabel, "a"},
		{TokNotIn, nil},
		{TokStringLiteral, "bar"},
		{TokAnd, nil},
		{TokNot, nil},
		{TokHas, "foo"},
		{TokOr, nil},
		{TokLabel, "b"},
		{TokIn, nil},
		{TokLabel, "c"},
		{TokEof, nil},
	}},
	{`a notin"bar"&&!has(foo)||b in"c"`, []Token{
		{TokLabel, "a"},
		{TokNotIn, nil},
		{TokStringLiteral, "bar"},
		{TokAnd, nil},
		{TokNot, nil},
		{TokHas, "foo"},
		{TokOr, nil},
		{TokLabel, "b"},
		{TokIn, nil},
		{TokStringLiteral, "c"},
		{TokEof, nil},
	}},
	{`a not in {}`, []Token{
		{TokLabel, "a"},
		{TokNotIn, nil},
		{TokLBrace, nil},
		{TokRBrace, nil},
		{TokEof, nil},
	}},
	{`a not in {"a"}`, []Token{
		{TokLabel, "a"},
		{TokNotIn, nil},
		{TokLBrace, nil},
		{TokStringLiteral, "a"},
		{TokRBrace, nil},
		{TokEof, nil},
	}},
	{`a not in {"a","B"}`, []Token{
		{TokLabel, "a"},
		{TokNotIn, nil},
		{TokLBrace, nil},
		{TokStringLiteral, "a"},
		{TokComma, nil},
		{TokStringLiteral, "B"},
		{TokRBrace, nil},
		{TokEof, nil},
	}},
}

var _ = Describe("Token", func() {

	for _, test := range tokenTests {
		test := test // Take copy for closure
		It(fmt.Sprintf("should tokenize %#v as %v", test.input, test.expected), func() {
			Expect(Tokenize(test.input)).To(Equal(test.expected))
		})
	}
})
