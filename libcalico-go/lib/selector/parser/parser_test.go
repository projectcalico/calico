// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.

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

package parser_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

type selectorTest struct {
	sel           string
	expMatches    []map[string]string
	expNonMatches []map[string]string
}

var selectorTests = []selectorTest{
	{`a == "b"`,
		[]map[string]string{
			{"a": "b"},
			{"a": "b", "c": "d"}},
		[]map[string]string{
			{},
			{"a": "c"},
			{"c": "d"},
		}},
	{`a == "b" && c == "d"`,
		[]map[string]string{
			{"a": "b", "c": "d"}},
		[]map[string]string{
			{},
			{"a": "b", "c": "e"},
			{"a": "c", "c": "d"},
			{"c": "d"},
			{"a": "b"},
		}},
	{`a == "b" || c == "d"`,
		[]map[string]string{
			{"a": "b", "c": "d"},
			{"a": "b"},
			{"c": "d"}},
		[]map[string]string{
			{},
			{"a": "e", "c": "e"},
			{"c": "e"},
			{"a": "e"},
		}},
	{`a in {"'", '"', "c"}`,
		[]map[string]string{
			{"a": "c"},
			{"a": `"`},
			{"a": `'`},
		},
		[]map[string]string{
			{},
			{"a": "e"},
		}},
	{`a not in {"'", '"', "c"}`,
		[]map[string]string{
			{},
			{"a": "e"},
		},
		[]map[string]string{
			{"a": "c"},
			{"a": `"`},
			{"a": `'`},
		}},

	{`a == 'a'`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`a == "a"`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`a != "b"`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`a != "a"`, []map[string]string{{}}, []map[string]string{}},
	{`a contains "a"`, []map[string]string{
		{"a": "a"},
		{"a": "bab"},
		{"a": "aaa", "b": "c"},
	}, []map[string]string{
		{},
		{"a": "b"},
		{"b": "aaa"},
	}},
	{`a starts with "a"`, []map[string]string{
		{"a": "a"},
		{"a": "abb"},
		{"a": "aaa", "b": "c"},
	}, []map[string]string{
		{},
		{"a": "b"},
		{"a": "baa"},
		{"b": "aaa"},
	}},
	{`a ends with "a"`, []map[string]string{
		{"a": "a"},
		{"a": "bba"},
		{"a": "aaa", "b": "c"},
	}, []map[string]string{
		{},
		{"a": "b"},
		{"a": "aab"},
		{"b": "aaa"},
	}},
	{`a in {"a"}`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`!a in {"a"}`, []map[string]string{{"a": "b"}}, []map[string]string{}},
	{`a in {"a", "b"}`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`a in {"a", "b"}`, []map[string]string{{"a": "b"}}, []map[string]string{}},
	{`a not in {"d", "e"}`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`has(a)`, []map[string]string{{"a": "b"}}, []map[string]string{}},
	{`!has(a)`, []map[string]string{{"b": "b"}}, []map[string]string{}},
	{``, []map[string]string{{}}, []map[string]string{}},
	{` `, []map[string]string{{}}, []map[string]string{}},
	{``, []map[string]string{{"a": "b"}}, []map[string]string{}},
	{`all()`, []map[string]string{{}}, []map[string]string{}},
	{` all()`, []map[string]string{{}}, []map[string]string{}},
	{` all()`, []map[string]string{{"a": "b"}}, []map[string]string{}},
	{`global()`, []map[string]string{{}}, []map[string]string{}},
	{` global()`, []map[string]string{{}}, []map[string]string{}},
	{` global()`, []map[string]string{{"a": "b"}}, []map[string]string{}},

	{`a == 'a'`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`a == 'a'`, []map[string]string{}, []map[string]string{{}}},
	{`a != "a"`, []map[string]string{}, []map[string]string{{"a": "a"}}},
	{`a != 'a'`, []map[string]string{}, []map[string]string{{"a": "a"}}},
	{`a in {"a"}`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`a not in {"a"}`, []map[string]string{}, []map[string]string{{"a": "a"}}},
	{`a in {"a", "b"}`, []map[string]string{}, []map[string]string{{"a": "c"}}},
	{`has(b)`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`!!has(b)`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`! has(a)`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`!has(a)`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`!!! has(a)`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`!!!has(a)`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`!! ! has(a)`, []map[string]string{}, []map[string]string{{"a": "b"}}},
	{`! !!has(a)`, []map[string]string{}, []map[string]string{{"a": "b"}}},

	// Boolean expressions...
	{`a == 'a1' && b == 'b1'`, []map[string]string{{"a": "a1", "b": "b1"}}, []map[string]string{}},
	{`a == 'a1' && b != 'b1'`, []map[string]string{}, []map[string]string{{"a": "a1", "b": "b1"}}},
	{`a != 'a1' && b == 'b1'`, []map[string]string{}, []map[string]string{{"a": "a1", "b": "b1"}}},
	{`a != 'a1' && b != 'b1'`, []map[string]string{}, []map[string]string{{"a": "a1", "b": "b1"}}},
	{`a != 'a1' && !b == 'b1'`, []map[string]string{}, []map[string]string{{"a": "a1", "b": "b1"}}},
	{`!a == 'a1' && b == 'b1'`, []map[string]string{}, []map[string]string{{"a": "a1", "b": "b1"}}},
	{`has(a) && !has(b)`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`!has(b) && has(a)`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`!(!has(a) || has(b))`, []map[string]string{{"a": "a"}}, []map[string]string{}},
	{`!(has(b) || !has(a))`, []map[string]string{{"a": "a"}}, []map[string]string{}},

	{`a == 'a1' || b == 'b1'`, []map[string]string{{"a": "a1", "b": "b1"}}, []map[string]string{}},
	{`a == 'a1' || b != 'b1'`, []map[string]string{{"a": "a1", "b": "b1"}}, []map[string]string{}},
	{`a != 'a1' || b == 'b1'`, []map[string]string{{"a": "a1", "b": "b1"}}, []map[string]string{}},
	{`a != 'a1' || b != 'b1'`, []map[string]string{}, []map[string]string{{"a": "a1", "b": "b1"}}},
	{`! a == 'a1' || ! b == 'b1'`, []map[string]string{}, []map[string]string{{"a": "a1", "b": "b1"}}},
}

var badSelectors = []string{
	"b == b",          // label == label
	"b contains b",    // label contains label
	"b starts with b", // label starts with label
	"b ends with b",   // label starts with label
	"'b1' == b",       // literal on lhs
	"b",               // bare label
	"a b",             // Garbage
	"!",               // Garbage
	`foo == "bar" &`,  // Garbage
	`foo == "bar" |`,  // Garbage
	`foo != ||`,       // Garbage
	`foo in {"", ||`,  // Garbage
	`foo in ""`,       // Expect set literal
	`"FOO`,            // Unterminated string
	`"FOO'`,           // Unterminated string
	`"FOO`,            // Unterminated string
	`'FOO`,            // Unterminated string
	`(`,               // Unterminated paren
	`(a == "foo"`,     // Unterminated paren
	`)`,               // Unterminated paren
	`()`,              // Unterminated paren
	`%`,               // Unexpected char
	`a == "b" && %`,   // Unexpected char
	`a == "b" || %`,   // Unexpected char
	`a `,              // should be followed by operator
	`has(foo) &&`,     // should be followed by operator
}

var canonicalisationTests = []struct {
	input       string
	expected    string
	expectedUid string
}{
	{"", "all()", "s:5y5I3VdRZfDU01O--xXAPx2yxCQQqMf0M6IWug"},
	{" all() ", "all()", "s:5y5I3VdRZfDU01O--xXAPx2yxCQQqMf0M6IWug"},
	{" (all() )", "all()", "s:5y5I3VdRZfDU01O--xXAPx2yxCQQqMf0M6IWug"},
	{`! (has( b)||! has(a ))`, "!(has(b) || !has(a))", "s:Iss0uCleLYv1GSv_pNm7hAO58kE9jAx1NKyG3Q"},
	{`! (a == "b"&&! c != "d")`, `!(a == "b" && !c != "d")`, "s:lh3haoY1ikTRkd4UZu0nWSaIBknYLPJLX16d-w"},
	// Double negations cancel, with or without parentheses between them.
	{`!!has(a)`, `has(a)`, ""},
	{`!(!has(a))`, `has(a)`, ""},
	{`!(!(!has(a)))`, `!has(a)`, ""},
	{`!(!(a == "b" || c == "d"))`, `(a == "b" || c == "d")`, ""},
	{`a == "'"`, `a == "'"`, ""},
	{`a == '"'`, `a == '"'`, ""},
	{`a contains '"'`, `a contains '"'`, ""},
	{`a contains "'"`, `a contains "'"`, ""},
	{`a startswith '"'`, `a starts with '"'`, ""},
	{`a endswith "'"`, `a ends with "'"`, ""},
	{`a!='"'`, `a != '"'`, ""},
	// Set items get sorted/de-duped.
	{`a in {"d"}`, `a in {"d"}`, ""},
	{`a in {"a", "b"}`, `a in {"a", "b"}`, ""},
	{`a in {"d", "a", "b"}`, `a in {"a", "b", "d"}`, ""},
	{`a in {"z", "x", "y", "a"}`, `a in {"a", "x", "y", "z"}`, ""},
	{`a in {"z", "z", "x", "y", "x", "a"}`, `a in {"a", "x", "y", "z"}`, ""},
}

var _ = Describe("Parser", func() {
	for _, test := range selectorTests {
		var test = test // Take copy of variable for the closure.
		Context(fmt.Sprintf("selector %#v", test.sel), func() {
			var sel *parser.Selector
			var err error
			BeforeEach(func() {
				sel, err = parser.Parse(test.sel)
				Expect(err).To(BeNil())
				err = parser.Validate(test.sel, parser.MaxAPIDepth)
				Expect(err).To(BeNil())
			})
			It("should match", func() {
				for _, labels := range test.expMatches {
					By(fmt.Sprintf("%#v matching %v", test.sel, labels))
					Expect(sel.Evaluate(labels)).To(BeTrue())
				}
			})
			It("should not match", func() {
				for _, labels := range test.expNonMatches {
					By(fmt.Sprintf("%#v not matching %v", test.sel, labels))
					Expect(sel.Evaluate(labels)).To(BeFalse())
				}
			})
			It("should match after canonicalising", func() {
				for _, labels := range test.expMatches {
					sel2, err := parser.Parse(sel.String())
					Expect(err).To(BeNil())
					By(fmt.Sprintf("%#v matching %v", test.sel, labels))
					Expect(sel2.Evaluate(labels)).To(BeTrue())
				}
			})
			It("should not match after canonicalising", func() {
				for _, labels := range test.expNonMatches {
					sel2, err := parser.Parse(sel.String())
					Expect(err).To(BeNil())
					By(fmt.Sprintf("%#v not matching %v", test.sel, labels))
					Expect(sel2.Evaluate(labels)).To(BeFalse())
				}
			})
			It("should give same UID on each call", func() {
				Expect(sel.UniqueID()).To(Equal(sel.UniqueID()))
			})
		})
	}

	It("Should reject bad selector", func() {
		for _, sel := range badSelectors {
			By(fmt.Sprint("Rejecting Parse()", sel))
			_, err := parser.Parse(sel)
			Expect(err).To(HaveOccurred())

			By(fmt.Sprint("Rejecting Validate()", sel))
			err = parser.Validate(sel, parser.MaxAPIDepth)
			Expect(err).To(HaveOccurred())
		}
	})

	DescribeTable("nesting depth limit",
		func(sel string, expParseErr, expAPIErr error) {
			expectErr := func(err, expErr error) {
				if expErr == nil {
					ExpectWithOffset(1, err).NotTo(HaveOccurred())
				} else {
					ExpectWithOffset(1, err).To(MatchError(expErr))
				}
			}

			_, err := parser.Parse(sel)
			expectErr(err, expParseErr)
			expectErr(parser.Validate(sel, parser.MaxParseDepth), expParseErr)
			expectErr(parser.Validate(sel, parser.MaxAPIDepth), expAPIErr)
		},
		Entry("parens at the API limit", nestedParens(parser.MaxAPIDepth), nil, nil),
		Entry("parens just over the API limit", nestedParens(parser.MaxAPIDepth+1), nil, parser.ErrNestingTooDeep),
		Entry("parens at the parse limit", nestedParens(parser.MaxParseDepth), nil, parser.ErrNestingTooDeep),
		Entry("parens just over the parse limit", nestedParens(parser.MaxParseDepth+1), parser.ErrNestingTooDeep, parser.ErrNestingTooDeep),
		Entry("parens far over the parse limit", nestedParens(1_000_000), parser.ErrNestingTooDeep, parser.ErrNestingTooDeep),
		Entry("ORs at the API limit", nestedOrs(parser.MaxAPIDepth), nil, nil),
		Entry("ORs just over the API limit", nestedOrs(parser.MaxAPIDepth+1), nil, parser.ErrNestingTooDeep),
		Entry("ORs at the parse limit", nestedOrs(parser.MaxParseDepth), nil, parser.ErrNestingTooDeep),
		Entry("ORs just over the parse limit", nestedOrs(parser.MaxParseDepth+1), parser.ErrNestingTooDeep, parser.ErrNestingTooDeep),
		Entry("ORs far over the parse limit", nestedOrs(10_000), parser.ErrNestingTooDeep, parser.ErrNestingTooDeep),
	)

	It("should allow a selector at the API limit to double in depth when re-rendered", func() {
		// String() parenthesises every && and || node, so alternating them
		// doubles the depth.
		sel := "a == 'x'"
		for range parser.MaxAPIDepth {
			sel = fmt.Sprintf("a == 'x' || b == 'y' && (%s)", sel)
		}
		Expect(parser.Validate(sel, parser.MaxAPIDepth)).To(Succeed())
		parsed, err := parser.Parse(sel)
		Expect(err).NotTo(HaveOccurred())

		_, err = parser.Parse(parsed.String())
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("And and Inverted should match parsing the equivalent string",
		func(a, b string) {
			mustParse := func(s string) *parser.Selector {
				sel, err := parser.Parse(s)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())
				return sel
			}
			expectSame := func(actual *parser.Selector, expected string) {
				ExpectWithOffset(1, actual.String()).To(Equal(mustParse(expected).String()))
				ExpectWithOffset(1, actual.UniqueID()).To(Equal(mustParse(expected).UniqueID()))
			}
			parsedA, parsedB := mustParse(a), mustParse(b)

			expectSame(parsedB.Inverted(), fmt.Sprintf("!(%s)", b))
			expectSame(parsedB.Inverted().Inverted(), b)
			expectSame(parsedA.And(parsedB), fmt.Sprintf("(%s) && (%s)", a, b))
			// Redundant parentheses don't affect the parsed form.
			expectSame(parsedA.And(parsedB.Inverted()), fmt.Sprintf("(%s) && (!(%s))", a, b))
			expectSame(parsedA.And(parsedB.Inverted()), fmt.Sprintf("(%s) && !(%s)", a, b))
		},
		Entry("simple", "a == 'b'", "has(c)"),
		Entry("all()", "all()", "all()"),
		Entry("ANDs", "a == 'b' && c == 'd'", "e == 'f' && g == 'h'"),
		Entry("ORs", "a == 'b' || c == 'd'", "e == 'f' || g == 'h'"),
		Entry("negations", "!has(a)", "!has(b)"),
		Entry("double negations", "!!has(a)", "!!has(b)"),
		Entry("parenthesised double negations", "!(!has(a))", "!(!has(b))"),
	)

	for _, test := range canonicalisationTests {
		It(fmt.Sprintf("should canonicalise %v as %v with UID %v and round-trip",
			test.input, test.expected, test.expectedUid), func() {
			sel, err := parser.Parse(test.input)
			Expect(err).To(BeNil())
			canon := sel.String()
			Expect(canon).To(Equal(test.expected))
			roundTripped, err := parser.Parse(canon)
			Expect(err).To(BeNil())
			Expect(roundTripped.String()).To(Equal(canon))
			uid := sel.UniqueID()
			Expect(roundTripped.UniqueID()).To(Equal(uid))
		})
	}

	for _, test := range canonicalisationTests {
		if test.expectedUid == "" {
			continue
		}
		It(fmt.Sprintf("should calculate the correct UID for %s", test.input), func() {
			sel, err := parser.Parse(test.input)
			Expect(err).To(BeNil())
			Expect(sel.UniqueID()).To(Equal(test.expectedUid),
				"incorrect UID for "+test.input)
			Expect(sel.UniqueID()).To(Equal(sel.UniqueID()),
				"inconsistent UID for "+test.input)
		})
	}
})

// nestedParens returns "((...(all())...))" with the given nesting depth.
func nestedParens(depth int) string {
	return strings.Repeat("(", depth) + "all()" + strings.Repeat(")", depth)
}

// nestedOrs returns "(n == '1' || (n == '2' || ... n == '<depth>'))" with the
// given nesting depth.
func nestedOrs(depth int) string {
	sel := fmt.Sprintf("n == '%d'", depth)
	for i := depth - 1; i >= 0; i-- {
		sel = fmt.Sprintf("(n == '%d' || %s)", i, sel)
	}
	return sel
}

var _ = Describe("Visitor", func() {

	testVisitor := parser.PrefixVisitor{Prefix: "visited/"}

	DescribeTable("Visitor tests",
		func(inSelector, outSelector string, visitor parser.Visitor) {
			s, err := parser.Parse(inSelector)
			By(fmt.Sprintf("parsing the selector %s", inSelector), func() {
				Expect(err).NotTo(HaveOccurred())
			})
			err = parser.Validate(inSelector, parser.MaxAPIDepth)
			By(fmt.Sprintf("validating the selector %s", inSelector), func() {
				Expect(err).NotTo(HaveOccurred())
			})

			// Run the visitor against the selector.
			s.AcceptVisitor(visitor)

			By("generating the correct output selector", func() {
				Expect(s.String()).To(Equal(outSelector))
			})
		},

		Entry("should visit a LabelEqValueNode", "k == 'v'", "visited/k == \"v\"", testVisitor),
		Entry("should visit a LabelNeValueNode", "k != 'v'", "visited/k != \"v\"", testVisitor),
		Entry("should visit a LabelContainsValueNode", "k contains 'v'", "visited/k contains \"v\"", testVisitor),
		Entry("should visit a LabelStartWithValueNode", "k starts with 'v'", "visited/k starts with \"v\"", testVisitor),
		Entry("should visit a LabelEndsWithValueNode", "k ends with 'v'", "visited/k ends with \"v\"", testVisitor),
		Entry("should visit an AndNode", "k == 'v' && x == 'y'", "(visited/k == \"v\" && visited/x == \"y\")", testVisitor),
		Entry("should visit an OrNode", "k == 'v' || has(x)", "(visited/k == \"v\" || has(visited/x))", testVisitor),
		Entry("should visit a NotNode", "!(k == 'v')", "!visited/k == \"v\"", testVisitor),
		Entry("should visit a LabelInSetNode", "k in {'v'}", "visited/k in {\"v\"}", testVisitor),
		Entry("should visit a LabelNotInSetNode", "k not in {'v'}", "visited/k not in {\"v\"}", testVisitor),
		Entry("should visit a big complex selector",
			"!(!(k == 'v' && has(t) || all()) && (a in {'b', 'c'}))",
			"!(!((visited/k == \"v\" && has(visited/t)) || all()) && visited/a in {\"b\", \"c\"})",
			testVisitor,
		),
	)
})
