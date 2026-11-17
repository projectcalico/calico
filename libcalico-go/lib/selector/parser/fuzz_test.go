// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"slices"
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/tokenizer"
)

// fuzzSeeds covers each operator, alone and negated, mixed with && and ||
// at different nesting levels.
var fuzzSeeds = []string{
	`all()`, `!all()`, `global()`, `!global()`, `has(a)`, `!has(a)`,
	`a == "x"`, `a != 'x'`, `a in {"x", 'y'}`, `a not in {"x"}`,
	`a contains "x"`, `a starts with "x"`, `a ends with "x"`,
	`!a in {"x"}`, `!a not in {"x"}`, `!a contains "x"`, `!a starts with 'x'`, `!a ends with "x"`,
	`projectcalico.org/namespace == "ns" && k8s-app == 'web'`,
	`a == "x" || b == "y" && c == "z"`,
	`(a == "x" || b == "y") && c == "z"`,
	`!(a == "x" && !(b == "y" || !has(c)))`,
	`!(!a == "x" || !(!b in {"y"} && !c contains "z"))`,
	`!!!!has(a)`, `!(!(!(!has(a))))`, `!!(!!(has(a)))`, `!(!!(!has(a)))`,
	`!(has(a) || !(has(b) && !(has(c) || !has(d))))`,
	`(((has(a))))`, `!((!(has(a))))`, `((!has(a)) && (!(!has(b))))`,
	`has(a) && (has(b) || (has(c) && (has(d) || has(e))))`,
	`global() && !all() || !global() && all()`,
	`a == "'" && b == '"' || c in {"'", '"'}`,
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	for _, t := range selectorTests {
		f.Add(t.sel)
	}
	for _, s := range badSelectors {
		f.Add(s)
	}
	for _, t := range canonicalisationTests {
		f.Add(t.input)
	}
	f.Add(nestedOrs(10))
	f.Add(nestedParens(10))
	f.Add(nestedOrs(parser.MaxAPIDepth))
	f.Add(nestedAlternating(parser.MaxAPIDepth))

	f.Fuzz(func(t *testing.T, s string) {
		sel, parseErr := parser.Parse(s)
		validateErr := parser.Validate(s, parser.MaxParseDepth)
		if (parseErr == nil) != (validateErr == nil) {
			t.Fatalf("Parse and Validate disagree on %q: Parse: %v, Validate: %v", s, parseErr, validateErr)
		}
		// Only API-valid selectors are guaranteed to survive re-rendering
		// within MaxParseDepth.
		if parser.Validate(s, parser.MaxAPIDepth) != nil {
			return
		}

		rendered := sel.String()
		if err := parser.Validate(rendered, 2*parser.MaxAPIDepth+4); err != nil {
			t.Fatalf("String() of %q is %q, which is too deep: %v", s, rendered, err)
		}
		assertRoundTrips(t, s, sel)
		assertSameID(t, s+" inverted twice", sel.Inverted().Inverted(), sel)

		// The empty selector can't be parenthesised.
		if toks, _ := tokenizer.Tokenize(s); len(toks) == 1 {
			s = "all()"
		}
		labelSets := labelSetsFor(rendered)
		equivalents := []struct {
			src  string
			want *parser.Selector
		}{
			{"(" + s + ")", sel},
			{"!!(" + s + ")", sel},
			{"!(!(" + s + "))", sel},
			{"!(" + s + ")", sel.Inverted()},
			{"!!!(" + s + ")", sel.Inverted()},
			{"(" + s + ") && (" + s + ")", sel.And(sel)},
			{"(" + s + ") && !(" + s + ")", sel.And(sel.Inverted())},
		}
		for _, e := range equivalents {
			parsed, err := parser.Parse(e.src)
			if err != nil {
				t.Fatalf("%q doesn't parse: %v", e.src, err)
			}
			assertSameID(t, e.src, parsed, e.want)
			assertRoundTrips(t, e.src, e.want)
			for _, labels := range labelSets {
				if parsed.Evaluate(labels) != e.want.Evaluate(labels) {
					t.Fatalf("%q and %q disagree on %v", e.src, e.want.String(), labels)
				}
			}
		}

		for _, labels := range labelSets {
			matches := sel.Evaluate(labels)
			if sel.Inverted().Evaluate(labels) == matches {
				t.Fatalf("%q and its inverse %q agree on %v", rendered, sel.Inverted().String(), labels)
			}
			if sel.And(sel.Inverted()).Evaluate(labels) {
				t.Fatalf("%q && its inverse matches %v", rendered, labels)
			}
			reparsed, _ := parser.Parse(rendered)
			if reparsed.Evaluate(labels) != matches {
				t.Fatalf("%q and its String() %q disagree on %v", s, rendered, labels)
			}
		}
	})
}

// nestedAlternating returns a selector with the given nesting depth that
// alternates || and &&, which String() renders about twice as deep.
func nestedAlternating(depth int) string {
	sel := "all()"
	for range depth {
		sel = fmt.Sprintf("a == 'x' || b == 'y' && (%s)", sel)
	}
	return sel
}

// labelSetsFor returns label sets built from the labels and values that a
// selector mentions, so that its clauses evaluate both ways.
func labelSetsFor(selector string) []map[string]string {
	const maxNames = 6
	toks, _ := tokenizer.Tokenize(selector)
	var labels, values []string
	for _, tok := range toks {
		switch tok.Kind {
		case tokenizer.TokLabel, tokenizer.TokHas:
			if !slices.Contains(labels, tok.Value) && len(labels) < maxNames {
				labels = append(labels, tok.Value)
			}
		case tokenizer.TokStringLiteral:
			if !slices.Contains(values, tok.Value) && len(values) < maxNames {
				values = append(values, tok.Value)
			}
		}
	}
	values = append(values, "")

	sets := []map[string]string{{}}
	for _, v := range values {
		for _, variant := range []string{v, v + "x", "x" + v} {
			set := map[string]string{}
			for _, l := range labels {
				set[l] = variant
			}
			sets = append(sets, set)
		}
	}
	// Give each label a different value, and leave each one out in turn.
	for offset := range max(len(labels), len(values)) {
		set := map[string]string{}
		for i, l := range labels {
			if i != offset {
				set[l] = values[(i+offset)%len(values)]
			}
		}
		sets = append(sets, set)
	}
	return sets
}

func FuzzLabelEquals(f *testing.F) {
	f.Add("a", "b")
	f.Add("projectcalico.org/namespace", "ns")
	f.Add("a", `b'c`)
	f.Add("a", `b"c`)
	f.Add("a", `b\c`)
	f.Add("a", "")

	f.Fuzz(func(t *testing.T, label, value string) {
		sel, err := parser.LabelEquals(label, value)
		if err != nil {
			return
		}
		assertRoundTrips(t, label+" == "+value, sel)
		if !sel.Evaluate(map[string]string{label: value}) {
			t.Fatalf("LabelEquals(%q, %q) = %q doesn't match its own label", label, value, sel.String())
		}
	})
}

// assertRoundTrips checks that sel's String() parses back to the same
// selector.
func assertRoundTrips(t *testing.T, desc string, sel *parser.Selector) {
	t.Helper()
	rendered := sel.String()
	reparsed, err := parser.Parse(rendered)
	if err != nil {
		t.Fatalf("String() of %q is %q, which doesn't parse: %v", desc, rendered, err)
	}
	if reparsed.String() != rendered {
		t.Fatalf("String() of %q is %q, which re-renders as %q", desc, rendered, reparsed.String())
	}
	assertSameID(t, "String() of "+desc, reparsed, sel)
}

func assertSameID(t *testing.T, desc string, got, want *parser.Selector) {
	t.Helper()
	if got.UniqueID() != want.UniqueID() {
		t.Fatalf("%s: got %q (%s), want %q (%s)",
			desc, got.String(), got.UniqueID(), want.String(), want.UniqueID())
	}
}
