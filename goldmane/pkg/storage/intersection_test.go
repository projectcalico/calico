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

package storage

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestSortedCSVIntersection(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected string
	}{
		{name: "identical", a: "a,b,c", b: "a,b,c", expected: "a,b,c"},
		{name: "complete overlap", a: "a,b,c", b: "a,b,c,d", expected: "a,b,c"},
		{name: "partial overlap", a: "a,c,e", b: "b,c,d,e", expected: "c,e"},
		{name: "no overlap", a: "a,b", b: "c,d", expected: ""},
		{name: "empty a", a: "", b: "a,b", expected: ""},
		{name: "empty b", a: "a,b", b: "", expected: ""},
		{name: "both empty", a: "", b: "", expected: ""},
		{name: "single element match", a: "x", b: "x", expected: "x"},
		{name: "single element no match", a: "x", b: "y", expected: ""},
		{
			name:     "realistic labels",
			a:        "app=frontend,env=prod,team=platform,tier=web",
			b:        "app=frontend,env=staging,team=platform,tier=web",
			expected: "app=frontend,team=platform,tier=web",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedCSVIntersection(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("sortedCSVIntersection(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// naiveCSVIntersection is the old O(n*m) implementation, preserved here so we can
// benchmark it against the sorted merge.
func naiveCSVIntersection(a, b string) string {
	if a == "" || b == "" {
		return ""
	}
	av := strings.Split(a, ",")
	bv := strings.Split(b, ",")
	common := make([]string, 0)
	for _, v := range av {
		if slices.Contains(bv, v) {
			common = append(common, v)
		}
	}
	return strings.Join(common, ",")
}

// buildSortedCSV generates a sorted, comma-separated string of n labels like "key-00=val-00,...".
func buildSortedCSV(n int) string {
	parts := make([]string, n)
	for i := range n {
		parts[i] = fmt.Sprintf("key-%02d=val-%02d", i, i)
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

// buildSortedCSVWithOffset generates labels where every other label is shifted, giving ~50% overlap
// with the output of buildSortedCSV.
func buildSortedCSVWithOffset(n int) string {
	parts := make([]string, n)
	for i := range n {
		if i%2 == 0 {
			parts[i] = fmt.Sprintf("key-%02d=val-%02d", i, i)
		} else {
			parts[i] = fmt.Sprintf("key-%02d=other-%02d", i, i)
		}
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

func BenchmarkCSVIntersection(b *testing.B) {
	for _, n := range []int{5, 10, 20} {
		a := buildSortedCSV(n)
		bStr := buildSortedCSVWithOffset(n)

		b.Run(fmt.Sprintf("naive/%d_labels", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				naiveCSVIntersection(a, bStr)
			}
		})

		b.Run(fmt.Sprintf("sorted_merge/%d_labels", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				sortedCSVIntersection(a, bStr)
			}
		})
	}
}
