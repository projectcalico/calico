// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intervals

import (
	"math"
	"slices"
	"testing"
)

type pair = [2]uint16

func TestCoalesced(t *testing.T) {
	const top = math.MaxUint16
	tests := []struct {
		name string
		in   []pair
		want []pair
	}{
		{"empty", nil, nil},
		{"single port", []pair{{80, 80}}, []pair{{80, 80}}},
		{"duplicate ports", []pair{{80, 80}, {80, 80}, {80, 80}}, []pair{{80, 80}}},
		{"duplicate ranges", []pair{{10, 20}, {10, 20}}, []pair{{10, 20}}},
		{"adjacent ports", []pair{{2, 2}, {1, 1}, {3, 3}}, []pair{{1, 3}}},
		{"gap of one", []pair{{1, 1}, {3, 3}}, []pair{{1, 1}, {3, 3}}},
		{"overlapping", []pair{{81, 90}, {80, 81}}, []pair{{80, 90}}},
		{"partial overlap chain", []pair{{1, 5}, {4, 8}, {7, 12}}, []pair{{1, 12}}},
		{"contained", []pair{{1, 100}, {50, 60}, {99, 100}}, []pair{{1, 100}}},
		{"container added last", []pair{{50, 60}, {70, 80}, {1, 100}}, []pair{{1, 100}}},
		{"disjoint unsorted", []pair{{9090, 9090}, {1, 4}, {80, 90}}, []pair{{1, 4}, {80, 90}, {9090, 9090}}},
		{"full range", []pair{{0, top}}, []pair{{0, top}}},
		{"full range absorbs others", []pair{{80, 80}, {0, top}, {top, top}, {1000, 2000}}, []pair{{0, top}}},
		{"full range from pieces", []pair{{1, top}, {0, 0}}, []pair{{0, top}}},
		{"top port", []pair{{top, top}}, []pair{{top, top}}},
		{"adjacent at top", []pair{{top, top}, {top - 1, top - 1}}, []pair{{top - 1, top}}},
		{"overlapping at top", []pair{{top - 10, top}, {top - 5, top}, {top, top}}, []pair{{top - 10, top}}},
		{"zero", []pair{{0, 0}, {0, 0}}, []pair{{0, 0}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s Set[uint16]
			for _, p := range tt.in {
				s.Add(p[0], p[1])
			}
			if n := s.NumIntervals(); n != len(tt.want) {
				t.Errorf("NumIntervals() of %v = %d, want %d", tt.in, n, len(tt.want))
			}
			if got := collect(&s); !slices.Equal(got, tt.want) {
				t.Errorf("Coalesced() of %v = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestCoalescedIsRepeatable(t *testing.T) {
	var s Set[uint16]
	s.Add(3, 4)
	s.Add(1, 2)
	first := collect(&s)
	if second := collect(&s); !slices.Equal(first, second) {
		t.Errorf("second Coalesced() = %v, want %v", second, first)
	}
}

func TestAddAfterCoalesced(t *testing.T) {
	var s Set[uint16]
	s.Add(1, 2)
	s.Add(10, 12)
	_ = collect(&s)
	s.Add(3, 9)
	want := []pair{{1, 12}}
	if got := collect(&s); !slices.Equal(got, want) {
		t.Errorf("Coalesced() after Add = %v, want %v", got, want)
	}
}

func TestCoalescedEarlyBreak(t *testing.T) {
	var s Set[uint16]
	s.Add(1, 1)
	s.Add(3, 3)
	for range s.Coalesced() {
		break
	}
}

func TestAddInvalidPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Add(5, 4) did not panic")
		}
	}()
	var s Set[uint16]
	s.Add(5, 4)
}

// FuzzCoalesced checks against a bitmap over the whole uint8 domain.
func FuzzCoalesced(f *testing.F) {
	f.Add([]byte{0, 255})
	f.Add([]byte{1, 2, 3, 4, 255, 255, 0, 0})
	f.Add([]byte{10, 20, 15, 25, 26, 26, 28, 30})
	f.Fuzz(func(t *testing.T, data []byte) {
		var s Set[uint8]
		var want [256]bool
		for i := 0; i+1 < len(data); i += 2 {
			lo, hi := min(data[i], data[i+1]), max(data[i], data[i+1])
			s.Add(lo, hi)
			for v := int(lo); v <= int(hi); v++ {
				want[v] = true
			}
		}

		var got [256]bool
		prevMax := -2
		for lo, hi := range s.Coalesced() {
			if int(lo) <= prevMax+1 {
				t.Fatalf("interval [%d, %d] overlaps or abuts previous max %d", lo, hi, prevMax)
			}
			for v := int(lo); v <= int(hi); v++ {
				got[v] = true
			}
			prevMax = int(hi)
		}
		if got != want {
			t.Fatalf("Coalesced() coverage differs from input; input pairs %v", data)
		}
	})
}

func collect(s *Set[uint16]) []pair {
	var out []pair
	for lo, hi := range s.Coalesced() {
		out = append(out, pair{lo, hi})
	}
	return out
}
