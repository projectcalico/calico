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

package parser

import (
	"sort"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

type StringSet []uniquestr.Handle

// Contains returns true if a given string in current set
func (ss StringSet) Contains(s uniquestr.Handle) bool {
	// Defer to the binary search impl in the stdlib.  Note: it returns
	// the "insertion point" for inserting the given string, so we need to
	// check that the string really is there.
	idx := sort.Search(len(ss), func(i int) bool { return ss[i].Value() >= s.Value() })
	return idx < len(ss) && ss[idx] == s
}

// SliceCopy returns a new slice that contains the elements of the set in
// sorted order.
func (ss StringSet) SliceCopy() []uniquestr.Handle {
	if ss == nil {
		return nil
	}
	cp := make([]uniquestr.Handle, len(ss), len(ss))
	copy(cp, ss)
	return cp
}

func (ss StringSet) StringSlice() []string {
	if ss == nil {
		return nil
	}
	out := make([]string, len(ss), len(ss))
	for i, h := range ss {
		out[i] = h.Value()
	}
	return out
}

func ConvertToStringSetInPlace(s []uniquestr.Handle) StringSet {
	if len(s) <= 1 {
		// Nothing to do for nil, zero or a single-entry slice.
		return s
	}
	sort.Slice(s, func(i, j int) bool {
		return s[i].Value() < s[j].Value()
	})
	out := s[:1]
	for _, v := range s[1:] {
		if v == out[len(out)-1] {
			continue
		}
		out = append(out, v)
	}
	return out
}
