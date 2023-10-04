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

import "sort"

type StringSet []string

// Contains returns true if a given string in current set
func (ss StringSet) Contains(s string) bool {
	// Defer to the binary search impl in the stdlib.  Note: it returns
	// the "insertion point" for inserting the given string, so we need to
	// check that the string really is there.
	idx := sort.SearchStrings(ss, s)
	return idx < len(ss) && ss[idx] == s
}

// SliceCopy returns a new slice that contains the elements of the set in
// sorted order.
func (ss StringSet) SliceCopy() []string {
	if ss == nil {
		return nil
	}
	cp := make([]string, len(ss), len(ss))
	copy(cp, ss)
	return cp
}

func ConvertToStringSetInPlace(s []string) StringSet {
	if len(s) <= 1 {
		// Nothing to do for nil, zero or a single-entry slice.
		return s
	}
	sort.Strings(s)
	out := s[:1]
	for _, v := range s[1:] {
		if v == out[len(out)-1] {
			continue
		}
		out = append(out, v)
	}
	return out
}
