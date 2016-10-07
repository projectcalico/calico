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

func (ss StringSet) Contains(s string) bool {
	if len(ss) == 0 {
		return false
	}
	min := 0
	max := len(ss)
	for min < (max - 1) {
		partitionIdx := (min + max) / 2
		partition := ss[partitionIdx]
		if s < partition {
			max = partitionIdx
		} else {
			min = partitionIdx
		}
	}
	return ss[min] == s
}

func AsStringSet(s []string) StringSet {
	if s != nil {
		sort.Strings(s)
	}
	return StringSet(s)
}
