// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
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

package iputils

import (
	"sort"
	"testing"

	. "github.com/onsi/gomega"
)

func TestIntersectCIDRs(t *testing.T) {
	for _, test := range []struct {
		Name        string
		as, bs, exp []string
	}{
		{"zero", []string{"0.0.0.0/0"}, []string{"128.0.0.0/1", "0.0.0.0/1"}, []string{"128.0.0.0/1", "0.0.0.0/1"}},
		{"self", []string{"10.0.0.1"}, []string{"10.0.0.1"}, []string{"10.0.0.1/32"}},
		{"different format", []string{"10.0.0.1/32"}, []string{"10.0.0.1"}, []string{"10.0.0.1/32"}},
		{"smallest wins", []string{"10.0.1.0/24"}, []string{"10.0.1.128/25"}, []string{"10.0.1.128/25"}},
		{"non-match", []string{"10.0.1.0/24"}, []string{"10.0.2.0/24"}, nil},
		{
			"some matches",
			[]string{"10.0.1.0/24", "10.1.0.0/16"},
			[]string{"10.0.2.0/24", "10.0.1.1/32", "10.0.1.2/32", "11.0.1.1/32", "10.0.1.128/26",
				"10.1.2.0/24"},
			[]string{"10.0.1.1/32", "10.0.1.2/32", "10.0.1.128/26", "10.1.2.0/24"},
		},
		{
			"overlap in both directions",
			[]string{"10.0.1.0/24", "10.0.2.1/32"},
			[]string{"10.0.2.0/24", "10.0.1.1/32"},
			[]string{"10.0.1.1/32", "10.0.2.1/32"},
		},
	} {
		test := test
		sort.Strings(test.as)
		sort.Strings(test.bs)
		sort.Strings(test.exp)

		t.Run(test.Name, func(t *testing.T) {
			RegisterTestingT(t)
			cidrs := IntersectCIDRs(test.as, test.bs)
			sort.Strings(cidrs)
			Expect(cidrs).To(Equal(test.exp))

			// Intersection should be commutative.
			t.Run("as and bs reversed", func(t *testing.T) {
				RegisterTestingT(t)
				cidrs := IntersectCIDRs(test.bs, test.as)
				sort.Strings(cidrs)
				Expect(cidrs).To(Equal(test.exp))
			})
		})
	}
}
