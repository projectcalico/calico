// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package set_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Set differences", func() {
	It("should get appropriate callbacks for IterDifferences", func() {
		By("Creating two sets with different contents")
		s1 := set.From[string]("a", "b", "c", "d")
		s2 := set.From[string]("c", "d", "e", "1")

		By("Iterating through differences and storing results")
		s1NotS2 := set.New[string]()
		s2NotS1 := set.New[string]()

		set.IterDifferences[string](s1, s2,
			func(diff string) error {
				s1NotS2.Add(diff)
				return nil
			},
			func(diff string) error {
				s2NotS1.Add(diff)
				return nil
			},
		)

		By("Checking the results")
		Expect(s1NotS2).To(Equal(set.From[string]("a", "b")))
		Expect(s2NotS1).To(Equal(set.From[string]("e", "1")))
	})
})
