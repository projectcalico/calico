// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
