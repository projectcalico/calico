// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package idalloc_test

import (
	. "github.com/projectcalico/calico/felix/idalloc"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("IndexAllocator", func() {

	var r *IndexAllocator

	BeforeEach(func() {
		By("constructing IndexAllocator")
		r = NewIndexAllocator(IndexRange{Min: 43, Max: 47})
		Expect(r).NotTo(BeNil())
	})

	It("provides mainline function as expected", func() {

		By("allocating the first index")
		idx, err := r.GrabIndex()
		Expect(err).NotTo(HaveOccurred())
		Expect(idx).To(Equal(43))

		By("allocating the next 4 available indices")
		for i := 44; i <= 47; i++ {
			idx, err = r.GrabIndex()
			Expect(err).NotTo(HaveOccurred())
			Expect(idx).To(Equal(i))
		}

		By("allocating when no more indices are available")
		_, err = r.GrabIndex()
		Expect(err).To(HaveOccurred())

		By("releasing and reallocating an index")
		r.ReleaseIndex(45)
		idx, err = r.GrabIndex()
		Expect(err).NotTo(HaveOccurred())
		Expect(idx).To(Equal(45))
	})

	It("GrabAllRemainingIndices works", func() {

		By("allocating the first index")
		idx, err := r.GrabIndex()
		Expect(err).NotTo(HaveOccurred())
		Expect(idx).To(Equal(43))

		By("grabbing all remaining indices")
		remaining := r.GrabAllRemainingIndices()
		Expect(remaining.Len()).To(BeNumerically("==", 4))

		By("allocating when no more indices are available")
		_, err = r.GrabIndex()
		Expect(err).To(HaveOccurred())
	})
})
