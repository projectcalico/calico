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

	Context("happy path", func() {
		BeforeEach(func() {
			By("constructing IndexAllocator")
			r = NewIndexAllocator(IndexRange{Min: 43, Max: 47}, IndexRange{Min: 2, Max: 4})
			Expect(r).NotTo(BeNil())
		})

		It("provides mainline function as expected", func() {

			By("allocating the first index")
			idx, err := r.GrabIndex()
			Expect(err).NotTo(HaveOccurred())
			Expect(idx).To(Equal(2))

			By("allocating the next 7 available indices")
			for i := 3; i <= 4; i++ {
				idx, err = r.GrabIndex()
				Expect(err).NotTo(HaveOccurred())
				Expect(idx).To(Equal(i))
			}
			for i := 43; i <= 47; i++ {
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
			Expect(idx).To(Equal(2))

			By("grabbing all remaining indices")
			remaining := r.GrabAllRemainingIndices()
			Expect(remaining.Len()).To(BeNumerically("==", 7))

			By("allocating when no more indices are available")
			_, err = r.GrabIndex()
			Expect(err).To(HaveOccurred())
		})
	})

	Context("allocator init with non-ideal ranges", func() {
		It("should remove duplicates caused by overlapping ranges", func() {
			By("constructing IndexAllocator with overlapping ranges")
			r = NewIndexAllocator(IndexRange{Min: 3, Max: 5}, IndexRange{Min: 2, Max: 2}, IndexRange{Min: 2, Max: 6}) // expected to be sorted and truncated to [2,3,4,5,6]
			Expect(r).NotTo(BeNil())

			By("allocating the first index")
			idx, err := r.GrabIndex()
			Expect(err).NotTo(HaveOccurred())
			Expect(idx).To(Equal(2))

			By("allocating the next 4 indices")
			for i := 3; i <= 6; i++ {
				idx, err := r.GrabIndex()
				Expect(err).NotTo(HaveOccurred())
				Expect(idx).To(Equal(i))
			}

			By("allocating when no indices are available")
			_, err = r.GrabIndex()
			Expect(err).To(HaveOccurred())
		})
	})
})
