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

package routetable_test

import (
	. "github.com/projectcalico/felix/routetable"
	v3 "github.com/projectcalico/libcalico-go/lib/apis/v3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RouteTableManager", func() {

	It("provides mainline function as expected", func() {

		By("constructing RouteTableManager")
		r := NewRouteTableManager(v3.RouteTableRange{Min: 43, Max: 47})
		Expect(r).NotTo(BeNil())

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
})
