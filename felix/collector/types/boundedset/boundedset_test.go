// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.
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

package boundedset

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	localIp1Str  = "10.0.0.1"
	localIp2Str  = "10.0.0.2"
	remoteIp1Str = "20.0.0.1"
	remoteIp2Str = "20.0.0.2"
)

var _ = Describe("Bounded set", func() {
	var (
		bs          *BoundedSet
		testMaxSize int
	)
	BeforeEach(func() {
		testMaxSize = 2
		bs = New(testMaxSize)
	})
	It("should be contain the correct elements", func() {
		expectedTotalCount := 0
		expectedDeltaCount := 0

		By("checking the lengths when there are no elements")
		Expect(bs.TotalCount()).To(Equal(expectedTotalCount))
		Expect(bs.TotalCountDelta()).To(Equal(expectedDeltaCount))
		bs.ResetDeltaCount()

		By("adding items")
		bs.Add(net.ParseIP(localIp1Str))
		bs.Add(net.ParseIP(localIp2Str))
		bs.Add(net.ParseIP(localIp2Str)) // Duplicate should have no effect
		expectedDeltaCount = 2
		expectedTotalCount += expectedDeltaCount

		By("checking the length")
		Expect(bs.TotalCount()).To(Equal(expectedTotalCount))
		Expect(bs.TotalCountDelta()).To(Equal(expectedDeltaCount))
		bs.ResetDeltaCount()

		By("increasing the total count")
		bs.IncreaseTotalCount(2)
		expectedDeltaCount = 2
		expectedTotalCount += expectedDeltaCount

		By("checking the length")
		Expect(bs.TotalCount()).To(Equal(expectedTotalCount))
		Expect(bs.TotalCountDelta()).To(Equal(expectedDeltaCount))
		bs.ResetDeltaCount()

		By("checking the contents")
		Expect(bs.Contains(net.ParseIP(localIp1Str))).To(BeTrue())
		Expect(bs.Contains(net.ParseIP(localIp2Str))).To(BeTrue())
		Expect(bs.Contains(net.ParseIP(remoteIp1Str))).To(BeFalse())

		By("adding an extra element and the total count changes but not the contents")
		bs.Add(net.ParseIP(remoteIp1Str))
		expectedDeltaCount = 1
		expectedTotalCount += expectedDeltaCount
		Expect(bs.TotalCount()).To(Equal(expectedTotalCount))
		Expect(bs.TotalCountDelta()).To(Equal(expectedDeltaCount))
		bs.ResetDeltaCount()
		Expect(bs.Contains(net.ParseIP(localIp1Str))).To(BeTrue())
		Expect(bs.Contains(net.ParseIP(localIp2Str))).To(BeTrue())
		Expect(bs.Contains(net.ParseIP(remoteIp1Str))).To(BeFalse())

		By("converting to a slice and checking the contents of the slice")
		ips := bs.ToIPSlice()
		Expect(ips).To(ConsistOf([]net.IP{net.ParseIP(localIp1Str), net.ParseIP(localIp2Str)}))

		By("copying the set and checking the contents")
		newBs := bs.Copy()
		newExpectedDeltaCount := bs.TotalCount()
		newExpectedTotalCount := bs.TotalCount()
		Expect(newBs.TotalCount()).To(Equal(newExpectedTotalCount))
		Expect(newBs.TotalCountDelta()).To(Equal(newExpectedDeltaCount))
		newBs.ResetDeltaCount()
		Expect(newBs.Contains(net.ParseIP(localIp1Str))).To(BeTrue())
		Expect(newBs.Contains(net.ParseIP(localIp2Str))).To(BeTrue())
		Expect(newBs.Contains(net.ParseIP(remoteIp1Str))).To(BeFalse())

		By("Updating the copy, the copy is updated, the original set isn't")
		newBs.Add(net.ParseIP(remoteIp1Str))
		newBs.Add(net.ParseIP(remoteIp2Str))
		newExpectedDeltaCount = 2
		newExpectedTotalCount += newExpectedDeltaCount
		Expect(newBs.TotalCount()).To(Equal(newExpectedTotalCount))
		Expect(newBs.TotalCountDelta()).To(Equal(newExpectedDeltaCount))
		newBs.ResetDeltaCount()
		// No updates since the last time we checked.
		expectedDeltaCount = 0
		Expect(bs.TotalCount()).To(Equal(expectedTotalCount))
		Expect(bs.TotalCountDelta()).To(Equal(expectedDeltaCount))
		bs.ResetDeltaCount()

		By("Resetting the set")
		bs.Reset()
		expectedDeltaCount = 0
		expectedTotalCount = 0
		Expect(bs.TotalCount()).To(Equal(expectedTotalCount))
		Expect(bs.TotalCountDelta()).To(Equal(expectedDeltaCount))
		bs.ResetDeltaCount()
		Expect(bs.Contains(net.ParseIP(localIp1Str))).To(BeFalse())
		Expect(bs.Contains(net.ParseIP(localIp2Str))).To(BeFalse())
	})
	It("should be combine multiple boundedSet", func() {
		By("checking the length when there are no elements")
		Expect(bs.TotalCount()).To(BeZero())

		By("adding items")
		bs.Add(net.ParseIP(localIp1Str))
		bs.Add(net.ParseIP(localIp2Str))
		Expect(bs.TotalCount()).To(Equal(2))
		Expect(bs.Contains(net.ParseIP(localIp1Str))).To(BeTrue())
		Expect(bs.Contains(net.ParseIP(localIp2Str))).To(BeTrue())

		By("creating a second bounded set from a array")
		inputIps := []net.IP{net.ParseIP(remoteIp1Str), net.ParseIP(remoteIp2Str)}
		secondSetMaxSize := 3
		secondSetTotalCount := 5
		moreBs := NewFromSliceWithTotalCount(secondSetMaxSize, inputIps, secondSetTotalCount)
		Expect(moreBs.TotalCount()).To(Equal(secondSetTotalCount))
		Expect(moreBs.Contains(net.ParseIP(remoteIp1Str))).To(BeTrue())
		Expect(moreBs.Contains(net.ParseIP(remoteIp2Str))).To(BeTrue())

		By("combining both sets")
		bs.Combine(moreBs)

		By("Initial set's size increases")
		Expect(bs.TotalCount()).To(Equal(secondSetTotalCount + testMaxSize))
		Expect(bs.Contains(net.ParseIP(localIp1Str))).To(BeTrue())
		Expect(bs.Contains(net.ParseIP(localIp2Str))).To(BeTrue())

		By("Initial set doesn't contain elements greater than maxSize")
		Expect(bs.Contains(net.ParseIP(remoteIp1Str))).To(BeFalse())
		Expect(bs.Contains(net.ParseIP(remoteIp2Str))).To(BeFalse())

		By("The secondary set is unchanged")
		Expect(moreBs.TotalCount()).To(Equal(secondSetTotalCount))
		Expect(moreBs.Contains(net.ParseIP(remoteIp1Str))).To(BeTrue())
		Expect(moreBs.Contains(net.ParseIP(remoteIp2Str))).To(BeTrue())
	})
})
