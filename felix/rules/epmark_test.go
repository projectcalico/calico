// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package rules_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/rules"
)

func init() {

	ErrMark := uint32(0)

	DescribeTable("EndpointMarkMapper initialization",
		func(mask, nonCaliMark uint32) {
			epmm := NewEndpointMarkMapperWithShim(mask, nonCaliMark, &mockHash32{})
			Expect(epmm.GetMask()).To(Equal(mask))

			mark, err := epmm.GetEndpointMark("/cali/Pseudo/NonCali/Endpoint/")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mark).To(Equal(uint32(nonCaliMark)))
		},
		Entry("should initialise with one bit", uint32(0x10), uint32(0x10)),
		Entry("should initialise with some bits", uint32(0x123f), uint32(0x01)),
		Entry("should initialise with max bits", uint32(0xffffffff), uint32(0x01)),
	)

	Describe("EndpointMarkMapper allocation/release", func() {

		var epmm EndpointMarkMapper
		BeforeEach(func() {
			epmm = NewEndpointMarkMapperWithShim(0x700, 0x100, &mockHash32{})
		})
		DescribeTable("EndpointMarkMapper allocation",
			func(eps []string, expected []uint32) {
				result := []uint32{}
				for _, ep := range eps {
					if strings.HasPrefix(ep, "x") {
						epmm.ReleaseEndpointMark(strings.TrimPrefix(ep, "x"))
					} else {
						// if error, function return 0 which match ErrMark.
						mark, _ := epmm.GetEndpointMark(ep)
						result = append(result, mark)
					}
				}
				Expect(result).To(Equal(expected))
			},
			Entry("should allocate sequentially and repeat",
				[]string{"cali1", "cali2", "cali3", "cali1", "cali2", "cali7"},
				[]uint32{0x200, 0x300, 0x400, 0x200, 0x300, 0x700}),
			Entry("should allocate with collision and fail correctly",
				[]string{"cali1", "cali6", "cali3", "cali11", "cali22", "cali33", "cali8", "cali9"},
				[]uint32{0x200, 0x600, 0x300, 0x400, 0x500, 0x700, ErrMark, ErrMark}),
			Entry("should allocate/release with collision",
				[]string{"cali1", "cali6", "cali3", "xcali1", "xcali2", "cali33", "cali11", "cali66"},
				[]uint32{0x200, 0x600, 0x300, 0x400, 0x200, 0x700}),
			Entry("should allocate/fail/release/allocate",
				[]string{"cali1", "cali6", "cali3", "cali11", "cali22", "cali33", "cali8", "cali5", "xcali3", "xcali6", "cali55", "cali66"},
				[]uint32{0x200, 0x600, 0x300, 0x400, 0x500, 0x700, ErrMark, ErrMark, 0x600, 0x300}),
		)
	})

	Describe("EndpointMarkMapper set endpoint mark", func() {

		var epmm EndpointMarkMapper
		BeforeEach(func() {
			epmm = NewEndpointMarkMapperWithShim(0x700, 0x100, &mockHash32{})
		})
		It("should not set mark with wrong value", func() {
			err := epmm.SetEndpointMark("cali1", uint32(0x210))
			Expect(err).Should(HaveOccurred())
		})
		It("should set mark with same value", func() {
			err := epmm.SetEndpointMark("cali1", uint32(0x300))
			Expect(err).ShouldNot(HaveOccurred())

			mark, err := epmm.GetEndpointMark("cali1")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mark).To(Equal(uint32(0x300)))

			err = epmm.SetEndpointMark("cali1", uint32(0x300))
			Expect(err).ShouldNot(HaveOccurred())
		})
		It("should not set mark with different value", func() {
			err := epmm.SetEndpointMark("cali1", uint32(0x300))
			Expect(err).ShouldNot(HaveOccurred())

			err = epmm.SetEndpointMark("cali1", uint32(0x100))
			Expect(err).Should(HaveOccurred())
		})
		It("should not set mark with different endpoint", func() {
			mark, err := epmm.GetEndpointMark("cali1")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mark).To(Equal(uint32(0x200)))

			err = epmm.SetEndpointMark("cali3", uint32(0x200))
			Expect(err).Should(HaveOccurred())

			epmm.ReleaseEndpointMark("cali1")
			err = epmm.SetEndpointMark("cali3", uint32(0x200))
			Expect(err).ShouldNot(HaveOccurred())
		})
		It("should set mark and allocate", func() {
			err := epmm.SetEndpointMark("cali1", uint32(0x300))
			Expect(err).ShouldNot(HaveOccurred())

			mark, err := epmm.GetEndpointMark("cali1")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mark).To(Equal(uint32(0x300)))

			mark, err = epmm.GetEndpointMark("cali13")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mark).To(Equal(uint32(0x400)))
		})
	})
}

// Mock a super simple Hash32Caculator interface.
type mockHash32 struct {
	lastByte byte
}

func (h *mockHash32) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		h.lastByte = 0
		return 0, nil
	}
	h.lastByte = b[len(b)-1]
	return 1, nil
}

func (h *mockHash32) Sum32() uint32 {
	return uint32(h.lastByte)
}

func (h *mockHash32) Reset() {
}
