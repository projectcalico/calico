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

package markbits_test

import (
	"errors"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/markbits"
)

const (
	SingleBitAlloc = 0
)

// getMarkBits allocate a single bit or a block of mark bits.
// It returns mark, bits allocated, current free bits and current count of free position number.

type markBitsResult struct {
	mark            uint32
	bitsAllocated   int
	currentFreeBits int
	currentFreePos  int
}

func init() {

	errMark := uint32(0)
	errNumber := 0
	errResult := markBitsResult{0, 0, -1, -1}

	DescribeTable("MarkBits initialization",
		func(mask uint32, expectedFreeBits int, expectedFreePos int) {
			m := markbits.NewMarkBitsManager(mask, "initialization")
			Expect(m.GetMask()).To(Equal(mask))
			Expect(m.AvailableMarkBitCount()).To(Equal(expectedFreeBits))
			Expect(m.CurrentFreeNumberOfMark()).To(Equal(expectedFreePos))
		},

		Entry("should initialise with one bit", uint32(0x10), 1, 2),
		Entry("should initialise with some bits", uint32(0x123f), 8, int(0x100)),
		Entry("should initialise with max bits", uint32(0xffffffff), 32, int(0x100000000)),
	)

	DescribeTable("MarkBits mixed single and block allocation",
		func(mask uint32, sizes []int, expected []markBitsResult) {
			Expect(len(sizes)).To(Equal(len(expected)))
			m := markbits.NewMarkBitsManager(mask, "allocation")

			for i, size := range sizes {
				result, err := getMarkBitsResult(m, size)
				if err != nil {
					Expect(expected[i]).To(Equal(errResult),
						"expected allocation error")
				} else {
					Expect(*result).To(Equal(expected[i]))
				}
			}
		},

		Entry("should allocate single bit", uint32(0x10), []int{SingleBitAlloc},
			[]markBitsResult{{uint32(0x10), 1, 0, 0}}),

		Entry("should not allocate single bit", uint32(0x10), []int{SingleBitAlloc, SingleBitAlloc},
			[]markBitsResult{{uint32(0x10), 1, 0, 0}, errResult}),

		Entry("should allocate multiple single bit", uint32(0x83),
			[]int{SingleBitAlloc, SingleBitAlloc, SingleBitAlloc, SingleBitAlloc},
			[]markBitsResult{
				{uint32(0x01), 1, 2, 4},
				{uint32(0x02), 1, 1, 2},
				{uint32(0x80), 1, 0, 0},
				errResult,
			}),
		Entry("should allocate single block bit", uint32(0x10), []int{1},
			[]markBitsResult{{uint32(0x10), 1, 0, 0}}),
		Entry("should allocate full block bit", uint32(0x83300), []int{4},
			[]markBitsResult{{uint32(0x3300), 4, 1, 2}}),
		Entry("should allocate partial block bit", uint32(0x83300), []int{6},
			[]markBitsResult{{uint32(0x83300), 5, 0, 0}}),
		Entry("should allocate multiple block bit", uint32(0x3333),
			[]int{4, 2, 3, 1},
			[]markBitsResult{
				{uint32(0x33), 4, 4, 16},
				{uint32(0x300), 2, 2, 4},
				{uint32(0x3000), 2, 0, 0},
				errResult,
			}),
		Entry("should allocate mixed single and block bit", uint32(0x3333),
			[]int{4, SingleBitAlloc, 3, SingleBitAlloc},
			[]markBitsResult{
				{uint32(0x33), 4, 4, 16},
				{uint32(0x100), 1, 3, 8},
				{uint32(0x3200), 3, 0, 0},
				errResult,
			}),
	)

	DescribeTable("MarkBits map number to mark",
		func(mask uint32, number int, expectedMark uint32) {
			m := markbits.NewMarkBitsManager(mask, "MapNumberToMark")

			resultMark, err := m.MapNumberToMark(number)
			if err != nil {
				Expect(expectedMark).To(Equal(errMark))
			} else {
				Expect(resultMark).To(Equal(expectedMark))
			}
		},

		Entry("should map with one bit", uint32(0x10), 1, uint32(0x10)),
		Entry("should map with some bits", uint32(0x12300004), 0xf, uint32(0x2300004)),
		Entry("should map with all bits", uint32(0x12300004), 0x1f, uint32(0x12300004)),
		Entry("should map with max bits", uint32(0xffffffff), 0xffffffff, uint32(0xffffffff)),
		Entry("should not map with less bits", uint32(0x12300004), 0x1235, errMark),
	)

	DescribeTable("MarkBits map mark to number",
		func(mask uint32, mark uint32, expectedNumber int) {
			m := markbits.NewMarkBitsManager(mask, "MapNumberToMark")

			resultNumber, err := m.MapMarkToNumber(mark)
			if err != nil {
				Expect(expectedNumber).To(Equal(errNumber))
			} else {
				Expect(resultNumber).To(Equal(expectedNumber))
			}
		},

		Entry("should map with one bit", uint32(0x10), uint32(0x10), 1),
		Entry("should map with some bits", uint32(0x12300004), uint32(0x2300004), 0xf),
		Entry("should map with all bits", uint32(0x12300004), uint32(0x12300004), 0x1f),
		Entry("should map with max bits", uint32(0xffffffff), uint32(0xffffffff), 0xffffffff),
		Entry("should not map with less bits", uint32(0x12300004), uint32(0x1230005), errNumber),
	)
}

func getMarkBitsResult(m *markbits.MarkBitsManager, size int) (*markBitsResult, error) {
	if size == SingleBitAlloc {
		mark, err := m.NextSingleBitMark()
		if err != nil {
			return nil, err
		}
		return &markBitsResult{
			mark:            mark,
			bitsAllocated:   1,
			currentFreeBits: m.AvailableMarkBitCount(),
			currentFreePos:  m.CurrentFreeNumberOfMark(),
		}, nil
	}

	mark, allocated := m.NextBlockBitsMark(size)
	if allocated == 0 {
		return nil, errors.New("Zero bits allocated.")
	}
	return &markBitsResult{
		mark:            mark,
		bitsAllocated:   allocated,
		currentFreeBits: m.AvailableMarkBitCount(),
		currentFreePos:  m.CurrentFreeNumberOfMark(),
	}, nil
}
