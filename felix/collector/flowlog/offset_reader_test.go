// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package flowlog

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("LogOffsetReader", func() {
	DescribeTable("Reads Offsets from",
		func(positions string, expected Offsets) {
			var positionFile, err = os.CreateTemp("", "pos")
			defer func() {
				err := os.Remove(positionFile.Name())
				Expect(err).NotTo(HaveOccurred(), "Failed to delete temp file")
			}()
			Expect(err).NotTo(HaveOccurred())
			_, err = positionFile.WriteString(positions)
			Expect(err).NotTo(HaveOccurred())
			err = positionFile.Close()
			Expect(err).NotTo(HaveOccurred())

			var fluentDLogOffsetReader = NewFluentDLogOffsetReader(positionFile.Name())
			var offsets = fluentDLogOffsetReader.Read()
			Expect(offsets).Should(Equal(expected))
		},
		Entry("empty file", "", Offsets{}),
		Entry("malformed file", "@#$!234132", Offsets{}),
		Entry("missing log file", "missing	1	1", Offsets{}),
		Entry("unwatched log file", "unwatched	ffffffffffffffff	1", Offsets{}),
		Entry("flows.log with position 1", "testdata/flows.log	1	1",
			Offsets{"testdata/flows.log": 3600}),
		Entry("flows.log with position 3601",
			"testdata/flows.log	e11	1",
			Offsets{"testdata/flows.log": 0}),
		Entry("flows.log with position 4000",
			"testdata/flows.log	fa0	1",
			Offsets{"testdata/flows.log": -399}),
	)

	It("should return empty offsets for missing position", func() {
		var fluentDLogOffsetReader = NewFluentDLogOffsetReader("missing file")
		var offsets = fluentDLogOffsetReader.Read()
		Expect(offsets).Should(Equal(Offsets{}))
	})
})

type readerMock struct {
	mock.Mock
}

func (m *readerMock) Read() Offsets {
	args := m.Called()
	v, _ := args.Get(0).(Offsets)
	return v
}

var _ = Describe("RangeLogOffset", func() {
	DescribeTable("IsBehind",
		func(offsets Offsets, threshold int64, expected bool) {
			var mockReader = &readerMock{}
			mockReader.On("Read").Return(offsets)
			var fluentDLogOffset = NewRangeLogOffset(mockReader, threshold)

			var isBehind = fluentDLogOffset.IsBehind(offsets)
			Expect(isBehind).Should(Equal(expected))
		},
		Entry("[] outside [0,1)", Offsets{}, int64(1), false),
		Entry("[anyFile: 0] outside [0,1)", Offsets{"anyFile": 0}, int64(1), false),
		Entry("[anyFile: -1] outside [0,1)", Offsets{"anyFile": -1}, int64(1), true),
		Entry("[anyFile: 1] outside [0,1)", Offsets{"anyFile": 1}, int64(1), true),
		Entry("[anyFile: 2] outside [0,1)", Offsets{"anyFile": 2}, int64(1), true),
		Entry("[anyFile: -1, anotherFile: 0] outside [0,1)",
			Offsets{"anyFile": -1, "anotherFile": 0}, int64(1), true),
		Entry("[anyFile: 1, anotherFile: -1] outside [0,1)",
			Offsets{"anyFile": 1, "anotherFile": 1}, int64(1), true),
		Entry("[anyFile: 1, anotherFile: 0] outside [0,1)",
			Offsets{"anyFile": 1, "anotherFile": 0}, int64(1), true),
		Entry("[anyFile: 0, anotherFile: 0] outside [0,1)",
			Offsets{"anyFile": 0, "anotherFile": 0}, int64(1), false),
		Entry("[anyFile: 1, anotherFile: 1] outside [0,1)",
			Offsets{"anyFile": 1, "anotherFile": 1}, int64(1), true),
		Entry("[anyFile: 1, anotherFile: 1] outside [0,2)",
			Offsets{"anyFile": 1, "anotherFile": 1}, int64(2), false),
		Entry("[anyFile: 1, anotherFile: -1, otherFile : 0] outside [0,1)",
			Offsets{"anyFile": 1, "anotherFile": 1, "otherFile": 0}, int64(1), true),
	)

	DescribeTable("GetIncreaseFactor",
		func(offsets Offsets, threshold int64, expectedLevel int) {
			var mockReader = &readerMock{}
			mockReader.On("Read").Return(offsets)
			var fluentDLogOffset = NewRangeLogOffset(mockReader, threshold)

			var level = fluentDLogOffset.GetIncreaseFactor(offsets)
			Expect(level).Should(Equal(expectedLevel))
		},
		Entry("[] increases with 0", Offsets{}, int64(1), 0),
		Entry("[anyFile: 0] increases with 0", Offsets{"anyFile": 0}, int64(1), int(MinAggregationLevel)),
		Entry("[anyFile: -1] increases with max", Offsets{"anyFile": -1}, int64(1), int(MaxAggregationLevel)),
		Entry("[anyFile: 1] increases with 1", Offsets{"anyFile": 1}, int64(1), 1),
		Entry("[anyFile: 2] increases with 2", Offsets{"anyFile": 2}, int64(1), 2),
		Entry("[anyFile: 3] increases with 0", Offsets{"anyFile": 2}, int64(100), 0),
		Entry("[anyFile: -1, anotherFile: 0] increases with max",
			Offsets{"anyFile": -1, "anotherFile": 0}, int64(1), int(MaxAggregationLevel)),
		Entry("[anyFile: 1, anotherFile: -1] increases with max",
			Offsets{"anyFile": 1, "anotherFile": -1}, int64(1), int(MaxAggregationLevel)),
		Entry("[anyFile: 1, anotherFile: 0] increases with 1",
			Offsets{"anyFile": 1, "anotherFile": 0}, int64(1), 1),
		Entry("[anyFile: 0, anotherFile: 0] increases with 0",
			Offsets{"anyFile": 0, "anotherFile": 0}, int64(1), int(MinAggregationLevel)),
		Entry("[anyFile: 1, anotherFile: 1] increases with 1",
			Offsets{"anyFile": 1, "anotherFile": 1}, int64(1), 1),
		Entry("[anyFile: 10, anotherFile: 1] increases with 1",
			Offsets{"anyFile": 10, "anotherFile": 1}, int64(10), 1),
	)

	DescribeTable("Invalid threshold",
		func(threshold int64) {
			var mockReader = &readerMock{}
			Expect(func() { NewRangeLogOffset(mockReader, threshold) }).Should(Panic())
		},
		Entry("negative threshold", int64(-1)),
		Entry("zero threshold", int64(0)),
	)
})
