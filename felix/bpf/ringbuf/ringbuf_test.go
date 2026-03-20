// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ringbuf

import (
	"encoding/binary"
	"testing"
	"unsafe"

	. "github.com/onsi/gomega"
)

// newTestRingBuffer creates a synthetic RingBuffer backed by plain byte slices
// (no mmap or BPF maps). The data region is 2*ringSize to match the kernel's
// double-mapped layout.
func newTestRingBuffer(ringSize int) *RingBuffer {
	consumerMem := make([]byte, 8)
	producerMem := make([]byte, 8+2*ringSize)

	return &RingBuffer{
		consumerPos: (*uint64)(unsafe.Pointer(&consumerMem[0])),
		producerPos: (*uint64)(unsafe.Pointer(&producerMem[0])),
		data:        producerMem[8:],
		mask:        uint64(ringSize) - 1,
		epollFD:     -1,
	}
}

// appendRecord writes a ring buffer record at pos and returns the total
// record size (header + data, rounded to 8 bytes).
func appendRecord(rb *RingBuffer, pos uint64, flags uint32, payload []byte) uint64 {
	offset := pos & rb.mask
	binary.LittleEndian.PutUint32(rb.data[offset:], uint32(len(payload))|flags)
	copy(rb.data[offset+ringbufHdrSize:], payload)
	return uint64(roundupLen(uint32(len(payload))))
}

func TestRoundupLen(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		dataLen  uint32
		expected uint32
	}{
		{0, 8},   // hdr(8) + 0, already aligned
		{1, 16},  // hdr(8) + 1 = 9, round to 16
		{8, 16},  // hdr(8) + 8 = 16, already aligned
		{9, 24},  // hdr(8) + 9 = 17, round to 24
		{16, 24}, // hdr(8) + 16 = 24, already aligned
		{24, 32}, // hdr(8) + 24 = 32, already aligned
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			Expect(roundupLen(tc.dataLen)).To(Equal(tc.expected))
		})
	}
}

func TestReadOneEmpty(t *testing.T) {
	RegisterTestingT(t)

	rb := newTestRingBuffer(64)

	_, ok, err := rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeFalse())

	// Same non-zero position — still empty.
	*rb.consumerPos = 100
	*rb.producerPos = 100
	_, ok, err = rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeFalse())
}

func TestReadOneSingleEvent(t *testing.T) {
	RegisterTestingT(t)

	rb := newTestRingBuffer(64)
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	recSize := appendRecord(rb, 0, 0, data)
	*rb.producerPos = recSize

	event, ok, err := rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeTrue())
	Expect(event.Data()).To(Equal(data))
	Expect(*rb.consumerPos).To(Equal(recSize))

	// Now empty.
	_, ok, err = rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeFalse())
}

func TestReadOneMultipleEvents(t *testing.T) {
	RegisterTestingT(t)

	rb := newTestRingBuffer(256)
	data1 := []byte{1, 2, 3, 4}
	data2 := []byte{5, 6, 7, 8, 9, 10, 11, 12}

	pos := uint64(0)
	pos += appendRecord(rb, pos, 0, data1)
	pos += appendRecord(rb, pos, 0, data2)
	*rb.producerPos = pos

	event1, ok, err := rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeTrue())
	Expect(event1.Data()).To(Equal(data1))

	event2, ok, err := rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeTrue())
	Expect(event2.Data()).To(Equal(data2))

	_, ok, err = rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeFalse())
}

func TestReadOneBusyBit(t *testing.T) {
	RegisterTestingT(t)

	rb := newTestRingBuffer(64)

	recSize := appendRecord(rb, 0, busyBit, []byte{1, 2, 3, 4})
	*rb.producerPos = recSize

	_, ok, err := rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeFalse())
	Expect(*rb.consumerPos).To(Equal(uint64(0)), "Consumer should not advance past busy record")
}

func TestReadOneDiscardBit(t *testing.T) {
	RegisterTestingT(t)

	rb := newTestRingBuffer(256)

	pos := uint64(0)
	discardSize := appendRecord(rb, pos, discardBit, []byte{0xFF, 0xFF})
	pos += discardSize
	pos += appendRecord(rb, pos, 0, []byte{0xAA, 0xBB})
	*rb.producerPos = pos

	// First read skips the discard (advances consumer, returns ok=false).
	_, ok, err := rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeFalse())
	Expect(*rb.consumerPos).To(Equal(discardSize))

	// Second read returns the valid event.
	event, ok, err := rb.readOne()
	Expect(err).NotTo(HaveOccurred())
	Expect(ok).To(BeTrue())
	Expect(event.Data()).To(Equal([]byte{0xAA, 0xBB}))
}

func TestDrain(t *testing.T) {
	RegisterTestingT(t)

	rb := newTestRingBuffer(256)
	Expect(rb.Drain()).To(Equal(0))

	pos := uint64(0)
	for i := range 5 {
		pos += appendRecord(rb, pos, 0, []byte{byte(i)})
	}
	*rb.producerPos = pos

	Expect(rb.Drain()).To(Equal(5))
	Expect(rb.Drain()).To(Equal(0))
}

func TestDrainSkipsDiscarded(t *testing.T) {
	RegisterTestingT(t)

	rb := newTestRingBuffer(256)

	pos := uint64(0)
	pos += appendRecord(rb, pos, 0, []byte{1})
	pos += appendRecord(rb, pos, discardBit, []byte{2})
	pos += appendRecord(rb, pos, 0, []byte{3})
	*rb.producerPos = pos

	// Drain processes all 3 records but only counts the 2 non-discarded ones.
	Expect(rb.Drain()).To(Equal(2))
}
