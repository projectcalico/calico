// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

package perf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

func TestPerfReadSize(t *testing.T) {
	RegisterTestingT(t)

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	tcs := []struct {
		name   string
		head   uint64
		tail   uint64
		expect []byte
		fails  bool
	}{
		{
			name:   "empty 0-0",
			head:   0,
			tail:   0,
			expect: nil,
			fails:  true,
		},
		{
			name:   "empty 1050-1050",
			head:   1050,
			tail:   1050,
			expect: nil,
			fails:  true,
		},
		{
			name:   "data too short",
			head:   23,
			tail:   19,
			expect: nil,
			fails:  true,
		},
		{
			name:   "single msg, from 0",
			head:   9,
			tail:   0,
			expect: data,
		},
		{
			name:   "single msg, unwrapped",
			head:   12,
			tail:   3,
			expect: data,
		},
		{
			name:   "single msg, wrapped",
			head:   20,
			tail:   11,
			expect: data,
		},
		{
			name:   "mode data",
			head:   14,
			tail:   3,
			expect: data,
		},
		{
			name:   "mode wrapped",
			head:   25,
			tail:   11,
			expect: data,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ring := make([]byte, 16)
			data2ring(ring, data, tc.tail)
			out, err := readSize(ring, tc.head, tc.tail, uint64(len(data)))
			Expect(err != nil).To(Equal(tc.fails))
			Expect(out).To(Equal(tc.expect))
		})
	}
}

func TestPerfNext(t *testing.T) {
	RegisterTestingT(t)

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	perfEvent := makeEvent(data)

	perfRing := &perfRing{
		ctrl: new(unix.PerfEventMmapPage),
		ring: make([]byte, 64),
	}

	Expect(perfRing.Empty()).To(BeTrue())

	_, err := perfRing.Next()
	Expect(err).To(HaveOccurred())

	data2ring(perfRing.ring, perfEvent, perfRing.ctrl.Data_tail)
	perfRing.ctrl.Data_head = uint64(len(perfEvent))

	Expect(perfRing.Empty()).NotTo(BeTrue())
	event, err := perfRing.Next()
	Expect(err).NotTo(HaveOccurred())
	Expect(perfRing.ctrl.Data_head).To(Equal(perfRing.ctrl.Data_tail))
	Expect(event.Data()).To(Equal(data))

	data2ring(perfRing.ring, perfEvent, perfRing.ctrl.Data_tail)
	perfRing.ctrl.Data_head += uint64(len(perfEvent))
	data2ring(perfRing.ring, perfEvent, perfRing.ctrl.Data_tail+uint64(len(perfEvent)))
	perfRing.ctrl.Data_head += uint64(len(perfEvent))
	// The ring buffer of 64 can only hold 3 events, so this one if going to be
	// wrapped around the buffer.
	data2ring(perfRing.ring, perfEvent, perfRing.ctrl.Data_tail+2*uint64(len(perfEvent)))
	perfRing.ctrl.Data_head += uint64(len(perfEvent))

	Expect(perfRing.Empty()).NotTo(BeTrue())

	iters := 0
	for {
		event, err := perfRing.Next()
		if err != nil {
			break
		}
		iters++
		Expect(event.Data()).To(Equal(data))
	}

	Expect(iters).To(Equal(3))
	Expect(perfRing.Empty()).To(BeTrue())

	lostHdr := perfEventHeaderToBytes(perfEventHeader{
		typ: perfEventTypeLost,
	})
	lostData := make([]byte, 2*8)
	binary.LittleEndian.PutUint64(lostData[:8], 0x1d)
	binary.LittleEndian.PutUint64(lostData[8:], 0xdead00beef)

	perfEventLost := append(lostHdr, lostData...)

	data2ring(perfRing.ring, perfEventLost, perfRing.ctrl.Data_tail)
	perfRing.ctrl.Data_head += uint64(len(perfEventLost))

	Expect(perfRing.Empty()).NotTo(BeTrue())
	event, err = perfRing.Next()
	Expect(err).NotTo(HaveOccurred())

	Expect(event.LostEvents()).To(Equal(0xdead00beef))
}

func perfEventHeaderToBytes(hdr perfEventHeader) []byte {
	bytes := make([]byte, perfEventHeaderSize)

	binary.LittleEndian.PutUint32(bytes[0:4], hdr.typ)
	binary.LittleEndian.PutUint16(bytes[4:6], hdr.misc)
	binary.LittleEndian.PutUint16(bytes[6:8], hdr.size)

	return bytes
}

func data2ring(ring []byte, data []byte, tail uint64) {
	l := uint64(len(ring))
	start := tail & (l - 1)

	for i, b := range data {
		ring[(start+uint64(i))&(l-1)] = b
	}
}

func makeEvent(data []byte) []byte {
	hdr := perfEventHeaderToBytes(perfEventHeader{
		typ: perfEventTypeSample,
	})
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(data)))

	perfEvent := append(hdr, size...)
	perfEvent = append(perfEvent, data...)

	return perfEvent
}

func ringAppend(ring *perfRing, event []byte) {
	data2ring(ring.ring, event, ring.ctrl.Data_head)
	ring.ctrl.Data_head += uint64(len(event))
}

func TestPerfPoll(t *testing.T) {
	RegisterTestingT(t)

	poller := &mockPoller{
		rings: make([]*perfRing, 3),
		wait: func(_ []*perfRing) (int, error) {
			return 0, errors.New("some error")
		},
	}

	for i := 0; i < 3; i++ {
		poller.rings[i] = &perfRing{
			ctrl: new(unix.PerfEventMmapPage),
			ring: make([]byte, 1024),
		}
	}

	events := &perf{
		rings:        poller.rings,
		ready:        make([]*perfRing, 3),
		poller:       poller,
		dequeueQuota: 2,
	}

	_, err := events.Next()
	Expect(err).To(HaveOccurred())

	ringAppend(poller.rings[1], makeEvent([]byte{1}))

	// poller.Wait is not executed because we first check each ring
	event, err := events.Next()
	Expect(err).NotTo(HaveOccurred())
	Expect(event.Data()).To(Equal([]byte{1}))

	// poller.Wait is called now as all the rings are empty and returns an error
	_, err = events.Next()
	Expect(err).To(HaveOccurred())

	ringAppend(poller.rings[0], makeEvent([]byte{1}))
	ringAppend(poller.rings[0], makeEvent([]byte{2}))
	ringAppend(poller.rings[0], makeEvent([]byte{3}))
	ringAppend(poller.rings[1], makeEvent([]byte{11}))
	ringAppend(poller.rings[2], makeEvent([]byte{21}))

	// Since  quota is 2, expect the 3rd message from the 1st ring to come
	// after 2nd and 3rd rings are dequeued. Expect no call to poller.Wait in
	// the meantime.
	for i, b := range []byte{1, 2, 11, 21, 3} {
		event, err := events.Next()
		Expect(err).NotTo(HaveOccurred())
		Expect(event.Data()).To(Equal([]byte{b}), fmt.Sprintf("iteration %d", i))
	}

	// All is empty now, we get an error
	_, err = events.Next()
	Expect(err).To(HaveOccurred())

	// Make poller block until there are data
	poller.wait = func(ready []*perfRing) (int, error) {
		ringAppend(poller.rings[2], makeEvent([]byte{22}))
		ready[0] = poller.rings[2]
		ringAppend(poller.rings[0], makeEvent([]byte{4}))
		ready[1] = poller.rings[0]
		return 2, nil
	}

	// Rings are polled in the order given by the poller.
	event, err = events.Next()
	Expect(err).NotTo(HaveOccurred())
	Expect(event.Data()).To(Equal([]byte{22}))
	event, err = events.Next()
	Expect(err).NotTo(HaveOccurred())
	Expect(event.Data()).To(Equal([]byte{4}))
}

type mockPoller struct {
	rings []*perfRing
	wait  func([]*perfRing) (int, error)
}

func (p *mockPoller) Wait(ready []*perfRing) (int, error) {
	if p.wait != nil {
		return p.wait(ready)
	}
	panic("no test case")
}
