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
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

const (
	// ringbufHdrSize is the size of struct bpf_ringbuf_hdr (u32 len + u32 pad).
	ringbufHdrSize = 8

	// busyBit indicates the record is still being written by the kernel.
	busyBit = 1 << 31
	// discardBit indicates the record was discarded and should be skipped.
	discardBit = 1 << 29
	// lenMask clears the top 2 flag bits to get the actual data length.
	lenMask = ^uint32(busyBit | discardBit)
)

// Event represents a single event record from a ring buffer.
type Event struct {
	data []byte
}

// Data returns the raw bytes of the event.
func (e Event) Data() []byte {
	return e.data
}

// RingBuffer reads events from a BPF_MAP_TYPE_RINGBUF map using a pure-Go
// mmap reader. The kernel ring buffer ABI:
//   - Consumer page (1 page, RW): contains consumer_pos (u64) at offset 0
//   - Producer page (1 page, RO): contains producer_pos (u64) at offset 0
//   - Data pages (2 * max_entries, RO, double-mapped for wraparound)
type RingBuffer struct {
	bpfMap maps.Map
	mapFD  int

	// mmap'd regions
	consumerMem []byte // consumer page (writable)
	producerMem []byte // producer page + data pages (read-only)

	// Pointers into mmap'd memory
	consumerPos *uint64 // points to consumer_pos in consumer page
	producerPos *uint64 // points to producer_pos in producer page
	data        []byte  // data region (2 * maxEntries bytes)

	mask     uint64 // maxEntries - 1
	pageSize int

	// epoll for blocking reads
	epollFD int

	closed atomic.Bool
}

// Map returns a bpf map suitable for ring buffer events.
func Map(name string, maxEntries int) maps.Map {
	return maps.NewPinnedMap(maps.MapParameters{
		Type:       "ringbuf",
		KeySize:    0,
		ValueSize:  0,
		MaxEntries: maxEntries,
		Name:       "cali_" + name,
		Version:    1,
	})
}

// SetMapSize registers the desired ring buffer size so that it is applied when
// the map is created or loaded from a stub .o file.
func SetMapSize(size int) {
	maps.SetSize(MapName, size)
}

// MapName is the versioned name of the ring buffer map.
const MapName = "cali_rb_evnt"

// DropsMapName is the name of the per-CPU array that counts events dropped
// by BPF programs when the ring buffer is full (bpf_ringbuf_output returns
// -ENOBUFS).
const DropsMapName = "cali_rb_drops"

// DropsMap returns a per-CPU array map used to count dropped ring buffer events.
func DropsMap() maps.Map {
	return maps.NewPinnedMap(maps.MapParameters{
		Type:       "percpu_array",
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
		Name:       DropsMapName,
		Version:    1,
	})
}

// ReadDrops reads the per-CPU drop counter and returns the total number of
// events dropped across all CPUs since the map was created.
func ReadDrops(m maps.Map) (uint64, error) {
	key := make([]byte, 4) // key = 0
	values, err := m.Get(key)
	if err != nil {
		return 0, errors.Wrap(err, "failed to read ring buffer drops map")
	}

	var total uint64
	cpus := maps.NumPossibleCPUs()
	for cpu := 0; cpu < cpus; cpu++ {
		offset := cpu * 8
		total += binary.LittleEndian.Uint64(values[offset : offset+8])
	}
	return total, nil
}

// New creates a new RingBuffer reader for the given BPF ring buffer map.
func New(m maps.Map, maxEntries int) (*RingBuffer, error) {
	fd := m.MapFD()
	pageSize := os.Getpagesize()

	var err error

	rb := &RingBuffer{
		bpfMap:   m,
		mapFD:    int(fd),
		pageSize: pageSize,
		mask:     uint64(maxEntries) - 1,
	}

	// Map writable consumer page.
	rb.consumerMem, err = unix.Mmap(rb.mapFD, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, errors.Wrap(err, "mmap consumer page")
	}
	rb.consumerPos = (*uint64)(unsafe.Pointer(&rb.consumerMem[0]))

	// Map read-only producer page and data pages.
	// Data is double-mapped (2 * maxEntries) for contiguous wraparound reads.
	prodMmapSize := pageSize + 2*maxEntries
	rb.producerMem, err = unix.Mmap(rb.mapFD, int64(pageSize), prodMmapSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(rb.consumerMem)
		return nil, errors.Wrap(err, "mmap producer + data pages")
	}
	rb.producerPos = (*uint64)(unsafe.Pointer(&rb.producerMem[0]))
	rb.data = rb.producerMem[pageSize:]

	// Create epoll for blocking on the map FD.
	rb.epollFD, err = unix.EpollCreate1(0)
	if err != nil {
		rb.cleanup()
		return nil, errors.Wrap(err, "EpollCreate1")
	}

	epollEvent := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(rb.mapFD),
	}
	if err := unix.EpollCtl(rb.epollFD, unix.EPOLL_CTL_ADD, rb.mapFD, &epollEvent); err != nil {
		rb.cleanup()
		return nil, errors.Wrap(err, "EpollCtl")
	}

	return rb, nil
}

// Next blocks until an event is available and returns it. Returns an error
// wrapping unix.EINTR if the ring buffer has been closed.
func (rb *RingBuffer) Next() (Event, error) {
	for {
		if rb.closed.Load() {
			return Event{}, unix.EINTR
		}

		event, ok, err := rb.readOne()
		if err != nil {
			return Event{}, err
		}
		if ok {
			return event, nil
		}

		// No data available — block on epoll.
		events := make([]unix.EpollEvent, 1)
		_, err = unix.EpollWait(rb.epollFD, events, -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return Event{}, errors.Wrap(err, "EpollWait")
		}
	}
}

// readOne attempts to read a single event from the ring buffer.
// Returns (event, true, nil) on success, (Event{}, false, nil) if no data,
// or (Event{}, false, err) on error.
func (rb *RingBuffer) readOne() (Event, bool, error) {
	consPos := atomic.LoadUint64(rb.consumerPos)
	prodPos := atomic.LoadUint64(rb.producerPos)

	if consPos >= prodPos {
		return Event{}, false, nil
	}

	// Read the record header.
	offset := consPos & rb.mask
	lenVal := atomic.LoadUint32((*uint32)(unsafe.Pointer(&rb.data[offset])))

	// If the busy bit is set, the kernel is still writing — treat as empty.
	if lenVal&busyBit != 0 {
		return Event{}, false, nil
	}

	// Calculate the total record size (header + data, rounded up to 8 bytes).
	dataLen := lenVal & lenMask
	totalSize := roundupLen(dataLen)

	// Advance consumer position past this record.
	newConsPos := consPos + uint64(totalSize)

	if lenVal&discardBit != 0 {
		// Discarded record — skip it.
		atomic.StoreUint64(rb.consumerPos, newConsPos)
		return Event{}, false, nil
	}

	// Read the event data. The double-mapping ensures we can read contiguously
	// even when the data wraps around.
	dataOffset := (consPos + ringbufHdrSize) & rb.mask
	eventData := make([]byte, dataLen)
	copy(eventData, rb.data[dataOffset:dataOffset+uint64(dataLen)])

	// Advance consumer position.
	atomic.StoreUint64(rb.consumerPos, newConsPos)

	return Event{data: eventData}, true, nil
}

// roundupLen calculates the total record size: header + data, rounded to 8 bytes.
func roundupLen(dataLen uint32) uint32 {
	return (dataLen + ringbufHdrSize + 7) &^ 7
}

// Close releases all resources and unblocks any waiting Next() calls.
func (rb *RingBuffer) Close() error {
	rb.closed.Store(true)
	return rb.cleanup()
}

func (rb *RingBuffer) cleanup() error {
	if rb.epollFD > 0 {
		unix.Close(rb.epollFD)
		rb.epollFD = 0
	}
	if rb.producerMem != nil {
		_ = unix.Munmap(rb.producerMem)
		rb.producerMem = nil
	}
	if rb.consumerMem != nil {
		_ = unix.Munmap(rb.consumerMem)
		rb.consumerMem = nil
	}
	return nil
}

// Map returns the underlying BPF map.
func (rb *RingBuffer) Map() maps.Map {
	return rb.bpfMap
}
