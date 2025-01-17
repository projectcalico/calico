// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

const (
	// perfEventHeaderSize is the size of struct perf_event_header
	perfEventHeaderSize = 4 + 2 + 2

	perfEventTypeSample uint32 = 9
	perfEventTypeLost   uint32 = 2

	dequeueQuota = 8 // max entries to dequeue from a ring before moving to another ring.
)

// Map returns a bpf map suitable for perf events
func Map(name string, maxCPUs int) maps.Map {
	return maps.NewPinnedMap(maps.MapParameters{
		Type:       "perf_event_array",
		KeySize:    4, // must be 4
		ValueSize:  4, // must be 4
		MaxEntries: maxCPUs,
		Name:       "cali_" + name,
		Version:    1,
	})
}

// Event represents a single event record retrieved from a perf event ring buffer.
type Event struct {
	cpu  int
	data []byte
	lost uint64
}

// CPU where the event was recorded
func (e Event) CPU() int {
	return e.cpu
}

// Data is the raw bytes of the event, to be interpreted by the user.
func (e Event) Data() []byte {
	return e.data
}

// LostEvents is the number of events lost when the producer could not
// output the events because the ring was full due to a slow reader.
func (e Event) LostEvents() int {
	return int(e.lost)
}

// Perf is an interface for reading events and other interations with a perf
// events stream.
type Perf interface {
	// Reads and return the next event
	Next() (Event, error)
	// Close releases resources and unblocks waiters.
	Close() error
}

type perf struct {
	bpfMap       maps.Map
	rings        []*perfRing
	ready        []*perfRing
	readyCnt     int
	readyIdx     int
	poller       poller
	dequeueQuota int

	watermark    int
	watermarkBit bool

	closed atomic.Bool
}

// New creates a new Perf that interfaces through the provided bpf map.
func New(m maps.Map, ringSize int, opts ...Option) (Perf, error) {
	var err error

	cpus := numCPUs()

	if m.Size() < cpus {
		return nil, fmt.Errorf("map has less entries %d than number of available CPUs %d", m.Size(), cpus)
	}

	p := &perf{
		bpfMap:       m,
		ready:        make([]*perfRing, cpus),
		watermark:    1,
		dequeueQuota: dequeueQuota,
	}

	for _, opt := range opts {
		opt(p)
	}

	// Create perf rings.
	p.rings, err = p.openPerfRings(cpus, ringSize)
	if err != nil {
		return nil, err
	}

	// Create epoll for the rings.
	epoller := &ePoll{
		events:  make([]unix.EpollEvent, len(p.rings)),
		fd2ring: make(map[int]*perfRing, cpus),
	}
	epoller.epoll, err = unix.EpollCreate1(0)
	if err != nil {
		return nil, errors.Wrapf(err, "EpollCreate1")
	}

	key := make([]byte, 4)
	val := make([]byte, 4)

	for _, ring := range p.rings {
		// Add rings to the epoll.
		epollEvent := unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(ring.fd),
		}
		if err := unix.EpollCtl(epoller.epoll, unix.EPOLL_CTL_ADD, ring.fd, &epollEvent); err != nil {
			return nil, errors.Wrapf(err, "EpollCtl")
		}
		epoller.fd2ring[ring.fd] = ring

		// Write the perf rings into the bpf map
		binary.LittleEndian.PutUint32(key, uint32(ring.cpu))
		binary.LittleEndian.PutUint32(val, uint32(ring.fd))
		if err := m.Update(key, val); err != nil {
			return nil, errors.Wrap(err, "bpf map update")
		}
	}

	p.poller = epoller

	return p, nil
}

func (p *perf) openPerfRings(cpus, ringSize int) ([]*perfRing, error) {
	pageSize := os.Getpagesize()

	if ringSize%pageSize != 0 {
		return nil, fmt.Errorf("ring size %d not a multiple of page size %d", ringSize, pageSize)
	}

	pages := ringSize / pageSize
	rings := make([]*perfRing, cpus)

	for cpu := 0; cpu < cpus; cpu++ {
		var err error
		rings[cpu], err = newPerfRing(cpu, pages, pageSize, p.watermark, p.watermarkBit)
		if err != nil {
			return nil, errors.WithMessagef(err, "new perfring for cpu %d", cpu)
		}
	}

	return rings, nil
}

func (p *perf) Next() (Event, error) {
	for {
		if p.readyIdx >= p.readyCnt {
			err := p.poll()
			if err != nil {
				if errors.Cause(err) != syscall.EINTR {
					return Event{}, err
				}
				continue // EINTR is benign a happens often, just retry the loop
			}
		}
		if p.closed.Load() {
			return Event{}, syscall.EINTR
		}

		ring := p.ready[p.readyIdx]
		event, err := ring.Next()

		switch err {
		case nil:
			ring.quota--
			if ring.quota == 0 {
				p.readyIdx++
			}
			return event, nil
		case unix.EAGAIN:
			p.readyIdx++
		default:
			return Event{}, err
		}

		// empty ring is dequeued, we try some other ring or we go back to poll
	}
}

func (p *perf) Close() error {
	p.closed.Store(true)
	for i, ring := range p.rings {
		if ring != nil {
			if err := ring.Close(); err != nil {
				return err
			}
			p.rings[i] = nil
		}
	}

	return nil
}

func (p *perf) poll() error {
	p.readyIdx = 0
	p.readyCnt = 0

	// Poll all the rings first, those with exhausted quota might still have
	// data, those that were empty might not be anymore.
	for _, ring := range p.rings {
		if !ring.Empty() {
			p.ready[p.readyCnt] = ring
			ring.quota = p.dequeueQuota
			p.readyCnt++
		}
	}

	// If we got any ready rings, return
	if p.readyCnt != 0 {
		return nil
	}

	n, err := p.poller.Wait(p.ready)
	if err != nil {
		return err
	}

	// Reset quotas
	p.readyCnt = n
	for i := 0; i < n; i++ {
		p.ready[i].quota = p.dequeueQuota
	}

	return nil
}

func numCPUs() int {
	// XXX As long as all CPUs are online, this is good enough, however, if some
	// are offline, the ids may be offsetted. To be robust, we need to know how
	// many CPU are in the system.
	return runtime.NumCPU()
}

type perfRing struct {
	fd    int
	cpu   int
	quota int
	mem   []byte
	ctrl  *unix.PerfEventMmapPage
	ring  []byte
}

func newPerfRing(cpu int, pages, pageSize, watermark int, watermarkBytes bool) (*perfRing, error) {
	if pages&(pages-1) != 0 {
		return nil, fmt.Errorf("ring size in pages %d not a power of 2", pages)
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      uint32(watermark),
	}

	if watermarkBytes {
		attr.Bits |= unix.PerfBitWatermark
	}

	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, errors.Wrapf(err, "PerfEventOpen")
	}

	pages++ // one more page for control block
	allocSize := pages * pageSize

	mem, err := unix.Mmap(fd, 0, allocSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, errors.Wrap(err, "unix.Mmap")
	}

	pr := &perfRing{
		fd:   fd,
		cpu:  cpu,
		mem:  mem,
		ctrl: (*unix.PerfEventMmapPage)(unsafe.Pointer(&mem[0])), // the first page contains metadata
	}

	// Assign the ring mem area
	pr.ring = pr.mem[pr.ctrl.Data_offset : pr.ctrl.Data_offset+pr.ctrl.Data_size]

	// We need to set finalizer since if the fd gets closed, the mmaped
	// memory may not be automatically released. For instance, if we allocate a
	// range of rings and one fails and we bail out, we may keep lots of memory
	// around.
	runtime.SetFinalizer(pr, (*perfRing).cleanup)

	return pr, nil
}

type perfEventHeader struct {
	typ  uint32
	misc uint16
	size uint16
}

func perfEventHeaderFromBytes(bytes []byte) perfEventHeader {
	return perfEventHeader{
		typ:  binary.LittleEndian.Uint32(bytes[0:4]),
		misc: binary.LittleEndian.Uint16(bytes[4:6]),
		size: binary.LittleEndian.Uint16(bytes[6:8]),
	}
}

func (pr *perfRing) Next() (Event, error) {
	head := atomic.LoadUint64(&pr.ctrl.Data_head)
	tail := atomic.LoadUint64(&pr.ctrl.Data_tail)

	if head == tail {
		return Event{}, unix.EAGAIN
	}

	perfHeaderRaw, err := readSize(pr.ring, head, tail, perfEventHeaderSize)
	if err != nil {
		return Event{}, err
	}
	perfHeader := perfEventHeaderFromBytes(perfHeaderRaw)

	var event Event

	// perfHeader.size is not used by either of the 2 interesting types
	n := uint64(perfHeader.size)

	switch perfHeader.typ {
	case perfEventTypeLost:
		event, n, err = readLost(pr.ring, head, tail)
	case perfEventTypeSample:
		event, n, err = readSample(pr.ring, head, tail)
	default:
		// Just to be sure, it never happens ;-), skip over the event.
		err = fmt.Errorf("unexpected event type %d", perfHeader.typ)
	}

	atomic.StoreUint64(&pr.ctrl.Data_tail, tail+perfEventHeaderSize+n)

	return event, err
}

func (pr *perfRing) Empty() bool {
	head := atomic.LoadUint64(&pr.ctrl.Data_head)
	tail := atomic.LoadUint64(&pr.ctrl.Data_tail)

	return head == tail
}

func readSample(ring []byte, head, tail uint64) (Event, uint64, error) {
	sizeRaw, err := readSize(ring, head, tail+perfEventHeaderSize, uint64(4 /* uint32 */))
	if err != nil {
		return Event{}, 0, err
	}

	size := uint64(binary.LittleEndian.Uint32(sizeRaw))
	n := uint64(4)

	eventRaw, err := readSize(ring, head, tail+perfEventHeaderSize+n, size)
	if err != nil {
		return Event{}, 0, err
	}

	n += size

	return Event{data: eventRaw}, n, nil
}

func readLost(ring []byte, head, tail uint64) (Event, uint64, error) {
	// lost sample has two u64 fields {ID,Lost}
	n := uint64(2 * 8)
	lostRaw, err := readSize(ring, head, tail+perfEventHeaderSize, n)
	if err != nil {
		return Event{}, 0, err
	}

	event := Event{
		lost: binary.LittleEndian.Uint64(lostRaw[8:16]),
	}

	return event, n, nil
}

func readSize(ring []byte, head, tail, size uint64) ([]byte, error) {
	if head-tail < size {
		return nil, fmt.Errorf("insufficient bytes (%d) for read size %d", head-tail, size)
	}

	retBytes := make([]byte, size)

	ringLen := uint64(cap(ring))
	offset := tail & (ringLen - 1)
	rem := uint64(0)

	if offset+size > ringLen {
		rem = offset + size - ringLen
	}

	copy(retBytes, ring[offset:offset+size-rem])

	if rem > 0 {
		copy(retBytes[size-rem:], ring[:rem])
	}

	return retBytes, nil
}

func (pr *perfRing) cleanup() error {
	if pr.mem != nil {
		_ = unix.Munmap(pr.mem)
		pr.mem = nil
	}
	if pr.fd != -1 {
		_ = unix.Close(pr.fd)
		pr.fd = -1
	}

	return nil
}

func (pr *perfRing) Close() error {
	return pr.cleanup()
}

type poller interface {
	Wait([]*perfRing) (int, error)
}

type ePoll struct {
	epoll   int
	events  []unix.EpollEvent
	fd2ring map[int]*perfRing
}

func (p *ePoll) Wait(ready []*perfRing) (int, error) {
	n, err := unix.EpollWait(p.epoll, p.events, -1)
	if err != nil {
		return 0, errors.Wrapf(err, "EpollWait")
	}

	// Fill in all now ready rings
	for i := 0; i < n; i++ {
		ready[i] = p.fd2ring[int(p.events[i].Fd)]
	}

	return n, nil
}

// Option is taken by New
type Option func(interface{})

// WithWakeUpBytes sets the wakup to be after reaching a watermark of n bytes.
func WithWakeUpBytes(n int) Option {
	return func(i interface{}) {
		p := i.(*perf)
		p.watermark = n
		p.watermarkBit = true
	}
}

// WithWakeUpEvents sets the wakup to be after reaching a watermark of n events.
// Default is a single event.
func WithWakeUpEvents(n int) Option {
	return func(i interface{}) {
		p := i.(*perf)
		p.watermark = n
		p.watermarkBit = false
	}
}

// WithDequeueQuota changes how many messages are dequeued from a ring before we
// switch to another one. Must be at least 1
func WithDequeueQuota(n int) Option {
	return func(i interface{}) {
		if n < 1 {
			return
		}
		p := i.(*perf)
		p.dequeueQuota = n
	}
}
