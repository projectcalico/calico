// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

package events

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/ringbuf"
	"github.com/projectcalico/calico/felix/bpf/state"
)

// Type defines the type of constants used for determining the type of an event.
type Type uint16

const (
	// TypeLostEvents is emitted by the BPF side when accumulated drop count
	// is flushed through the ring buffer.
	TypeLostEvents Type = 0
	// TypeProtoStats protocol v4 stats
	TypeProtoStats Type = 1
	// TypeDNSEvent reports information on DNS packets
	TypeDNSEvent Type = 2
	// TypePolicyVerdict is emitted when a policy program reaches a verdict
	TypePolicyVerdict Type = 3
	// TypeTcpStats reports L4 TCP socket information
	TypeTcpStats Type = 4
	// TypeProcessPath reports process exec path, arguments
	TypeProcessPath Type = 5
	// TypeDNSEventL3 is like TypeDNSEvent but from a L3 device - i.e. one whose packets begin
	// with the L3 header
	TypeDNSEventL3 Type = 6
	// TypePolicyVerdictV6 is emitted when a v6 policy program reaches a verdict
	TypePolicyVerdictV6 Type = 7
)

func (t Type) String() string {
	return strconv.Itoa(int(t))
}

// Event represents the common denominator of all events
type Event struct {
	typ  Type
	data []byte
}

// Type returns the event type
func (e Event) Type() Type {
	return e.typ
}

// Data returns the data of the event as an unparsed byte string
func (e Event) Data() []byte {
	return e.data
}

// Source is where do we read the event from
type Source string

const (
	// SourceRingBuffer consumes events using the BPF ring buffer
	SourceRingBuffer Source = "ring-buffer"
)

type eventRaw interface {
	Data() []byte
}

// Events is an interface for consuming events
type Events interface {
	Next() (Event, error)
	Map() maps.Map
	Close() error
}

// New creates a new Events object to consume events.
func New(src Source, size int) (Events, error) {
	switch src {
	case SourceRingBuffer:
		return newRingBufferEvents(size)
	}

	return nil, fmt.Errorf("unknown events source: %s", src)
}

type ringBufferEventsReader struct {
	rb     *ringbuf.RingBuffer
	bpfMap maps.Map
}

func newRingBufferEvents(size int) (Events, error) {
	rbMap := ringbuf.Map("rb_evnt", size)
	if err := rbMap.EnsureExists(); err != nil {
		return nil, errors.Wrap(err, "failed to ensure ring buffer map exists")
	}

	dropsMap := ringbuf.DropsMap()
	if err := dropsMap.EnsureExists(); err != nil {
		return nil, errors.Wrap(err, "failed to ensure ring buffer drops map exists")
	}

	rb, err := ringbuf.New(rbMap, size)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ring buffer reader")
	}

	return &ringBufferEventsReader{
		rb:     rb,
		bpfMap: rbMap,
	}, nil
}

func (r *ringBufferEventsReader) Next() (Event, error) {
	e, err := r.rb.Next()
	if err != nil {
		return Event{}, errors.WithMessage(err, "failed to get next event")
	}

	evt, err := parseEventData(e.Data())
	if err != nil {
		return Event{}, err
	}

	// The BPF side emits EVENT_LOST_EVENTS with a u64 count payload when
	// accumulated drops are flushed. Convert to ErrLostEvents so callers
	// (bpfEventPoller) handle it the same way as the old perf lost records.
	if evt.typ == TypeLostEvents {
		count := uint64(0)
		if len(evt.data) >= 8 {
			count = binary.LittleEndian.Uint64(evt.data[:8])
		}
		return Event{}, ErrLostEvents(count)
	}

	return evt, nil
}

func (r *ringBufferEventsReader) Close() error {
	return r.rb.Close()
}

func (r *ringBufferEventsReader) Map() maps.Map {
	return r.bpfMap
}

type eventHdr struct {
	Type uint32
	Len  uint32
}

func parseEventData(data []byte) (Event, error) {
	var hdr eventHdr
	hdrBytes := (*[unsafe.Sizeof(eventHdr{})]byte)((unsafe.Pointer)(&hdr))
	consumed := copy(hdrBytes[:], data)
	l := len(data)
	if int(hdr.Len) > l {
		return Event{}, fmt.Errorf("mismatched length %d vs data length %d", hdr.Len, l)
	}
	return Event{
		typ:  Type(hdr.Type),
		data: data[consumed:hdr.Len],
	}, nil
}

// ParseEvent reads the event header and returns a typed Event.
func ParseEvent(raw eventRaw) (Event, error) {
	return parseEventData(raw.Data())
}

// ErrLostEvents reports how many events were lost (dropped by the BPF program
// because the ring buffer was full).
type ErrLostEvents int

func (e ErrLostEvents) Error() string {
	return fmt.Sprintf("%d lost events", e)
}

func (e ErrLostEvents) Num() int {
	return int(e)
}

// ParsePolicyVerdict converts a bpf event data and converts to go structure
// Policy verdict event offsets: the event is the start of the BPF state after its event header.
const (
	evtHdrSize    = unsafe.Offsetof(state.State{}.SrcAddr)
	offsetSrcAddr = unsafe.Offsetof(state.State{}.SrcAddr) - evtHdrSize
	// The event reports the pre-NAT destination.
	offsetDstAddr        = unsafe.Offsetof(state.State{}.PreNATDstAddr) - evtHdrSize
	offsetPostNATDstAddr = unsafe.Offsetof(state.State{}.PostNATDstAddr) - evtHdrSize
	offsetNATTunSrcAddr  = unsafe.Offsetof(state.State{}.TunIP) - evtHdrSize
	offsetPolicyRC       = unsafe.Offsetof(state.State{}.PolicyRC) - evtHdrSize
	offsetSrcPort        = unsafe.Offsetof(state.State{}.SrcPort) - evtHdrSize
	offsetDstPort        = unsafe.Offsetof(state.State{}.PreNATDstPort) - evtHdrSize
	offsetPostNATDstPort = unsafe.Offsetof(state.State{}.PostNATDstPort) - evtHdrSize
	offsetIPProto        = unsafe.Offsetof(state.State{}.IPProto) - evtHdrSize
	offsetIPSize         = unsafe.Offsetof(state.State{}.IPSize) - evtHdrSize
	offsetRulesHit       = unsafe.Offsetof(state.State{}.RulesHit) - evtHdrSize
	offsetRuleIDs        = unsafe.Offsetof(state.State{}.RuleIDs) - evtHdrSize
)

func ParsePolicyVerdict(data []byte, isIPv6 bool) PolicyVerdict {
	fl := PolicyVerdict{
		PolicyRC:       state.PolicyResult(binary.LittleEndian.Uint32(data[offsetPolicyRC : offsetPolicyRC+4])),
		SrcPort:        binary.LittleEndian.Uint16(data[offsetSrcPort : offsetSrcPort+2]),
		DstPort:        binary.LittleEndian.Uint16(data[offsetDstPort : offsetDstPort+2]),
		PostNATDstPort: binary.LittleEndian.Uint16(data[offsetPostNATDstPort : offsetPostNATDstPort+2]),
		IPProto:        data[offsetIPProto],
		IPSize:         binary.BigEndian.Uint16(data[offsetIPSize : offsetIPSize+2]),
		RulesHit:       binary.LittleEndian.Uint32(data[offsetRulesHit : offsetRulesHit+4]),
	}

	if fl.RulesHit > state.MaxRuleIDs {
		fl.RulesHit = state.MaxRuleIDs
	}

	ipLen := uintptr(4)
	if isIPv6 {
		ipLen = 16
	}
	fl.SrcAddr = net.IP(data[offsetSrcAddr : offsetSrcAddr+ipLen])
	fl.DstAddr = net.IP(data[offsetDstAddr : offsetDstAddr+ipLen])
	fl.PostNATDstAddr = net.IP(data[offsetPostNATDstAddr : offsetPostNATDstAddr+ipLen])
	fl.NATTunSrcAddr = net.IP(data[offsetNATTunSrcAddr : offsetNATTunSrcAddr+ipLen])

	off := offsetRuleIDs
	for i := 0; i < int(fl.RulesHit); i++ {
		fl.RuleIDs[i] = binary.LittleEndian.Uint64(data[off : off+8])
		off += 8
	}

	return fl
}

// PolicyVerdict describes the policy verdict event and must match the initial part of
// bpf/state.State after the space reserved for the event header.
type PolicyVerdict struct {
	SrcAddr        net.IP
	DstAddr        net.IP
	PostNATDstAddr net.IP
	NATTunSrcAddr  net.IP
	PolicyRC       state.PolicyResult
	SrcPort        uint16
	DstPort        uint16
	PostNATDstPort uint16
	IPProto        uint8
	pad8           uint8 //nolint:unused // Ignore U1000 unused
	IPSize         uint16
	RulesHit       uint32
	RuleIDs        [state.MaxRuleIDs]uint64
}

// Type return TypePolicyVerdict
func (PolicyVerdict) Type() Type {
	return TypePolicyVerdict
}
