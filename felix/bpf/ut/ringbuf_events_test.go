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

package ut_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/ringbuf"
)

const (
	// eventSize must match sizeof(struct tuple) in ringbuf_events.c:
	// event_header(8) + ip_src(4) + ip_dst(4) + port_src(2) + port_dst(2) + proto(1) + _pad(1027)
	eventSize uint32 = 8 + 4 + 4 + 2 + 2 + 1 + 1027
	rbSize    int    = 1024 * 1024
)

func TestRingBufBasic(t *testing.T) {
	RegisterTestingT(t)
	hostIP = node1ip

	_, iphdr, l4, _, pktBytes, err := testPacket(4, nil, nil, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	ipv4 := iphdr.(*layers.IPv4)
	udp := l4.(*layers.UDP)

	rb, err := ringbuf.New(ringBufMap, rbSize)
	Expect(err).NotTo(HaveOccurred())
	defer rb.Close()

	// Send a UDP packet and verify the event.
	runBpfUnitTest(t, "ringbuf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	eventRaw, err := rb.Next()
	Expect(err).NotTo(HaveOccurred())

	eventHdr := eventHdrFromBytes(eventRaw.Data()[0:8])
	Expect(eventHdr.typ).To(Equal(uint32(0xdead)))
	Expect(eventHdr.size).To(Equal(eventSize))

	event := eventFromBytes(eventRaw.Data())
	Expect(event.srcIP).To(Equal(ipv4.SrcIP))
	Expect(event.dstIP).To(Equal(ipv4.DstIP))
	Expect(event.srcPort).To(Equal(uint16(udp.SrcPort)))
	Expect(event.dstPort).To(Equal(uint16(udp.DstPort)))
	Expect(event.proto).To(Equal(uint8(ipv4.Protocol)))

	// Send an ICMP packet and verify the event is also delivered via the ring buffer.
	// Unlike the old perf test, there are no kernel-appended context bytes — the event
	// struct is the same size regardless of protocol.
	icmpUNreachable := makeICMPError(ipv4, udp, 3 /* Unreachable */, 1 /* Host unreachable */)

	runBpfUnitTest(t, "ringbuf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	eventRaw, err = rb.Next()
	Expect(err).NotTo(HaveOccurred())
	eventHdr = eventHdrFromBytes(eventRaw.Data()[0:8])
	// The BPF program sets type to 0xdead for all protocols (no special ICMP path anymore).
	Expect(eventHdr.typ).To(Equal(uint32(0xdead)))
	Expect(eventHdr.size).To(Equal(eventSize))

	event = eventFromBytes(eventRaw.Data())
	Expect(event.proto).To(Equal(uint8(layers.IPProtocolICMPv4)))
}

// TestRingBufReaderRecovery verifies that closing and re-opening a ring buffer
// reader on the same map allows the new reader to receive subsequent events.
// This is the ring buffer equivalent of the old TestPerfCrash.
func TestRingBufReaderRecovery(t *testing.T) {
	RegisterTestingT(t)

	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	rb, err := ringbuf.New(ringBufMap, rbSize)
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "ringbuf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	eventRaw, err := rb.Next()
	Expect(err).NotTo(HaveOccurred())
	Expect(len(eventRaw.Data())).To(BeNumerically(">", 0))

	// Close the first reader and create a new one on the same map.
	rb.Close()

	rb2, err := ringbuf.New(ringBufMap, rbSize)
	Expect(err).NotTo(HaveOccurred())
	defer rb2.Close()

	// Send another event — the new reader should pick it up.
	runBpfUnitTest(t, "ringbuf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	eventRaw, err = rb2.Next()
	Expect(err).NotTo(HaveOccurred())
	Expect(len(eventRaw.Data())).To(BeNumerically(">", 0))
}

// TestRingBufFillup verifies that the ring buffer correctly handles being filled
// to capacity. When full, bpf_ringbuf_output returns an error and the BPF program
// returns TC_ACT_SHOT. After draining, a subsequent successful event triggers
// ringbuf_flush_drops, emitting a TYPE_LOST_EVENTS event with the accumulated
// drop count.
func TestRingBufFillup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping a long test")
	}

	RegisterTestingT(t)

	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	rb, err := ringbuf.New(ringBufMap, rbSize)
	Expect(err).NotTo(HaveOccurred())
	defer rb.Close()

	// Drain any leftover events from previous tests and reset the drops map
	// so we start with a completely clean state.
	rb.Drain()
	// Reset the single-entry drops map (struct rb_drops_val = 24 bytes).
	k := make([]byte, 4) // key = 0
	zeroVal := make([]byte, 24)
	err = ringBufDropsMap.Update(k, zeroVal)
	Expect(err).NotTo(HaveOccurred())

	// Each event record in the ring buffer is: 8-byte ringbuf header + eventSize, rounded up to 8.
	eventRecordSize := int(eventSize) + 8
	if eventRecordSize%8 != 0 {
		eventRecordSize += 8 - (eventRecordSize % 8)
	}
	maxEvents := rbSize / eventRecordSize

	// Fill the ring buffer by sending events without consuming them.
	eventsWritten := 0
	for {
		retval := resTC_ACT_UNSPEC
		runBpfUnitTest(t, "ringbuf_events.c",
			func(bpfrun bpfProgRunFn) {
				res, err := bpfrun(pktBytes)
				Expect(err).NotTo(HaveOccurred())
				retval = res.Retval
			},
			withSubtests(false), withLogLevel(log.WarnLevel),
		)
		if retval == resTC_ACT_SHOT {
			// Ring buffer is full — bpf_ringbuf_output returned -ENOBUFS.
			// This increments cali_rb_drops[0] by 1.
			break
		}
		eventsWritten++
		// Safety check: we should fill up within maxEvents.
		Expect(eventsWritten).To(BeNumerically("<=", maxEvents),
			"Ring buffer should have been full by now")
	}

	// We should have written at least one event before filling up.
	Expect(eventsWritten).To(BeNumerically(">", 0))

	// Drain all data events from the ring buffer to free space.
	drained := rb.Drain()
	Expect(drained).To(Equal(eventsWritten))

	// Send one more event after draining. This succeeds and triggers
	// ringbuf_flush_drops(), which emits a TYPE_LOST_EVENTS event with the
	// drop count (exactly 1 from the failed submit above).
	// The ring order is: data event first, then lost event.
	runBpfUnitTest(t, "ringbuf_events.c",
		func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		},
		withSubtests(false), withLogLevel(log.WarnLevel),
	)

	// First: the data event.
	dataEvent, err := rb.Next()
	Expect(err).NotTo(HaveOccurred())
	dataHdr := eventHdrFromBytes(dataEvent.Data()[0:8])
	Expect(dataHdr.typ).To(Equal(uint32(0xdead)))

	// Second: the TYPE_LOST_EVENTS event with exactly 1 drop.
	lostEvent, err := rb.Next()
	Expect(err).NotTo(HaveOccurred())
	lostData := lostEvent.Data()
	lostHdr := eventHdrFromBytes(lostData[0:8])
	Expect(lostHdr.typ).To(Equal(uint32(0)), "Expected EVENT_LOST_EVENTS (type 0)")
	Expect(lostHdr.size).To(Equal(uint32(16)), "Expected event_header(8) + u64 count(8)")
	droppedCount := binary.LittleEndian.Uint64(lostData[8:16])
	Expect(droppedCount).To(Equal(uint64(1)),
		"Expected exactly 1 drop from the failed submit when ring was full")
}

// TestRingBufMultipleEvents sends multiple events and verifies they are all
// received in order.
func TestRingBufMultipleEvents(t *testing.T) {
	RegisterTestingT(t)
	hostIP = node1ip

	rb, err := ringbuf.New(ringBufMap, rbSize)
	Expect(err).NotTo(HaveOccurred())
	defer rb.Close()

	numEvents := 10
	for range numEvents {
		_, _, _, _, pktBytes, err := testPacketUDPDefault()
		Expect(err).NotTo(HaveOccurred())

		runBpfUnitTest(t, "ringbuf_events.c", func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		})
	}

	for range numEvents {
		eventRaw, err := rb.Next()
		Expect(err).NotTo(HaveOccurred())
		Expect(len(eventRaw.Data())).To(BeNumerically(">", 0))

		hdr := eventHdrFromBytes(eventRaw.Data()[0:8])
		Expect(hdr.typ).To(Equal(uint32(0xdead)))
		Expect(hdr.size).To(Equal(eventSize))
	}
}

type eventHdr struct {
	typ  uint32
	size uint32
}

func eventHdrFromBytes(bytes []byte) eventHdr {
	return eventHdr{
		typ:  binary.LittleEndian.Uint32(bytes[0:4]),
		size: binary.LittleEndian.Uint32(bytes[4:8]),
	}
}

type event struct {
	eventHdr
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	proto   uint8
}

func eventFromBytes(bytes []byte) event {
	hdr := eventHdrFromBytes(bytes)

	return event{
		eventHdr: hdr,
		srcIP:    net.IP(bytes[8:12]),
		dstIP:    net.IP(bytes[12:16]),
		srcPort:  binary.LittleEndian.Uint16(bytes[16:18]),
		dstPort:  binary.LittleEndian.Uint16(bytes[18:20]),
		proto:    bytes[20],
	}
}
