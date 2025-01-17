// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"runtime"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/perf"
)

const (
	eventSize uint32 = 8 + 4 + 4 + 2 + 2 + 1 + 1027
	ringSize  int    = 4 << 10
)

func TestPerfBasic(t *testing.T) {
	RegisterTestingT(t)
	hostIP = node1ip

	_, iphdr, l4, _, pktBytes, err := testPacket(4, nil, nil, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	ipv4 := iphdr.(*layers.IPv4)
	udp := l4.(*layers.UDP)

	runBpfUnitTest(t, "perf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		// no buffers allocated yet
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	perfEvents, err := perf.New(perfMap, ringSize)
	Expect(err).NotTo(HaveOccurred())
	defer perfEvents.Close()

	runBpfUnitTest(t, "perf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	eventRaw, err := perfEvents.Next()
	Expect(err).NotTo(HaveOccurred())

	Expect(eventRaw.LostEvents()).To(Equal(0))

	eventHdr := eventHdrFromBytes(eventRaw.Data()[0:4])
	Expect(eventHdr.typ).To(Equal(uint32(0xdead)))
	Expect(eventHdr.size).To(Equal(eventSize))

	event := eventFromBytes(eventRaw.Data())
	Expect(event.srcIP).To(Equal(ipv4.SrcIP))
	Expect(event.dstIP).To(Equal(ipv4.DstIP))
	Expect(event.srcPort).To(Equal(uint16(udp.SrcPort)))
	Expect(event.dstPort).To(Equal(uint16(udp.DstPort)))
	Expect(event.proto).To(Equal(uint8(ipv4.Protocol)))
	Expect(event.pkt).To(BeNil())

	icmpUNreachable := makeICMPError(ipv4, udp, 3 /* Unreachable */, 1 /*Host unreachable error */)

	runBpfUnitTest(t, "perf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	eventRaw, err = perfEvents.Next()
	Expect(err).NotTo(HaveOccurred())
	eventHdr = eventHdrFromBytes(eventRaw.Data()[0:4])
	Expect(eventHdr.typ).To(Equal(uint32(0xdead + 1)))
	Expect(eventHdr.size).To(Equal(eventSize + uint32(len(icmpUNreachable))))

	event = eventFromBytes(eventRaw.Data())
	Expect(event.pkt).NotTo(BeNil())
	Expect(icmpUNreachable).To(Equal(event.pkt.Data()))
}

func TestPerfCrash(t *testing.T) {
	RegisterTestingT(t)

	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	perfEvents, err := perf.New(perfMap, ringSize)
	Expect(err).NotTo(HaveOccurred())
	defer perfEvents.Close()

	runBpfUnitTest(t, "perf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	eventRaw, err := perfEvents.Next()
	Expect(err).NotTo(HaveOccurred())
	Expect(eventRaw.LostEvents()).To(Equal(0))

	// Create a new perf event ring with the same map, the original is still
	// live, but we should receive the events here.
	perfEvents2, err := perf.New(perfMap, ringSize)
	Expect(err).NotTo(HaveOccurred())
	defer perfEvents2.Close()

	runBpfUnitTest(t, "perf_events.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	eventRaw, err = perfEvents2.Next()
	Expect(err).NotTo(HaveOccurred())
	Expect(eventRaw.LostEvents()).To(Equal(0))
}

func TestPerfFillup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping a long test")
	}

	RegisterTestingT(t)

	numcpu := runtime.NumCPU()
	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	perfEvents, err := perf.New(perfMap, ringSize)
	Expect(err).NotTo(HaveOccurred())
	defer perfEvents.Close()

	retval := resTC_ACT_UNSPEC
	for {
		runBpfUnitTest(t, "perf_events.c",
			func(bpfrun bpfProgRunFn) {
				res, err := bpfrun(pktBytes)
				Expect(err).NotTo(HaveOccurred())
				retval = res.Retval
			},
			withSubtests(false), withLogLevel(log.WarnLevel),
		)
		if retval == resTC_ACT_SHOT {
			break
		}
	}

	// Round up to 8
	eventRingSize := eventSize
	if eventSize%8 != 0 {
		eventRingSize += 8 - (eventSize % 8)
	}
	eventRingSize += 8 // the kernel/ring header
	ringMaxMsgs := ringSize / int(eventRingSize)
	cpus := make([]int, numcpu)

	for {
		event, err := perfEvents.Next()
		Expect(err).NotTo(HaveOccurred())
		cpus[event.CPU()]++
		// One of the rings must be full
		if cpus[event.CPU()] == ringMaxMsgs-1 {
			return
		}
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
	pkt     gopacket.Packet
}

func eventFromBytes(bytes []byte) event {
	hdr := eventHdrFromBytes(bytes)

	event := event{
		eventHdr: hdr,
		srcIP:    net.IP(bytes[8:12]),
		dstIP:    net.IP(bytes[12:16]),
		srcPort:  binary.LittleEndian.Uint16(bytes[16:18]),
		dstPort:  binary.LittleEndian.Uint16(bytes[18:20]),
		proto:    bytes[20],
	}

	if hdr.size > eventSize {
		pktSize := hdr.size - eventSize
		event.pkt = gopacket.NewPacket(bytes[eventSize:eventSize+pktSize], layers.LayerTypeEthernet, gopacket.Default)
	}

	return event
}
