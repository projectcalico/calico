// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package conntrack_test

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/collector"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

var now = mocktime.StartKTime

var _ = Describe("BPF Conntrack InfoReader", func() {

	clientIP := net.IPv4(1, 1, 1, 1)
	clientPort := uint16(1111)

	svcIP := net.IPv4(4, 3, 2, 1)
	svcPort := uint16(4321)

	backendIP := net.IPv4(2, 2, 2, 2)
	backendPort := uint16(2222)

	LegSrcDst := conntrack.Leg{Opener: true}
	LegDstSrc := conntrack.Leg{}

	var (
		reader                *conntrack.InfoReader
		mockTime              *mocktime.MockTime
		collectorCtInfoReader *conntrack.CollectorCtInfoReader
	)

	BeforeEach(func() {
		mockTime = mocktime.New()
		Expect(mockTime.KTimeNanos()).To(BeNumerically("==", now))
		collectorCtInfoReader = conntrack.NewCollectorCtInfoReader()
		reader = conntrack.NewInfoReader(timeouts, false, mockTime, collectorCtInfoReader)
	})

	DescribeTable("forward entries",
		func(k conntrack.Key, v conntrack.Value, expected collector.ConntrackInfo) {
			reader.IterationStart()
			reader.Check(k, v, nil)
			reader.IterationEnd()
			got := <-collectorCtInfoReader.ConntrackInfoChan()

			Expect(got[0]).To(Equal(expected))
		},
		Entry("normal entry - no NAT",
			conntrack.NewKey(123, clientIP, clientPort, backendIP, backendPort),
			conntrack.NewValueNormal(now, now, 0, LegSrcDst, LegDstSrc),
			collector.ConntrackInfo{
				Tuple: makeTuple(clientIP, backendIP, clientPort, backendPort, 123),
			},
		),
		Entry("normal entry - no NAT - swapped legs",
			conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort),
			conntrack.NewValueNormal(now, now, 0, LegDstSrc, LegSrcDst),
			collector.ConntrackInfo{
				Tuple: makeTuple(clientIP, backendIP, clientPort, backendPort, 123),
			},
		),
		Entry("normal entry - no NAT - expired",
			conntrack.NewKey(123, clientIP, clientPort, backendIP, backendPort),
			conntrack.NewValueNormal(now-2*time.Hour, now-time.Hour, 0, LegSrcDst, LegDstSrc),
			collector.ConntrackInfo{
				Expired: true,
				Tuple:   makeTuple(clientIP, backendIP, clientPort, backendPort, 123),
			},
		),
		Entry("normal entry - no NAT - expired - swapped legs",
			conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort),
			conntrack.NewValueNormal(now-2*time.Hour, now-time.Hour, 0, LegDstSrc, LegSrcDst),
			collector.ConntrackInfo{
				Expired: true,
				Tuple:   makeTuple(clientIP, backendIP, clientPort, backendPort, 123),
			},
		),

		Entry("reverse entry - NAT",
			conntrack.NewKey(123, clientIP, clientPort, backendIP, backendPort),
			conntrack.NewValueNATReverse(now, now, 0, LegSrcDst, LegDstSrc, net.IPv4(0, 0, 0, 0), svcIP, svcPort),
			collector.ConntrackInfo{
				IsDNAT:       true,
				Tuple:        makeTuple(clientIP, backendIP, clientPort, backendPort, 123),
				PreDNATTuple: makeTuple(clientIP, svcIP, clientPort, svcPort, 123),
			},
		),
		Entry("reverse entry - NAT - swapped legs",
			conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort),
			conntrack.NewValueNATReverse(now, now, 0, LegDstSrc, LegSrcDst, net.IPv4(0, 0, 0, 0), svcIP, svcPort),
			collector.ConntrackInfo{
				IsDNAT:       true,
				Tuple:        makeTuple(clientIP, backendIP, clientPort, backendPort, 123),
				PreDNATTuple: makeTuple(clientIP, svcIP, clientPort, svcPort, 123),
			},
		),
		Entry("reverse entry - NAT - expired",
			conntrack.NewKey(123, clientIP, clientPort, backendIP, backendPort),
			conntrack.NewValueNATReverse(now-2*time.Hour, now-time.Hour, 0, LegSrcDst, LegDstSrc, net.IPv4(0, 0, 0, 0), svcIP, svcPort),
			collector.ConntrackInfo{
				Expired:      true,
				IsDNAT:       true,
				Tuple:        makeTuple(clientIP, backendIP, clientPort, backendPort, 123),
				PreDNATTuple: makeTuple(clientIP, svcIP, clientPort, svcPort, 123),
			},
		),
		Entry("reverse entry - NAT - expired - swapped legs",
			conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort),
			conntrack.NewValueNATReverse(now-2*time.Hour, now-time.Hour, 0, LegDstSrc, LegSrcDst, net.IPv4(0, 0, 0, 0), svcIP, svcPort),
			collector.ConntrackInfo{
				Expired:      true,
				IsDNAT:       true,
				Tuple:        makeTuple(clientIP, backendIP, clientPort, backendPort, 123),
				PreDNATTuple: makeTuple(clientIP, svcIP, clientPort, svcPort, 123),
			},
		),
	)
})

func makeTuple(src, dst net.IP, srcP, dstP uint16, proto uint8) tuple.Tuple {
	var s, d [16]byte
	copy(s[:], src.To16())
	copy(d[:], dst.To16())
	return tuple.Make(s, d, int(proto), int(srcP), int(dstP))
}
