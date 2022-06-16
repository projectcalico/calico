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

package conntrack_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	v2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"
	"github.com/projectcalico/calico/felix/bpf/mock"
)

var now = mocktime.StartKTime

var (
	ip1        = net.ParseIP("10.0.0.1")
	ip2        = net.ParseIP("10.0.0.2")
	tcpKey     = conntrack.NewKey(conntrack.ProtoTCP, ip1, 1234, ip2, 3456)
	udpKey     = conntrack.NewKey(conntrack.ProtoUDP, ip1, 1234, ip2, 3456)
	icmpKey    = conntrack.NewKey(conntrack.ProtoICMP, ip1, 1234, ip2, 3456)
	genericKey = conntrack.NewKey(253, ip1, 0, ip2, 0)

	timeouts = conntrack.DefaultTimeouts()

	genericJustCreated    = makeValue(now-1, now-1, conntrack.Leg{}, conntrack.Leg{})
	genericAlmostTimedOut = makeValue(now-(20*time.Minute), now-(599*time.Second), conntrack.Leg{Whitelisted: true}, conntrack.Leg{})
	genericTimedOut       = makeValue(now-(20*time.Minute), now-(601*time.Second), conntrack.Leg{Whitelisted: true}, conntrack.Leg{})

	udpJustCreated    = makeValue(now-1, now-1, conntrack.Leg{}, conntrack.Leg{})
	udpAlmostTimedOut = makeValue(now-(2*time.Minute), now-(59*time.Second), conntrack.Leg{Whitelisted: true}, conntrack.Leg{})
	udpTimedOut       = makeValue(now-(2*time.Minute), now-(61*time.Second), conntrack.Leg{Whitelisted: true}, conntrack.Leg{})

	icmpJustCreated    = makeValue(now-1, now-1, conntrack.Leg{}, conntrack.Leg{})
	icmpAlmostTimedOut = makeValue(now-(2*time.Minute), now-(4*time.Second), conntrack.Leg{Whitelisted: true}, conntrack.Leg{})
	icmpTimedOut       = makeValue(now-(2*time.Minute), now-(6*time.Second), conntrack.Leg{Whitelisted: true}, conntrack.Leg{})

	tcpJustCreated        = makeValue(now-1, now-1, conntrack.Leg{SynSeen: true}, conntrack.Leg{})
	tcpHandshakeTimeout   = makeValue(now-22*time.Second, now-21*time.Second, conntrack.Leg{SynSeen: true}, conntrack.Leg{})
	tcpHandshakeTimeout2  = makeValue(now-22*time.Second, now-21*time.Second, conntrack.Leg{SynSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpEstablished        = makeValue(now-(10*time.Second), now-1, conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpEstablishedTimeout = makeValue(now-(3*time.Hour), now-(2*time.Hour), conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpSingleFin          = makeValue(now-(3*time.Hour), now-(50*time.Minute), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpSingleFinTimeout   = makeValue(now-(3*time.Hour), now-(2*time.Hour), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpBothFin            = makeValue(now-(3*time.Hour), now-(29*time.Second), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true})
	tcpBothFinTimeout     = makeValue(now-(3*time.Hour), now-(31*time.Second), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true})
)

func makeValue(created time.Duration, lastSeen time.Duration, legA conntrack.Leg, legB conntrack.Leg) conntrack.Value {
	return conntrack.NewValueNormal(created, lastSeen, 0, legA, legB)
}

var _ = Describe("BPF Conntrack LivenessCalculator", func() {
	var lc *conntrack.LivenessScanner
	var scanner *conntrack.Scanner
	var ctMap *mock.Map
	var mockTime *mocktime.MockTime

	BeforeEach(func() {
		mockTime = mocktime.New()
		Expect(mockTime.KTimeNanos()).To(BeNumerically("==", now))
		ctMap = mock.NewMockMap(conntrack.MapParams)
		lc = conntrack.NewLivenessScanner(timeouts, false, conntrack.WithTimeShim(mockTime))
		scanner = conntrack.NewScanner(ctMap, lc)
	})

	DescribeTable(
		"expiry tests",
		func(key conntrack.Key, entry conntrack.Value, expExpired bool) {
			By("calculating expiry of normal entry")
			reason, expired := timeouts.EntryExpired(int64(now), key.Proto(), entry)
			Expect(expired).To(Equal(expExpired), fmt.Sprintf("EntryExpired returned unexpected value with reason: %s", reason))
			if expired {
				Expect(reason).ToNot(BeEmpty())
			}

			By("calculating expiry with legs reversed")
			var eReversed conntrack.Value
			copy(eReversed[:], entry[:])
			copy(eReversed[24:32], entry[32:40])
			copy(eReversed[32:40], entry[24:32])
			reason, expired = timeouts.EntryExpired(int64(now), key.Proto(), entry)
			Expect(expired).To(Equal(expExpired), fmt.Sprintf("EntryExpired returned unexpected value (for reversed legs) with reason: %s", reason))
			if expired {
				Expect(reason).ToNot(BeEmpty())
			}

			By("correctly handling the entry as part of a scan")
			err := ctMap.Update(key.AsBytes(), entry[:])
			Expect(err).NotTo(HaveOccurred())

			scanner.Scan()
			_, err = ctMap.Get(key.AsBytes())
			if expExpired {
				Expect(bpf.IsNotExists(err)).To(BeTrue(), "Scan() should have cleaned up entry")
			} else {
				Expect(err).NotTo(HaveOccurred(), "Scan() deleted entry unexpectedly")
			}

			By("always deleting the entry if we fast-forward time")
			err = ctMap.Update(key.AsBytes(), entry[:])
			Expect(err).NotTo(HaveOccurred())
			mockTime.IncrementTime(2 * time.Hour)
			scanner.Scan()
			_, err = ctMap.Get(key.AsBytes())
			Expect(bpf.IsNotExists(err)).To(BeTrue(), "Scan() should have cleaned up entry")
		},
		Entry("TCP just created", tcpKey, tcpJustCreated, false),
		Entry("TCP handshake timeout", tcpKey, tcpHandshakeTimeout, true),
		Entry("TCP handshake timeout on response", tcpKey, tcpHandshakeTimeout2, true),
		Entry("TCP established", tcpKey, tcpEstablished, false),
		Entry("TCP established timed out", tcpKey, tcpEstablishedTimeout, true),
		Entry("TCP single fin", tcpKey, tcpSingleFin, false),
		Entry("TCP single fin timed out", tcpKey, tcpSingleFinTimeout, true),
		Entry("TCP both fin", tcpKey, tcpBothFin, false),
		Entry("TCP both fin timed out", tcpKey, tcpBothFinTimeout, true),

		Entry("UDP just created", udpKey, udpJustCreated, false),
		Entry("UDP almost timed out", udpKey, udpAlmostTimedOut, false),
		Entry("UDP timed out", udpKey, udpTimedOut, true),

		Entry("Generic just created", genericKey, genericJustCreated, false),
		Entry("Generic almost timed out", genericKey, genericAlmostTimedOut, false),
		Entry("Generic timed out", genericKey, genericTimedOut, true),

		Entry("icmp just created", icmpKey, icmpJustCreated, false),
		Entry("icmp almost timed out", icmpKey, icmpAlmostTimedOut, false),
		Entry("icmp timed out", icmpKey, icmpTimedOut, true),
	)
})

type dummyNATChecker struct {
	check func(fIP net.IP, fPort uint16, bIP net.IP, bPort uint16, proto uint8) bool
}

func (d dummyNATChecker) ConntrackFrontendHasBackend(fIP net.IP, fPort uint16, bIP net.IP,
	bPort uint16, proto uint8) bool {

	return d.check(fIP, fPort, bIP, bPort, proto)
}

func (dummyNATChecker) ConntrackScanStart() {}
func (dummyNATChecker) ConntrackScanEnd()   {}

var _ = Describe("BPF Conntrack StaleNATScanner", func() {

	clientIP := net.IPv4(1, 1, 1, 1)
	clientPort := uint16(1111)

	svcIP := net.IPv4(4, 3, 2, 1)
	svcPort := uint16(4321)

	backendIP := net.IPv4(2, 2, 2, 2)
	backendPort := uint16(2222)

	snatPort := uint16(456)

	withSNATPort := func(snatport uint16, v conntrack.Value) conntrack.Value {
		binary.LittleEndian.PutUint16(v[40:42], snatport)
		return v
	}

	DescribeTable("forward entries",
		func(k conntrack.Key, v conntrack.Value, verdict conntrack.ScanVerdict) {
			staleNATScanner := conntrack.NewStaleNATScanner(dummyNATChecker{
				check: func(fIP net.IP, fPort uint16, bIP net.IP, bPort uint16, proto uint8) bool {
					Expect(proto).To(Equal(uint8(123)))
					Expect(fIP.Equal(svcIP)).To(BeTrue())
					Expect(fPort).To(Equal(svcPort))
					Expect(bIP.Equal(backendIP)).To(BeTrue())
					Expect(bPort).To(Equal(backendPort))
					return false
				},
			},
			)

			Expect(verdict).To(Equal(staleNATScanner.Check(k, v, nil)))
		},
		Entry("keyA - revA",
			conntrack.NewKey(123, clientIP, clientPort, svcIP, svcPort),
			conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, clientIP, clientPort, backendIP, backendPort)),
			conntrack.ScanVerdictDelete,
		),
		Entry("keyA - revB",
			conntrack.NewKey(123, clientIP, clientPort, svcIP, svcPort),
			conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort)),
			conntrack.ScanVerdictDelete,
		),
		Entry("keyB - revA",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, clientIP, clientPort, backendIP, backendPort)),
			conntrack.ScanVerdictDelete,
		),
		Entry("keyB - revB",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort)),
			conntrack.ScanVerdictDelete,
		),
		Entry("mismatch key port",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, 54545),
			conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort)),
			conntrack.ScanVerdictOK,
		),
		Entry("mismatch key IP",
			conntrack.NewKey(123, svcIP, svcPort, net.IPv4(2, 1, 2, 1), clientPort),
			conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort)),
			conntrack.ScanVerdictOK,
		),
		Entry("mismatch rev port",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, 12321)),
			conntrack.ScanVerdictOK,
		),
		Entry("mismatch rev IP",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, backendIP, backendPort, net.IPv4(3, 2, 2, 3), clientPort)),
			conntrack.ScanVerdictOK,
		),
		Entry("snatport keyA - revA",
			conntrack.NewKey(123, clientIP, clientPort, svcIP, svcPort),
			withSNATPort(snatPort,
				conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, clientIP, snatPort, backendIP, backendPort))),
			conntrack.ScanVerdictDelete,
		),
		Entry("snatport keyA - revB",
			conntrack.NewKey(123, clientIP, clientPort, svcIP, svcPort),
			withSNATPort(snatPort,
				conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, snatPort))),
			conntrack.ScanVerdictDelete,
		),
		Entry("snatport keyB - revA",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			withSNATPort(snatPort,
				conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, clientIP, snatPort, backendIP, backendPort))),
			conntrack.ScanVerdictDelete,
		),
		Entry("snatport keyB - revB",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			withSNATPort(snatPort,
				conntrack.NewValueNATForward(0, 0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, snatPort))),
			conntrack.ScanVerdictDelete,
		),
	)
})

var _ = Describe("BPF Conntrack upgrade entries", func() {
	k2 := v2.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)
	k3 := conntrack.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)

	v2Normal := v2.NewValueNormal(now-1, now-1, 0, v2.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v2.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201})
	v3Normal := conntrack.NewValueNormal(now-1, now-1, 0, conntrack.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, conntrack.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201})

	v2NatReverse := v2.NewValueNATReverse(now-1, now-1, 0, v2.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v2.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234)
	v3NatReverse := conntrack.NewValueNATReverse(now-1, now-1, 0, conntrack.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, conntrack.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234)

	v2NatRevSnat := v2.NewValueNATReverseSNAT(now-1, now-1, 0, v2.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v2.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), net.IPv4(9, 10, 11, 12), 1234)
	v3NatRevSnat := conntrack.NewValueNATReverseSNAT(now-1, now-1, 0, conntrack.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, conntrack.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), net.IPv4(9, 10, 11, 12), 1234)

	v2NatFwd := v2.NewValueNATForward(now-1, now-1, 0, v2.NewKey(3, net.ParseIP("20.0.0.1"), 0, net.ParseIP("20.0.0.2"), 0))
	v3NatFwd := conntrack.NewValueNATForward(now-1, now-1, 0, conntrack.NewKey(3, net.ParseIP("20.0.0.1"), 0, net.ParseIP("20.0.0.2"), 0))
	DescribeTable("upgrade entries",
		func(k2 v2.Key, v2 v2.Value, k3 conntrack.Key, v3 conntrack.Value) {
			upgradedKey := k2.Upgrade()
			upgradedValue := v2.Upgrade()
			Expect(upgradedKey.AsBytes()).To(Equal(k3.AsBytes()))
			Expect(upgradedValue.AsBytes()).To(Equal(v3.AsBytes()))
		},
		Entry("conntrack normal entry",
			k2, v2Normal, k3, v3Normal,
		),
		Entry("conntrack nat rev entry",
			k2, v2NatReverse, k3, v3NatReverse,
		),
		Entry("conntrack nat rev entry",
			k2, v2NatRevSnat, k3, v3NatRevSnat,
		),
		Entry("conntrack nat rev entry",
			k2, v2NatFwd, k3, v3NatFwd,
		),
	)
})
