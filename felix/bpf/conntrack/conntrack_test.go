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

package conntrack_test

import (
	"encoding/binary"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/cttestdata"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	v2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"
	v3 "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

var _ = Describe("BPF Conntrack LivenessCalculator", func() {
	var lc *conntrack.LivenessScanner
	var scanner *conntrack.Scanner
	var ctMap, ctCleanupMap *mock.Map
	var mockTime *mocktime.MockTime

	BeforeEach(func() {
		mockTime = mocktime.New()
		Expect(mockTime.KTimeNanos()).To(BeNumerically("==", cttestdata.Now))
		ctMap = mock.NewMockMap(conntrack.MapParams)
		ctCleanupMap = mock.NewMockMap(conntrack.MapParamsCleanup)
		lc = conntrack.NewLivenessScanner(timeouts.DefaultTimeouts(), false, conntrack.WithTimeShim(mockTime))
		scanner = conntrack.NewScanner(ctMap, conntrack.KeyFromBytes, conntrack.ValueFromBytes, nil, "Disabled",
			ctCleanupMap, 4, mock.NewMockBPFCleaner(ctMap, ctCleanupMap), lc)
	})

	// Convert test cases from the testdata package into Ginkgo table entries.
	// We share the test data with the tests for the BPF program.
	var entries []TableEntry
	for _, tc := range cttestdata.CTCleanupTests {
		entries = append(entries, Entry(tc.Description, tc))
	}

	DescribeTable(
		"expiry tests",
		func(tc cttestdata.CTCleanupTest) {
			for k, v := range tc.KVs {
				err := ctMap.Update(k.AsBytes(), v[:])
				Expect(err).NotTo(HaveOccurred())
			}

			scanner.Scan()
			var deletedEntries []conntrack.Key
			for k := range tc.KVs {
				_, err := ctMap.Get(k.AsBytes())
				if maps.IsNotExists(err) {
					deletedEntries = append(deletedEntries, k)
				} else {
					Expect(err).NotTo(HaveOccurred(), "unexpected error from map lookup")
				}
			}
			Expect(deletedEntries).To(ConsistOf(tc.ExpectedDeletions),
				"Scan() did not delete the expected entries")
		},
		entries,
	)

	DescribeTable(
		"should always delete entries if we fast-forward time",
		func(tc cttestdata.CTCleanupTest) {
			for k, v := range tc.KVs {
				err := ctMap.Update(k.AsBytes(), v[:])
				Expect(err).NotTo(HaveOccurred())
			}

			mockTime.IncrementTime(2 * time.Hour)
			scanner.Scan()

			Expect(ctMap.IsEmpty()).To(BeTrue(), "all entries should have been deleted, but map isn't empty")
		},
		entries,
	)
})

type dummyNATChecker struct {
	check func(fIP net.IP, fPort uint16, bIP net.IP, bPort uint16, proto uint8) bool
}

func (d dummyNATChecker) ConntrackFrontendHasBackend(
	fIP net.IP, fPort uint16, bIP net.IP,
	bPort uint16, proto uint8,
) bool {
	return d.check(fIP, fPort, bIP, bPort, proto)
}

func (dummyNATChecker) ConntrackDestIsService(ip net.IP, port uint16, proto uint8) bool {
	return true
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

	backendIP2 := net.IPv4(2, 2, 2, 3)
	backendPort2 := uint16(223)

	snatPort := uint16(456)

	withSNATPort := func(snatport uint16, v conntrack.Value) conntrack.Value {
		binary.LittleEndian.PutUint16(v[40:42], snatport)
		return v
	}

	DescribeTable("forward entries",
		func(k conntrack.Key, v conntrack.Value, verdict conntrack.ScanVerdict, getFn ...conntrack.EntryGet) {
			staleNATScanner := conntrack.NewStaleNATScanner(dummyNATChecker{
				check: func(fIP net.IP, fPort uint16, bIP net.IP, bPort uint16, proto uint8) bool {
					Expect(proto).To(Equal(uint8(123)))
					Expect(fIP.Equal(svcIP)).To(BeTrue())
					Expect(fPort).To(Equal(svcPort))

					if bIP.Equal(backendIP2) && bPort == backendPort2 {
						return true
					}

					Expect(bIP.Equal(backendIP)).To(BeTrue())
					Expect(bPort).To(Equal(backendPort))
					return false
				},
			},
			)

			var get conntrack.EntryGet
			if len(getFn) == 1 {
				get = getFn[0]
			}

			sv, _ := staleNATScanner.Check(k, v, get)
			Expect(verdict).To(Equal(sv))
		},
		Entry("keyA - revA",
			conntrack.NewKey(123, clientIP, clientPort, svcIP, svcPort),
			conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, clientIP, clientPort, backendIP, backendPort)),
			conntrack.ScanVerdictDeleteImmediate,
		),
		Entry("keyA - revB",
			conntrack.NewKey(123, clientIP, clientPort, svcIP, svcPort),
			conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort)),
			conntrack.ScanVerdictDeleteImmediate,
		),
		Entry("keyB - revA",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, clientIP, clientPort, backendIP, backendPort)),
			conntrack.ScanVerdictDeleteImmediate,
		),
		Entry("keyB - revB",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, clientPort)),
			conntrack.ScanVerdictDeleteImmediate,
		),
		Entry("mismatch IP",
			conntrack.NewKey(123, svcIP, svcPort, net.IPv4(6, 6, 6, 6), clientPort),
			conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, backendIP2, backendPort2, clientIP, clientPort)),
			conntrack.ScanVerdictOK,
			func(conntrack.KeyInterface) (conntrack.ValueInterface, error) {
				return conntrack.NewValueNATReverse(0, 0, conntrack.Leg{}, conntrack.Leg{},
					net.IPv4(0, 0, 0, 0), svcIP, svcPort), nil
			},
		),
		Entry("mismatch rev IP missing rev",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, backendIP, backendPort, net.IPv4(3, 2, 2, 3), clientPort)),
			conntrack.ScanVerdictDelete,
			func(conntrack.KeyInterface) (conntrack.ValueInterface, error) {
				return nil, unix.ENOENT
			},
		),
		Entry("snatport keyA - revA",
			conntrack.NewKey(123, clientIP, clientPort, svcIP, svcPort),
			withSNATPort(snatPort,
				conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, clientIP, snatPort, backendIP, backendPort))),
			conntrack.ScanVerdictDeleteImmediate,
		),
		Entry("snatport keyA - revB",
			conntrack.NewKey(123, clientIP, clientPort, svcIP, svcPort),
			withSNATPort(snatPort,
				conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, snatPort))),
			conntrack.ScanVerdictDeleteImmediate,
		),
		Entry("snatport keyB - revA",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			withSNATPort(snatPort,
				conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, clientIP, snatPort, backendIP, backendPort))),
			conntrack.ScanVerdictDeleteImmediate,
		),
		Entry("snatport keyB - revB",
			conntrack.NewKey(123, svcIP, svcPort, clientIP, clientPort),
			withSNATPort(snatPort,
				conntrack.NewValueNATForward(0, 0, conntrack.NewKey(123, backendIP, backendPort, clientIP, snatPort))),
			conntrack.ScanVerdictDeleteImmediate,
		),
	)
})

var _ = Describe("BPF Conntrack upgrade entries", func() {
	k2 := v2.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)
	k3 := v3.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)
	k4 := conntrack.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)

	v2Normal := v2.NewValueNormal(cttestdata.Now-1, cttestdata.Now-1, 0, v2.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v2.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201})
	v3Normal := v3.NewValueNormal(cttestdata.Now-1, 0, v3.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v3.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201})
	v4Normal := conntrack.NewValueNormal(cttestdata.Now-1, 0, conntrack.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, conntrack.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201})

	v2NatReverse := v2.NewValueNATReverse(cttestdata.Now-1, cttestdata.Now-1, 0, v2.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v2.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234)
	v3NatReverse := v3.NewValueNATReverse(cttestdata.Now-1, 0, v3.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v3.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234)
	v4NatReverse := conntrack.NewValueNATReverse(cttestdata.Now-1, 0, conntrack.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, conntrack.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234)

	v2NatRevSnat := v2.NewValueNATReverseSNAT(cttestdata.Now-1, cttestdata.Now-1, 0, v2.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v2.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), net.IPv4(9, 10, 11, 12), 1234)
	v3NatRevSnat := v3.NewValueNATReverseSNAT(cttestdata.Now-1, 0, v3.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, v3.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), net.IPv4(9, 10, 11, 12), 1234)
	v4NatRevSnat := conntrack.NewValueNATReverseSNAT(cttestdata.Now-1, 0, conntrack.Leg{Seqno: 1000, SynSeen: true, Ifindex: 200}, conntrack.Leg{Seqno: 1001, RstSeen: true, Ifindex: 201}, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), net.IPv4(9, 10, 11, 12), 1234)

	v2NatFwd := v2.NewValueNATForward(cttestdata.Now-1, cttestdata.Now-1, 0, v2.NewKey(3, net.ParseIP("20.0.0.1"), 0, net.ParseIP("20.0.0.2"), 0))
	v3NatFwd := v3.NewValueNATForward(cttestdata.Now-1, 0, v3.NewKey(3, net.ParseIP("20.0.0.1"), 0, net.ParseIP("20.0.0.2"), 0))
	v4NatFwd := conntrack.NewValueNATForward(cttestdata.Now-1, 0, conntrack.NewKey(3, net.ParseIP("20.0.0.1"), 0, net.ParseIP("20.0.0.2"), 0))
	DescribeTable("upgrade entries",
		func(k, v, expectedKey, expectedValue maps.Upgradable) {
			upgradedKey := k.Upgrade()
			upgradedValue := v.Upgrade()
			Expect(upgradedKey.AsBytes()).To(Equal(expectedKey.AsBytes()))
			Expect(upgradedValue.AsBytes()[8:]).To(Equal(expectedValue.AsBytes()[8:])) // Create is not copied over into RSTSeen
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
		Entry("conntrack normal entry",
			k3, v3Normal, k4, v4Normal,
		),
		Entry("conntrack nat rev entry",
			k3, v3NatReverse, k4, v4NatReverse,
		),
		Entry("conntrack nat rev entry",
			k3, v3NatRevSnat, k4, v4NatRevSnat,
		),
		Entry("conntrack nat rev entry",
			k3, v3NatFwd, k4, v4NatFwd,
		),
	)
})
