// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ut_test

import (
	"net"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/cleanupv1"
	"github.com/projectcalico/calico/felix/bpf/conntrack/cttestdata"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

func TestBPFProgCleaner(t *testing.T) {
	for _, tc := range cttestdata.CTCleanupTests {
		t.Run(tc.Description, func(t *testing.T) {
			runCTCleanupTest(t, tc)
		})
	}
	t.Run("IPv6 expired orphan NAT reverse", func(t *testing.T) {
		runCTCleanupV6ExpiredOrphanNATReverseTest(t)
	})
}

func runCTCleanupV6ExpiredOrphanNATReverseTest(t *testing.T) {
	RegisterTestingT(t)
	scanner := setUpConntrackV6ScanTest(t)
	revKey := conntrack.NewKeyV6(
		conntrack.ProtoTCP,
		net.ParseIP("2001:db8::1"), 5555,
		net.ParseIP("2001:db8::2"), 8080,
	)
	revVal := conntrack.NewValueV6NATReverse(
		cttestdata.Now-31*time.Second,
		0,
		conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true},
		conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true},
		nil, nil, 5555,
	)
	err := ctMapV6.Update(revKey.AsBytes(), revVal.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	scanner.Scan()
	_, err = ctMapV6.Get(revKey.AsBytes())
	Expect(maps.IsNotExists(err)).To(BeTrue(), "expired IPv6 orphan NAT reverse entry should be deleted")
	cleanUpMapMem, err := cleanupv1.LoadMapMemV6(ctCleanupMapV6)
	Expect(err).NotTo(HaveOccurred(), "Failed to load IPv6 ct cleanup map")
	Expect(len(cleanUpMapMem)).To(Equal(0))
}

func runCTCleanupTest(t *testing.T, tc cttestdata.CTCleanupTest) {
	scanner := setUpConntrackScanTest(t)

	// Load the starting conntrack state.
	for k, v := range tc.KVs {
		err := ctMap.Update(k.AsBytes(), v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	// Run the scanner, mocking out the current time to match the conntrack state.
	scanner.Scan()
	// Check that the expected entries were deleted.
	deletedEntries := calculateDeletedEntries(tc, ctMap)
	Expect(deletedEntries).To(ConsistOf(tc.ExpectedDeletions),
		"Scan() did not delete the expected entries")
	cleanUpMapMem, err := cleanupv1.LoadMapMem(ctCleanupMap)
	Expect(err).NotTo(HaveOccurred(), "Failed to load ct cleanup map")
	Expect(len(cleanUpMapMem)).To(Equal(0))
}

func setUpConntrackScanTest(t *testing.T) *conntrack.Scanner {
	RegisterTestingT(t)
	lc := conntrack.NewLivenessScanner(timeouts.DefaultTimeouts(), true, 4, conntrack.WithTimeShim(mocktime.New()))
	cleaner, err := conntrack.NewBPFProgCleaner(4, timeouts.DefaultTimeouts(), conntrack.BPFLogLevelDebug)
	Expect(err).NotTo(HaveOccurred(), "Failed to create BPFCleaner")
	scanner := conntrack.NewScanner(ctMap, conntrack.KeyFromBytes,
		conntrack.ValueFromBytes,
		nil, "Disabled", ctCleanupMap.(maps.MapWithExistsCheck), 4,
		cleaner, lc)
	t.Cleanup(func() {
		scanner.Close()
	})

	clearCTMap := func() {
		resetMap(ctMap)
		resetMap(ctCleanupMap)
	}
	clearCTMap()          // Make sure we start with an empty map.
	t.Cleanup(clearCTMap) // Make sure we leave a clean map.
	return scanner
}

func setUpConntrackV6ScanTest(t *testing.T) *conntrack.Scanner {
	RegisterTestingT(t)
	lc := conntrack.NewLivenessScanner(timeouts.DefaultTimeouts(), true, 6, conntrack.WithTimeShim(mocktime.New()))
	cleaner, err := conntrack.NewBPFProgCleaner(6, timeouts.DefaultTimeouts(), conntrack.BPFLogLevelDebug)
	Expect(err).NotTo(HaveOccurred(), "Failed to create IPv6 BPFCleaner")
	scanner := conntrack.NewScanner(ctMapV6, conntrack.KeyV6FromBytes,
		conntrack.ValueV6FromBytes,
		nil, "Disabled", ctCleanupMapV6.(maps.MapWithExistsCheck), 6,
		cleaner, lc)
	t.Cleanup(func() {
		scanner.Close()
	})

	clearCTMap := func() {
		resetMap(ctMapV6)
		resetMap(ctCleanupMapV6)
	}
	clearCTMap()          // Make sure we start with an empty map.
	t.Cleanup(clearCTMap) // Make sure we leave a clean map.
	return scanner
}

func calculateDeletedEntries(tc cttestdata.CTCleanupTest, ctMap maps.Map) []conntrack.Key {
	var deletedEntries []conntrack.Key
	for k := range tc.KVs {
		_, err := ctMap.Get(k.AsBytes())
		if maps.IsNotExists(err) {
			deletedEntries = append(deletedEntries, k)
		} else {
			Expect(err).NotTo(HaveOccurred(), "unexpected error from map lookup")
		}
	}
	return deletedEntries
}

func TestBPFProgCleanerRepointIfindex(t *testing.T) {
	RegisterTestingT(t)
	resetMap(ctMap)
	t.Cleanup(func() { resetMap(ctMap) })

	c, err := conntrack.NewBPFProgCleaner(4, timeouts.DefaultTimeouts(), conntrack.BPFLogLevelDebug)
	Expect(err).NotTo(HaveOccurred())
	t.Cleanup(func() { _ = c.Close() })
	cleaner, ok := c.(conntrack.IfindexRepointer)
	Expect(ok).To(BeTrue())

	const oldIf, newIf, otherIf = 7, 22, 3
	tunnelLeg := func(ifindex uint32) conntrack.Leg {
		return conntrack.Leg{SynSeen: true, AckSeen: true, Approved: true,
			Tunnel: true, Checked: true, Ifindex: ifindex}
	}
	key := func(sport uint16) conntrack.Key {
		return conntrack.NewKey(conntrack.ProtoTCP, net.ParseIP("10.0.0.1"), sport, net.ParseIP("10.0.1.1"), 80)
	}

	normal := conntrack.NewValueNormal(cttestdata.Now, 0, tunnelLeg(otherIf), tunnelLeg(oldIf))
	natRev := conntrack.NewValueNATReverse(cttestdata.Now, 0, tunnelLeg(oldIf), tunnelLeg(otherIf),
		nil, net.ParseIP("10.96.0.1"), 443)
	natFwd := conntrack.NewValueNATForward(cttestdata.Now, 0, key(3))
	untouched := conntrack.NewValueNormal(cttestdata.Now, 0, tunnelLeg(otherIf), tunnelLeg(otherIf))

	for k, v := range map[conntrack.Key]conntrack.Value{
		key(1): normal, key(2): natRev, key(4): natFwd, key(5): untouched,
	} {
		Expect(ctMap.Update(k.AsBytes(), v.AsBytes())).To(Succeed())
	}

	n, err := cleaner.RepointIfindex(oldIf, newIf)
	Expect(err).NotTo(HaveOccurred())
	Expect(n).To(Equal(2))

	get := func(k conntrack.Key) conntrack.ValueInterface {
		b, err := ctMap.Get(k.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return conntrack.ValueFromBytes(b)
	}

	Expect(get(key(1)).Data().A2B).To(Equal(tunnelLeg(otherIf)))
	Expect(get(key(1)).Data().B2A).To(Equal(tunnelLeg(newIf)), "flags must survive the repoint")
	Expect(get(key(2)).Data().A2B).To(Equal(tunnelLeg(newIf)))
	Expect(get(key(2)).Data().B2A).To(Equal(tunnelLeg(otherIf)))
	Expect(get(key(4)).AsBytes()).To(Equal(natFwd.AsBytes()), "NAT forward entries have no legs")
	Expect(get(key(5)).AsBytes()).To(Equal(untouched.AsBytes()))

	n, err = cleaner.RepointIfindex(oldIf, newIf)
	Expect(err).NotTo(HaveOccurred())
	Expect(n).To(BeZero())
}
