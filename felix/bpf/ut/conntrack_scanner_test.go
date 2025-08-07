// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"net"
	"os"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	v4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

func BenchmarkScanner(b *testing.B) {
	scannerBenchmark(b, 4000000 /*v4.MaxEntries*/, 0)
}

func scannerBenchmark(b *testing.B, entries, batchSize int) {
	RegisterTestingT(b)

	logrus.SetLevel(logrus.InfoLevel)

	conntrack.SetMapSize(entries)
	m := conntrack.Map()
	err := m.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		os.Remove(m.Path())
		m.Close()
	}()

	ipA := net.IPv4(1, 2, 3, 4)
	ipB := net.IPv4(5, 6, 7, 8)
	ipC := net.IPv4(1, 0, 1, 0)

	now := bpf.KTimeNanos()

	batchK := make([][]byte, 1000)
	batchV := make([][]byte, 1000)

	c := 0

	for i := 0; i < entries; i += 2 {
		k1 := v4.NewKey(6, ipA, uint16(i/(1<<16)), ipB, uint16(i%(1<<16)))
		k2 := v4.NewKey(6, ipC, uint16(i/(1<<16)), ipB, uint16(i%(1<<16)))

		v1 := conntrack.NewValueNATReverse(time.Duration(now), 0,
			conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true},
			nil, nil, 0)
		v2 := conntrack.NewValueNATForward(time.Duration(now), 0, k1)

		batchK[c] = k1[:]
		batchK[c+1] = k2[:]
		batchV[c] = v1[:]
		batchV[c+1] = v2[:]

		c += 2

		if c == 1000 {
			n, err := m.(*maps.PinnedMap).BatchUpdate(batchK, batchV, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(c))
			c = 0
		}
	}

	if c > 0 {
		n, err := m.(*maps.PinnedMap).BatchUpdate(batchK[0:c], batchV[0:c], 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(c))
	}

	ctKey := conntrack.KeyFromBytes
	ctVal := conntrack.ValueFromBytes

	conntrackScanner := conntrack.NewScanner(m, ctKey, ctVal, nil, "none", nil, 4, nil)

	for b.Loop() {
		conntrackScanner.Scan()
	}
}

type testScanner struct {
	cleaner bool
	count   int
	m       map[conntrack.KeyInterface]conntrack.ValueInterface
}

func (ts *testScanner) Check(k conntrack.KeyInterface, v conntrack.ValueInterface, _ conntrack.EntryGet) (
	conntrack.ScanVerdict, int64) {

	if ts.cleaner {
		return conntrack.ScanVerdictDelete, 0
	} else {
		ts.m[k] = v
		ts.count++
		return conntrack.ScanVerdictOK, 0
	}
}

func TestScannerBatchIteration(t *testing.T) {
	RegisterTestingT(t)

	logrus.SetLevel(logrus.InfoLevel)

	entries := 50000

	ipA := net.IPv4(1, 2, 3, 4)
	ipB := net.IPv4(5, 6, 7, 8)
	ipC := net.IPv4(1, 0, 1, 0)

	now := bpf.KTimeNanos()

	batchK := make([][]byte, 1000)
	batchV := make([][]byte, 1000)

	c := 0

	mx := make(map[conntrack.KeyInterface]conntrack.ValueInterface)

	for i := 0; i < entries; i += 2 {
		k1 := v4.NewKey(6, ipA, uint16(i/(1<<16)), ipB, uint16(i%(1<<16)))
		k2 := v4.NewKey(6, ipC, uint16(i/(1<<16)), ipB, uint16(i%(1<<16)))

		v1 := conntrack.NewValueNATReverse(time.Duration(now), 0,
			conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true},
			nil, nil, 0)
		v2 := conntrack.NewValueNATForward(time.Duration(now), 0, k1)

		mx[k1] = v1
		mx[k2] = v2

		batchK[c] = k1[:]
		batchK[c+1] = k2[:]
		batchV[c] = v1[:]
		batchV[c+1] = v2[:]

		c += 2

		if c == 1000 {
			n, err := ctMap.(*maps.PinnedMap).BatchUpdate(batchK, batchV, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(c))
			c = 0
		}
	}

	Expect(len(mx)).To(Equal(entries))

	if c > 0 {
		n, err := ctMap.(*maps.PinnedMap).BatchUpdate(batchK[0:c], batchV[0:c], 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(c))
	}

	ctKey := conntrack.KeyFromBytes
	ctVal := conntrack.ValueFromBytes

	ts := testScanner{
		m: make(map[conntrack.KeyInterface]conntrack.ValueInterface),
	}

	conntrackScanner := conntrack.NewScanner(ctMap, ctKey, ctVal, nil, "none", nil, 4, nil, &ts)
	conntrackScanner.Scan()

	Expect(len(ts.m)).To(Equal(entries))
	for k, v := range ts.m {
		x, ok := mx[k]
		if !ok {
			t.Fatalf("Missing key %v", k)
		}
		Expect(x).To(Equal(v))
	}

	ts.count = 0
	ts.m = make(map[conntrack.KeyInterface]conntrack.ValueInterface)
	conntrackScanner.Scan()

	Expect(ts.count).To(Equal(entries))

	ts.cleaner = true
	conntrackScanner.Scan()

	ts.cleaner = false
	ts.count = 0
	ts.m = make(map[conntrack.KeyInterface]conntrack.ValueInterface)
	conntrackScanner.Scan()

	Expect(ts.count).To(Equal(0))
}
