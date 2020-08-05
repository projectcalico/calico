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
	"fmt"
	"net"
	"reflect"
	"runtime"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/conntrack"
)

func TestMapEntryDeletion(t *testing.T) {
	k, err1 := setUpMapTestWithSingleKV(t)

	err2 := ctMap.Delete(k.AsBytes())
	err3 := ctMap.Delete(k.AsBytes())

	// Defer error checking since the Delete calls do the cleanup for this test...
	Expect(err1).NotTo(HaveOccurred(), "Failed to create map entry")
	Expect(err2).NotTo(HaveOccurred(), "Failed to delete map entry")
	Expect(bpf.IsNotExists(err3)).To(Equal(true), "Error from deletion of non-existent entry was incorrect")
}

func TestMapIteration(t *testing.T) {
	k, err1 := setUpMapTestWithSingleKV(t)

	seenKey := false
	iterErr := ctMap.Iter(func(k2, v []byte) {
		seenKey = seenKey || reflect.DeepEqual(k2, k[:])
	})

	err2 := ctMap.Delete(k.AsBytes())

	seenKeyAfterDel := false
	iterErr2 := ctMap.Iter(func(k2, v []byte) {
		seenKeyAfterDel = seenKeyAfterDel || reflect.DeepEqual(k2, k[:])
	})

	// Defer error checking since the Delete call does the cleanup for this test...
	Expect(err1).NotTo(HaveOccurred(), "Failed to create map entry")
	Expect(iterErr).ToNot(HaveOccurred(), "Failed to iterate map")
	Expect(seenKey).To(BeTrue(), "Expected to see the key we put in the map")
	Expect(seenKeyAfterDel).To(BeFalse(), "Saw key we'd just deleted")
	Expect(iterErr2).ToNot(HaveOccurred(), "Failed to iterate map after delete")
	Expect(err2).NotTo(HaveOccurred(), "Failed to delete map entry")
}

func setUpMapTestWithSingleKV(t *testing.T) (conntrack.Key, error) {
	RegisterTestingT(t)
	k := conntrack.NewKey(1, net.ParseIP("10.0.0.1"), 51234, net.ParseIP("10.0.0.2"), 8080)
	v := conntrack.Value{}
	for i := range v {
		v[i] = uint8(i)
	}
	err1 := ctMap.Update(k.AsBytes(), v[:])
	return k, err1
}

func BenchmarkMapIteration10k(b *testing.B) {
	benchMapIteration(b, 10000)
}

func BenchmarkMapIteration100k(b *testing.B) {
	benchMapIteration(b, 100000)
}

func BenchmarkMapIteration500k(b *testing.B) {
	benchMapIteration(b, 500000)
}

var benchVal interface{}

func benchMapIteration(b *testing.B, n int) {
	logLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	defer logrus.SetLevel(logLevel)
	setUpConntrackMapEntries(b, n)
	for i := 0; i < b.N; i++ {
		err := ctMap.Iter(func(k, v []byte) {
			benchVal = v
		})
		if err != nil {
			panic(err)
		}
	}
	runtime.KeepAlive(benchVal)
	b.StopTimer()
	cleanUpMaps()
}

func setUpConntrackMapEntries(b *testing.B, n int) {
	b.StopTimer()
	for i := 0; i < n; i++ {
		var k conntrack.Key
		var v conntrack.Value
		binary.LittleEndian.PutUint32(k[:], uint32(i))
		err := ctMap.Update(k.AsBytes(), v[:])
		if err != nil {
			panic(err)
		}
	}
	b.StartTimer()
}

func BenchmarkMapIterator10k(b *testing.B) {
	benchMapIterator(b, 10000)
}

func BenchmarkMapIterator100k(b *testing.B) {
	benchMapIterator(b, 100000)
}

func BenchmarkMapIterator500k(b *testing.B) {
	benchMapIterator(b, 500000)
}

func benchMapIterator(b *testing.B, n int) {
	logLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	defer logrus.SetLevel(logLevel)
	setUpConntrackMapEntries(b, n)

	for i := 0; i < b.N; i++ {
		iter, err := bpf.NewMapIterator(ctMap.MapFD(), conntrack.KeySize, conntrack.ValueSize)
		if err != nil {
			panic(err)
		}

		numIterations := 0
		for {
			k, v, err := iter.Next()
			if err != nil {
				if bpf.IsNotExists(err) {
					break
				}
				panic(err)
			}
			benchVal = k
			benchVal = v
			numIterations++
		}
		if numIterations < n {
			panic(fmt.Sprintf("Unexpected number of iterations: %d", numIterations))
		}
		benchVal = nil
		_ = iter.Close()
	}
	b.StopTimer()
	cleanUpMaps()
}
