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
	"os"
	"reflect"
	"runtime"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	bpfmaps "github.com/projectcalico/calico/felix/bpf/maps"
)

func restoreMaps(maps *bpfmap.Maps) {
	if maps != nil {
		maps.Destroy()
	}
	bpfmaps.ResetSizes()
	// close the already created map and recreate them
	for _, m := range allMaps {
		os.Remove(m.Path())
		os.Remove(m.Path() + "_old")
		m.(*bpfmaps.PinnedMap).Close()
		err := m.EnsureExists()
		if err != nil {
			logrus.WithError(err).Panic("Failed to initialise maps")
		}
	}
	logrus.Info("maps restored")
}

func TestMapResize(t *testing.T) {
	// Resize the bpfmaps.
	RegisterTestingT(t)
	conntrack.SetMapSize(600)
	defer bpfmaps.ResetSizes()

	maps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())

	defer restoreMaps(maps)
	// New CT map should have max_entries as 600
	ctMapInfo, err := bpfmaps.GetMapInfo(maps.V4.CtMap.MapFD())
	Expect(err).NotTo(HaveOccurred(), "Failed to get ct map info")
	Expect(ctMapInfo.MaxEntries).To(Equal(600))
	// Except CT map, other map's old pins should be deleted.
	_, err = os.Stat(maps.V4.RouteMap.Path() + "_old")
	Expect(err).To(HaveOccurred(), "old route map present")
	_, err = os.Stat(maps.V4.CtMap.Path() + "_old")
	Expect(err).NotTo(HaveOccurred(), "old ct map not present")
}

func TestMapResizeWithCopy(t *testing.T) {
	// Add a k,v pair to the old ctmap
	k, err := setUpMapTestWithSingleKV(t)
	Expect(err).NotTo(HaveOccurred(), "Failed to create ct entry")

	// Resize the CT map to 600. New map should have the entry in the old map
	conntrack.SetMapSize(600)
	maps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())

	defer restoreMaps(maps)
	val, err := maps.V4.CtMap.Get(k.AsBytes())
	Expect(err).NotTo(HaveOccurred(), "ct entry not present in the new map")
	v := conntrack.Value{}
	for i := range v {
		v[i] = uint8(i)
	}
	Expect(v.AsBytes()).To(Equal(val))
	err = maps.V4.CtMap.CopyDeltaFromOldMap()
	Expect(err).NotTo(HaveOccurred(), "migration failed")
}

func TestMapDownSize(t *testing.T) {
	RegisterTestingT(t)
	// Add 10 entries to the old map
	numEntries := 10
	for i := 0; i < numEntries; i++ {
		err := insertNumberedKey(i)
		Expect(err).NotTo(HaveOccurred())
	}

	// Resize the ct map to 6, which is less than the total number of entries
	conntrack.SetMapSize(6)

	// New map creation should panic as the number of entries in old map is more than what the new map can
	// accommodate
	maps, err := bpfmap.CreateBPFMaps(false)
	defer restoreMaps(maps)
	expectedError := fmt.Sprintf("failed to create %s map, err=new map cannot hold all the data from the old map %s", ctMap.GetName(), ctMap.GetName())
	Expect(err.Error()).To(Equal(expectedError))
}

func TestCTDeltaMigration(t *testing.T) {
	// Add 1 k,v pair in old ctmap
	k, err := setUpMapTestWithSingleKV(t)
	Expect(err).NotTo(HaveOccurred(), "Failed to create ct entry")

	// Resize the ctmap
	conntrack.SetMapSize(666)

	maps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())

	defer restoreMaps(maps)
	v := conntrack.Value{}
	for i := range v {
		v[i] = uint8(i)
	}

	// Total number of k,v in old map should be 1
	ctSaved := saveCTMap(maps.V4.CtMap)
	Expect(ctSaved).To(HaveLen(1))
	Expect(ctSaved).Should(HaveKeyWithValue(k, v))

	t.Log("STEP: update existing key in the old map")

	// update the value for the old key in the old map
	newVal := conntrack.Value{}
	for i := range newVal {
		newVal[i] = uint8(i + 10)
	}

	err = ctMap.Update(k.AsBytes(), newVal[:])
	Expect(err).NotTo(HaveOccurred())

	t.Log("STEP: add 10 entries to the old map")

	// Add 10 more entries to the old map
	numEntries := 10
	for i := 0; i < numEntries; i++ {
		err := insertNumberedKey(i)
		Expect(err).NotTo(HaveOccurred())
	}

	matchKeyVals := func(ctSaved conntrack.MapMem) {
		Expect(ctSaved).Should(HaveKeyWithValue(k, newVal))
		Expect(ctSaved).ShouldNot(HaveKeyWithValue(k, v))
		for i := 0; i < numEntries; i++ {
			key := conntrack.NewKey(1, net.ParseIP("10.0.0.1"), uint16(i), net.ParseIP("10.0.0.2"), uint16(i>>16))
			val := conntrack.Value{}
			for j := range val {
				val[j] = uint8(j + i)
			}
			Expect(ctSaved).Should(HaveKeyWithValue(key, val))
		}
	}

	t.Log("STEP: copy delta")

	_, err = os.Stat(maps.V4.CtMap.Path() + "_old")
	Expect(err).NotTo(HaveOccurred(), "old conntrack map present")
	// Migrate the delta (10 k,v pairs) to the new map
	err = maps.V4.CtMap.CopyDeltaFromOldMap()
	Expect(err).NotTo(HaveOccurred(), "migration failed")
	ctSaved = saveCTMap(maps.V4.CtMap)
	Expect(ctSaved).To(HaveLen(numEntries + 1))
	matchKeyVals(ctSaved)

	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(maps.V4.CtMap.Path() + "_old")
	Expect(err).To(HaveOccurred(), "old conntrack map present")
}

func TestMapEntryDeletion(t *testing.T) {
	k, err1 := setUpMapTestWithSingleKV(t)

	err2 := ctMap.Delete(k.AsBytes())
	err3 := ctMap.Delete(k.AsBytes())

	// Defer error checking since the Delete calls do the cleanup for this test...
	Expect(err1).NotTo(HaveOccurred(), "Failed to create map entry")
	Expect(err2).NotTo(HaveOccurred(), "Failed to delete map entry")
	Expect(bpfmaps.IsNotExists(err3)).To(Equal(true), "Error from deletion of nonexistent entry was incorrect")
}

func TestMapIterActionDelete(t *testing.T) {
	k, err1 := setUpMapTestWithSingleKV(t)

	seenKey := false
	iterErr := ctMap.Iter(func(k2, v []byte) bpfmaps.IteratorAction {
		seenKey = seenKey || reflect.DeepEqual(k2, k[:])
		return bpfmaps.IterDelete
	})

	seenKeyAfterDel := false
	iterErr2 := ctMap.Iter(func(k2, v []byte) bpfmaps.IteratorAction {
		seenKeyAfterDel = seenKeyAfterDel || reflect.DeepEqual(k2, k[:])
		return bpfmaps.IterNone
	})

	// Defer error checking since the Delete call does the cleanup for this test...
	Expect(err1).NotTo(HaveOccurred(), "Failed to create map entry")
	Expect(iterErr).ToNot(HaveOccurred(), "Failed to iterate map")
	Expect(seenKey).To(BeTrue(), "Expected to see the key we put in the map")
	Expect(seenKeyAfterDel).To(BeFalse(), "Saw key we'd just deleted")
	Expect(iterErr2).ToNot(HaveOccurred(), "Failed to iterate map after delete")
}

func TestMapIterationDeleteAfter(t *testing.T) {
	k, err1 := setUpMapTestWithSingleKV(t)

	seenKey := false
	iterErr := ctMap.Iter(func(k2, v []byte) bpfmaps.IteratorAction {
		seenKey = seenKey || reflect.DeepEqual(k2, k[:])
		return bpfmaps.IterNone
	})

	err2 := ctMap.Delete(k.AsBytes())

	seenKeyAfterDel := false
	iterErr2 := ctMap.Iter(func(k2, v []byte) bpfmaps.IteratorAction {
		seenKeyAfterDel = seenKeyAfterDel || reflect.DeepEqual(k2, k[:])
		return bpfmaps.IterNone
	})

	// Defer error checking since the Delete call does the cleanup for this test...
	Expect(err1).NotTo(HaveOccurred(), "Failed to create map entry")
	Expect(iterErr).ToNot(HaveOccurred(), "Failed to iterate map")
	Expect(seenKey).To(BeTrue(), "Expected to see the key we put in the map")
	Expect(seenKeyAfterDel).To(BeFalse(), "Saw key we'd just deleted")
	Expect(iterErr2).ToNot(HaveOccurred(), "Failed to iterate map after delete")
	Expect(err2).NotTo(HaveOccurred(), "Failed to delete map entry")
}

// TestDeleteDuringIter tries to validate that BPF map iteration is working as we want even when keys are being added
// to and deleted from the map during iteration.
func TestDeleteDuringIter(t *testing.T) {
	RegisterTestingT(t)
	defer cleanUpMaps()
	logLevel := logrus.GetLevel()
	defer func() {
		logrus.SetLevel(logLevel)
	}()
	logrus.SetLevel(logrus.InfoLevel)

	testDelDuringIterN(10)
	testDelDuringIterN(11)
	testDelDuringIterN(100)
	testDelDuringIterN(10000)
	testDelDuringIterN(100000)
}

func testDelDuringIterN(numEntries int) {
	cleanUpMaps()
	for i := 0; i < numEntries; i++ {
		err := insertNumberedKey(i)
		Expect(err).NotTo(HaveOccurred())
	}
	// First pass, no deletions.
	seenKeys := map[conntrack.KeyInterface]bool{}
	err := ctMap.Iter(func(k, v []byte) bpfmaps.IteratorAction {
		key := conntrack.KeyFromBytes(k)
		Expect(seenKeys[key]).To(BeFalse(), "Saw a duplicate key")
		seenKeys[key] = true
		return bpfmaps.IterNone
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(seenKeys).To(HaveLen(numEntries), "Should have seen expected num entries on first iteration")

	// Second pass, delete alternate keys.
	seenKeys = map[conntrack.KeyInterface]bool{}
	deleteNextKey := false
	expectedKeys := map[conntrack.KeyInterface]bool{}
	err = ctMap.Iter(func(k, v []byte) bpfmaps.IteratorAction {
		defer func() {
			deleteNextKey = !deleteNextKey
		}()
		key := conntrack.KeyFromBytes(k)
		Expect(seenKeys[key]).To(BeFalse(), "Saw a duplicate key")
		seenKeys[key] = true
		if deleteNextKey {
			return bpfmaps.IterDelete
		} else {
			expectedKeys[key] = true
			return bpfmaps.IterNone
		}
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(seenKeys).To(HaveLen(numEntries), "Should have seen expected num entries on deletion iteration")

	// Third pass, insert key on each iteration an delete on alternate iterations.
	numLeftAfterSecondPass := len(expectedKeys)
	seenKeys = map[conntrack.KeyInterface]bool{}
	deleteNextKey = false
	insertClock := 0
	insertIdx := numEntries
	numInsertedInThirdPass := 0
	err = ctMap.Iter(func(k, v []byte) bpfmaps.IteratorAction {
		defer func() {
			deleteNextKey = !deleteNextKey
			insertClock++
		}()
		key := conntrack.KeyFromBytes(k)
		Expect(seenKeys[key]).To(BeFalse(), "Saw a duplicate key")
		seenKeys[key] = true
		delete(expectedKeys, key)
		if insertClock%3 == 0 {
			err := insertNumberedKey(insertIdx)
			Expect(err).NotTo(HaveOccurred())
			insertIdx++
			numInsertedInThirdPass++
		}
		if deleteNextKey {
			return bpfmaps.IterDelete
		} else {
			return bpfmaps.IterNone
		}
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(expectedKeys).To(BeEmpty(), "Didn't see every key in third pass")
	Expect(len(seenKeys)).To(BeNumerically(">=", numLeftAfterSecondPass),
		"Should see at least as many entries as we left in the second pass")
	Expect(len(seenKeys)).To(BeNumerically("<=", numLeftAfterSecondPass+numInsertedInThirdPass),
		"Should see all of the numLeftAfterSecondPass and some of the numInsertedInThirdPass")
	logrus.WithField("numSeen", len(seenKeys)).Info("Saw this many keys")
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

func insertNumberedKey(n int) error {
	k := conntrack.NewKey(1, net.ParseIP("10.0.0.1"), uint16(n), net.ParseIP("10.0.0.2"), uint16(n>>16))
	v := conntrack.Value{}
	for i := range v {
		v[i] = uint8(i + n)
	}
	return ctMap.Update(k.AsBytes(), v[:])
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

func benchMapIteration(b *testing.B, n int) {
	defer cleanUpMaps()
	logLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	defer logrus.SetLevel(logLevel)
	setUpConntrackMapEntries(b, n)
	var keepK, keepV []byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		err := ctMap.Iter(func(k, v []byte) bpfmaps.IteratorAction {
			keepK = k
			keepV = v
			return bpfmaps.IterNone
		})
		if err != nil {
			panic(err)
		}
	}
	runtime.KeepAlive(keepK)
	runtime.KeepAlive(keepV)
	b.StopTimer()
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

func BenchmarkMapIteratorMulti10(b *testing.B) {
	benchMapIteratorMulti(b, 10)
}

func BenchmarkMapIteratorMulti100(b *testing.B) {
	benchMapIteratorMulti(b, 100)
}

func BenchmarkMapIteratorMulti101(b *testing.B) {
	benchMapIteratorMulti(b, 101)
}

func BenchmarkMapIteratorMulti10k(b *testing.B) {
	benchMapIteratorMulti(b, 10000)
}

func BenchmarkMapIteratorMulti100k(b *testing.B) {
	benchMapIteratorMulti(b, 100000)
}

func BenchmarkMapIteratorMulti500k(b *testing.B) {
	benchMapIteratorMulti(b, 500000)
}

func benchMapIteratorMulti(b *testing.B, n int) {
	logLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	defer logrus.SetLevel(logLevel)
	setUpConntrackMapEntries(b, n)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		doSingleMapIteratorMultiTest(n)
	}
	b.StopTimer()
	cleanUpMaps()
}

func doSingleMapIteratorMultiTest(n int) {
	iter, err := bpfmaps.NewIterator(ctMap.MapFD(), conntrack.KeySize, conntrack.ValueSize, conntrack.MaxEntries, true)
	if err != nil {
		panic(err)
	}

	numIterations := 0
	var k, v []byte
	for {
		k, v, err = iter.Next()
		if err != nil {
			if err == bpfmaps.ErrIterationFinished {
				break
			}
			panic(err)
		}
		numIterations++
	}
	if numIterations != n {
		panic(fmt.Sprintf("Unexpected number of iterations: %d", numIterations))
	}
	_ = iter.Close()
	runtime.KeepAlive(k)
	runtime.KeepAlive(v)
}

// Test slow iteration of failsafe map.
func TestFailsafeMapIteration(t *testing.T) {
	RegisterTestingT(t)
	defer cleanUpMaps()
	port := []uint16{8080, 8081, 8082, 8083, 8084}
	keys := make([]failsafes.Key, 0, len(port))
	for _, p := range port {
		k := failsafes.MakeKey(17, p, false, "0.0.0.0", 32)
		err := fsafeMap.Update(k.ToSlice(), []byte{1, 2, 3, 4})
		Expect(err).NotTo(HaveOccurred())
		keys = append(keys, k.(failsafes.Key))
	}

	iter, err := bpfmaps.NewIterator(fsafeMap.MapFD(), failsafes.KeySize, failsafes.ValueSize, failsafes.MapParams.MaxEntries, false)
	Expect(err).NotTo(HaveOccurred())
	var k []byte
	numIterations := 0
	for {
		k, _, err = iter.Next()
		if err != nil {
			if err == bpfmaps.ErrIterationFinished {
				break
			}
			Expect(err).NotTo(HaveOccurred())
		}
		numIterations++
		key := failsafes.KeyFromSlice(k)
		Expect(keys).To(ContainElement(key.(failsafes.Key)), "Unexpected key found during iteration")
	}

	Expect(numIterations).To(Equal(len(port)))
	_ = iter.Close()
}
