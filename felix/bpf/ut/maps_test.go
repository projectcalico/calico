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
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	conntrackv2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"
)

func restoreMaps(mc *bpf.MapContext) {
	bpfmap.DestroyBPFMaps(mc)
	// close the already created map and recreate them
	for _, m := range allMaps {
		os.Remove(m.Path())
		os.Remove(m.Path() + "_old")
		switch m.(type) {
		case *bpf.PinnedMap:
			m.(*bpf.PinnedMap).Close()
		case *conntrack.MultiVersionMap:
			m.(*conntrack.MultiVersionMap).Close()
		}
		err := m.EnsureExists()
		if err != nil {
			logrus.WithError(err).Panic("Failed to initialise maps")
		}
	}
}

/*
func TestCTMapUpgradeWithInvalidEntry(t *testing.T) {
       RegisterTestingT(t)
        ctMap.(*bpf.PinnedMap).Close()
        os.Remove(ctMap.Path())
        mc := &bpf.MapContext{}
        // create version 2 map
        ctMapV2 := conntrack.MapV2(mc)
        err := ctMapV2.EnsureExists()
        Expect(err).NotTo(HaveOccurred(), "Failed to create version2 ct map")

        created := time.Duration(1)
        lastSeen := time.Duration(2)
        flags := conntrack.FlagNATOut | conntrack.FlagSkipFIB
        k := conntrackv2.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)
        revKey := conntrackv2.NewKey(1, net.ParseIP("10.0.0.2"), 0, net.ParseIP("10.0.0.3"), 0)
        v := conntrackv2.NewValueNATForward(created, lastSeen, flags, revKey)
        v.SetNATSport(uint16(4000))
	v[16] = 4
        err = ctMapV2.Update(k.AsBytes(), v[:])
        Expect(err).NotTo(HaveOccurred())

        ctMapV3 := conntrack.Map(mc)
        err = ctMapV3.EnsureExists()
        Expect(err).NotTo(HaveOccurred(), "Failed to create ct map")

        ctMapMemV3 := saveCTMap(ctMapV3)
        Expect(len(ctMapMemV3)).To(Equal(0))

        ctMapV2.(*bpf.PinnedMap).Close()
        ctMapV3.(*bpf.PinnedMap).Close()

        os.Remove(ctMapV2.Path())
        os.Remove(ctMapV3.Path())
        for _, m := range allMaps {
                err := m.EnsureExists()
                Expect(err).NotTo(HaveOccurred())
        }
}

func TestCtMapUpgradeWithNATFwdEntries(t *testing.T) {
	RegisterTestingT(t)
	ctMap.(*bpf.PinnedMap).Close()
	os.Remove(ctMap.Path())
	mc := &bpf.MapContext{}
	// create version 2 map
	ctMapV2 := conntrack.MapV2(mc)
	err := ctMapV2.EnsureExists()
	Expect(err).NotTo(HaveOccurred(), "Failed to create version2 ct map")

	created := time.Duration(1)
	lastSeen := time.Duration(2)
	flags := conntrack.FlagNATOut | conntrack.FlagSkipFIB
	k := conntrackv2.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)
	revKey := conntrackv2.NewKey(1, net.ParseIP("10.0.0.2"), 0, net.ParseIP("10.0.0.3"), 0)
	v := conntrackv2.NewValueNATForward(created, lastSeen, flags, revKey)
	v.SetNATSport(uint16(4000))
	err = ctMapV2.Update(k.AsBytes(), v[:])
	Expect(err).NotTo(HaveOccurred())

	ctMapMemV2, err := conntrackv2.LoadMapMem(ctMapV2)
	Expect(err).NotTo(HaveOccurred())

	ctMapV3 := conntrack.Map(mc)
	err = ctMapV3.EnsureExists()
	Expect(err).NotTo(HaveOccurred(), "Failed to create ct map")

	ctMapMemV3 := saveCTMap(ctMapV3)
	Expect(len(ctMapMemV3)).To(Equal(len(ctMapMemV2)))

	k3 := conntrack.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)
	value3 := ctMapMemV3[k3]

	revKey3 := conntrack.NewKey(1, net.ParseIP("10.0.0.2"), 0, net.ParseIP("10.0.0.3"), 0)
	Expect(value3.Created()).To(Equal(int64(1)))
	Expect(value3.LastSeen()).To(Equal(int64(2)))
	Expect(value3.Flags()).To(Equal(flags))
	Expect(value3.ReverseNATKey()).To(Equal(revKey3))
	Expect(value3.NATSPort()).To(Equal(uint16(4000)))

	ctMapV2.(*bpf.PinnedMap).Close()
	ctMapV3.(*bpf.PinnedMap).Close()

	os.Remove(ctMapV2.Path())
	os.Remove(ctMapV3.Path())
	for _, m := range allMaps {
		err := m.EnsureExists()
		Expect(err).NotTo(HaveOccurred())
	}
}

func TestCtMapUpgradeWithNATRevEntries(t *testing.T) {
	RegisterTestingT(t)
	ctMap.(*bpf.PinnedMap).Close()
	os.Remove(ctMap.Path())
	mc := &bpf.MapContext{}
	// create version 2 map
	ctMapV2 := conntrack.MapV2(mc)
	err := ctMapV2.EnsureExists()
	Expect(err).NotTo(HaveOccurred(), "Failed to create version2 ct map")

	var created, lastSeen time.Duration
	flags := conntrack.FlagNATOut | conntrack.FlagSkipFIB
	tunIP := net.IP{20, 0, 0, 1}
	origIP := net.IP{30, 0, 0, 1}
	origPort := uint16(4000)
	origSport := uint16(5000)
	k := conntrackv2.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)
	created = time.Duration(1)
	lastSeen = time.Duration(2)
	seqNoAB := uint32(1000)
	ifIndexAB := uint32(2000)
	seqNoBA := uint32(1001)
	ifIndexBA := uint32(2001)
	legAB := conntrackv2.Leg{Seqno: seqNoAB, SynSeen: true, AckSeen: false, FinSeen: true, RstSeen: false, Whitelisted: true, Opener: false, Ifindex: ifIndexAB}
	legBA := conntrackv2.Leg{Seqno: seqNoBA, SynSeen: false, AckSeen: true, FinSeen: false, RstSeen: true, Whitelisted: false, Opener: true, Ifindex: ifIndexBA}
	v := conntrackv2.NewValueNATReverse(created, lastSeen, flags, legAB, legBA, tunIP, origIP, uint16(origPort))
	v.SetOrigSport(origSport)
	err = ctMapV2.Update(k.AsBytes(), v[:])
	Expect(err).NotTo(HaveOccurred())

	ctMapMemV2, err := conntrackv2.LoadMapMem(ctMapV2)
	Expect(err).NotTo(HaveOccurred())

	ctMapV3 := conntrack.Map(mc)
	err = ctMapV3.EnsureExists()
	Expect(err).NotTo(HaveOccurred(), "Failed to create ct map")

	ctMapMemV3 := saveCTMap(ctMapV3)
	Expect(len(ctMapMemV3)).To(Equal(len(ctMapMemV2)))

	k3 := conntrack.NewKey(1, net.ParseIP("10.0.0.1"), 0, net.ParseIP("10.0.0.2"), 0)
	value3 := ctMapMemV3[k3]
	Expect(value3.OrigIP()).To(Equal(origIP))
	data := value3.Data()
	Expect(data.TunIP).To(Equal(tunIP))
	Expect(value3.OrigPort()).To(Equal(origPort))
	Expect(value3.OrigSPort()).To(Equal(origSport))
	ctMapV2.(*bpf.PinnedMap).Close()
	ctMapV3.(*bpf.PinnedMap).Close()

	os.Remove(ctMapV2.Path())
	os.Remove(ctMapV3.Path())
	for _, m := range allMaps {
		err := m.EnsureExists()
		Expect(err).NotTo(HaveOccurred())
	}
}*/

func TestCtMapUpgradeWithNormalEntries(t *testing.T) {
	RegisterTestingT(t)
	ctMap.(*conntrack.MultiVersionMap).Close()
	os.Remove(ctMap.Path())

	mc := &bpf.MapContext{}
	// create version 2 map
	ctMapV2 := conntrack.MapV2(mc)
	err := ctMapV2.EnsureExists()
	Expect(err).NotTo(HaveOccurred(), "Failed to create version2 ct map")

	var created, lastSeen time.Duration
	flags := conntrack.FlagNATOut | conntrack.FlagSkipFIB
	for n := 0; n < 2; n++ {
		k := conntrackv2.NewKey(1, net.ParseIP("10.0.0.1"), uint16(n), net.ParseIP("10.0.0.2"), uint16(n>>16))
		created = time.Duration(1 + int64(n))
		lastSeen = time.Duration(2 + int64(n))
		seqNoAB := 1000 + uint32(n)
		ifIndexAB := 2000 + uint32(n)
		seqNoBA := 1001 + uint32(n)
		ifIndexBA := 2001 + uint32(n)
		legAB := conntrackv2.Leg{Seqno: seqNoAB, SynSeen: true, AckSeen: false, FinSeen: true, RstSeen: false, Whitelisted: true, Opener: false, Ifindex: ifIndexAB}
		legBA := conntrackv2.Leg{Seqno: seqNoBA, SynSeen: false, AckSeen: true, FinSeen: false, RstSeen: true, Whitelisted: false, Opener: true, Ifindex: ifIndexBA}
		v := conntrackv2.NewValueNormal(created, lastSeen, flags, legAB, legBA)
		err := ctMapV2.Update(k.AsBytes(), v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	ctMapMemV2, err := conntrackv2.LoadMapMem(ctMapV2)
	Expect(err).NotTo(HaveOccurred())

	ctMapV3 := conntrack.Map(mc)
	err = ctMapV3.EnsureExists()
	Expect(err).NotTo(HaveOccurred(), "Failed to create ct map")

	ctMapMemV3 := saveCTMap(ctMapV3)
	Expect(len(ctMapMemV3)).To(Equal(len(ctMapMemV2)))

	for n := 0; n < 2; n++ {
		k := conntrack.NewKey(1, net.ParseIP("10.0.0.1"), uint16(n), net.ParseIP("10.0.0.2"), uint16(n>>16))
		value := ctMapMemV3[k]
		Expect(value.Created()).To(Equal(1 + int64(n)))
		Expect(value.LastSeen()).To(Equal(2 + int64(n)))
		Expect(value.Flags()).To(Equal(flags))
		legAB := value.Data().A2B
		legBA := value.Data().B2A
		Expect(legAB.Bytes).To(Equal(uint64(0)))
		Expect(legAB.Packets).To(Equal(uint32(0)))
		Expect(legAB.Seqno).To(Equal(uint32(1000 + n)))
		Expect(legAB.Ifindex).To(Equal(uint32(2000 + n)))
		Expect(legAB.SynSeen).To(Equal(true))
		Expect(legAB.FinSeen).To(Equal(true))
		Expect(legAB.RstSeen).To(Equal(false))
		Expect(legAB.AckSeen).To(Equal(false))
		Expect(legAB.Whitelisted).To(Equal(true))
		Expect(legAB.Opener).To(Equal(false))

		Expect(legBA.Bytes).To(Equal(uint64(0)))
		Expect(legBA.Packets).To(Equal(uint32(0)))
		Expect(legBA.Seqno).To(Equal(uint32(1001 + n)))
		Expect(legBA.Ifindex).To(Equal(uint32(2001 + n)))
		Expect(legBA.SynSeen).To(Equal(false))
		Expect(legBA.FinSeen).To(Equal(false))
		Expect(legBA.RstSeen).To(Equal(true))
		Expect(legBA.AckSeen).To(Equal(true))
		Expect(legBA.Whitelisted).To(Equal(false))
		Expect(legBA.Opener).To(Equal(true))
	}

	ctMapV2.(*bpf.PinnedMap).Close()
	ctMapV3.(*conntrack.MultiVersionMap).Close()

	os.Remove(ctMapV2.Path())
	os.Remove(ctMapV3.Path())
	for _, m := range allMaps {
		err := m.EnsureExists()
		Expect(err).NotTo(HaveOccurred())
	}
}

func TestMapResize(t *testing.T) {
	// Resize the maps.
	RegisterTestingT(t)
	ipsetsMapSize := 100
	natFeMapSize := 200
	natBeMapSize := 300
	natAffMapSize := 400
	rtMapSize := 500
	ctMapSize := 600
	mc := bpfmap.CreateBPFMapContext(ipsetsMapSize, natFeMapSize, natBeMapSize, natAffMapSize, rtMapSize, ctMapSize, true)
	err := bpfmap.CreateBPFMaps(mc)
	Expect(err).NotTo(HaveOccurred())
	defer restoreMaps(mc)
	// New CT map should have max_entries as 600
	ctMapInfo, err := bpf.GetMapInfo(mc.CtMap.MapFD())
	Expect(err).NotTo(HaveOccurred(), "Failed to get ct map info")
	Expect(ctMapInfo.MaxEntries).To(Equal(ctMapSize))
	// Except CT map, other map's old pins should be deleted.
	_, err = os.Stat(mc.RouteMap.Path() + "_old")
	Expect(err).To(HaveOccurred(), "old route map present")
	_, err = os.Stat(mc.CtMap.Path() + "_old")
	Expect(err).NotTo(HaveOccurred(), "old ct map not present")
}

func TestMapResizeWithCopy(t *testing.T) {
	// Add a k,v pair to the old ctmap
	k, err := setUpMapTestWithSingleKV(t)
	Expect(err).NotTo(HaveOccurred(), "Failed to create ct entry")
	ipsetsMapSize := 100
	natFeMapSize := 200
	natBeMapSize := 300
	natAffMapSize := 400
	rtMapSize := 500
	ctMapSize := 600

	// Resize the CT map to 600. New map should have the entry in the old map
	mc := bpfmap.CreateBPFMapContext(ipsetsMapSize, natFeMapSize, natBeMapSize, natAffMapSize, rtMapSize, ctMapSize, true)
	err = bpfmap.CreateBPFMaps(mc)
	Expect(err).NotTo(HaveOccurred())
	defer restoreMaps(mc)
	val, err := mc.CtMap.Get(k.AsBytes())
	Expect(err).NotTo(HaveOccurred(), "ct entry not present in the new map")
	v := conntrack.Value{}
	for i := range v {
		v[i] = uint8(i)
	}
	Expect(v.AsBytes()).To(Equal(val))
	bpfmap.MigrateDataFromOldMap(mc)
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
	ipsetsMapSize := 100
	natFeMapSize := 200
	natBeMapSize := 300
	natAffMapSize := 400
	rtMapSize := 500
	ctMapSize := 6

	// New map creation should panic as the number of entries in old map is more than what the new map can
	// accommodate
	mc := bpfmap.CreateBPFMapContext(ipsetsMapSize, natFeMapSize, natBeMapSize, natAffMapSize, rtMapSize, ctMapSize, true)
	defer restoreMaps(mc)
	err := bpfmap.CreateBPFMaps(mc)
	fmt.Println(err)
	expectedError := fmt.Sprintf("Failed to create %s map, err=new map cannot hold all the data from the old map %s", ctMap.GetName(), ctMap.GetName())
	Expect(err.Error()).To(Equal(expectedError))
}

func TestCTDeltaMigration(t *testing.T) {
	// Add 1 k,v pair in old ctmap
	k, err := setUpMapTestWithSingleKV(t)
	Expect(err).NotTo(HaveOccurred(), "Failed to create ct entry")

	// Resize the ctmap to size 600 entries
	ipsetsMapSize := 100
	natFeMapSize := 200
	natBeMapSize := 300
	natAffMapSize := 400
	rtMapSize := 500
	ctMapSize := 600
	mc := bpfmap.CreateBPFMapContext(ipsetsMapSize, natFeMapSize, natBeMapSize, natAffMapSize, rtMapSize, ctMapSize, true)
	err = bpfmap.CreateBPFMaps(mc)
	Expect(err).NotTo(HaveOccurred())

	defer restoreMaps(mc)
	v := conntrack.Value{}
	for i := range v {
		v[i] = uint8(i)
	}

	// Total number of k,v in old map should be 1
	ctSaved := saveCTMap(mc.CtMap)
	Expect(ctSaved).To(HaveLen(1))
	Expect(ctSaved).Should(HaveKeyWithValue(k, v))

	// update the value for the old key in the old map
	newVal := conntrack.Value{}
	for i := range newVal {
		newVal[i] = uint8(i + 10)
	}

	err = ctMap.Update(k.AsBytes(), newVal[:])
	Expect(err).NotTo(HaveOccurred())

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

	_, err = os.Stat(mc.CtMap.Path() + "_old")
	Expect(err).NotTo(HaveOccurred(), "old route map present")
	// Migrate the delta (10 k,v pairs) to the new map
	bpfmap.MigrateDataFromOldMap(mc)
	ctSaved = saveCTMap(mc.CtMap)
	Expect(ctSaved).To(HaveLen(numEntries + 1))
	matchKeyVals(ctSaved)

	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(mc.CtMap.Path() + "_old")
	Expect(err).To(HaveOccurred(), "old conntrack map present")
}

func TestMapEntryDeletion(t *testing.T) {
	k, err1 := setUpMapTestWithSingleKV(t)

	err2 := ctMap.Delete(k.AsBytes())
	err3 := ctMap.Delete(k.AsBytes())

	// Defer error checking since the Delete calls do the cleanup for this test...
	Expect(err1).NotTo(HaveOccurred(), "Failed to create map entry")
	Expect(err2).NotTo(HaveOccurred(), "Failed to delete map entry")
	Expect(bpf.IsNotExists(err3)).To(Equal(true), "Error from deletion of non-existent entry was incorrect")
}

func TestMapIterActionDelete(t *testing.T) {
	k, err1 := setUpMapTestWithSingleKV(t)

	seenKey := false
	iterErr := ctMap.Iter(func(k2, v []byte) bpf.IteratorAction {
		seenKey = seenKey || reflect.DeepEqual(k2, k[:])
		return bpf.IterDelete
	})

	seenKeyAfterDel := false
	iterErr2 := ctMap.Iter(func(k2, v []byte) bpf.IteratorAction {
		seenKeyAfterDel = seenKeyAfterDel || reflect.DeepEqual(k2, k[:])
		return bpf.IterNone
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
	iterErr := ctMap.Iter(func(k2, v []byte) bpf.IteratorAction {
		seenKey = seenKey || reflect.DeepEqual(k2, k[:])
		return bpf.IterNone
	})

	err2 := ctMap.Delete(k.AsBytes())

	seenKeyAfterDel := false
	iterErr2 := ctMap.Iter(func(k2, v []byte) bpf.IteratorAction {
		seenKeyAfterDel = seenKeyAfterDel || reflect.DeepEqual(k2, k[:])
		return bpf.IterNone
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
	seenKeys := map[conntrack.Key]bool{}
	err := ctMap.Iter(func(k, v []byte) bpf.IteratorAction {
		key := conntrack.KeyFromBytes(k)
		Expect(seenKeys[key]).To(BeFalse(), "Saw a duplicate key")
		seenKeys[key] = true
		return bpf.IterNone
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(seenKeys).To(HaveLen(numEntries), "Should have seen expected num entries on first iteration")

	// Second pass, delete alternate keys.
	seenKeys = map[conntrack.Key]bool{}
	deleteNextKey := false
	expectedKeys := map[conntrack.Key]bool{}
	err = ctMap.Iter(func(k, v []byte) bpf.IteratorAction {
		defer func() {
			deleteNextKey = !deleteNextKey
		}()
		key := conntrack.KeyFromBytes(k)
		Expect(seenKeys[key]).To(BeFalse(), "Saw a duplicate key")
		seenKeys[key] = true
		if deleteNextKey {
			return bpf.IterDelete
		} else {
			expectedKeys[key] = true
			return bpf.IterNone
		}
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(seenKeys).To(HaveLen(numEntries), "Should have seen expected num entries on deletion iteration")

	// Third pass, insert key on each iteration an delete on alternate iterations.
	numLeftAfterSecondPass := len(expectedKeys)
	seenKeys = map[conntrack.Key]bool{}
	deleteNextKey = false
	insertClock := 0
	insertIdx := numEntries
	numInsertedInThirdPass := 0
	err = ctMap.Iter(func(k, v []byte) bpf.IteratorAction {
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
			return bpf.IterDelete
		} else {
			return bpf.IterNone
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
		err := ctMap.Iter(func(k, v []byte) bpf.IteratorAction {
			keepK = k
			keepV = v
			return bpf.IterNone
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
	iter, err := bpf.NewMapIterator(ctMap.MapFD(), conntrack.KeySize, conntrack.ValueSize, conntrack.MaxEntries)
	if err != nil {
		panic(err)
	}

	numIterations := 0
	var k, v []byte
	for {
		k, v, err = iter.Next()
		if err != nil {
			if err == bpf.ErrIterationFinished {
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
