// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"os"
	"testing"

	. "github.com/onsi/gomega"

	"net"
	"time"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	conntrackv2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"
	mock "github.com/projectcalico/calico/felix/bpf/mock/multiversion"
	v2 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v2"
	v3 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v3"
	v4 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v4"
	v5 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v5"
)

const key = 0xdeadbeef
const val = 0xa0b1c2d3

func deleteMap(bpfMap bpf.Map) {
	bpfMap.(*bpf.PinnedMap).Close()
	os.Remove(bpfMap.Path())
	os.Remove(bpfMap.Path() + "_old")
}

func TestMapUpgradeV2ToV3(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv2 := mock.MapV2(mc, 0)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v2.NewKey(key)
	v := v2.NewValue(val)

	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv3 := mock.MapV3(mc, 0)
	err = mockMapv3.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k3 := v3.NewKey(key)
	v3 := v3.NewValue(val)
	val, err := mockMapv3.Get(k3.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(val).To(Equal(v3.AsBytes()))
	deleteMap(mockMapv2)
	deleteMap(mockMapv3)
}

func TestMapUpgradeV2ToV4(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv2 := mock.MapV2(mc, 0)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v2.NewKey(key)
	v := v2.NewValue(val)

	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv4 := mock.MapV4(mc, 0)
	err = mockMapv4.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k4 := v4.NewKey(key)
	v4 := v4.NewValue(val)
	val, err := mockMapv4.Get(k4.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(val).To(Equal(v4.AsBytes()))
	deleteMap(mockMapv2)
	deleteMap(mockMapv4)
}

func TestMapUpgradeV2ToV5(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv2 := mock.MapV2(mc, 0)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v2.NewKey(key)
	v := v2.NewValue(val)

	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv5 := mock.MapV5(mc, 0)
	err = mockMapv5.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k5 := v5.NewKey(key)
	v5 := v5.NewValue(val)
	val, err := mockMapv5.Get(k5.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(val).To(Equal(v5.AsBytes()))
	deleteMap(mockMapv2)
	deleteMap(mockMapv5)
}

func TestMapUpgradeV3ToV5(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv3 := mock.MapV3(mc, 0)
	err := mockMapv3.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v3.NewKey(key)
	v := v3.NewValue(val)

	err = mockMapv3.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv5 := mock.MapV5(mc, 0)
	err = mockMapv5.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k5 := v5.NewKey(key)
	v5 := v5.NewValue(val)
	val, err := mockMapv5.Get(k5.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(val).To(Equal(v5.AsBytes()))
	deleteMap(mockMapv3)
	deleteMap(mockMapv5)
}

func TestMapUpgradeV3ToV5WithDifferentSize(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv3 := mock.MapV3(mc, 10)
	err := mockMapv3.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v3.NewKey(key)
	v := v3.NewValue(val)

	err = mockMapv3.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv5 := mock.MapV5(mc, 20)
	err = mockMapv5.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k5 := v5.NewKey(key)
	v5 := v5.NewValue(val)
	val, err := mockMapv5.Get(k5.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(val).To(Equal(v5.AsBytes()))
	deleteMap(mockMapv3)
	deleteMap(mockMapv5)
}

func TestMapUpgradeV3ToV5WithLowerSize(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv3 := mock.MapV3(mc, 10)
	err := mockMapv3.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		k := v3.NewKey(0x1234 + uint32(i))
		v := v3.NewValue(0x4568 + uint32(i))

		err = mockMapv3.Update(k.AsBytes(), v.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}

	mockMapv5 := mock.MapV5(mc, 7)
	err = mockMapv5.EnsureExists()
	defer func() {
		deleteMap(mockMapv3)
		deleteMap(mockMapv5)
	}()
	Expect(err).To(HaveOccurred())

}

func TestMapUpgradeV5ToV3(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv5 := mock.MapV5(mc, 0)
	err := mockMapv5.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	mockMapv3 := mock.MapV3(mc, 0)
	err = mockMapv3.EnsureExists()
	Expect(err).To(HaveOccurred())
	deleteMap(mockMapv5)
	deleteMap(mockMapv3)
}

func TestMapUpgradeWithDeltaEntries(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv2 := mock.MapV2(mc, 0)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v2.NewKey(key)
	v := v2.NewValue(val)

	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv5 := mock.MapV5(mc, 0)
	err = mockMapv5.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k5 := v5.NewKey(key)
	val5 := v5.NewValue(val)
	val, err := mockMapv5.Get(k5.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(val).To(Equal(val5.AsBytes()))

	// update v2 map with new k,v pairs
	for i := 0; i < 10; i++ {
		k = v2.NewKey(0x1234 + uint32(i))
		v = v2.NewValue(0x4568 + uint32(i))
		err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}

	// update the value for the old entry
	k = v2.NewKey(key)
	v = v2.NewValue(uint32(0xabcddead))
	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	err = mockMapv5.CopyDeltaFromOldMap()
	Expect(err).NotTo(HaveOccurred())

	val, err = mockMapv5.Get(k5.AsBytes())
	val5 = v5.NewValue(uint32(0xabcddead))
	Expect(err).NotTo(HaveOccurred())
	Expect(val).To(Equal(val5.AsBytes()))

	for i := 0; i < 10; i++ {
		k5 = v5.NewKey(0x1234 + uint32(i))
		val5 = v5.NewValue(0x4568 + uint32(i))
		val, err = mockMapv5.Get(k5.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(val).To(Equal(val5.AsBytes()))
	}

	deleteMap(mockMapv2)
	deleteMap(mockMapv5)
}

func TestMapResizeWhileUpgradeInProgress(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}

	// create v2 map and add 10 entries to it
	mockMapv2 := mock.MapV2(mc, 20)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		k := v2.NewKey(0x1234 + uint32(i))
		v := v2.NewValue(0x4568 + uint32(i))
		err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}

	// create v5 map
	mockMapv5 := mock.MapV5(mc, 20)
	err = mockMapv5.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		k := v5.NewKey(0x1234 + uint32(i))
		v := v5.NewValue(0x4568 + uint32(i))
		val, err := mockMapv5.Get(k.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(val).To(Equal(v.AsBytes()))
	}

	for i := 0; i < 5; i++ {
		k := v5.NewKey(0x1234 + uint32(i))
		err := mockMapv5.Delete(k.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}

	mockMapv5_new := mock.MapV5(mc, 30)
	err = mockMapv5_new.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		k := v5.NewKey(0x1234 + uint32(i))
		v := v5.NewValue(0x4568 + uint32(i))
		val, err := mockMapv5_new.Get(k.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(val).To(Equal(v.AsBytes()))
	}
	deleteMap(mockMapv2)
	deleteMap(mockMapv5)
	deleteMap(mockMapv5_new)

}

func TestMapUpgradeWhileResizeInProgress(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}

	// create v2 map and add 10 entries to it
	mockMapv2_old := mock.MapV2(mc, 20)
	err := mockMapv2_old.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		k := v2.NewKey(0x1234 + uint32(i))
		v := v2.NewValue(0x4568 + uint32(i))
		err = mockMapv2_old.Update(k.AsBytes(), v.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}

	// repin /sys/fs/bpf/tc/globals/cali_mock2 to /sys/fs/bpt/tc/globals/cali_mock2_old1
	err = bpf.RepinMap(mockMapv2_old.GetName(), mockMapv2_old.Path()+"_old1")
	Expect(err).NotTo(HaveOccurred())
	// Delete /sys/fs/bpf/tc/globals/cali_mock2
	os.Remove(mockMapv2_old.Path())
	mapId, err := bpf.GetMapIdFromPin(mockMapv2_old.Path() + "_old1")
	Expect(err).NotTo(HaveOccurred())

	// create another v2 map and add only the last 5 entries
	mockMapv2 := mock.MapV2(mc, 30)
	err = mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 5; i < 10; i++ {
		k := v2.NewKey(0x1234 + uint32(i))
		v := v2.NewValue(0x4568 + uint32(i))
		err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}

	// Reping /sys/fs/bpt/tc/globals/cali_mock2_old1 to /sys/fs/bpt/tc/globals/cali_mock2_old
	err = bpf.RepinMapFromId(mapId, mockMapv2.Path()+"_old")
	Expect(err).NotTo(HaveOccurred())
	// Remove /sys/fs/bpt/tc/globals/cali_mock2_old1
	os.Remove(mockMapv2_old.Path() + "_old1")

	// At this point we /sys/fs/bpt/tc/globals/cali_mock2 with 5 entries and
	// /sys/fs/bpt/tc/globals/cali_mock2_old with 10 entries.
	// Now create v5 map. This should trigger the following steps
	// 1. Create /sys/fs/bpt/tc/globals/cali_mock5
	// 2. Reads the old version as 2
	// 3. Calls EnsureExists with version 2 map params
	// 4. Finds out /sys/fs/bpt/tc/globals/cali_mock2_old is present.
	// 5. Removes /sys/fs/bpt/tc/globals/cali_mock2
	// 6. Repins /sys/fs/bpt/tc/globals/cali_mock2_old as /sys/fs/bpt/tc/globals/cali_mock2
	// 7. Upgrades k,v from version 2 to version 5
	mockMapv5 := mock.MapV5(mc, 40)
	err = mockMapv5.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		k := v5.NewKey(0x1234 + uint32(i))
		v := v5.NewValue(0x4568 + uint32(i))
		val, err := mockMapv5.Get(k.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(val).To(Equal(v.AsBytes()))
	}
	deleteMap(mockMapv2_old)
	deleteMap(mockMapv2)
	deleteMap(mockMapv5)
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
}

func TestCtMapUpgradeWithNormalEntries(t *testing.T) {
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
	ctMapV3.(*bpf.PinnedMap).Close()

	os.Remove(ctMapV2.Path())
	os.Remove(ctMapV3.Path())
	for _, m := range allMaps {
		err := m.EnsureExists()
		Expect(err).NotTo(HaveOccurred())
	}
}
