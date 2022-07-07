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
	"os/exec"

	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf"
	mock "github.com/projectcalico/calico/felix/bpf/mock/multiversion"
	v2 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v2"
	v3 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v3"
	v4 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v4"
	v5 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v5"
)

const key = 0xdeadbeef
const val = 0xa0b1c2d3

func bpfMapList() string {
	cmd := exec.Command("bpftool", "map", "list", "-j")
	out, _ := cmd.CombinedOutput()
	return string(out)
}
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv2.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv3.GetName()))
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv2.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv4.GetName()))
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv2.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv5.GetName()))
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv5.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv3.GetName()))
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv5.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv3.GetName()))
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
	Expect(err).To(HaveOccurred())
	deleteMap(mockMapv3)
	deleteMap(mockMapv5)
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv5.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv3.GetName()))
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv5.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv3.GetName()))
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv5.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv2.GetName()))
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv5.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv2.GetName()))
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
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv5.GetName()))
	Eventually(bpfMapList, "10s", "200ms").ShouldNot(ContainSubstring(mockMapv2.GetName()))
}
