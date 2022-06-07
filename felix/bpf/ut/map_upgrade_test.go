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

	"github.com/projectcalico/calico/felix/bpf"
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
}

func TestMapUpgradeV2ToV3(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv2 := mock.MapV2(mc)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v2.NewKey(key)
	v := v2.NewValue(val)

	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv3 := mock.MapV3(mc)
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
	mockMapv2 := mock.MapV2(mc)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v2.NewKey(key)
	v := v2.NewValue(val)

	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv4 := mock.MapV4(mc)
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
	mockMapv2 := mock.MapV2(mc)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v2.NewKey(key)
	v := v2.NewValue(val)

	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv5 := mock.MapV5(mc)
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
	mockMapv3 := mock.MapV3(mc)
	err := mockMapv3.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v3.NewKey(key)
	v := v3.NewValue(val)

	err = mockMapv3.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv5 := mock.MapV5(mc)
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

func TestMapUpgradeV5ToV3(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv5 := mock.MapV5(mc)
	err := mockMapv5.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	mockMapv3 := mock.MapV3(mc)
	err = mockMapv3.EnsureExists()
	Expect(err).To(HaveOccurred())
	deleteMap(mockMapv5)
	deleteMap(mockMapv3)
}

func TestMapUpgradeWithDeltaEntries(t *testing.T) {
	RegisterTestingT(t)
	mc := &bpf.MapContext{}
	mockMapv2 := mock.MapV2(mc)
	err := mockMapv2.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	k := v2.NewKey(key)
	v := v2.NewValue(val)

	err = mockMapv2.Update(k.AsBytes(), v.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	mockMapv5 := mock.MapV5(mc)
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

	err = mockMapv5.UpgradeDeltaFromOldMap()
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
