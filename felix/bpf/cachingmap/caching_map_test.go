// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package cachingmap_test

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	. "github.com/projectcalico/calico/felix/bpf/cachingmap"
	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/logutils"
)

func init() {
	logutils.ConfigureEarlyLogging()
	logrus.SetLevel(logrus.DebugLevel)
}

var cachingMapParams = bpf.MapParameters{
	Name:      "mock-map",
	KeySize:   2,
	ValueSize: 4,
}

type Key [2]byte

func (k Key) String() string {
	return string(k[:])
}

func (k Key) AsBytes() []byte {
	return k[:]
}

type Value [4]byte

func (v Value) String() string {
	return string(v[:])
}

func (v Value) AsBytes() []byte {
	return v[:]
}

// TestCachingMap_Empty verifies loading of an empty map with no changes queued.
func TestCachingMap_Empty(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
}

var ErrFail = fmt.Errorf("fail")

// TestCachingMap_Errors tests returning of errors from the underlying map.
func TestCachingMap_Errors(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	mockMap.IterErr = ErrFail
	err := cm.ApplyAllChanges()
	Expect(err).To(HaveOccurred())

	// Failure should have cleared the cache again so next Apply should see this new entry.
	mockMap.Contents = map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
	}
	mockMap.IterErr = nil
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())

	// Now check errors on update
	cm.SetDesired(Key{1, 1}, Value{1, 2, 4, 4})
	mockMap.UpdateErr = ErrFail
	err = cm.ApplyAllChanges()
	Expect(err).To(HaveOccurred())

	// And then success
	mockMap.UpdateErr = nil
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 4}.String(),
	}))

	// And delete.
	mockMap.DeleteErr = ErrFail
	cm.DeleteAllDesired()
	err = cm.ApplyAllChanges()
	Expect(err).To(HaveOccurred())

	mockMap.DeleteErr = nil
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
}

// TestCachingMap_CleanUp verifies cleaning up of a whole map.
func TestCachingMap_CleanUp(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	_ = mockMap.Update(Key{1, 2}.AsBytes(), Value{1, 2, 3, 4}.AsBytes())
	_ = mockMap.Update(Key{1, 3}.AsBytes(), Value{1, 2, 4, 4}.AsBytes())

	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
}

// TestCachingMap_ApplyAll mainline test using separate Apply calls for adds and deletes.
func TestCachingMap_SplitUpdateAndDelete(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	mockMap.Contents = map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 4}.String(),
		Key{1, 3}.String(): Value{1, 2, 4, 4}.String(),
	}

	cm.SetDesired(Key{1, 1}, Value{1, 2, 4, 3}) // Same value for existing key.
	cm.SetDesired(Key{1, 2}, Value{1, 2, 3, 6}) // New value for existing key.
	cm.SetDesired(Key{1, 4}, Value{1, 2, 3, 5}) // New K/V
	// Shouldn't do anything until we hit apply.
	Expect(mockMap.OpCount()).To(Equal(0))

	err := cm.ApplyUpdatesOnly()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(), // No change
		Key{1, 2}.String(): Value{1, 2, 3, 6}.String(), // Updated
		Key{1, 3}.String(): Value{1, 2, 4, 4}.String(), // Not desired but should be left alone
		Key{1, 4}.String(): Value{1, 2, 3, 5}.String(), // Added
	}))
	// Two updates and an iteration to load the map initially.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.DeleteCount).To(Equal(0))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.IterCount).To(Equal(1))

	err = cm.ApplyDeletionsOnly()
	Expect(err).NotTo(HaveOccurred())

	Expect(mockMap.Contents).To(Equal(map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 6}.String(),
		Key{1, 4}.String(): Value{1, 2, 3, 5}.String(),
	}))
	// No new updates or iterations but should get one extra deletion.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.DeleteCount).To(Equal(1))
	Expect(mockMap.IterCount).To(Equal(1))

	// Doing an extra apply should make no changes.
	preApplyOpCount := mockMap.OpCount()
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.OpCount()).To(Equal(preApplyOpCount))
}

// TestCachingMap_ApplyAll mainline test using ApplyAll() to update the dataplane.
func TestCachingMap_ApplyAll(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	mockMap.Contents = map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 4}.String(),
		Key{1, 3}.String(): Value{1, 2, 4, 4}.String(),
	}

	cm.SetDesired(Key{1, 1}, Value{1, 2, 4, 3}) // Same value for existing key.
	cm.SetDesired(Key{1, 2}, Value{1, 2, 3, 6}) // New value for existing key.
	cm.SetDesired(Key{1, 4}, Value{1, 2, 3, 5}) // New K/V
	// Shouldn't do anything until we hit apply.
	Expect(mockMap.OpCount()).To(Equal(0))

	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 6}.String(),
		Key{1, 4}.String(): Value{1, 2, 3, 5}.String(),
	}))
	// Two updates and an iteration to load the map initially.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.DeleteCount).To(Equal(1))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.IterCount).To(Equal(1))

	// Doing an extra apply should make no changes.
	preApplyOpCount := mockMap.OpCount()
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.OpCount()).To(Equal(preApplyOpCount))

	// Finish with a DeleteAll()
	cm.DeleteAllDesired()
	Expect(mockMap.OpCount()).To(Equal(preApplyOpCount)) // No immediate change
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
	Expect(mockMap.DeleteCount).To(Equal(4))

	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
	Expect(mockMap.DeleteCount).To(Equal(4))
}

// TestCachingMap_DeleteBeforeLoad does some set and delete calls before loading from
// the dataplane.
func TestCachingMap_DeleteBeforeLoad(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	mockMap.Contents = map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 4}.String(),
		Key{1, 3}.String(): Value{1, 2, 4, 4}.String(),
	}

	cm.SetDesired(Key{1, 1}, Value{1, 2, 4, 3}) // Same value for existing key.
	cm.SetDesired(Key{1, 2}, Value{1, 2, 3, 6}) // New value for existing key.
	cm.SetDesired(Key{1, 4}, Value{1, 2, 3, 5}) // New K/V
	cm.DeleteDesired(Key{1, 2})                 // Changed my mind.
	cm.DeleteDesired(Key{1, 4})                 // Changed my mind.
	cm.DeleteDesired(Key{1, 8})                 // Delete of non-existent key is a no-op.
	// Shouldn't do anything until we hit apply.
	Expect(mockMap.OpCount()).To(Equal(0))

	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
	}))
	// Just the two deletes.
	Expect(mockMap.UpdateCount).To(Equal(0))
	Expect(mockMap.DeleteCount).To(Equal(2))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.IterCount).To(Equal(1))

	// Doing an extra apply should make no changes.
	preApplyOpCount := mockMap.OpCount()
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.OpCount()).To(Equal(preApplyOpCount))
}

// TestCachingMap_PreLoad verifies calling LoadCacheFromDataplane before setting values.
func TestCachingMap_PreLoad(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	mockMap.Contents = map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 4}.String(),
		Key{1, 3}.String(): Value{1, 2, 4, 4}.String(),
	}
	err := cm.LoadCacheFromDataplane()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.IterCount).To(Equal(1))
	Expect(mockMap.OpCount()).To(Equal(1))

	// Check we can query the cache.
	v, ok := cm.GetDataplaneCache(Key{1, 1})
	Expect(ok).To(BeTrue())
	Expect(v).To(Equal(Value{1, 2, 4, 3}))
	seenValues := make(map[string]string)
	cm.IterDataplaneCache(func(k Key, v Value) {
		seenValues[k.String()] = v.String()
	})
	Expect(seenValues).To(Equal(mockMap.Contents))

	cm.SetDesired(Key{1, 1}, Value{1, 2, 4, 3}) // Same value for existing key.
	cm.SetDesired(Key{1, 2}, Value{1, 2, 3, 6}) // New value for existing key.
	cm.SetDesired(Key{1, 4}, Value{1, 2, 3, 5}) // New K/V
	cm.DeleteDesired(Key{1, 8})                 // Delete of non-existent key is a no-op.

	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 6}.String(),
		Key{1, 4}.String(): Value{1, 2, 3, 5}.String(),
	}))
	// Two updates and an iteration to load the map initially.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.DeleteCount).To(Equal(1))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.IterCount).To(Equal(1))

	// Doing an extra apply should make no changes.
	preApplyOpCount := mockMap.OpCount()
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.OpCount()).To(Equal(preApplyOpCount))
}

// TestCachingMap_Resync verifies handling of a dataplane reload while there are pending
// changes.  Pending changes should be dropped if the reload finds that they've already
// been made.
func TestCachingMap_Resync(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	mockMap.Contents = map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 4}.String(),
		Key{1, 3}.String(): Value{1, 2, 4, 4}.String(),
	}
	err := cm.LoadCacheFromDataplane()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.IterCount).To(Equal(1))
	Expect(mockMap.OpCount()).To(Equal(1))

	cm.SetDesired(Key{1, 1}, Value{1, 2, 4, 3}) // Same value for existing key.
	cm.SetDesired(Key{1, 2}, Value{1, 2, 3, 6}) // New value for existing key.
	cm.SetDesired(Key{1, 4}, Value{1, 2, 3, 5}) // New K/V

	// At this point we've got some updates and a deletion queued up. Change the contents
	// of the map:
	// - Remove the key that was already correct.
	// - Remove the key that we were about to delete.
	// - Correct the value of the other key.
	mockMap.Contents = map[string]string{
		Key{1, 2}.String(): Value{1, 2, 3, 6}.String(),
	}

	err = cm.LoadCacheFromDataplane()
	Expect(err).NotTo(HaveOccurred())

	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		Key{1, 1}.String(): Value{1, 2, 4, 3}.String(),
		Key{1, 2}.String(): Value{1, 2, 3, 6}.String(),
		Key{1, 4}.String(): Value{1, 2, 3, 5}.String(),
	}))
	// Two updates and an iteration to load the map initially.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.DeleteCount).To(Equal(0))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.IterCount).To(Equal(2))

	// Doing an extra apply should make no changes.
	preApplyOpCount := mockMap.OpCount()
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.OpCount()).To(Equal(preApplyOpCount))
}

func setupCachingMapTest(t *testing.T) (*mock.Map, *CachingMap[Key, Value]) {
	RegisterTestingT(t)
	mockMap := mock.NewMockMap(cachingMapParams)

	cm := New[Key, Value]("mock-map",
		bpf.NewTypedMap[Key, Value](mockMap,
			func(b []byte) Key {
				var k Key
				copy(k[:], b)
				return k
			},
			func(b []byte) Value {
				var v Value
				copy(v[:], b)
				return v
			},
		),
	)

	return mockMap, cm
}
