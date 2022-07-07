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
	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/felix/bpf/cachingmap"
	"github.com/projectcalico/calico/felix/logutils"
)

func init() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)
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
	mockMap.LoadErr = ErrFail
	err := cm.ApplyAllChanges()
	Expect(err).To(HaveOccurred())

	// Failure should have cleared the cache again so next Apply should see this new entry.
	mockMap.Contents = map[string]string{
		"1, 1": "1, 2, 4, 3",
	}
	mockMap.LoadErr = nil
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())

	// Now check errors on update
	cm.SetDesired("1, 1", "1, 2, 4, 4")
	mockMap.UpdateErr = ErrFail
	err = cm.ApplyAllChanges()
	Expect(err).To(HaveOccurred())

	// And then success
	mockMap.UpdateErr = nil
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"1, 1": "1, 2, 4, 4",
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
	_ = mockMap.Update("1, 2", "1, 2, 3, 4")
	_ = mockMap.Update("1, 3", "1, 2, 4, 4")

	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
}

// TestCachingMap_ApplyAll mainline test using separate Apply calls for adds and deletes.
func TestCachingMap_SplitUpdateAndDelete(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t)
	mockMap.Contents = map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}

	cm.SetDesired("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.SetDesired("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.SetDesired("1, 4", "1, 2, 3, 5") // New K/V
	// Shouldn't do anything until we hit apply.
	Expect(mockMap.OpCount()).To(Equal(0))

	err := cm.ApplyUpdatesOnly()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"1, 1": "1, 2, 4, 3", // No change
		"1, 2": "1, 2, 3, 6", // Updated
		"1, 3": "1, 2, 4, 4", // Not desired but should be left alone
		"1, 4": "1, 2, 3, 5", // Added
	}))
	// Two updates and an iteration to load the map initially.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.DeleteCount).To(Equal(0))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.LoadCount).To(Equal(1))

	err = cm.ApplyDeletionsOnly()
	Expect(err).NotTo(HaveOccurred())

	Expect(mockMap.Contents).To(Equal(map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 6",
		"1, 4": "1, 2, 3, 5",
	}))
	// No new updates or iterations but should get one extra deletion.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.DeleteCount).To(Equal(1))
	Expect(mockMap.LoadCount).To(Equal(1))

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
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}

	cm.SetDesired("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.SetDesired("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.SetDesired("1, 4", "1, 2, 3, 5") // New K/V
	// Shouldn't do anything until we hit apply.
	Expect(mockMap.OpCount()).To(Equal(0))

	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 6",
		"1, 4": "1, 2, 3, 5",
	}))
	// Two updates and an iteration to load the map initially.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.DeleteCount).To(Equal(1))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.LoadCount).To(Equal(1))

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
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}

	cm.SetDesired("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.SetDesired("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.SetDesired("1, 4", "1, 2, 3, 5") // New K/V
	cm.DeleteDesired("1, 2")            // Changed my mind.
	cm.DeleteDesired("1, 4")            // Changed my mind.
	cm.DeleteDesired("1, 8")            // Delete of non-existent key is a no-op.
	// Shouldn't do anything until we hit apply.
	Expect(mockMap.OpCount()).To(Equal(0))

	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"1, 1": "1, 2, 4, 3",
	}))
	// Just the two deletes.
	Expect(mockMap.UpdateCount).To(Equal(0))
	Expect(mockMap.DeleteCount).To(Equal(2))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.LoadCount).To(Equal(1))

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
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}
	err := cm.LoadCacheFromDataplane()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.LoadCount).To(Equal(1))
	Expect(mockMap.OpCount()).To(Equal(1))

	// Check we can query the cache.
	v, ok := cm.GetDataplaneCache("1, 1")
	Expect(ok).To(BeTrue())
	Expect(v).To(Equal("1, 2, 4, 3"))
	seenValues := make(map[string]string)
	cm.IterDataplaneCache(func(k string, v string) {
		seenValues[k] = v
	})
	Expect(seenValues).To(Equal(mockMap.Contents))

	cm.SetDesired("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.SetDesired("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.SetDesired("1, 4", "1, 2, 3, 5") // New K/V
	cm.DeleteDesired("1, 8")            // Delete of non-existent key is a no-op.

	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 6",
		"1, 4": "1, 2, 3, 5",
	}))
	// Two updates and an iteration to load the map initially.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.DeleteCount).To(Equal(1))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.LoadCount).To(Equal(1))

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
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}
	err := cm.LoadCacheFromDataplane()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.LoadCount).To(Equal(1))
	Expect(mockMap.OpCount()).To(Equal(1))

	cm.SetDesired("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.SetDesired("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.SetDesired("1, 4", "1, 2, 3, 5") // New K/V

	// At this point we've got some updates and a deletion queued up. Change the contents
	// of the map:
	// - Remove the key that was already correct.
	// - Remove the key that we were about to delete.
	// - Correct the value of the other key.
	mockMap.Contents = map[string]string{
		"1, 2": "1, 2, 3, 6",
	}

	err = cm.LoadCacheFromDataplane()
	Expect(err).NotTo(HaveOccurred())

	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 6",
		"1, 4": "1, 2, 3, 5",
	}))
	// Two updates and an iteration to load the map initially.
	Expect(mockMap.UpdateCount).To(Equal(2))
	Expect(mockMap.DeleteCount).To(Equal(0))
	Expect(mockMap.GetCount).To(Equal(0))
	Expect(mockMap.LoadCount).To(Equal(2))

	// Doing an extra apply should make no changes.
	preApplyOpCount := mockMap.OpCount()
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.OpCount()).To(Equal(preApplyOpCount))
}

func setupCachingMapTest(t *testing.T) (*Map, *CachingMap[string, string]) {
	RegisterTestingT(t)
	mockMap := newMockMap()

	cm := New[string, string]("mock-map", mockMap)

	return mockMap, cm
}

type Map struct {
	Contents map[string]string

	UpdateCount int
	GetCount    int
	DeleteCount int
	LoadCount   int

	LoadErr   error
	UpdateErr error
	DeleteErr error
}

func (m *Map) Update(k, v string) error {
	log.Debugf("Update(\"%s\", \"%s\")", k, v)
	m.UpdateCount++
	if m.UpdateErr != nil {
		return m.UpdateErr
	}

	m.Contents[string(k)] = string(v)

	return nil
}

func (m *Map) Get(k string) (string, error) {
	log.Debugf("Get(\"%s\")", k)
	m.GetCount++

	v, ok := m.Contents[k]
	if !ok {
		return "", ErrNotExists
	}
	return v, nil
}

func (m *Map) Delete(k string) error {
	log.Debugf("Delete(\"%s\")", k)
	m.DeleteCount++
	if m.DeleteErr != nil {
		return m.DeleteErr
	}

	delete(m.Contents, k)
	return nil
}

func (m *Map) Load() (map[string]string, error) {
	m.LoadCount++
	if m.LoadErr != nil {
		return nil, m.LoadErr
	}

	return m.Contents, nil
}

func (m *Map) OpCount() int {
	return m.UpdateCount + m.LoadCount + m.GetCount + m.DeleteCount
}

func newMockMap() *Map {
	m := &Map{
		Contents: map[string]string{},
	}
	return m
}
