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

	. "github.com/projectcalico/calico/felix/cachingmap"
	"github.com/projectcalico/calico/felix/logutils"
)

func init() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)
}

// TestCachingMap_Empty verifies loading of an empty map with no changes queued.
func TestCachingMap_Empty(t *testing.T) {
	testCachingMap_Empty(t, true)
	testCachingMap_Empty(t, false)
}

func testCachingMap_Empty(t *testing.T, batched bool) {
	mockMap, cm := setupCachingMapTest(t, batched)
	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
}

var ErrFail = fmt.Errorf("fail")

// TestCachingMap_Errors tests returning of errors from the underlying map.
func TestCachingMap_Errors(t *testing.T) {
	testCachingMap_Errors(t, true)
	testCachingMap_Errors(t, false)
}

func testCachingMap_Errors(t *testing.T, batched bool) {
	mockMap, cm := setupCachingMapTest(t, batched)
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
	cm.Desired().Set("1, 1", "1, 2, 4, 4")
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
	cm.Desired().DeleteAll()
	err = cm.ApplyAllChanges()
	Expect(err).To(HaveOccurred())

	mockMap.DeleteErr = nil
	err = cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
}

// TestCachingMap_CleanUp verifies cleaning up of a whole map.
func TestCachingMap_CleanUp(t *testing.T) {
	testCachingMap_CleanUp(t, true)
	testCachingMap_CleanUp(t, false)
}

func testCachingMap_CleanUp(t *testing.T, batched bool) {
	mockMap, cm := setupCachingMapTest(t, batched)
	_ = mockMap.Update("1, 2", "1, 2, 3, 4")
	_ = mockMap.Update("1, 3", "1, 2, 4, 4")

	err := cm.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(BeEmpty())
}

// TestCachingMap_ApplyAll mainline test using separate Apply calls for adds and deletes.
func TestCachingMap_SplitUpdateAndDelete(t *testing.T) {
	testCachingMap_SplitUpdateAndDelete(t, true)
	testCachingMap_SplitUpdateAndDelete(t, false)
}

func testCachingMap_SplitUpdateAndDelete(t *testing.T, batched bool) {
	mockMap, cm := setupCachingMapTest(t, batched)
	mockMap.Contents = map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}

	cm.Desired().Set("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.Desired().Set("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.Desired().Set("1, 4", "1, 2, 3, 5") // New K/V
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
	testCachingMap_ApplyAll(t, true)
	testCachingMap_ApplyAll(t, false)
}

func testCachingMap_ApplyAll(t *testing.T, batched bool) {
	mockMap, cm := setupCachingMapTest(t, batched)
	mockMap.Contents = map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}

	cm.Desired().Set("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.Desired().Set("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.Desired().Set("1, 4", "1, 2, 3, 5") // New K/V
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
	cm.Desired().DeleteAll()
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
	testCachingMap_DeleteBeforeLoad(t, true)
	testCachingMap_DeleteBeforeLoad(t, false)
}

func testCachingMap_DeleteBeforeLoad(t *testing.T, batched bool) {
	mockMap, cm := setupCachingMapTest(t, batched)
	mockMap.Contents = map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}

	cm.Desired().Set("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.Desired().Set("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.Desired().Set("1, 4", "1, 2, 3, 5") // New K/V
	cm.Desired().Delete("1, 2")            // Changed my mind.
	cm.Desired().Delete("1, 4")            // Changed my mind.
	cm.Desired().Delete("1, 8")            // Delete of nonexistent key is a no-op.
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
	testCachingMap_PreLoad(t, true)
	testCachingMap_PreLoad(t, false)
}

func testCachingMap_PreLoad(t *testing.T, batched bool) {
	mockMap, cm := setupCachingMapTest(t, batched)
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
	v, ok := cm.Dataplane().Get("1, 1")
	Expect(ok).To(BeTrue())
	Expect(v).To(Equal("1, 2, 4, 3"))
	seenValues := make(map[string]string)
	cm.Dataplane().Iter(func(k string, v string) {
		seenValues[k] = v
	})
	Expect(seenValues).To(Equal(mockMap.Contents))

	cm.Desired().Set("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.Desired().Set("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.Desired().Set("1, 4", "1, 2, 3, 5") // New K/V
	cm.Desired().Delete("1, 8")            // Delete of nonexistent key is a no-op.

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
	testCachingMap_Resync(t, true)
	testCachingMap_Resync(t, false)
}

func testCachingMap_Resync(t *testing.T, batched bool) {
	mockMap, cm := setupCachingMapTest(t, batched)
	mockMap.Contents = map[string]string{
		"1, 1": "1, 2, 4, 3",
		"1, 2": "1, 2, 3, 4",
		"1, 3": "1, 2, 4, 4",
	}
	err := cm.LoadCacheFromDataplane()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.LoadCount).To(Equal(1))
	Expect(mockMap.OpCount()).To(Equal(1))

	cm.Desired().Set("1, 1", "1, 2, 4, 3") // Same value for existing key.
	cm.Desired().Set("1, 2", "1, 2, 3, 6") // New value for existing key.
	cm.Desired().Set("1, 4", "1, 2, 3, 5") // New K/V

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

// TestCachingMap_BatchUpdateFailures tests that when some updates fail and some succeed
// during ApplyUpdatesOnly, the successful ones are applied and errors are returned.
func TestCachingMap_BatchUpdateFailures(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t, false) // Test with non-batched for key-specific failures
	mockMap.Contents = map[string]string{
		"existing": "value",
	}

	// Set up some pending updates
	cm.Desired().Set("key1", "value1") // This should succeed
	cm.Desired().Set("key2", "value2") // This will fail
	cm.Desired().Set("key3", "value3") // This should succeed
	cm.Desired().Set("key4", "value4") // This will fail

	// Configure specific failures
	mockMap.UpdateFailures["key2"] = fmt.Errorf("update key2 failed")
	mockMap.UpdateFailures["key4"] = fmt.Errorf("update key4 failed")

	err := cm.ApplyUpdatesOnly()

	// Should get an error slice with 2 errors
	Expect(err).To(HaveOccurred())
	errSlice, ok := err.(ErrSlice)
	Expect(ok).To(BeTrue(), "Expected ErrSlice type")
	Expect(len(errSlice)).To(Equal(2), "Expected 2 errors")

	// Check that successful operations were applied
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"existing": "value",
		"key1":     "value1", // succeeded
		"key3":     "value3", // succeeded
		// key2 and key4 should not be present due to failures
	}))

	// All update calls should have been attempted
	Expect(mockMap.UpdateCount).To(Equal(4))
	Expect(mockMap.LoadCount).To(Equal(1))
}

// TestCachingMap_BatchDeleteFailures tests that when some deletions fail and some succeed
// during ApplyDeletionsOnly, the successful ones are applied and errors are returned.
func TestCachingMap_BatchDeleteFailures(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t, false) // Test with non-batched for key-specific failures
	mockMap.Contents = map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
		"key4": "value4",
		"keep": "keepvalue",
	}

	// Set up desired state that will cause deletions
	cm.Desired().Set("keep", "keepvalue") // This key should remain

	// Configure specific delete failures
	mockMap.DeleteFailures["key2"] = fmt.Errorf("delete key2 failed")
	mockMap.DeleteFailures["key4"] = fmt.Errorf("delete key4 failed")

	err := cm.ApplyDeletionsOnly()

	// Should get an error slice with 2 errors
	Expect(err).To(HaveOccurred())
	errSlice, ok := err.(ErrSlice)
	Expect(ok).To(BeTrue(), "Expected ErrSlice type")
	Expect(len(errSlice)).To(Equal(2), "Expected 2 errors")

	// Check that successful deletions were applied
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"key2": "value2",    // failed to delete
		"key4": "value4",    // failed to delete
		"keep": "keepvalue", // kept as desired
	}))

	// Deletion attempts should have been made
	Expect(mockMap.DeleteCount).To(Equal(4)) // key1, key2, key3, key4 deletion attempts
	Expect(mockMap.LoadCount).To(Equal(1))
}

// TestCachingMap_BatchAllChangesFailures tests that when both updates and deletions
// have partial failures during ApplyAllChanges, successful operations are applied
// and all errors are returned.
func TestCachingMap_BatchAllChangesFailures(t *testing.T) {
	mockMap, cm := setupCachingMapTest(t, false) // Test with non-batched for key-specific failures
	mockMap.Contents = map[string]string{
		"delete1": "value1",
		"delete2": "value2", // Will fail to delete
		"update1": "oldval", // Will be updated
	}

	// Set up desired state
	cm.Desired().Set("update1", "newval")  // Update existing (should succeed)
	cm.Desired().Set("update2", "newval2") // Add new (will fail)
	cm.Desired().Set("update3", "newval3") // Add new (should succeed)

	// Configure failures
	mockMap.UpdateFailures["update2"] = fmt.Errorf("update2 failed")
	mockMap.DeleteFailures["delete2"] = fmt.Errorf("delete2 failed")

	err := cm.ApplyAllChanges()

	// Should get errors from both deletions and updates
	Expect(err).To(HaveOccurred())
	errSlice, ok := err.(ErrSlice)
	Expect(ok).To(BeTrue(), "Expected ErrSlice type")
	Expect(len(errSlice)).To(Equal(2), "Expected 2 errors (1 delete + 1 update)")

	// Check final state - successful operations should be applied
	Expect(mockMap.Contents).To(Equal(map[string]string{
		"delete2": "value2",  // failed to delete
		"update1": "newval",  // successfully updated
		"update3": "newval3", // successfully added
		// update2 not present due to failure
	}))

	// Verify operation counts
	Expect(mockMap.DeleteCount).To(Equal(2)) // delete1, delete2 attempts
	Expect(mockMap.UpdateCount).To(Equal(3)) // update1, update2, update3 attempts
	Expect(mockMap.LoadCount).To(Equal(1))
}

func setupCachingMapTest(t *testing.T, batched bool) (*Map, *CachingMap[string, string]) {
	RegisterTestingT(t)

	var (
		mockMap DataplaneMap[string, string]
		retMap  *Map
	)

	if batched {
		m := newMockBatchMap()
		mockMap = m
		retMap = m.Map
	} else {
		m := newMockMap()
		mockMap = m
		retMap = m
	}

	cm := New[string, string]("mock-map", mockMap)

	return retMap, cm
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

	// Maps to specify which specific keys should fail
	UpdateFailures map[string]error
	DeleteFailures map[string]error
}

var errNotExists = fmt.Errorf("does not exist")

func (m *Map) ErrIsNotExists(err error) bool {
	return err == errNotExists
}

func (m *Map) Update(k, v string) error {
	log.Debugf("Update(\"%s\", \"%s\")", k, v)
	m.UpdateCount++

	// Check for key-specific failure first
	if m.UpdateFailures != nil {
		if err, exists := m.UpdateFailures[k]; exists {
			return err
		}
	}

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
		return "", errNotExists
	}
	return v, nil
}

func (m *Map) Delete(k string) error {
	log.Debugf("Delete(\"%s\")", k)
	m.DeleteCount++

	// Check for key-specific failure first
	if m.DeleteFailures != nil {
		if err, exists := m.DeleteFailures[k]; exists {
			return err
		}
	}

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
		Contents:       map[string]string{},
		UpdateFailures: make(map[string]error),
		DeleteFailures: make(map[string]error),
	}
	return m
}

type BatchMap struct {
	*Map
}

func (m *BatchMap) BatchUpdate(ks []string, vs []string) (int, error) {
	for i, k := range ks {
		err := m.Update(k, vs[i])
		if err != nil {
			return i, err
		}
	}

	return len(ks), nil
}

func (m *BatchMap) BatchDelete(ks []string) (int, error) {
	for i, k := range ks {
		err := m.Delete(k)
		if err != nil {
			return i, err
		}
	}

	return len(ks), nil
}

func newMockBatchMap() *BatchMap {
	return &BatchMap{
		Map: newMockMap(),
	}
}
