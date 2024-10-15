// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deltatracker

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/logutils"
)

func init() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)
}

// TestDeltaTracker_Empty verifies loading of an empty map with no changes queued.
func TestDeltaTracker_Empty(t *testing.T) {
	dt := setupDeltaTrackerTest(t)
	dt.Desired().Iter(func(k string, v string) {
		t.Errorf("Iter unexpectedly called func with %v, %v", k, v)
	})
	dt.Dataplane().Iter(func(k string, v string) {
		t.Errorf("Iter unexpectedly called func with %v, %v", k, v)
	})
	dt.PendingUpdates().Iter(func(k string, v string) IterAction {
		t.Errorf("IterPendingUpdates unexpectedly called func with %v, %v", k, v)
		return IterActionNoOp
	})
	dt.PendingDeletions().Iter(func(k string) IterAction {
		t.Errorf("IterPendingDeletions unexpectedly called func with %v", k)
		return IterActionNoOp
	})
	Expect(dt.Desired().Len()).To(BeZero())
}

// TestDeltaTracker_CleanUp verifies cleaning up of a whole map.
func TestDeltaTracker_CleanUp(t *testing.T) {
	dt := setupDeltaTrackerTest(t)
	err := dt.Dataplane().ReplaceAllIter(mapIter(map[string]string{
		"1": "A1",
		"2": "B1",
	}))
	Expect(err).NotTo(HaveOccurred())
	Expect(pendingUpdates(dt, IterActionNoOp)).To(BeEmpty())
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
	}))
	Expect(dt.Desired().Len()).To(Equal(0))
}

func pendingDeletions(dt *DeltaTracker[string, string], action IterAction) map[string]string {
	result := map[string]string{}
	dt.PendingDeletions().Iter(func(k string) IterAction {
		v, ok := dt.Dataplane().Get(k)
		if !ok {
			panic(fmt.Sprintf("IterPendingDeletions iterated over key that wasn't returned by Get: %v", k))
		}
		result[k] = v
		vGet, ok := dt.PendingDeletions().Get(k)
		Expect(ok).To(BeTrue(), "Iterator returned pending update but Get did not")
		Expect(vGet).To(Equal(v), "Iterator returned pending update but Get did not")
		return action
	})
	return result
}

func pendingUpdates(dt *DeltaTracker[string, string], action IterAction) map[string]string {
	result := map[string]string{}
	dt.PendingUpdates().Iter(func(k string, v string) IterAction {
		result[k] = v
		vGet, ok := dt.PendingUpdates().Get(k)
		Expect(ok).To(BeTrue(), "Iterator returned pending update but Get did not")
		Expect(vGet).To(Equal(v), "Iterator returned pending update but Get did not")
		return action
	})
	return result
}

func allDesired(dt *DeltaTracker[string, string]) map[string]string {
	result := map[string]string{}
	dt.Desired().Iter(func(k string, v string) {
		result[k] = v
	})
	return result
}

func allDataplane(dt *DeltaTracker[string, string]) map[string]string {
	result := map[string]string{}
	dt.Dataplane().Iter(func(k string, v string) {
		result[k] = v
	})
	return result
}

func mapIter(m map[string]string) func(func(k string, v string)) error {
	return func(f func(k string, v string)) error {
		for k, v := range m {
			f(k, v)
		}
		return nil
	}
}

func TestDeltaTracker_GetDesired(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	// Empty dataplane, set followed by get should return what we just set!
	dt.Desired().Set("1", "A1")
	if v, ok := dt.Desired().Get("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key that we just set")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value: %q", v)
	}
	Expect(dt.Desired().Len()).To(Equal(1))

	// Delete it again.  Should no longer be returned.
	dt.Desired().Delete("1")
	if _, ok := dt.Desired().Get("1"); ok {
		t.Fatal("Delete had no effect?")
	}
	Expect(dt.Desired().Len()).To(Equal(0))

	// Recreate, so we can test adding the value to the dataplane.
	dt.Desired().Set("1", "A1")
	if v, ok := dt.Desired().Get("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key that we just set")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value: %q", v)
	}
	Expect(dt.Desired().Len()).To(Equal(1))

	// Adding to the dataplane shouldn't affect the desired state.
	dt.Dataplane().Set("1", "A1")
	if v, ok := dt.Desired().Get("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key once it was also in DP")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value once it was also in DP: %q", v)
	}
	Expect(dt.Desired().Len()).To(Equal(1))

	// Delete the desired while the value is in the dataplane.  Again, should be independent
	// of whether it's in the dataplane.
	dt.Desired().Delete("1")
	if _, ok := dt.Desired().Get("1"); ok {
		t.Fatal("Delete had no effect?")
	}
	Expect(dt.Desired().Len()).To(Equal(0))

	// Recreate the desired key while it is in the dataplane.
	dt.Desired().Set("1", "A1")
	if v, ok := dt.Desired().Get("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key that we just recreated")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value: %q", v)
	}
	Expect(dt.Desired().Len()).To(Equal(1))

	// Delete from dataplane while the key is in the desired map, should not impact desired.
	dt.Dataplane().Delete("1")
	if v, ok := dt.Desired().Get("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired after deleting from DP")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value after deleting from DP: %q", v)
	}
	Expect(dt.Desired().Len()).To(Equal(1))

	// Adding a different value to the dataplane shouldn't affect desired.
	dt.Dataplane().Set("1", "A2")
	if v, ok := dt.Desired().Get("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key with different value in DP")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value with different value in DP: %q", v)
	}

	// Delete it again.
	dt.Desired().Delete("1")
	if _, ok := dt.Desired().Get("1"); ok {
		t.Fatal("Delete had no effect?")
	}
	if v, ok := dt.Dataplane().Get("1"); !ok {
		t.Fatal("Delete removed dataplane key")
	} else if v != "A2" {
		t.Fatal("Delete changed dataplane key")
	}
	Expect(dt.Desired().Len()).To(Equal(0))

	// Recreate while there's a different dataplane key...
	dt.Desired().Set("1", "A1")
	if v, ok := dt.Desired().Get("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key that we just recreated")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value: %q", v)
	}
	Expect(dt.Desired().Len()).To(Equal(1))
}

func TestDeltaTracker_DesiredDeleteAll(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dt.Desired().Set("1", "A1") // Same value for existing key.
	dt.Desired().Set("2", "B1") // New value for existing key.
	dt.Desired().Set("4", "D1") // New K/V
	Expect(dt.Desired().Len()).To(Equal(3))
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(BeEmpty())

	dt.Desired().DeleteAll()
	Expect(dt.Desired().Len()).To(Equal(0))

	Expect(pendingUpdates(dt, IterActionNoOp)).To(BeEmpty())
	Expect(pendingDeletions(dt, IterActionNoOp)).To(BeEmpty())
}

func ExampleDeltaTracker_resync() {
	dt := New[string, int](WithValuesEqualFn[string, int](func(a, b int) bool {
		return a == b // ints support simple comparison.
	}))

	// Set up our desired state.
	desired := map[string]int{
		"one": 1,
		"two": 2,
	}
	for k, v := range desired {
		dt.Desired().Set(k, v)
	}
	fmt.Printf("Desired state: %v\n", desired)

	// Resync with the dataplane
	mockDataplane := map[string]int{
		"one":   1,
		"three": 3,
	}
	fmt.Printf("Initial dataplane state: %v\n", mockDataplane)
	_ = dt.Dataplane().ReplaceAllIter(func(f func(k string, v int)) error {
		// Replace this with the actual dataplane loading logic.
		for k, v := range mockDataplane {
			f(k, v)
		}
		return nil
	})

	// Check the deltas.
	dt.PendingUpdates().Iter(func(k string, v int) IterAction {
		fmt.Printf("Applying pending update: %s = %v\n", k, v)
		mockDataplane[k] = v
		// Tell the tracker that we updated the dataplane.
		return IterActionUpdateDataplane
	})

	dt.PendingDeletions().Iter(func(k string) IterAction {
		fmt.Printf("Applying pending deletion: %v\n", k)
		delete(mockDataplane, k)
		// Tell the tracker that we updated the dataplane.
		return IterActionUpdateDataplane
	})

	// Dataplane should now be in sync.
	fmt.Printf("Updated dataplane state: %v\n", mockDataplane)

	// Output:
	// Desired state: map[one:1 two:2]
	// Initial dataplane state: map[one:1 three:3]
	// Applying pending update: two = 2
	// Applying pending deletion: three
	// Updated dataplane state: map[one:1 two:2]
}

func TestDeltaTracker_UpdateThenReplaceDataplaneCacheFromIter(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dt.Desired().Set("1", "A1") // Same value for existing key.
	dt.Desired().Set("2", "B1") // New value for existing key.
	dt.Desired().Set("4", "D1") // New K/V
	Expect(dt.Desired().Len()).To(Equal(3))
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(BeEmpty())

	// Do a successful resync.
	dpContents := map[string]string{
		"1": "A1",
		"2": "B2",
		"3": "C1",
	}
	dt.Dataplane().ReplaceAllMap(dpContents)
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	// Do a second one but this time some keys have been removed. "1" should
	// move to the pending updates and "3" should disappear from the deletions.
	dpContents = map[string]string{
		"2": "B2",
		"5": "E1",
	}
	dt.Dataplane().ReplaceAllMap(dpContents)
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"5": "E1",
	}))
	Expect(dt.Desired().Len()).To(Equal(3))
}

func TestDeltaTracker_DataplaneDeleteAll(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	// Start with some data in both maps.
	dpContents := map[string]string{
		"1": "A1",
		"2": "B2",
		"3": "C1",
	}
	dt.Dataplane().ReplaceAllMap(dpContents)
	Expect(dt.Dataplane().Len()).To(Equal(3))
	dt.Desired().Set("1", "A1") // Same value for existing key.
	dt.Desired().Set("2", "B1") // New value for existing key.
	dt.Desired().Set("4", "D1") // New K/V
	Expect(dt.Desired().Len()).To(Equal(3))
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"2": "B1",
		"4": "D1",
	}))
	Expect(dt.PendingUpdates().Len()).To(Equal(2))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))
	Expect(dt.PendingDeletions().Len()).To(Equal(1))

	// DeleteAll...
	dt.Dataplane().DeleteAll()
	Expect(dt.Dataplane().Len()).To(Equal(0))
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(BeEmpty())
	Expect(dt.Desired().Len()).To(Equal(3))
}

func TestDeltaTracker_ReplaceDataplaneCacheFromIterThenUpdate(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dpContents := map[string]string{
		"1": "A1",
		"2": "B2",
		"3": "C1",
	}
	err := dt.Dataplane().ReplaceAllIter(mapIter(dpContents))
	Expect(err).NotTo(HaveOccurred())

	dt.Desired().Set("1", "A1") // Same value for existing key.
	dt.Desired().Set("2", "B1") // New value for existing key.
	dt.Desired().Set("4", "D1") // New K/V
	Expect(dt.Desired().Len()).To(Equal(3))

	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	// Make expected updates to dataplane, should update the pending sets accordingly.
	dt.Dataplane().Set("2", "B1")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	dt.Dataplane().Set("4", "D1")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(BeEmpty())
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	dt.Dataplane().Delete("3")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(BeEmpty())
	Expect(pendingDeletions(dt, IterActionNoOp)).To(BeEmpty())

	// Disrupt a desired key, add a key that shouldn't be there.
	dt.Dataplane().Set("1", "A2")
	dt.Dataplane().Set("3", "C3")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C3",
	}))

	// Delete a key that was in sync.
	dt.Dataplane().Delete("2")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C3",
	}))
	Expect(dt.Desired().Len()).To(Equal(3))
}

func TestDeltaTracker_IterPendingActions(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dt.Desired().Set("1", "A1") // Same value for existing key.
	dt.Desired().Set("2", "B1") // New value for existing key.
	dt.Desired().Set("4", "D1") // New K/V
	Expect(dt.Desired().Len()).To(Equal(3))
	dpContents := map[string]string{
		"1": "A1",
		"2": "B2",
		"3": "C1",
	}
	err := dt.Dataplane().ReplaceAllIter(mapIter(dpContents))
	Expect(err).NotTo(HaveOccurred())

	// Loop to check IterActionNoOp really is a no-op
	for i := 0; i < 2; i++ {
		Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
			"2": "B1",
			"4": "D1",
		}))
		Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
			"3": "C1",
		}))
		Expect(allDataplane(dt)).To(Equal(dpContents))
	}

	// Return IterActionUpdateDataplane, pending ops should go away.
	Expect(pendingUpdates(dt, IterActionUpdateDataplane)).To(Equal(map[string]string{
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionUpdateDataplane)).To(Equal(map[string]string{
		"3": "C1",
	}))
	Expect(pendingUpdates(dt, IterActionNoOp)).To(BeEmpty())
	Expect(pendingDeletions(dt, IterActionNoOp)).To(BeEmpty())

	// Dataplane should be updated, desired should be correct.
	Expect(allDataplane(dt)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(allDesired(dt)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(dt.Desired().Len()).To(Equal(3))
}

// TestDeltaTracker_ReplaceDataplaneCacheFromIterErrors tests error handling of
// ReplaceAllIter.
func TestDeltaTracker_ReplaceDataplaneCacheFromIterErrors(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	// Set up our usual 3 keys...
	dt.Desired().Set("1", "A1") // Same value for existing key.
	dt.Desired().Set("2", "B1") // New value for existing key.
	dt.Desired().Set("4", "D1") // New K/V
	Expect(dt.Desired().Len()).To(Equal(3))

	// Do a dataplane resync but fail after 2 keys have been produced.
	err := dt.Dataplane().ReplaceAllIter(func(f func(k string, v string)) error {
		f("3", "C1")
		f("2", "B2")
		return fmt.Errorf("dummy error")
	})
	Expect(err).To(HaveOccurred(), "ReplaceAllIter should propagate errors")

	Expect(allDesired(dt)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}), "Error during resync shouldn't corrupt desired KVs")
	Expect(allDataplane(dt)).To(Equal(map[string]string{
		"3": "C1",
		"2": "B2",
	}), "Keys seen during resync should be recorded.")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	// Do another failed resync but this time we emit a key that matches the desired
	// and one that is in the pending deletions.
	err = dt.Dataplane().ReplaceAllIter(func(f func(k string, v string)) error {
		f("1", "A1")
		f("3", "C1")
		return fmt.Errorf("dummy error")
	})
	Expect(err).To(HaveOccurred(), "ReplaceAllIter should propagate errors")
	Expect(allDesired(dt)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}), "Error during resync shouldn't corrupt desired KVs")
	Expect(allDataplane(dt)).To(Equal(map[string]string{
		"1": "A1",
		"3": "C1",
		"2": "B2",
	}), "Keys seen during resync should be recorded.")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	// Do a successful resync.
	dpContents := map[string]string{
		"1": "A1",
		"2": "B2",
		"3": "C1",
	}
	err = dt.Dataplane().ReplaceAllIter(mapIter(dpContents))
	Expect(err).NotTo(HaveOccurred())
	Expect(allDesired(dt)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}), "Resync shouldn't corrupt desired KVs")
	Expect(allDataplane(dt)).To(Equal(map[string]string{
		"1": "A1",
		"3": "C1",
		"2": "B2",
	}), "Keys seen during resync should be recorded.")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))
	Expect(dt.Desired().Len()).To(Equal(3))
}

func TestDeltaTracker_IterDesired(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dt.Desired().Set("1", "A1") // Same value for existing key.
	dt.Desired().Set("2", "B1") // New value for existing key.
	dt.Desired().Set("4", "D1") // New K/V
	Expect(allDesired(dt)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))

	dpContents := map[string]string{
		"1": "A1",
		"2": "B2",
		"3": "C1",
	}
	err := dt.Dataplane().ReplaceAllIter(mapIter(dpContents))
	Expect(err).NotTo(HaveOccurred())

	Expect(allDesired(dt)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}), "Refreshing dataplane shouldn't affect desired values")
}

func setupDeltaTrackerTest(t *testing.T) *DeltaTracker[string, string] {
	RegisterTestingT(t)

	dt := New[string, string]()

	return dt
}
