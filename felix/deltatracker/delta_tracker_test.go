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

	log "github.com/sirupsen/logrus"

	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/logutils"
)

func init() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)
}

// TestDeltaTracker_Empty verifies loading of an empty map with no changes queued.
func TestDeltaTracker_Empty(t *testing.T) {
	dt := setupDeltaTrackerTest(t)
	dt.IterDesired(func(k string, v string) {
		t.Errorf("IterDesired unexpectedly called func with %v, %v", k, v)
	})
	dt.IterDataplane(func(k string, v string) {
		t.Errorf("IterDesired unexpectedly called func with %v, %v", k, v)
	})
	dt.IterPendingUpdates(func(k string, v string) IterAction {
		t.Errorf("IterPendingUpdates unexpectedly called func with %v, %v", k, v)
		return IterActionNoOp
	})
	dt.IterPendingDeletions(func(k string) IterAction {
		t.Errorf("IterPendingDeletions unexpectedly called func with %v", k)
		return IterActionNoOp
	})
}

// TestDeltaTracker_CleanUp verifies cleaning up of a whole map.
func TestDeltaTracker_CleanUp(t *testing.T) {
	dt := setupDeltaTrackerTest(t)
	err := dt.ReplaceDataplaneCacheFromIter(mapIter(map[string]string{
		"1": "A1",
		"2": "B1",
	}))
	Expect(err).NotTo(HaveOccurred())
	Expect(pendingUpdates(dt, IterActionNoOp)).To(BeEmpty())
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
	}))
}

func pendingDeletions(dt *DeltaTracker[string, string], action IterAction) map[string]string {
	result := map[string]string{}
	dt.IterPendingDeletions(func(k string) IterAction {
		v, ok := dt.GetDataplane(k)
		if !ok {
			panic(fmt.Sprintf("IterPendingDeletions iterated over key that wasn't returned by GetDataplane: %v", k))
		}
		result[k] = v
		return action
	})
	return result
}

func pendingUpdates(dt *DeltaTracker[string, string], action IterAction) map[string]string {
	result := map[string]string{}
	dt.IterPendingUpdates(func(k string, v string) IterAction {
		result[k] = v
		return action
	})
	return result
}

func allDesired(dt *DeltaTracker[string, string]) map[string]string {
	result := map[string]string{}
	dt.IterDesired(func(k string, v string) {
		result[k] = v
	})
	return result
}

func allDataplane(dt *DeltaTracker[string, string]) map[string]string {
	result := map[string]string{}
	dt.IterDataplane(func(k string, v string) {
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
	dt.SetDesired("1", "A1")
	if v, ok := dt.GetDesired("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key that we just set")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value: %q", v)
	}

	// Delete it again.
	dt.DeleteDesired("1")
	if _, ok := dt.GetDesired("1"); ok {
		t.Fatal("DeleteDesired had no effect?")
	}

	// Recreate...
	dt.SetDesired("1", "A1")
	if v, ok := dt.GetDesired("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key that we just set")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value: %q", v)
	}

	// Make sure we get the desired value even if the key is also in the dataplane.
	dt.SetDataplane("1", "A1")
	if v, ok := dt.GetDesired("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key once it was also in DP")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value once it was also in DP: %q", v)
	}

	// Delete it again.
	dt.DeleteDesired("1")
	if _, ok := dt.GetDesired("1"); ok {
		t.Fatal("DeleteDesired had no effect?")
	}

	// Recreate...
	dt.SetDesired("1", "A1")
	if v, ok := dt.GetDesired("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key that we just recreated")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value: %q", v)
	}

	// Make sure we still get the value even if it agrees with dataplane.
	dt.SetDataplane("1", "A1")
	if v, ok := dt.GetDesired("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key once it matched in DP")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value once it matched in DP: %q", v)
	}

	// Delete it again.
	dt.DeleteDesired("1")
	if _, ok := dt.GetDesired("1"); ok {
		t.Fatal("DeleteDesired had no effect?")
	}

	// Recreate...
	dt.SetDesired("1", "A1")
	if v, ok := dt.GetDesired("1"); !ok {
		t.Errorf("DeltaTracker failed to get desired key that we just recreated")
	} else if v != "A1" {
		t.Errorf("DeltaTracker returned incorrect value: %q", v)
	}
}

func TestDeltaTracker_DeleteAll(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dt.SetDesired("1", "A1") // Same value for existing key.
	dt.SetDesired("2", "B1") // New value for existing key.
	dt.SetDesired("4", "D1") // New K/V
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(BeEmpty())

	dt.DeleteAllDesired()

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
		dt.SetDesired(k, v)
	}
	fmt.Printf("Desired state: %v\n", desired)

	// Resync with the dataplane
	mockDataplane := map[string]int{
		"one":   1,
		"three": 3,
	}
	fmt.Printf("Initial dataplane state: %v\n", mockDataplane)
	_ = dt.ReplaceDataplaneCacheFromIter(func(f func(k string, v int)) error {
		// Replace this with the actual dataplane loading logic.
		for k, v := range mockDataplane {
			f(k, v)
		}
		return nil
	})

	// Check the deltas.
	dt.IterPendingUpdates(func(k string, v int) IterAction {
		fmt.Printf("Applying pending update: %s = %v\n", k, v)
		mockDataplane[k] = v
		// Tell the tracker that we updated the dataplane.
		return IterActionUpdateDataplane
	})

	dt.IterPendingDeletions(func(k string) IterAction {
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

	dt.SetDesired("1", "A1") // Same value for existing key.
	dt.SetDesired("2", "B1") // New value for existing key.
	dt.SetDesired("4", "D1") // New K/V
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
	err := dt.ReplaceDataplaneCacheFromIter(mapIter(dpContents))
	Expect(err).NotTo(HaveOccurred())
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
	err = dt.ReplaceDataplaneCacheFromIter(mapIter(dpContents))
	Expect(err).NotTo(HaveOccurred())
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"5": "E1",
	}))
}

func TestDeltaTracker_ReplaceDataplaneCacheFromIterThenUpdate(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dpContents := map[string]string{
		"1": "A1",
		"2": "B2",
		"3": "C1",
	}
	err := dt.ReplaceDataplaneCacheFromIter(mapIter(dpContents))
	Expect(err).NotTo(HaveOccurred())

	dt.SetDesired("1", "A1") // Same value for existing key.
	dt.SetDesired("2", "B1") // New value for existing key.
	dt.SetDesired("4", "D1") // New K/V

	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"2": "B1",
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	// Make expected updates to dataplane, should update the pending sets accordingly.
	dt.SetDataplane("2", "B1")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"4": "D1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	dt.SetDataplane("4", "D1")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(BeEmpty())
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C1",
	}))

	dt.DeleteDataplane("3")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(BeEmpty())
	Expect(pendingDeletions(dt, IterActionNoOp)).To(BeEmpty())

	// Disrupt a desired key, add a key that shouldn't be there.
	dt.SetDataplane("1", "A2")
	dt.SetDataplane("3", "C3")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C3",
	}))

	// Delete a key that was in sync.
	dt.DeleteDataplane("2")
	Expect(pendingUpdates(dt, IterActionNoOp)).To(Equal(map[string]string{
		"1": "A1",
		"2": "B1",
	}))
	Expect(pendingDeletions(dt, IterActionNoOp)).To(Equal(map[string]string{
		"3": "C3",
	}))
}

func TestDeltaTracker_IterPendingActions(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dt.SetDesired("1", "A1") // Same value for existing key.
	dt.SetDesired("2", "B1") // New value for existing key.
	dt.SetDesired("4", "D1") // New K/V
	dpContents := map[string]string{
		"1": "A1",
		"2": "B2",
		"3": "C1",
	}
	err := dt.ReplaceDataplaneCacheFromIter(mapIter(dpContents))
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
}

// TestDeltaTracker_ReplaceDataplaneCacheFromIterErrors tests error handling of
// ReplaceDataplaneCacheFromIter.
func TestDeltaTracker_ReplaceDataplaneCacheFromIterErrors(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	// Set up our usual 3 keys...
	dt.SetDesired("1", "A1") // Same value for existing key.
	dt.SetDesired("2", "B1") // New value for existing key.
	dt.SetDesired("4", "D1") // New K/V

	// Do a dataplane resync but fail after 2 keys have been produced.
	err := dt.ReplaceDataplaneCacheFromIter(func(f func(k string, v string)) error {
		f("3", "C1")
		f("2", "B2")
		return fmt.Errorf("dummy error")
	})
	Expect(err).To(HaveOccurred(), "ReplaceDataplaneCacheFromIter should propagate errors")

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
	err = dt.ReplaceDataplaneCacheFromIter(func(f func(k string, v string)) error {
		f("1", "A1")
		f("3", "C1")
		return fmt.Errorf("dummy error")
	})
	Expect(err).To(HaveOccurred(), "ReplaceDataplaneCacheFromIter should propagate errors")
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
	err = dt.ReplaceDataplaneCacheFromIter(mapIter(dpContents))
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
}

func TestDeltaTracker_IterDesired(t *testing.T) {
	dt := setupDeltaTrackerTest(t)

	dt.SetDesired("1", "A1") // Same value for existing key.
	dt.SetDesired("2", "B1") // New value for existing key.
	dt.SetDesired("4", "D1") // New K/V
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
	err := dt.ReplaceDataplaneCacheFromIter(mapIter(dpContents))
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
