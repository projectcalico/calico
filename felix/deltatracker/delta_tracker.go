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
	"reflect"

	"github.com/sirupsen/logrus"
)

// DeltaTracker (conceptually) tracks the differences between two key/value maps
// the "desired" map contains the KV-pairs that we _want_ to be in the
// dataplane; the "dataplane" map contains the KV-pairs that we think are
// _actually_ in the dataplane. The name "dataplane" map is intended to hint at
// its use but(!) this is a pure in-memory datastructure; it doesn't actually
// interact with the dataplane directly.
//
// The desired and dataplane maps are exposed via the Desired() and Dataplane()
// methods, which each return a similar map API featuring Set(...) Get(...)
// Delete() and Iter(...). The dataplane map view has an additional
// ReplaceAllIter method, which allows for the whole contents of the
// dataplane map to be replaced via an iterator; this is more efficient than
// doing an external iteration and Set/Delete calls.
//
// In addition to the desired and dataplane maps, the differences between them
// are continuously tracked in two other maps: the "pending updates" map and
// the "pending deletions" map. "Pending updates" contains all keys that are
// in the "desired" map but not in the dataplane map (or that have a different
// value in the desired map vs the dataplane map). "Pending deletions" contains
// keys that are in the dataplane map but not in the desired map.  The
// pending maps are exposed via the IterPendingUpdates and IterPendingDeletions
// methods.
//
// Note: it is not safe to mutate keys/values that are stored in a DeltaTracker
// because it would corrupt the internal state. Surprisingly(!), it is also
// unsafe to delete a key, modify the value and then re-insert the value!  This
// is because (as an occupancy optimisation) the DeltaTracker aliases the
// Desired and Dataplane values if they happen to be equal.  So, to safely
// mutate a value, you must take a copy, mutate the copy and re-insert the
// copy.
type DeltaTracker[K comparable, V any] struct {
	// To reduce occupancy, we treat the set of KVs in the dataplane and in the
	// desired state like a Venn diagram, and we only store each region once
	// (with the caveat below[1]).
	//
	//   Desired        In-dataplane
	//         ____   ____
	//        /    \ /    \
	//       /      X      \
	//      /      / \      \
	//      |   o | o |   o---- inDataplaneNotDesired
	//      \   |  \ X      /
	//       \  |   X \    /
	//        \_|__/ \_\__/
	//         /        \
	//   desiredUpdates  inDataplaneAndDesired
	//
	// We can then reconstruct the desired and dataplane states as follows:
	//
	//    desired state             = inDataplaneAndDesired + desiredUpdates
	//    actual state of dataplane = inDataplaneAndDesired + inDataplaneNotDesired
	//
	// When we're told about an update to the dataplane (for example during a resync),
	// we may need to shuffle KVs between the different sets.
	//
	// [1] A key can only appear in one of the inDataplaneXXX maps at a time.
	// However, the desiredUpdates map may contain a key that also exists in one
	// of the other maps if and only if the value in desiredUpdates differs from
	// that in the other map.  This means that the KV is in the dataplane, but it
	// has the wrong value, and it needs to be updated.

	inDataplaneAndDesired map[K]V
	inDataplaneNotDesired map[K]V
	desiredUpdates        map[K]V

	desiredLen int

	// valuesEqual is the comparison function for the value type, it defaults to
	// reflect.DeepEqual.
	valuesEqual func(a, b V) bool
	logCtx      *logrus.Entry
}

type Option[K comparable, V any] func(tracker *DeltaTracker[K, V])

func WithValuesEqualFn[K comparable, V any](f func(a, b V) bool) Option[K, V] {
	return func(tracker *DeltaTracker[K, V]) {
		tracker.valuesEqual = f
	}
}
func WithLogCtx[K comparable, V any](lc *logrus.Entry) Option[K, V] {
	return func(tracker *DeltaTracker[K, V]) {
		tracker.logCtx = lc
	}
}

func New[K comparable, V any](opts ...Option[K, V]) *DeltaTracker[K, V] {
	var valueZero V
	valType := reflect.TypeOf(valueZero)
	if valType != nil && valType.Kind() == reflect.Map {
		// Storing a map as the value is particularly confusing.  Even if
		// the caller does Desired().Delete(k) to remove the mapping, we may
		// keep hold of the same map in the inDataplaneNotDesired map resulting
		// in aliasing.
		logrus.Panic("Map values should not be used in a DeltaTracker.")
	}
	cm := &DeltaTracker[K, V]{
		inDataplaneAndDesired: make(map[K]V),
		inDataplaneNotDesired: make(map[K]V),
		desiredUpdates:        make(map[K]V),
		valuesEqual:           func(a, b V) bool { return reflect.DeepEqual(a, b) },
		logCtx:                logrus.WithFields(nil),
	}
	for _, o := range opts {
		o(cm)
	}
	return cm
}

type DesiredView[K comparable, V any] DeltaTracker[K, V]

func (c *DeltaTracker[K, V]) Desired() *DesiredView[K, V] {
	return (*DesiredView[K, V])(c)
}

// Set sets the desired state of the given key to the given value. If the value differs from what
// the dataplane cache records as being in the dataplane, the update is added to the pending updates set.
// Removes the key from the pending deletions set.
func (c *DesiredView[K, V]) Set(k K, v V) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		c.logCtx.WithFields(logrus.Fields{"k": k, "v": v}).Debug("Set")
	}

	currentVal, presentInDP := c.inDataplaneNotDesired[k]
	if presentInDP {
		// Key was present in dataplane, but, previously it wasn't desired; move the dataplane KV from
		// the "not desired" map to the "desired map".
		c.inDataplaneAndDesired[k] = currentVal
		delete(c.inDataplaneNotDesired, k)
		c.desiredLen++
	} else {
		// Didn't find the key in the "not-desired" map, check the "desired" map.
		currentVal, presentInDP = c.inDataplaneAndDesired[k]
	}

	// Check if we think we need to update the dataplane as a result.
	if !presentInDP {
		if _, presentInDesired := c.desiredUpdates[k]; !presentInDesired {
			// New key, increment our count.
			c.desiredLen++
		}
	} else if c.valuesEqual(currentVal, v) {
		// Dataplane already agrees with the new value so clear any pending update.
		c.logCtx.Debug("Set: Key in dataplane already, ignoring.")
		delete(c.desiredUpdates, k)
		return
	}

	// Either key is not in the dataplane, or the value associated with it is not as desired.
	// Queue up an update.
	c.desiredUpdates[k] = v
}

// Get gets a single value from the desired map.
func (c *DesiredView[K, V]) Get(k K) (V, bool) {
	if v, ok := c.desiredUpdates[k]; ok {
		return v, ok
	}
	v, ok := c.inDataplaneAndDesired[k]
	return v, ok
}

// Delete deletes the given key from the desired state of the dataplane. If the KV is in the dataplane
// cache, it is added to the pending deletions set.  Removes the key from the pending updates set.
func (c *DesiredView[K, V]) Delete(k K) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		c.logCtx.WithFields(logrus.Fields{"k": k}).Debug("Delete (desired)")
	}
	_, presentInDesired := c.desiredUpdates[k]
	if presentInDesired {
		// Key was present.
		delete(c.desiredUpdates, k)
	}

	// Check if we need to update the dataplane.
	currentVal, presentInDPDesired := c.inDataplaneAndDesired[k]
	if presentInDPDesired {
		// Value is in dataplane, move it to pending deletions.
		c.inDataplaneNotDesired[k] = currentVal
		delete(c.inDataplaneAndDesired, k)
	}

	if presentInDesired || presentInDPDesired {
		// Key was present, decrement the count.
		c.desiredLen--
	}
}

// DeleteAll deletes all entries from the in-memory desired state, updating pending updates/deletions
// accordingly.
func (c *DesiredView[K, V]) DeleteAll() {
	c.logCtx.Debug("DeleteAll")
	c.Iter(func(k K, v V) {
		c.Delete(k)
	})
}

// Iter iterates over the desired KVs.
func (c *DesiredView[K, V]) Iter(f func(k K, v V)) {
	for k, v := range c.desiredUpdates {
		f(k, v)
	}
	for k, v := range c.inDataplaneAndDesired {
		if _, ok := c.desiredUpdates[k]; ok {
			continue
		}
		f(k, v)
	}
}

func (c *DesiredView[K, V]) Len() int {
	return c.desiredLen
}

type DataplaneView[K comparable, V any] DeltaTracker[K, V]

func (c *DeltaTracker[K, V]) Dataplane() *DataplaneView[K, V] {
	return (*DataplaneView[K, V])(c)
}

// ReplaceAllMap replaces the state of the dataplane map with the KVs from
// dpKVs; the input map is not modified or retained.  The pending update and deletion
// tracking is updated accordingly.
func (c *DataplaneView[K, V]) ReplaceAllMap(dpKVs map[K]V) {
	err := c.ReplaceAllIter(func(f func(k K, v V)) error {
		for k, v := range dpKVs {
			f(k, v)
		}
		return nil
	})
	if err != nil {
		// Should be impossible to hit because ReplaceAllIter only returns errors
		// from the iterator.
		c.logCtx.WithError(err).Panic("Unexpected error from ReplaceAllIter")
	}
}

// ReplaceAllIter clears the dataplane cache and replaces its contents with the KVs returned
// by the iterator.  The pending update and deletion tracking is updated accordingly.
//
// Only returns an error if the iterator returns an error.  In case of error, the dataplane state is
// partially updated with the keys that have already been seen.
func (c *DataplaneView[K, V]) ReplaceAllIter(iter func(func(k K, v V)) error) error {
	c.logCtx.Debug("Loading cache of dataplane state.")

	// To reduce occupancy and to do the update in one pass, we use the old maps as scratch space.
	// As we iterate over the new values, we add them to the newXXX maps and delete them from the old.
	// Then, at the end, the oldXXX maps will contain only the values that are now missing from the
	// dataplane, we then handle those at the bottom.
	oldInDPDesired := c.inDataplaneAndDesired
	newInDPDesired := make(map[K]V)
	oldInDPNotDesired := c.inDataplaneNotDesired
	newInDPNotDesired := make(map[K]V)

	err := iter(func(k K, v V) {
		// Figure out if we _want_ it to exist and tee up update/deletion accordingly.
		if desiredV, desired := c.asDesiredView().Get(k); desired {
			// Record that this key exists in the new copy of the cache.
			newInDPDesired[k] = v

			// Check if the value is correct,
			if c.valuesEqual(desiredV, v) {
				// Value in dataplane is correct, clean up any pending update.
				delete(c.desiredUpdates, k)
			} else {
				// Value in dataplane is incorrect.  Queue up an update (if there isn't one already).
				c.desiredUpdates[k] = desiredV
			}
		} else {
			// We don't want this key, but it's in the dataplane.  Queue up deletion.
			newInDPNotDesired[k] = v
		}

		// Remove the key from the old cache, we'll then scan the old cache to find keys that are missing.
		delete(oldInDPDesired, k)
		delete(oldInDPNotDesired, k)
	})
	if err != nil {
		// We may have failed mid-iteration, if we just returned an error here, we'd leave our internal
		// state broken because we've removed all the keys that we've seen from oldInDPDesired and
		// oldInDPNotDesired, and updated c.desiredUpdates to match the new KV's from the iterator.
		// Fix that up by applying the new keys to the old in-DP maps:
		for k, v := range newInDPDesired {
			oldInDPDesired[k] = v
		}
		for k, v := range newInDPNotDesired {
			oldInDPNotDesired[k] = v
		}
		return fmt.Errorf("failed to iterate over dataplane state: %w", err)
	}

	// oldInDPDesired now only contains KVs that we _thought_ were in the dataplane but are now gone.
	for k := range oldInDPDesired {
		if desiredV, desired := c.asDesiredView().Get(k); desired {
			// We want this key, but it's missing, queue up an add.
			c.desiredUpdates[k] = desiredV
		} // else we don't want it, and it's gone; nothing to do.
		delete(oldInDPDesired, k)
	}

	// Now done with oldInDPDesired, replace it.
	c.inDataplaneAndDesired = newInDPDesired
	c.inDataplaneNotDesired = newInDPNotDesired
	c.logCtx.WithFields(logrus.Fields{
		"totalInDataplane":        len(c.inDataplaneAndDesired) + len(c.inDataplaneNotDesired),
		"pendingCreatesOrUpdates": len(c.desiredUpdates),
		"pendingDeletions":        len(c.inDataplaneNotDesired),
	}).Debug("Updated dataplane state.")

	return nil
}

// Set updates a key in the dataplane cache.  I.e. it tells this tracker that the dataplane
// has the given KV.  Updated the pending update/deletion set if the new KV differs from what is
// desired.
func (c *DataplaneView[K, V]) Set(k K, v V) {
	desiredV, desired := c.asDesiredView().Get(k)
	if desired {
		// Dataplane key has a corresponding desired key.  Check if the values match.
		c.inDataplaneAndDesired[k] = v
		if !c.valuesEqual(desiredV, v) {
			// Desired value is different, queue up an update.
			c.desiredUpdates[k] = desiredV
		} else {
			delete(c.desiredUpdates, k)
		}
	} else {
		// Dataplane key has no corresponding desired key, queue up a deletion.
		c.inDataplaneNotDesired[k] = v
	}
}

// Delete deletes a key from the dataplane cache.  I.e. it tells this tracker that the key
// no longer exists in the dataplane.
func (c *DataplaneView[K, V]) Delete(k K) {
	desiredV, desired := c.asDesiredView().Get(k)
	delete(c.inDataplaneAndDesired, k)
	delete(c.inDataplaneNotDesired, k)
	if desired {
		// We've now been told this KV is not in the dataplane but the desired state says it should be there.
		c.desiredUpdates[k] = desiredV
	}
}

func (c *DataplaneView[K, V]) DeleteAll() {
	c.ReplaceAllMap(nil)
}

// Iter iterates over the cache of the dataplane.
func (c *DataplaneView[K, V]) Iter(f func(k K, v V)) {
	for k, v := range c.inDataplaneAndDesired {
		f(k, v)
	}
	for k, v := range c.inDataplaneNotDesired {
		f(k, v)
	}
}

func (c *DataplaneView[K, V]) Len() int {
	return len(c.inDataplaneNotDesired) + len(c.inDataplaneAndDesired)
}

// Get gets a single value from the cache of the dataplane. The cache must have previously been
// loaded with a successful call to LoadCacheFromDataplane() or one of the ApplyXXX methods.
func (c *DataplaneView[K, V]) Get(k K) (V, bool) {
	v, ok := c.inDataplaneAndDesired[k]
	if !ok {
		v, ok = c.inDataplaneNotDesired[k]
	}
	return v, ok
}

func (c *DataplaneView[K, V]) asDesiredView() *DesiredView[K, V] {
	return (*DesiredView[K, V])(c)
}

type IterAction int

const (
	IterActionNoOp IterAction = iota
	IterActionUpdateDataplane
	IterActionNoOpStopIteration
)

type PendingUpdatesView[K comparable, V any] DeltaTracker[K, V]

func (c *DeltaTracker[K, V]) PendingUpdates() *PendingUpdatesView[K, V] {
	return (*PendingUpdatesView[K, V])(c)
}

func (c *PendingUpdatesView[K, V]) Get(k K) (V, bool) {
	v, ok := c.desiredUpdates[k]
	return v, ok
}

// Iter iterates over the pending updates. If the passed in function returns
// IterActionUpdateDataplane then the pending update is cleared, and, the KV is applied
// to the dataplane cache (as if the function had called Dataplane().Set(k, v)).
func (c *PendingUpdatesView[K, V]) Iter(f func(k K, v V) IterAction) {
	for k, v := range c.desiredUpdates {
		updateDataplane := f(k, v)
		switch updateDataplane {
		case IterActionNoOp:
			// Ignore.
		case IterActionUpdateDataplane:
			delete(c.desiredUpdates, k)
			c.inDataplaneAndDesired[k] = v
		case IterActionNoOpStopIteration:
			break
		}
	}
}

func (c *PendingUpdatesView[K, V]) Len() int {
	return len(c.desiredUpdates)
}

func (c *DeltaTracker[K, V]) InSync() bool {
	return c.PendingDeletions().Len() == 0 && c.PendingUpdates().Len() == 0
}

type PendingDeletionsView[K comparable, V any] DeltaTracker[K, V]

func (c *DeltaTracker[K, V]) PendingDeletions() *PendingDeletionsView[K, V] {
	return (*PendingDeletionsView[K, V])(c)
}

func (c *PendingDeletionsView[K, V]) Get(k K) (V, bool) {
	v, ok := c.inDataplaneNotDesired[k]
	return v, ok
}

// Iter iterates over the pending deletion set. If the passed in function returns
// IterActionUpdateDataplane then the pending deletion is cleared, and, the KV is applied
// to the dataplane cache (as if the function had called Dataplane().Delete(k)).
func (c *PendingDeletionsView[K, V]) Iter(f func(k K) IterAction) {
	for k := range c.inDataplaneNotDesired {
		updateDataplane := f(k)
		switch updateDataplane {
		case IterActionNoOp:
			// Ignore.
		case IterActionUpdateDataplane:
			delete(c.inDataplaneNotDesired, k)
		case IterActionNoOpStopIteration:
			break
		}
	}
}

func (c *PendingDeletionsView[K, V]) Len() int {
	return len(c.inDataplaneNotDesired)
}
