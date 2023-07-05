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

	// valuesEqual is the comparison function for the value type, it defaults to
	// reflect.DeepEqual.
	valuesEqual func(a, b V) bool
}

type Option[K comparable, V any] func(tracker *DeltaTracker[K, V])

func WithValuesEqualFn[K comparable, V any](f func(a, b V) bool) Option[K, V] {
	return func(tracker *DeltaTracker[K, V]) {
		tracker.valuesEqual = f
	}
}

func New[K comparable, V any](opts ...Option[K, V]) *DeltaTracker[K, V] {
	cm := &DeltaTracker[K, V]{
		inDataplaneAndDesired: make(map[K]V),
		inDataplaneNotDesired: make(map[K]V),
		desiredUpdates:        make(map[K]V),
		valuesEqual:           func(a, b V) bool { return reflect.DeepEqual(a, b) },
	}
	for _, o := range opts {
		o(cm)
	}
	return cm
}

// SetDesired sets the desired state of the given key to the given value. If the value differs from what
// the dataplane cache records as being in the dataplane, the update is added ot the pending updates set.
// Removes the key from the pending deletions set.
func (c *DeltaTracker[K, V]) SetDesired(k K, v V) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"k": k, "v": v}).Debug("SetDesired")
	}
	if v, ok := c.inDataplaneNotDesired[k]; ok {
		c.inDataplaneAndDesired[k] = v
	}
	delete(c.inDataplaneNotDesired, k)

	// Check if we think we need to update the dataplane as a result.
	currentVal, ok := c.inDataplaneAndDesired[k]
	if ok && c.valuesEqual(currentVal, v) {
		// Dataplane already agrees with the new value so clear any pending update.
		logrus.Debug("SetDesired: Key in dataplane already, ignoring.")
		delete(c.desiredUpdates, k)
		return
	}
	c.desiredUpdates[k] = v
}

// GetDesired gets a single value from the desired map.
func (c *DeltaTracker[K, V]) GetDesired(k K) (V, bool) {
	if v, ok := c.desiredUpdates[k]; ok {
		return v, ok
	}
	v, ok := c.inDataplaneAndDesired[k]
	return v, ok
}

// DeleteDesired deletes the given key from the desired state of the dataplane. If the KV is in the dataplane
// cache, it is added to the pending deletions set.  Removes the key from the pending updates set.
func (c *DeltaTracker[K, V]) DeleteDesired(k K) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"k": k}).Debug("DeleteDesired")
	}
	delete(c.desiredUpdates, k)

	// Check if we need to update the dataplane.
	if currentVal, ok := c.inDataplaneAndDesired[k]; ok {
		// Value is in dataplane, move it to pending deletions.
		c.inDataplaneNotDesired[k] = currentVal
		delete(c.inDataplaneAndDesired, k)
	}
}

// DeleteAllDesired deletes all entries from the in-memory desired state, updating pending updates/deletions
// accordingly.
func (c *DeltaTracker[K, V]) DeleteAllDesired() {
	logrus.Debug("DeleteAll")
	c.IterDesired(func(k K, v V) {
		c.DeleteDesired(k)
	})
}

// IterDesired iterates over the desired KVs.
func (c *DeltaTracker[K, V]) IterDesired(f func(k K, v V)) {
	for k, v := range c.desiredUpdates {
		f(k, v)
	}
	for k, v := range c.inDataplaneAndDesired {
		if _, ok := c.desiredUpdates[k]; ok {
			continue
		}
		if _, ok := c.inDataplaneNotDesired[k]; ok {
			continue
		}
		f(k, v)
	}
}

// ReplaceDataplaneCacheFromIter clears the dataplane cache and replaces its contents with the KVs returned
// by the iterator.  The pending update and deletion tracking is updated accordingly.
func (c *DeltaTracker[K, V]) ReplaceDataplaneCacheFromIter(iter func(func(k K, v V)) error) error {
	logrus.Debug("Loading cache of dataplane state.")

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
		if desiredV, desired := c.GetDesired(k); desired {
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
		if desiredV, desired := c.GetDesired(k); desired {
			// We want this key, but it's missing, queue up an add.
			c.desiredUpdates[k] = desiredV
		} // else we don't want it, and it's gone; nothing to do.
		delete(oldInDPDesired, k)
	}

	// Now done with oldInDPDesired, replace it.
	c.inDataplaneAndDesired = newInDPDesired
	c.inDataplaneNotDesired = newInDPNotDesired
	logrus.WithFields(logrus.Fields{
		"totalNumInDP":          len(c.inDataplaneAndDesired),
		"desiredUpdates":        len(c.desiredUpdates),
		"inDataplaneNotDesired": len(c.inDataplaneNotDesired),
	}).Debug("Updated dataplane state.")

	return nil
}

// SetDataplane updates a key in the dataplane cache.  I.e. it tells this tracker that the dataplane
// has the given KV.  Updated the pending update/deletion set if the new KV differs from what is
// desired.
func (c *DeltaTracker[K, V]) SetDataplane(k K, v V) {
	desiredV, desired := c.GetDesired(k)
	c.inDataplaneAndDesired[k] = v
	if desired {
		// Dataplane key has a corresponding desired key.  Check if the values match.
		if !c.valuesEqual(desiredV, v) {
			// Desired value is different, queue up an update.
			c.desiredUpdates[k] = desiredV
		}
	} else {
		// Dataplane key has no corresponding desired key, queue up a deletion.
		c.inDataplaneNotDesired[k] = v
	}
}

// DeleteDataplane deletes a key from the dataplane cache.  I.e. it tells this tracker that the key
// no longer exists in the dataplane.
func (c *DeltaTracker[K, V]) DeleteDataplane(k K) {
	desiredV, desired := c.GetDesired(k)
	delete(c.inDataplaneAndDesired, k)
	delete(c.inDataplaneNotDesired, k)
	if desired {
		// We've now been told this KV is not in the dataplane but the desired state says it should be there.
		c.desiredUpdates[k] = desiredV
	}
}

// IterDataplane iterates over the cache of the dataplane.
func (c *DeltaTracker[K, V]) IterDataplane(f func(k K, v V)) {
	for k, v := range c.inDataplaneAndDesired {
		f(k, v)
	}
	for k, v := range c.inDataplaneNotDesired {
		f(k, v)
	}
}

// GetDataplane gets a single value from the cache of the dataplane. The cache must have previously been
// loaded with a successful call to LoadCacheFromDataplane() or one of the ApplyXXX methods.
func (c *DeltaTracker[K, V]) GetDataplane(k K) (V, bool) {
	v, ok := c.inDataplaneAndDesired[k]
	if !ok {
		v, ok = c.inDataplaneNotDesired[k]
	}
	return v, ok
}

type PendingChangeAction int

const (
	PendingChangeActionNoOp PendingChangeAction = iota
	PendingChangeActionUpdateDataplane
)

// IterPendingUpdates iterates over the pending updates. If the passed in function returns
// PendingChangeActionUpdateDataplane then the pending update is cleared, and, the KV is applied
// to the dataplane cache (as if the function had called SetDataplane(k, v)).
func (c *DeltaTracker[K, V]) IterPendingUpdates(f func(k K, v V) PendingChangeAction) {
	for k, v := range c.desiredUpdates {
		updateDataplane := f(k, v)
		switch updateDataplane {
		case PendingChangeActionNoOp:
			// Ignore.
		case PendingChangeActionUpdateDataplane:
			delete(c.desiredUpdates, k)
			c.inDataplaneAndDesired[k] = v
		}
	}
}

// IterPendingDeletions iterates over the pending deletion set. If the passed in function returns
// PendingChangeActionUpdateDataplane then the pending deletion is cleared, and, the KV is applied
// to the dataplane cache (as if the function had called DeleteDataplane(k)).
func (c *DeltaTracker[K, V]) IterPendingDeletions(f func(k K) PendingChangeAction) {
	for k := range c.inDataplaneNotDesired {
		updateDataplane := f(k)
		switch updateDataplane {
		case PendingChangeActionNoOp:
			// Ignore.
		case PendingChangeActionUpdateDataplane:
			delete(c.inDataplaneNotDesired, k)
			delete(c.inDataplaneAndDesired, k)
		}
	}
}
