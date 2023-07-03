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
	// desiredStateOfDataplane stores the complete set of key/value pairs that we _want_ to
	// be in the dataplane.
	//
	// For occupancy's sake we may want to drop this copy and instead maintain the invariant:
	// desiredStateOfDataplane = cacheOfDataplane - pendingDeletions + pendingUpdates.
	desiredStateOfDataplane map[K]V

	cacheOfDataplane map[K]V
	pendingUpdates   map[K]V
	pendingDeletions map[K]V

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
		desiredStateOfDataplane: make(map[K]V),
		cacheOfDataplane:        make(map[K]V),
		pendingUpdates:          make(map[K]V),
		pendingDeletions:        make(map[K]V),
		valuesEqual:             func(a, b V) bool { return reflect.DeepEqual(a, b) },
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
	c.desiredStateOfDataplane[k] = v
	delete(c.pendingDeletions, k)

	// Check if we think we need to update the dataplane as a result.
	currentVal, ok := c.cacheOfDataplane[k]
	if ok && c.valuesEqual(currentVal, v) {
		// Dataplane already agrees with the new value so clear any pending update.
		logrus.Debug("SetDesired: Key in dataplane already, ignoring.")
		delete(c.pendingUpdates, k)
		return
	}
	c.pendingUpdates[k] = v
}

// GetDesired gets a single value from the desired map.
func (c *DeltaTracker[K, V]) GetDesired(k K) (V, bool) {
	v, ok := c.desiredStateOfDataplane[k]
	return v, ok
}

// DeleteDesired deletes the given key from the desired state of the dataplane. If the KV is in the dataplane
// cache, it is added to the pending deletions set.  Removes the key from the pending updates set.
func (c *DeltaTracker[K, V]) DeleteDesired(k K) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"k": k}).Debug("DeleteDesired")
	}
	delete(c.desiredStateOfDataplane, k)
	delete(c.pendingUpdates, k)

	// Check if we need to update the dataplane.
	currentVal, ok := c.cacheOfDataplane[k]
	if !ok {
		// We don't think this value is in the dataplane so clear any pending delete.
		logrus.Debug("DeleteDesired: Key not in dataplane, ignoring.")
		delete(c.pendingDeletions, k)
		return
	}
	c.pendingDeletions[k] = currentVal
}

// DeleteAllDesired deletes all entries from the in-memory desired state, updating pending updates/deletions
// accordingly.
func (c *DeltaTracker[K, V]) DeleteAllDesired() {
	logrus.Debug("DeleteAll")
	for k := range c.desiredStateOfDataplane {
		c.DeleteDesired(k)
	}
}

// IterDesired iterates over the desired KVs.
func (c *DeltaTracker[K, V]) IterDesired(f func(k K, v V)) {
	for k, v := range c.desiredStateOfDataplane {
		f(k, v)
	}
}

// ReplaceDataplaneCacheFromIter clears the dataplane cache and replaces its contents with the KVs returned
// by the iterator.  The pending update and deletion tracking is updated accordingly.
func (c *DeltaTracker[K, V]) ReplaceDataplaneCacheFromIter(iter func(func(k K, v V)) error) error {
	logrus.Debug("Loading cache of dataplane state.")
	c.cacheOfDataplane = make(map[K]V)
	c.pendingUpdates = make(map[K]V)
	c.pendingDeletions = make(map[K]V)
	err := iter(c.SetDataplane)
	if err != nil {
		return fmt.Errorf("failed to iterate over dataplane state: %w", err)
	}

	// Scan for any desired KVs that are missing from the dataplane.
	for k, v := range c.desiredStateOfDataplane {
		// Don't need to consider the case where the key exists, that is covered above.
		if _, ok := c.cacheOfDataplane[k]; !ok {
			c.pendingUpdates[k] = v
		}
	}
	logrus.WithFields(logrus.Fields{
		"totalNumInDP":     len(c.cacheOfDataplane),
		"pendingUpdates":   len(c.pendingUpdates),
		"pendingDeletions": len(c.pendingDeletions),
	}).Debug("Updated dataplane state.")

	return nil
}

// SetDataplane updates a key in the dataplane cache.  I.e. it tells this tracker that the dataplane
// has the given KV.  Updated the pending update/deletion set if the new KV differs from what is
// desired.
func (c *DeltaTracker[K, V]) SetDataplane(k K, v V) {
	c.cacheOfDataplane[k] = v
	if desiredV, ok := c.desiredStateOfDataplane[k]; ok {
		// Dataplane key has a corresponding desired key.  Check if the values match.
		if !c.valuesEqual(desiredV, v) {
			// Desired value is different, queue up an update.
			c.pendingUpdates[k] = desiredV
		}
	} else {
		// Dataplane key has no corresponding desired key, queue up a deletion.
		c.pendingDeletions[k] = v
	}
}

// DeleteDataplane deletes a key from the dataplane cache.  I.e. it tells this tracker that the key
// no longer exists in the dataplane.
func (c *DeltaTracker[K, V]) DeleteDataplane(k K) {
	delete(c.cacheOfDataplane, k)
	delete(c.pendingDeletions, k)
	if desiredV, ok := c.desiredStateOfDataplane[k]; ok {
		// We've now been told this KV is not in the dataplane but the desired state says it should be there.
		c.pendingUpdates[k] = desiredV
	}
}

// IterDataplane iterates over the cache of the dataplane.
func (c *DeltaTracker[K, V]) IterDataplane(f func(k K, v V)) {
	for k, v := range c.cacheOfDataplane {
		f(k, v)
	}
}

// GetDataplane gets a single value from the cache of the dataplane. The cache must have previously been
// loaded with a successful call to LoadCacheFromDataplane() or one of the ApplyXXX methods.
func (c *DeltaTracker[K, V]) GetDataplane(k K) (V, bool) {
	v, ok := c.cacheOfDataplane[k]
	return v, ok
}

type PendingKVAction int

const (
	PendingKVActionNoOp PendingKVAction = iota
	PendingKVActionUpdateDataplane
)

// IterPendingUpdates iterates over the pending updates. If the passed in function returns
// PendingKVActionUpdateDataplane then the pending update is cleared, and, the KV is applied
// to the dataplane cache (as if the function had called SetDataplane(k, v)).
func (c *DeltaTracker[K, V]) IterPendingUpdates(f func(k K, v V) PendingKVAction) {
	for k, v := range c.pendingUpdates {
		updateDataplane := f(k, v)
		switch updateDataplane {
		case PendingKVActionNoOp:
			// Ignore.
		case PendingKVActionUpdateDataplane:
			delete(c.pendingUpdates, k)
			c.cacheOfDataplane[k] = v
		}
	}
}

// IterPendingDeletions iterates over the pending deletion set. If the passed in function returns
// PendingKVActionUpdateDataplane then the pending deletion is cleared, and, the KV is applied
// to the dataplane cache (as if the function had called DeleteDataplane(k)).
func (c *DeltaTracker[K, V]) IterPendingDeletions(f func(k K) PendingKVAction) {
	for k := range c.pendingDeletions {
		updateDataplane := f(k)
		switch updateDataplane {
		case PendingKVActionNoOp:
			// Ignore.
		case PendingKVActionUpdateDataplane:
			delete(c.pendingDeletions, k)
			delete(c.cacheOfDataplane, k)
		}
	}
}
