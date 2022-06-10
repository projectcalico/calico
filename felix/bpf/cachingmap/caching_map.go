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

package cachingmap

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
)

// DataplaneMap is an interface of the underlying map that is being cached by the
// CachingMap. It implements interaction with the dataplane.
type DataplaneMap[K comparable, V comparable] interface {
	Update(K, V) error
	Get(K) (V, error)
	Delete(K) error
	Load() (map[K]V, error)
}

// CachingMap provides a caching layer around a DataplaneMap, when one of the Apply methods is called, it applies
// a minimal set of changes to the dataplane map to bring it into sync with the desired state.  Updating the
// desired state in and of itself has no effect on the dataplane.
//
// CachingMap will load a cache of the dataplane state on the first call to ApplyXXX, or the cache can be loaded
// explicitly by calling LoadCacheFromDataplane().  This allows for client code to inspect the dataplane cache
// with IterDataplaneCache and GetDataplaneCache.
type CachingMap[K comparable, V comparable] struct {
	// dpMap is the backing map in the dataplane
	dpMap DataplaneMap[K, V]
	name  string

	// desiredStateOfDataplane stores the complete set of key/value pairs that we _want_ to
	// be in the dataplane.  Calling ApplyAllChanges attempts to bring the dataplane into
	// sync.
	//
	// For occupancy's sake we may want to drop this copy and instead maintain the invariant:
	// desiredStateOfDataplane = cacheOfDataplane - pendingDeletions + pendingUpdates.
	desiredStateOfDataplane map[K]V

	cacheOfDataplane map[K]V
	pendingUpdates   map[K]V
	pendingDeletions map[K]V
}

func New[K comparable, V comparable](name string, dpMap DataplaneMap[K, V]) *CachingMap[K, V] {
	cm := &CachingMap[K, V]{
		name:                    name,
		dpMap:                   dpMap,
		desiredStateOfDataplane: make(map[K]V),
	}
	return cm
}

// LoadCacheFromDataplane loads the contents of the BPF map into the dataplane cache, allowing it to be queried with
// GetDataplaneCache and IterDataplaneCache.
func (c *CachingMap[K, V]) LoadCacheFromDataplane() error {
	logrus.WithField("name", c.name).Debug("Loading cache of dataplane state.")
	c.initCache()
	dp, err := c.dpMap.Load()

	if err != nil {
		logrus.WithError(err).WithField("name", c.name).Warn("Failed to load cache of dataplane map")
		c.clearCache()
		return err
	}
	c.cacheOfDataplane = dp
	logrus.WithField("name", c.name).WithField("count", len(c.cacheOfDataplane)).Info(
		"Loaded cache from dataplane.")
	c.recalculatePendingOperations()
	return nil
}

func (c *CachingMap[K, V]) initCache() {
	c.pendingUpdates = make(map[K]V)
	c.pendingDeletions = make(map[K]V)
}

func (c *CachingMap[K, V]) clearCache() {
	logrus.WithField("name", c.name).Debug("Clearing cache of dataplane map")
	c.cacheOfDataplane = nil
	c.pendingDeletions = nil
	c.pendingUpdates = nil
}

// recalculatePendingOperations compares the dataplane cache against he desired state and adds entries to
// pendingUpdates/pendingDeletions that would bring the dataplane into sync with the desired state.
func (c *CachingMap[K, V]) recalculatePendingOperations() {
	debug := logrus.GetLevel() >= logrus.DebugLevel

	// Look for any discrepancies and queue up updates.
	for k, desiredVal := range c.desiredStateOfDataplane {
		actualVal := c.cacheOfDataplane[k]
		if actualVal != desiredVal {
			c.pendingUpdates[k] = desiredVal
		}
	}

	// Scan for any dataplane keys that are not in the desired map at all and
	// queue up deletions.
	for k, actualVal := range c.cacheOfDataplane {
		desiredVal, ok := c.desiredStateOfDataplane[k]
		if debug {
			logrus.WithFields(logrus.Fields{
				"k":        k,
				"v":        actualVal,
				"expected": desiredVal,
			}).Debug("Checking cache against desired")
		}
		if !ok {
			c.pendingDeletions[k] = actualVal
		}
	}

	logrus.WithFields(logrus.Fields{
		"cached":         len(c.cacheOfDataplane),
		"pendingDels":    len(c.pendingDeletions),
		"pendingUpdates": len(c.pendingUpdates),
		"name":           c.name,
	}).Info("Recalculated pending operations")
}

// SetDesired sets the desired state of the given key to the given value. This is an in-memory operation,
// it doesn't actually touch the dataplane.
func (c *CachingMap[K, V]) SetDesired(k K, v V) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"name": c.name, "k": k, "v": v}).Debug("SetDesired")
	}
	c.desiredStateOfDataplane[k] = v
	if c.cacheOfDataplane == nil {
		logrus.Debug("SetDesired: initial sync pending.")
		return // Initial sync is pending, we're not tracking deltas yet.
	}
	delete(c.pendingDeletions, k)

	// Check if we think we need to update the dataplane as a result.
	currentVal := c.cacheOfDataplane[k]
	if currentVal == v {
		// Dataplane already agrees with the new value so clear any pending update.
		logrus.Debug("SetDesired: Key in dataplane already, ignoring.")
		delete(c.pendingUpdates, k)
		return
	}
	c.pendingUpdates[k] = v
}

// DeleteDesired deletes the given key from the desired state of the dataplane. This is an in-memory operation,
// it doesn't actually touch the dataplane.
func (c *CachingMap[K, V]) DeleteDesired(k K) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"name": c.name, "k": k}).Debug("DeleteDesired")
	}
	delete(c.desiredStateOfDataplane, k)
	if c.cacheOfDataplane == nil {
		logrus.Debug("DeleteDesired: initial sync pending.")
		return // Initial sync is pending, we're not tracking deltas yet.
	}
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

// DeleteAllDesired deletes all entries from the in-memory desired state of the map.  It doesn't actually touch
// the dataplane.
func (c *CachingMap[K, V]) DeleteAllDesired() {
	logrus.WithField("name", c.name).Debug("DeleteAll")
	for k := range c.desiredStateOfDataplane {
		c.DeleteDesired(k)
	}
}

// IterDataplaneCache iterates over the cache of the dataplane. The cache must have previously been loaded with
// a successful call to LoadCacheFromDataplane() or one of the ApplyXXX methods.
func (c *CachingMap[K, V]) IterDataplaneCache(f func(k K, v V)) {
	for k, v := range c.cacheOfDataplane {
		f(k, v)
	}
}

// GetDataplaneCache gets a single value from the cache of the dataplane. The cache must have previously been
// loaded with a successful call to LoadCacheFromDataplane() or one of the ApplyXXX methods.
func (c *CachingMap[K, V]) GetDataplaneCache(k K) (V, bool) {
	v, ok := c.cacheOfDataplane[k]
	return v, ok
}

// ApplyAllChanges attempts to bring the dataplane map into sync with the desired state.
func (c *CachingMap[K, V]) ApplyAllChanges() error {
	var errs ErrSlice
	err := c.ApplyDeletionsOnly()
	if err != nil {
		errs = append(errs, err)
	}
	err = c.ApplyUpdatesOnly()
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (c *CachingMap[K, V]) maybeLoadCache() error {
	if c.cacheOfDataplane == nil {
		err := c.LoadCacheFromDataplane()
		if err != nil {
			return err
		}
	}
	return nil
}

// ApplyUpdatesOnly applies any pending adds/updates to the dataplane map.  It doesn't delete any keys that are no
// longer wanted.
func (c *CachingMap[K, V]) ApplyUpdatesOnly() error {
	logrus.WithField("name", c.name).Debug("Applying updates to BPF map.")
	err := c.maybeLoadCache()
	if err != nil {
		return err
	}
	var errs ErrSlice
	for k, v := range c.pendingUpdates {
		err := c.dpMap.Update(k, v)
		if err != nil {
			logrus.WithError(err).Warn("Error while updating BPF map")
			errs = append(errs, err)
		} else {
			delete(c.pendingUpdates, k)
			c.cacheOfDataplane[k] = v
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ApplyDeletionsOnly applies any pending deletions to the dataplane map.  It doesn't add or update any keys that
// are new/changed.
func (c *CachingMap[K, V]) ApplyDeletionsOnly() error {
	logrus.WithField("name", c.name).Debug("Applying deletions to BPF map.")
	err := c.maybeLoadCache()
	if err != nil {
		return err
	}
	var errs ErrSlice
	for k := range c.pendingDeletions {
		err := c.dpMap.Delete(k)
		if err != nil && !bpf.IsNotExists(err) {
			logrus.WithError(err).Warn("Error while deleting from BPF map")
			errs = append(errs, err)
		} else {
			delete(c.pendingDeletions, k)
			delete(c.cacheOfDataplane, k)
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

type ErrSlice []error

func (e ErrSlice) Error() string {
	return fmt.Sprintf("multiple errors while updating dataplane (%d)", len(e))
}
