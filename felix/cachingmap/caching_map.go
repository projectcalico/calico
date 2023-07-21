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

	"github.com/projectcalico/calico/felix/deltatracker"
)

// DataplaneMap is an interface of the underlying map that is being cached by the
// CachingMap. It implements interaction with the dataplane.
type DataplaneMap[K comparable, V comparable] interface {
	Update(K, V) error
	Delete(K) error
	Load() (map[K]V, error)
	ErrIsNotExists(error) bool
}

// CachingMap provides a caching layer around a DataplaneMap, when one of the Apply methods is called, it applies
// a minimal set of changes to the dataplane map to bring it into sync with the desired state.  Updating the
// desired state in and of itself has no effect on the dataplane.
//
// CachingMap will load a cache of the dataplane state on the first call to ApplyXXX, or the cache can be loaded
// explicitly by calling LoadCacheFromDataplane().  This allows for client code to inspect the dataplane cache
// with IterDataplane and GetDataplane.
type CachingMap[K comparable, V comparable] struct {
	// dpMap is the backing map in the dataplane
	dpMap DataplaneMap[K, V]
	name  string

	deltaTracker *deltatracker.DeltaTracker[K, V]

	cacheLoaded bool
}

func New[K comparable, V comparable](name string, dpMap DataplaneMap[K, V]) *CachingMap[K, V] {
	cm := &CachingMap[K, V]{
		name:  name,
		dpMap: dpMap,
		deltaTracker: deltatracker.New[K, V](
			deltatracker.WithValuesEqualFn[K, V](func(a, b V) bool {
				// Since we require V to be comparable, can just use '==' here.
				return a == b
			}),
			deltatracker.WithLogCtx[K, V](logrus.WithField("bpfMap", name)),
		),
	}
	return cm
}

// LoadCacheFromDataplane loads the contents of the DP map into the dataplane cache, allowing it to be queried with
// GetDataplane and IterDataplane.
func (c *CachingMap[K, V]) LoadCacheFromDataplane() error {
	logrus.WithField("name", c.name).Debug("Loading BPF map from dataplane.")
	dp, err := c.dpMap.Load()
	if err != nil {
		logrus.WithError(err).WithField("name", c.name).Warn("Failed to load cache of dataplane map")
		return err
	}
	c.deltaTracker.Dataplane().ReplaceAllMap(dp)
	c.cacheLoaded = true
	return nil
}

type ReadOnlyMap[K comparable, V any] interface {
	Get(k K) (v V, exists bool)
	Iter(func(k K, v V))
}

type ReadWriteMap[K comparable, V any] interface {
	ReadOnlyMap[K, V]
	Set(k K, v V)
	Delete(k K)
	DeleteAll()
}

func (c *CachingMap[K, V]) Desired() ReadWriteMap[K, V] {
	// Pass through to the delta tracker.
	return c.deltaTracker.Desired()
}

func (c *CachingMap[K, V]) Dataplane() ReadOnlyMap[K, V] {
	// Pass through to the delta tracker.
	return c.deltaTracker.Dataplane()
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
	if c.cacheLoaded {
		return nil
	}
	return c.LoadCacheFromDataplane()
}

// ApplyUpdatesOnly applies any pending adds/updates to the dataplane map.  It doesn't delete any keys that are no
// longer wanted.
func (c *CachingMap[K, V]) ApplyUpdatesOnly() error {
	logrus.WithField("name", c.name).Debug("Applying updates to DP map.")
	err := c.maybeLoadCache()
	if err != nil {
		return err
	}
	var errs ErrSlice
	c.deltaTracker.PendingUpdates().Iter(func(k K, v V) deltatracker.IterAction {
		err := c.dpMap.Update(k, v)
		if err != nil {
			logrus.WithError(err).Warn("Error while updating DP map")
			errs = append(errs, err)
			return deltatracker.IterActionNoOp
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ApplyDeletionsOnly applies any pending deletions to the dataplane map.  It doesn't add or update any keys that
// are new/changed.
func (c *CachingMap[K, V]) ApplyDeletionsOnly() error {
	logrus.WithField("name", c.name).Debug("Applying deletions to DP map.")
	err := c.maybeLoadCache()
	if err != nil {
		return err
	}
	var errs ErrSlice
	c.deltaTracker.PendingDeletions().Iter(func(k K) deltatracker.IterAction {
		err := c.dpMap.Delete(k)
		if err != nil && !c.dpMap.ErrIsNotExists(err) {
			logrus.WithError(err).Warn("Error while deleting from DP map")
			errs = append(errs, err)
			return deltatracker.IterActionNoOp
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if len(errs) > 0 {
		return errs
	}
	return nil
}

type ErrSlice []error

func (e ErrSlice) Error() string {
	return fmt.Sprintf("multiple errors while updating dataplane (%d)", len(e))
}
