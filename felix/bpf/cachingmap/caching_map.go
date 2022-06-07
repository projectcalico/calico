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
	"log"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
)

// CachingMap provides a caching layer around a bpf.Map, when one of the Apply methods is called, it applies
// a minimal set of changes to the dataplane map to bring it into sync with the desired state.  Updating the
// desired state in and of itself has no effect on the dataplane.
//
// CachingMap will load a cache of the dataplane state on the first call to ApplyXXX, or the cache can be loaded
// explicitly by calling LoadCacheFromDataplane().  This allows for client code to inspect the dataplane cache
// with IterDataplaneCache and GetDataplaneCache.
type CachingMap struct {
	// dataplaneMap is the backing map in the dataplane
	dataplaneMap bpf.Map
	params       bpf.MapParameters

	// desiredStateOfDataplane stores the complete set of key/value pairs that we _want_ to
	// be in the dataplane.  Calling ApplyAllChanges attempts to bring the dataplane into
	// sync.
	//
	// For occupancy's sake we may want to drop this copy and instead maintain the invariant:
	// desiredStateOfDataplane = cacheOfDataplane - pendingDeletions + pendingUpdates.
	desiredStateOfDataplane *ByteArrayToByteArrayMap

	cacheOfDataplane *ByteArrayToByteArrayMap
	pendingUpdates   *ByteArrayToByteArrayMap
	pendingDeletions *ByteArrayToByteArrayMap
}

func New(mapParams bpf.MapParameters, dataplaneMap bpf.Map) *CachingMap {
	cm := &CachingMap{
		params:                  mapParams,
		dataplaneMap:            dataplaneMap,
		desiredStateOfDataplane: NewByteArrayToByteArrayMap(mapParams.KeySize, mapParams.ValueSize),
	}
	return cm
}

// LoadCacheFromDataplane loads the contents of the BPF map into the dataplane cache, allowing it to be queried with
// GetDataplaneCache and IterDataplaneCache.
func (c *CachingMap) LoadCacheFromDataplane() error {
	logrus.WithField("name", c.params.Name).Debug("Loading cache of dataplane state.")
	c.initCache()
	err := c.dataplaneMap.Iter(func(k, v []byte) bpf.IteratorAction {
		c.cacheOfDataplane.Set(k, v)
		return bpf.IterNone
	})
	if err != nil {
		logrus.WithError(err).WithField("name", c.params.Name).Warn("Failed to load cache of BPF map")
		c.clearCache()
		return err
	}
	logrus.WithField("name", c.params.Name).WithField("count", c.cacheOfDataplane.Len()).Info(
		"Loaded cache of BPF map")
	c.recalculatePendingOperations()
	return nil
}

func (c *CachingMap) initCache() {
	c.cacheOfDataplane = NewByteArrayToByteArrayMap(c.params.KeySize, c.params.ValueSize)
	c.pendingUpdates = NewByteArrayToByteArrayMap(c.params.KeySize, c.params.ValueSize)
	c.pendingDeletions = NewByteArrayToByteArrayMap(c.params.KeySize, c.params.ValueSize)
}

func (c *CachingMap) clearCache() {
	logrus.WithField("name", c.params.Name).Debug("Clearing cache of BPF map")
	c.cacheOfDataplane = nil
	c.pendingDeletions = nil
	c.pendingUpdates = nil
}

// recalculatePendingOperations compares the dataplane cache against he desired state and adds entries to
// pendingUpdates/pendingDeletions that would bring the dataplane into sync with the desired state.
func (c *CachingMap) recalculatePendingOperations() {
	debug := logrus.GetLevel() >= logrus.DebugLevel

	// Look for any discrepancies and queue up updates.
	c.desiredStateOfDataplane.Iter(func(k, desiredVal []byte) {
		actualVal := c.cacheOfDataplane.Get(k)
		if slicesEqual(actualVal, desiredVal) {
			return
		}
		c.pendingUpdates.Set(k, desiredVal)
	})

	// Scan for any dataplane keys that are not in the desired map at all and
	// queue up deletions.
	c.cacheOfDataplane.Iter(func(k, actualVal []byte) {
		desiredVal := c.desiredStateOfDataplane.Get(k)
		if debug {
			logrus.WithFields(logrus.Fields{
				"k":        k,
				"v":        actualVal,
				"expected": desiredVal,
			}).Debug("Checking cache against desired")
		}
		if desiredVal == nil {
			c.pendingDeletions.Set(k, actualVal)
			return
		}
	})

	logrus.WithFields(logrus.Fields{
		"cached":         c.cacheOfDataplane.Len(),
		"pendingDels":    c.pendingDeletions.Len(),
		"pendingUpdates": c.pendingUpdates.Len(),
		"name":           c.params.Name,
	}).Info("Recalculated pending operations")
}

// SetDesired sets the desired state of the given key to the given value. This is an in-memory operation,
// it doesn't actually touch the dataplane.
func (c *CachingMap) SetDesired(k, v []byte) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"name": c.params.Name, "k": k, "v": v}).Debug("SetDesired")
	}
	c.desiredStateOfDataplane.Set(k, v)
	if c.cacheOfDataplane == nil {
		logrus.Debug("SetDesired: initial sync pending.")
		return // Initial sync is pending, we're not tracking deltas yet.
	}
	c.pendingDeletions.Delete(k)

	// Check if we think we need to update the dataplane as a result.
	currentVal := c.cacheOfDataplane.Get(k)
	if slicesEqual(currentVal, v) {
		// Dataplane already agrees with the new value so clear any pending update.
		logrus.Debug("SetDesired: Key in dataplane already, ignoring.")
		c.pendingUpdates.Delete(k)
		return
	}
	c.pendingUpdates.Set(k, v)
}

// GetDesired returns the desired (latest) value.
func (c *CachingMap) GetDesired(k []byte) []byte {
	return c.desiredStateOfDataplane.Get(k)
}

func slicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

// DeleteDesired deletes the given key from the desired state of the dataplane. This is an in-memory operation,
// it doesn't actually touch the dataplane.
func (c *CachingMap) DeleteDesired(k []byte) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"name": c.params.Name, "k": k}).Debug("DeleteDesired")
	}
	c.desiredStateOfDataplane.Delete(k)
	if c.cacheOfDataplane == nil {
		logrus.Debug("DeleteDesired: initial sync pending.")
		return // Initial sync is pending, we're not tracking deltas yet.
	}
	c.pendingUpdates.Delete(k)

	// Check if we need to update the dataplane.
	currentVal := c.cacheOfDataplane.Get(k)
	if currentVal == nil {
		// We don't think this value is in the dataplane so clear any pending delete.
		logrus.Debug("DeleteDesired: Key not in dataplane, ignoring.")
		c.pendingDeletions.Delete(k)
		return
	}
	c.pendingDeletions.Set(k, currentVal)
}

// DeleteAllDesired deletes all entries from the in-memory desired state of the map.  It doesn't actually touch
// the dataplane.
func (c *CachingMap) DeleteAllDesired() {
	logrus.WithField("name", c.params.Name).Debug("DeleteAll")
	c.desiredStateOfDataplane.Iter(func(k, v []byte) {
		c.DeleteDesired(k)
	})
}

// IterDataplaneCache iterates over the cache of the dataplane. The cache must have previously been loaded with
// a successful call to LoadCacheFromDataplane() or one of the ApplyXXX methods.
func (c *CachingMap) IterDataplaneCache(f func(k, v []byte)) {
	c.cacheOfDataplane.Iter(f)
}

// GetDataplaneCache gets a single value from the cache of the dataplane. The cache must have previously been
// loaded with a successful call to LoadCacheFromDataplane() or one of the ApplyXXX methods.
func (c *CachingMap) GetDataplaneCache(k []byte) []byte {
	return c.cacheOfDataplane.Get(k)
}

// ApplyAllChanges attempts to bring the dataplane map into sync with the desired state.
func (c *CachingMap) ApplyAllChanges() error {
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

func (c *CachingMap) maybeLoadCache() error {
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
func (c *CachingMap) ApplyUpdatesOnly() error {
	logrus.WithField("name", c.params.Name).Debug("Applying updates to BPF map.")
	err := c.maybeLoadCache()
	if err != nil {
		return err
	}
	var errs ErrSlice
	c.pendingUpdates.Iter(func(k, v []byte) {
		err := c.dataplaneMap.Update(k, v)
		if err != nil {
			logrus.WithError(err).Warn("Error while updating BPF map")
			errs = append(errs, err)
		} else {
			c.pendingUpdates.Delete(k)
			c.cacheOfDataplane.Set(k, v)
		}
	})
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ApplyDeletionsOnly applies any pending deletions to the dataplane map.  It doesn't add or update any keys that
// are new/changed.
func (c *CachingMap) ApplyDeletionsOnly() error {
	logrus.WithField("name", c.params.Name).Debug("Applying deletions to BPF map.")
	err := c.maybeLoadCache()
	if err != nil {
		return err
	}
	var errs ErrSlice
	c.pendingDeletions.Iter(func(k, v []byte) {
		err := c.dataplaneMap.Delete(k)
		if err != nil && !bpf.IsNotExists(err) {
			logrus.WithError(err).Warn("Error while deleting from BPF map")
			errs = append(errs, err)
		} else {
			c.pendingDeletions.Delete(k)
			c.cacheOfDataplane.Delete(k)
		}
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

// ByteArrayToByteArrayMap uses reflection to implements a map from a fixed size array of bytes to
// a fixed size array of bytes where the key and value sizes are set at map creation time.  It exposes
// an API that uses slices for Get/Set/Delete, making it much more convenient to interact with.
// All operations panic if passed a slice of incorrect size.
type ByteArrayToByteArrayMap struct {
	keySize   int
	valueSize int
	keyType   reflect.Type
	valueType reflect.Type

	m reflect.Value // map[[keySize]byte][valueSize]byte

	// key and value that we reuse when reading/writing the map.  Since the map uses value types (not
	// pointers), we can reuse the same key/value to read/write the map and the map will save the
	// actual key/value internally rather than sharing storage with our reflect.Value.
	key        reflect.Value
	value      reflect.Value
	keySlice   []byte // Slice backed by key
	valueSlice []byte // Slice backed by value
}

func NewByteArrayToByteArrayMap(keySize, valueSize int) *ByteArrayToByteArrayMap {
	// Effectively make(map[[keySize]byte][valueSize]byte)
	keyType := reflect.ArrayOf(keySize, reflect.TypeOf(byte(0)))
	valueType := reflect.ArrayOf(valueSize, reflect.TypeOf(byte(0)))
	mapType := reflect.MapOf(keyType, valueType)
	mapVal := reflect.MakeMap(mapType)

	key := reflect.New(keyType).Elem()
	value := reflect.New(valueType).Elem()
	return &ByteArrayToByteArrayMap{
		keySize:    keySize,
		valueSize:  valueSize,
		keyType:    keyType,
		valueType:  valueType,
		m:          mapVal,
		key:        key,
		value:      value,
		keySlice:   key.Slice(0, keySize).Interface().([]byte),
		valueSlice: value.Slice(0, valueSize).Interface().([]byte),
	}
}

func (b *ByteArrayToByteArrayMap) Set(k, v []byte) {
	if len(k) != b.keySize {
		log.Panic("ByteArrayToByteArrayMap.Set() called with incorrect key length")
	}
	if len(v) != b.valueSize {
		log.Panic("ByteArrayToByteArrayMap.Set() called with incorrect key length")
	}

	copy(b.keySlice, k)
	copy(b.valueSlice, v)
	b.m.SetMapIndex(b.key, b.value)
}

func (b *ByteArrayToByteArrayMap) Get(k []byte) []byte {
	if len(k) != b.keySize {
		log.Panic("ByteArrayToByteArrayMap.Get() called with incorrect key length")
	}

	copy(b.keySlice, k)
	valVal := b.m.MapIndex(b.key)
	if !valVal.IsValid() {
		return nil
	}
	valSlice := make([]byte, b.valueSize)
	reflect.Copy(reflect.ValueOf(valSlice), valVal)
	return valSlice
}

func (b *ByteArrayToByteArrayMap) Delete(k []byte) {
	if len(k) != b.keySize {
		log.Panic("ByteArrayToByteArrayMap.Delete() called with incorrect key length")
	}

	copy(b.keySlice, k)
	var zeroVal reflect.Value
	b.m.SetMapIndex(b.key, zeroVal)
}

// Iter iterates over the map, passing each key/value to the given func as a slice.  For performance,
// The slice is reused between iterations and should not be retained.  As with a normal map, it is safe
// to delete from the map during iteration.
func (b *ByteArrayToByteArrayMap) Iter(f func(k, v []byte)) {
	iter := b.m.MapRange()
	// Since it's valid for a user to call Get/Set while we're iterating, make sure we have our own
	// values for key/value to avoid aliasing.
	key := reflect.New(b.keyType).Elem()
	val := reflect.New(b.valueType).Elem()
	keySlice := key.Slice(0, b.keySize).Interface().([]byte)
	valSlice := val.Slice(0, b.valueSize).Interface().([]byte)
	for iter.Next() {
		reflect.Copy(key, iter.Key())
		reflect.Copy(val, iter.Value())
		f(keySlice, valSlice)
	}
}

func (b *ByteArrayToByteArrayMap) Len() int {
	return b.m.Len()
}
