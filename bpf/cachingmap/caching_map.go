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

	"github.com/projectcalico/felix/bpf"
)

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

func (c *CachingMap) recalculatePendingOperations() {
	debug := logrus.GetLevel() >= logrus.DebugLevel

	// Look for any discrepancies and queue up updates.
	c.desiredStateOfDataplane.Iter(func(k, desiredVal []byte) {
		actualVal := c.cacheOfDataplane.Get(k)
		if reflect.DeepEqual(actualVal, desiredVal) {
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

func (c *CachingMap) SetDesiredState(k, v []byte) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"name": c.params.Name, "k": k, "v": v}).Debug("SetDesiredState")
	}
	c.desiredStateOfDataplane.Set(k, v)
	if c.cacheOfDataplane == nil {
		logrus.Debug("SetDesiredState: initial sync pending.")
		return // Initial sync is pending, we're not tracking deltas yet.
	}
	c.pendingDeletions.Delete(k)

	// Check if we think we need to update the dataplane as a result.
	currentVal := c.cacheOfDataplane.Get(k)
	if reflect.DeepEqual(currentVal, v) {
		// Dataplane already agrees with the new value so clear any pending update.
		logrus.Debug("SetDesiredState: Key in dataplane already, ignoring.")
		c.pendingUpdates.Delete(k)
		return
	}
	c.pendingUpdates.Set(k, v)
}

func (c *CachingMap) DeleteDesiredState(k []byte) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{"name": c.params.Name, "k": k}).Debug("DeleteDesiredState")
	}
	c.desiredStateOfDataplane.Delete(k)
	if c.cacheOfDataplane == nil {
		logrus.Debug("DeleteDesiredState: initial sync pending.")
		return // Initial sync is pending, we're not tracking deltas yet.
	}
	c.pendingUpdates.Delete(k)

	// Check if we need to update the dataplane.
	currentVal := c.cacheOfDataplane.Get(k)
	if currentVal == nil {
		// We don't think this value is in the dataplane so clear any pending delete.
		logrus.Debug("DeleteDesiredState: Key not in dataplane, ignoring.")
		c.pendingDeletions.Delete(k)
		return
	}
	c.pendingDeletions.Set(k, currentVal)
}

func (c *CachingMap) DeleteAll() {
	logrus.WithField("name", c.params.Name).Debug("DeleteAll")
	c.desiredStateOfDataplane.Iter(func(k, v []byte) {
		c.DeleteDesiredState(k)
	})
}

func (c *CachingMap) IterDataplaneCache(f func(k, v []byte)) {
	c.cacheOfDataplane.Iter(f)
}

func (c *CachingMap) GetDataplaneCache(k []byte) []byte {
	return c.cacheOfDataplane.Get(k)
}

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
}

func NewByteArrayToByteArrayMap(keySize, valueSize int) *ByteArrayToByteArrayMap {
	// Effectively make(map[[keySize]byte][valueSize]byte)
	keyType := reflect.ArrayOf(keySize, reflect.TypeOf(byte(0)))
	valueType := reflect.ArrayOf(valueSize, reflect.TypeOf(byte(0)))
	mapType := reflect.MapOf(keyType, valueType)
	mapVal := reflect.MakeMap(mapType)

	return &ByteArrayToByteArrayMap{
		keySize:   keySize,
		valueSize: valueSize,
		keyType:   keyType,
		valueType: valueType,
		m:         mapVal,
	}
}

func (b *ByteArrayToByteArrayMap) Set(k, v []byte) {
	if len(k) != b.keySize {
		log.Panic("ByteArrayToByteArrayMap.Set() called with incorrect key length")
	}
	if len(v) != b.valueSize {
		log.Panic("ByteArrayToByteArrayMap.Set() called with incorrect key length")
	}

	key := reflect.New(b.keyType).Elem()
	val := reflect.New(b.valueType).Elem()
	reflect.Copy(key, reflect.ValueOf(k))
	reflect.Copy(val, reflect.ValueOf(v))

	b.m.SetMapIndex(key, val)
}

func (b *ByteArrayToByteArrayMap) Get(k []byte) []byte {
	if len(k) != b.keySize {
		log.Panic("ByteArrayToByteArrayMap.Get() called with incorrect key length")
	}

	key := reflect.New(b.keyType).Elem()
	reflect.Copy(key, reflect.ValueOf(k))

	valVal := b.m.MapIndex(key)
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

	key := reflect.New(b.keyType).Elem()
	reflect.Copy(key, reflect.ValueOf(k))
	var zeroVal reflect.Value
	b.m.SetMapIndex(key, zeroVal)
}

func (b *ByteArrayToByteArrayMap) Iter(f func(k, v []byte)) {
	iter := b.m.MapRange()
	for iter.Next() {
		key := reflect.New(b.keyType).Elem()
		val := reflect.New(b.valueType).Elem()
		reflect.Copy(key, iter.Key())
		reflect.Copy(val, iter.Value())
		f(key.Slice(0, b.keySize).Interface().([]byte), val.Slice(0, b.valueSize).Interface().([]byte))
	}
}

func (b *ByteArrayToByteArrayMap) Len() int {
	return b.m.Len()
}
