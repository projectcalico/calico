// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package packedmap

import (
	"encoding/json"
	"unique"

	"github.com/golang/snappy"
)

// PackedMap is a map that stores values as compressed JSON strings. It requires
// that the value type is serializable to JSON.
type PackedMap[K comparable, V any] struct {
	m map[K]string
}

func New[K comparable, V any]() *PackedMap[K, V] {
	return &PackedMap[K, V]{
		m: make(map[K]string),
	}
}

func (pm PackedMap[K, V]) Set(key K, val V) {
	value := encode(val)
	pm.m[key] = value
}

func (pm PackedMap[K, V]) Get(key K) (val V, ok bool) {
	packed, ok := pm.m[key]
	if !ok {
		return
	}
	val = decode[V](packed)
	return
}

func (pm PackedMap[K, V]) Delete(key K) {
	delete(pm.m, key)
}

func (pm PackedMap[K, V]) Len() int {
	return len(pm.m)
}

// DedupingPackedMap is a variant of PackedMap that also dedupes its values
// so that the same value is only stored once.  This has an additional CPU
// cost but can save memory if the same value is stored many times.
type DedupingPackedMap[K comparable, V any] struct {
	m map[K]unique.Handle[string]
}

func NewDeduping[K comparable, V any]() *DedupingPackedMap[K, V] {
	return &DedupingPackedMap[K, V]{
		m: make(map[K]unique.Handle[string]),
	}
}

func (pm DedupingPackedMap[K, V]) Set(key K, val V) {
	value := encode(val)
	pm.m[key] = unique.Make(value)
}

func (pm DedupingPackedMap[K, V]) Get(key K) (val V, ok bool) {
	packed, ok := pm.m[key]
	if !ok {
		return
	}
	val = decode[V](packed.Value())
	return
}

func (pm DedupingPackedMap[K, V]) Delete(key K) {
	delete(pm.m, key)
}

func (pm DedupingPackedMap[K, V]) Len() int {
	return len(pm.m)
}

func encode[V any](val V) string {
	buf, err := json.Marshal(val)
	if err != nil {
		panic(err)
	}
	var arr [1024 * 16]byte
	packed := snappy.Encode(arr[:], buf)
	value := string(packed)
	return value
}

func decode[V any](packed string) V {
	var arr [1024 * 16]byte
	buf, err := snappy.Decode(arr[:], []byte(packed))
	if err != nil {
		panic(err)
	}
	var val V
	err = json.Unmarshal(buf, &val)
	if err != nil {
		panic(err)
	}
	return val
}
