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
	"fmt"
	"unique"

	"github.com/golang/snappy"
)

// RawPackedMap is a map that stores input VIn values as packed VPacked values.
// the packing/unpacking is done by an Encoder.  It's often more convenient to
// use the Map and Deduped wrapper types, which hide the VPacked internal type.
// See also MakeCompressedJSON and MakeDedupedCompressedJSON.
type RawPackedMap[K comparable, VIn, VPacked any] struct {
	encoder Encoder[VIn, VPacked]
	m       map[K]VPacked
}

func Make[K comparable, VIn, VPacked any](encoder Encoder[VIn, VPacked]) RawPackedMap[K, VIn, VPacked] {
	return RawPackedMap[K, VIn, VPacked]{
		encoder: encoder,
		m:       make(map[K]VPacked),
	}
}

// MakeCompressedJSON returns a new map that stores JSON-encoded values,
// compressed with snappy compression.
func MakeCompressedJSON[K comparable, V any]() Map[K, V] {
	return Map[K, V]{
		Make[K, V, string](
			SnappyEncoderWrapper[V, JSONEncoder[V]]{
				encoder: JSONEncoder[V]{},
			},
		),
	}
}

// Map is a convenience wrapper around RawPackedMap that assumes string as the
// packed type.
type Map[K comparable, V any] struct {
	RawPackedMap[K, V, string]
}

// MakeDedupedCompressedJSON returns a new map that stores JSON-encoded values,
// compressed with snappy compression and then deduped using the unique package.
func MakeDedupedCompressedJSON[K comparable, V any]() Deduped[K, V] {
	pm := Make[K, V, unique.Handle[string]](
		DedupingEncoderWrapper[V, string]{
			encoder: SnappyEncoderWrapper[V, JSONEncoder[V]]{
				encoder: JSONEncoder[V]{},
			},
		},
	)
	return Deduped[K, V]{pm}
}

// Deduped is a convenience wrapper around RawPackedMap that assumes
// unique.Handle[string], as used by the DedupingEncoderWrapper.
type Deduped[K comparable, V any] struct {
	RawPackedMap[K, V, unique.Handle[string]]
}

func (pm RawPackedMap[K, VIn, VPacked]) Set(key K, val VIn) {
	pm.m[key] = pm.encoder.Pack(val)
}

func (pm RawPackedMap[K, VIn, VPacked]) Get(key K) (val VIn, ok bool) {
	packed, ok := pm.m[key]
	if !ok {
		return
	}
	val = pm.encoder.Unpack(packed)
	return
}

func (pm RawPackedMap[K, VIn, VPacked]) Delete(key K) {
	delete(pm.m, key)
}

func (pm RawPackedMap[K, VIn, VPacked]) Len() int {
	return len(pm.m)
}

// Encoder is a type that can pack and unpack values for use in a packed map.
type Encoder[VIn, VOut any] interface {
	Pack(val VIn) VOut
	Unpack(val VOut) VIn
}

// DedupingEncoderWrapper is an Encoder that wraps another Encoder and dedupes
// the packed values using the unique package.
type DedupingEncoderWrapper[VIn any, VOut comparable] struct {
	encoder Encoder[VIn, VOut]
}

func (p DedupingEncoderWrapper[VIn, VOut]) Pack(val VIn) unique.Handle[VOut] {
	packed := p.encoder.Pack(val)
	return unique.Make(packed)
}

func (p DedupingEncoderWrapper[VIn, VOut]) Unpack(packed unique.Handle[VOut]) VIn {
	return p.encoder.Unpack(packed.Value())
}

// SnappyEncoderWrapper is an Encoder that wraps another Encoder and compresses
// the packed values using snappy.
type SnappyEncoderWrapper[V any, E Encoder[V, string]] struct {
	encoder Encoder[V, string]
	buf     [1024 * 16]byte
}

func (p SnappyEncoderWrapper[V, E]) Pack(val V) string {
	buf := p.encoder.Pack(val)
	packed := snappy.Encode(p.buf[:], []byte(buf))
	// We're relying on this string conversion to copy the data out of our
	// re-used buffer.
	s := string(packed)
	return s
}

func (p SnappyEncoderWrapper[V, E]) Unpack(packed string) V {
	buf, err := snappy.Decode(p.buf[:], []byte(packed))
	if err != nil {
		panic(err)
	}
	return p.encoder.Unpack(string(buf))
}

// JSONEncoder is an Encoder that packs and unpacks values as JSON.
type JSONEncoder[V any] struct{}

func (p JSONEncoder[V]) Pack(val V) string {
	buf, err := json.Marshal(val)
	if err != nil {
		panic(fmt.Sprintf("failed to pack value as JSON: %s", err))
	}
	return string(buf)
}

func (p JSONEncoder[V]) Unpack(packed string) V {
	var val V
	err := json.Unmarshal([]byte(packed), &val)
	if err != nil {
		panic(fmt.Sprintf("failed to unpack value as JSON: %s", err))
	}
	return val
}
