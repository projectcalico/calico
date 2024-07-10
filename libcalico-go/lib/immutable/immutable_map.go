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

package immutable

// CopyingMap is an immutable map implemented by copying a native go map[k]v
// on mutation.  The zero value is the empty map for a given type.
//
// Due to copying, the implementation is only suitable for small maps.
type CopyingMap[K comparable, V any] struct {
	m map[K]V
}

func (im CopyingMap[K, V]) WithKey(key K, value V) CopyingMap[K, V] {
	newMap := make(map[K]V)
	for k, v := range im.m {
		newMap[k] = v
	}
	newMap[key] = value
	return CopyingMap[K, V]{m: newMap}
}

func (im CopyingMap[K, V]) Get(key K) (V, bool) {
	v, ok := im.m[key]
	return v, ok
}

func (im CopyingMap[K, V]) WithKeyDeleted(key K) CopyingMap[K, V] {
	var newMap map[K]V
	for k, v := range im.m {
		if k == key {
			continue
		}
		if newMap == nil {
			newMap = make(map[K]V)
		}
		newMap[k] = v
	}
	return CopyingMap[K, V]{m: newMap}
}

func (im CopyingMap[K, V]) Len() int {
	return len(im.m)
}

func (im CopyingMap[K, V]) Iter(f func(K, V) bool) {
	for k, v := range im.m {
		carryOn := f(k, v)
		if !carryOn {
			break
		}
	}
}
