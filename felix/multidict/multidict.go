// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package multidict

import (
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type Multidict[K comparable, V comparable] map[K]set.Typed[V]

func New[K comparable, V comparable]() Multidict[K, V] {
	return make(Multidict[K, V])
}

func (md Multidict[K, V]) Len() int {
	return len(md)
}

func (md Multidict[K, V]) Put(key K, value V) {
	s, ok := md[key]
	if !ok {
		s = set.New[V]()
		md[key] = s
	}
	s.Add(value)
}

func (md Multidict[K, V]) Discard(key K, value V) {
	s, ok := md[key]
	if !ok {
		return
	}
	s.Discard(value)
	if s.Len() == 0 {
		delete(md, key)
	}
}

func (md Multidict[K, V]) Contains(key K, value V) bool {
	s, ok := md[key]
	return ok && s != nil && s.Contains(value)
}

func (md Multidict[K, V]) ContainsKey(key K) bool {
	_, ok := md[key]
	return ok
}

func (md Multidict[K, V]) IterKeys(f func(key K)) {
	for k := range md {
		f(k)
	}
}

func (md Multidict[K, V]) Iter(key K, f func(value V)) {
	s := md[key]
	if s == nil {
		return
	}
	for v := range s.All() {
		f(v)
	}
}

func (md Multidict[K, V]) DiscardKey(k K) {
	delete(md, k)
}
