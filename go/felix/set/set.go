// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package set

import (
	"errors"
	log "github.com/Sirupsen/logrus"
)

type Set interface {
	Len() int
	Add(interface{})
	Discard(interface{})
	Contains(interface{}) bool
	Iter(func(item interface{}) error)
	Copy() Set
}

type empty struct{}

var emptyValue = empty{}

var (
	StopIteration = errors.New("Stop iteration")
	RemoveItem    = errors.New("Remove item")
)

func New() Set {
	return make(mapSet)
}

func Empty() Set {
	return mapSet(nil)
}

type mapSet map[interface{}]empty

func (set mapSet) Len() int {
	return len(set)
}

func (set mapSet) Add(item interface{}) {
	set[item] = emptyValue
}

func (set mapSet) Discard(item interface{}) {
	delete(set, item)
}

func (set mapSet) Contains(item interface{}) bool {
	_, present := set[item]
	return present
}

func (set mapSet) Iter(visitor func(item interface{}) error) {
loop:
	for item := range set {
		err := visitor(item)
		switch err {
		case StopIteration:
			break loop
		case RemoveItem:
			delete(set, item)
		case nil:
			break
		default:
			log.WithError(err).Panic("Unexpected iteration error")
		}
	}
}

func (set mapSet) Copy() Set {
	cpy := New()
	for item := range set {
		cpy.Add(item)
	}
	return cpy
}
