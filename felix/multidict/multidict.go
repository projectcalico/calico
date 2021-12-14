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

type StringToString interface {
	Put(key, value string)
	Discard(key, value string)
	DiscardKey(key string)
	Contains(key, value string) bool
	ContainsKey(key string) bool
	Iter(key string, f func(value string))
}

type stringToString map[string]map[string]bool

func NewStringToString() StringToString {
	sToS := make(stringToString)
	return sToS
}

func (md stringToString) Put(key, value string) {
	set, ok := md[key]
	if !ok {
		set = make(map[string]bool)
		md[key] = set
	}
	set[value] = true
}

func (md stringToString) Discard(key, value string) {
	set, ok := md[key]
	if !ok {
		return
	}
	delete(set, value)
	if len(set) == 0 {
		delete(md, key)
	}
}

func (md stringToString) DiscardKey(key string) {
	delete(md, key)
}

func (md stringToString) Contains(key, value string) bool {
	set, ok := md[key]
	return ok && set[value]
}

func (md stringToString) ContainsKey(key string) bool {
	_, ok := md[key]
	return ok
}

func (md stringToString) Iter(key string, f func(value string)) {
	for value := range md[key] {
		f(value)
	}
}

type IfaceToIface interface {
	Len() int
	Put(key, value interface{})
	Discard(key, value interface{})
	Contains(key, value interface{}) bool
	ContainsKey(key interface{}) bool
	IterKeys(f func(key interface{}))
	Iter(key interface{}, f func(value interface{}))
}

type ifaceToIfaceMap map[interface{}]map[interface{}]bool

func NewIfaceToIface() IfaceToIface {
	iToI := make(ifaceToIfaceMap)
	return iToI
}

func (md ifaceToIfaceMap) Len() int {
	return len(md)
}

func (md ifaceToIfaceMap) Put(key, value interface{}) {
	set, ok := md[key]
	if !ok {
		set = make(map[interface{}]bool)
		md[key] = set
	}
	set[value] = true
}

func (md ifaceToIfaceMap) Discard(key, value interface{}) {
	set, ok := md[key]
	if !ok {
		return
	}
	delete(set, value)
	if len(set) == 0 {
		delete(md, key)
	}
}

func (md ifaceToIfaceMap) Contains(key, value interface{}) bool {
	set, ok := md[key]
	return ok && set[value]
}

func (md ifaceToIfaceMap) ContainsKey(key interface{}) bool {
	_, ok := md[key]
	return ok
}

func (md ifaceToIfaceMap) IterKeys(f func(value interface{})) {
	for k := range md {
		f(k)
	}
}

func (md ifaceToIfaceMap) Iter(key interface{}, f func(value interface{})) {
	for value := range md[key] {
		f(value)
	}
}

type IfaceToString interface {
	Put(key interface{}, value string)
	Discard(key interface{}, value string)
	Contains(key interface{}, value string) bool
	ContainsKey(key interface{}) bool
	Iter(key interface{}, f func(value string))
	Empty() bool
}

type ifaceToStringMap map[interface{}]map[string]bool

func NewIfaceToString() IfaceToString {
	iToI := make(ifaceToStringMap)
	return iToI
}

func (md ifaceToStringMap) Put(key interface{}, value string) {
	set, ok := md[key]
	if !ok {
		set = make(map[string]bool)
		md[key] = set
	}
	set[value] = true
}
func (md ifaceToStringMap) Empty() bool {
	return len(md) == 0
}

func (md ifaceToStringMap) Discard(key interface{}, value string) {
	set, ok := md[key]
	if !ok {
		return
	}
	delete(set, value)
	if len(set) == 0 {
		delete(md, key)
	}
}

func (md ifaceToStringMap) Contains(key interface{}, value string) bool {
	set, ok := md[key]
	return ok && set[value]
}

func (md ifaceToStringMap) ContainsKey(key interface{}) bool {
	_, ok := md[key]
	return ok
}

func (md ifaceToStringMap) Iter(key interface{}, f func(value string)) {
	for value := range md[key] {
		f(value)
	}
}

type StringToIface interface {
	Len() int
	Put(key string, value interface{})
	Discard(key string, value interface{})
	DiscardKey(key string)
	Contains(key string, value interface{}) bool
	ContainsKey(key string) bool
	Iter(key string, f func(value interface{}))
	IterKeys(f func(key string))
}

type stringToIfaceMap map[string]map[interface{}]bool

func NewStringToIface() StringToIface {
	iToI := make(stringToIfaceMap)
	return iToI
}

func (md stringToIfaceMap) Len() int {
	return len(md)
}

func (md stringToIfaceMap) Put(key string, value interface{}) {
	set, ok := md[key]
	if !ok {
		set = make(map[interface{}]bool)
		md[key] = set
	}
	set[value] = true
}

func (md stringToIfaceMap) Discard(key string, value interface{}) {
	set, ok := md[key]
	if !ok {
		return
	}
	delete(set, value)
	if len(set) == 0 {
		delete(md, key)
	}
}

func (md stringToIfaceMap) DiscardKey(key string) {
	delete(md, key)
}

func (md stringToIfaceMap) Contains(key string, value interface{}) bool {
	set, ok := md[key]
	return ok && set[value]
}

func (md stringToIfaceMap) ContainsKey(key string) bool {
	_, ok := md[key]
	return ok
}

func (md stringToIfaceMap) Iter(key string, f func(value interface{})) {
	for value := range md[key] {
		f(value)
	}
}

func (md stringToIfaceMap) IterKeys(f func(key string)) {
	for k := range md {
		f(k)
	}
}
