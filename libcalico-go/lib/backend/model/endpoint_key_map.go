// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package model

import "iter"

// WorkloadEndpointKeyMap is a map keyed by WorkloadEndpointKey that avoids
// interface boxing by dispatching to per-variant sub-maps. The zero value is
// usable; internal maps are allocated lazily on first Set.
type WorkloadEndpointKeyMap[V any] struct {
	generic    map[GenericWEPKey]V
	k8s        map[K8sWEPKey]V
	k8sDefault map[K8sDefaultWEPKey]V
}

func (m *WorkloadEndpointKeyMap[V]) Get(key WorkloadEndpointKey) (v V, ok bool) {
	switch key := key.(type) {
	case K8sDefaultWEPKey:
		v, ok = m.k8sDefault[key]
	case K8sWEPKey:
		v, ok = m.k8s[key]
	case GenericWEPKey:
		v, ok = m.generic[key]
	}
	return
}

func (m *WorkloadEndpointKeyMap[V]) Set(key WorkloadEndpointKey, v V) {
	switch key := key.(type) {
	case K8sDefaultWEPKey:
		if m.k8sDefault == nil {
			m.k8sDefault = make(map[K8sDefaultWEPKey]V)
		}
		m.k8sDefault[key] = v
	case K8sWEPKey:
		if m.k8s == nil {
			m.k8s = make(map[K8sWEPKey]V)
		}
		m.k8s[key] = v
	case GenericWEPKey:
		if m.generic == nil {
			m.generic = make(map[GenericWEPKey]V)
		}
		m.generic[key] = v
	}
}

func (m *WorkloadEndpointKeyMap[V]) Delete(key WorkloadEndpointKey) {
	switch key := key.(type) {
	case K8sDefaultWEPKey:
		delete(m.k8sDefault, key)
	case K8sWEPKey:
		delete(m.k8s, key)
	case GenericWEPKey:
		delete(m.generic, key)
	}
}

func (m *WorkloadEndpointKeyMap[V]) Len() int {
	return len(m.generic) + len(m.k8s) + len(m.k8sDefault)
}

func (m *WorkloadEndpointKeyMap[V]) All() iter.Seq2[WorkloadEndpointKey, V] {
	return func(yield func(WorkloadEndpointKey, V) bool) {
		for k, v := range m.generic {
			if !yield(k, v) {
				return
			}
		}
		for k, v := range m.k8s {
			if !yield(k, v) {
				return
			}
		}
		for k, v := range m.k8sDefault {
			if !yield(k, v) {
				return
			}
		}
	}
}

// EndpointKeyMap is a map keyed by EndpointKey (workload or host endpoints)
// that avoids interface boxing. It embeds WorkloadEndpointKeyMap for WEP
// support and adds a separate map for host endpoints.
type EndpointKeyMap[V any] struct {
	WorkloadEndpointKeyMap[V]
	hep map[HostEndpointKey]V
}

func (m *EndpointKeyMap[V]) Get(key EndpointKey) (v V, ok bool) {
	switch key := key.(type) {
	case HostEndpointKey:
		v, ok = m.hep[key]
	case WorkloadEndpointKey:
		return m.WorkloadEndpointKeyMap.Get(key)
	}
	return
}

func (m *EndpointKeyMap[V]) Set(key EndpointKey, v V) {
	switch key := key.(type) {
	case HostEndpointKey:
		if m.hep == nil {
			m.hep = make(map[HostEndpointKey]V)
		}
		m.hep[key] = v
	case WorkloadEndpointKey:
		m.WorkloadEndpointKeyMap.Set(key, v)
	}
}

func (m *EndpointKeyMap[V]) Delete(key EndpointKey) {
	switch key := key.(type) {
	case HostEndpointKey:
		delete(m.hep, key)
	case WorkloadEndpointKey:
		m.WorkloadEndpointKeyMap.Delete(key)
	}
}

func (m *EndpointKeyMap[V]) Len() int {
	return m.WorkloadEndpointKeyMap.Len() + len(m.hep)
}

func (m *EndpointKeyMap[V]) All() iter.Seq2[EndpointKey, V] {
	return func(yield func(EndpointKey, V) bool) {
		for k, v := range m.WorkloadEndpointKeyMap.All() {
			if !yield(k, v) {
				return
			}
		}
		for k, v := range m.hep {
			if !yield(k, v) {
				return
			}
		}
	}
}

// EndpointKeySet is a set of EndpointKeys backed by an EndpointKeyMap.
type EndpointKeySet struct {
	EndpointKeyMap[struct{}]
}

func (s *EndpointKeySet) Add(key EndpointKey) {
	s.EndpointKeyMap.Set(key, struct{}{})
}

func (s *EndpointKeySet) Discard(key EndpointKey) {
	s.EndpointKeyMap.Delete(key)
}

func (s *EndpointKeySet) Contains(key EndpointKey) bool {
	_, ok := s.EndpointKeyMap.Get(key)
	return ok
}

func (s *EndpointKeySet) Clear() {
	s.EndpointKeyMap = EndpointKeyMap[struct{}]{}
}

func (s *EndpointKeySet) AllKeys() iter.Seq[EndpointKey] {
	return func(yield func(EndpointKey) bool) {
		for k := range s.EndpointKeyMap.All() {
			if !yield(k) {
				return
			}
		}
	}
}
