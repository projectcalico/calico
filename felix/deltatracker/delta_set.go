// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package deltatracker

type SetDeltaTracker[K comparable] struct {
	dt *DeltaTracker[K, struct{}]
}

func NewSetDeltaTracker[K comparable]() *SetDeltaTracker[K] {
	dt := New[K, struct{}](WithValuesEqualFn[K, struct{}](func(a, b struct{}) bool {
		return true // empty struct always equals itself.
	}))
	return &SetDeltaTracker[K]{dt: dt}
}

func (s *SetDeltaTracker[K]) AddDesired(k K) {
	s.dt.SetDesired(k, struct{}{})
}

func (s *SetDeltaTracker[K]) ContainsDesired(k K) bool {
	_, exists := s.dt.GetDesired(k)
	return exists
}

func (s *SetDeltaTracker[K]) DeleteDesired(k K) {
	s.dt.DeleteDesired(k)
}

func (s *SetDeltaTracker[K]) DeleteAllDesired() {
	s.dt.DeleteAllDesired()
}

func (s *SetDeltaTracker[K]) IterDesired(f func(k K)) {
	s.dt.IterDesired(func(k K, _ struct{}) {
		f(k)
	})
}

func (s *SetDeltaTracker[K]) ReplaceDataplaneCacheFromIter(iter func(func(k K)) error) error {
	return s.dt.ReplaceDataplaneCacheFromIter(func(f func(k K, v struct{})) error {
		return iter(func(k K) {
			f(k, struct{}{})
		})
	})
}

func (s *SetDeltaTracker[K]) AddDataplane(k K) {
	s.dt.SetDataplane(k, struct{}{})
}

func (s *SetDeltaTracker[K]) DeleteDataplane(k K) {
	s.dt.DeleteDataplane(k)
}

func (s *SetDeltaTracker[K]) ContainsDataplane(k K) bool {
	_, exists := s.dt.GetDataplane(k)
	return exists
}

func (s *SetDeltaTracker[K]) IterDataplane(f func(k K)) {
	s.dt.IterDataplane(func(k K, v struct{}) {
		f(k)
	})
}

func (s *SetDeltaTracker[K]) IterPendingUpdates(f func(k K) PendingChangeAction) {
	s.dt.IterPendingUpdates(func(k K, v struct{}) PendingChangeAction {
		return f(k)
	})
}

func (s *SetDeltaTracker[K]) IterPendingDeletions(f func(k K) PendingChangeAction) {
	s.dt.IterPendingDeletions(f)
}
