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

// SetDeltaTracker (conceptually) tracks the differences between two sets
// the "desired" set contains the members that we _want_ to be in the
// dataplane; the "dataplane" set contains the members that we think are
// _actually_ in the dataplane. The name "dataplane" set is intended to hint at
// its use but(!) this is a pure in-memory datastructure; it doesn't actually
// interact with the dataplane directly.
//
// The desired and dataplane sets can be updated directly via their
// SetXXX/DeleteXXX methods and they each have a corresponding IterXXX method to
// iterate over them.  The dataplane set has an additional
// ReplaceDataplaneCacheFromIter, which allows for the whole contents of the
// dataplane set to be replaced via an iterator; this is more efficient than
// doing an external iteration and Set/Delete calls.
//
// In addition to the desired and dataplane sets, the differences between them
// are tracked in two other sets: the "pending updates" set and the "pending
// deletions" set "Pending updates" contains all keys that are in the "desired"
// set but not in the dataplane set (or that have a different value in the
// desired set vs the dataplane set). "Pending deletions" contains keys that are
// in the dataplane set but not in the desired set.
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

func (s *SetDeltaTracker[K]) IterPendingUpdates(f func(k K) IterAction) {
	s.dt.IterPendingUpdates(func(k K, v struct{}) IterAction {
		return f(k)
	})
}

func (s *SetDeltaTracker[K]) IterPendingDeletions(f func(k K) IterAction) {
	s.dt.IterPendingDeletions(f)
}

func (s *SetDeltaTracker[K]) InSync() bool {
	return s.NumPendingDeletions() == 0 && s.NumPendingUpdates() == 0
}

func (s *SetDeltaTracker[K]) NumPendingUpdates() int {
	return len(s.dt.desiredUpdates)
}

func (s *SetDeltaTracker[K]) NumPendingDeletions() int {
	return len(s.dt.inDataplaneNotDesired)
}

func (s *SetDeltaTracker[K]) DeleteAllDataplane() {
	s.dt.DeleteAllDataplane()
}
