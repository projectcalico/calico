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

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// SetDeltaTracker is a light wrapper around DeltaTracker, so we're really just
// testing that the wrapper calls the right methods.

func TestDeltaSet_DesiredSet(t *testing.T) {
	ds := NewSetDeltaTracker[int]()
	ds.Desired().Add(1)
	ds.Desired().Add(2)

	desired := set.New[int]()
	ds.Desired().Iter(func(k int) {
		if desired.Contains(k) {
			t.Errorf("Iter returned duplicate key: %v", k)
		}
		desired.Add(k)
	})

	if !ds.Desired().Contains(1) {
		t.Errorf("ContainsDesired(1) should be true")
	}
	if ds.Desired().Contains(3) {
		t.Errorf("ContainsDesired(3) should be false")
	}
	ds.Desired().Delete(1)
	if ds.Desired().Contains(1) {
		t.Errorf("ContainsDesired(1) should be false after removing that item")
	}
	if !ds.Desired().Contains(2) {
		t.Errorf("ContainsDesired(2) should be true")
	}
	ds.Desired().DeleteAll()
	if ds.Desired().Contains(2) {
		t.Errorf("ContainsDesired(2) should be false after DeleteAll")
	}
}

func TestDeltaSet_DataplaneSet(t *testing.T) {
	ds := NewSetDeltaTracker[int]()
	ds.Dataplane().Add(1)
	ds.Dataplane().Add(2)

	dp := set.New[int]()
	ds.Dataplane().Iter(func(k int) {
		if dp.Contains(k) {
			t.Errorf("Iter returned duplicate key: %v", k)
		}
		dp.Add(k)
	})

	if !ds.Dataplane().Contains(1) {
		t.Errorf("ContainsDataplane(1) should be true")
	}
	if ds.Dataplane().Contains(3) {
		t.Errorf("ContainsDataplane(3) should be false")
	}
	ds.Dataplane().Delete(1)
	if ds.Dataplane().Contains(1) {
		t.Errorf("ContainsDataplane(1) should be false after removing that item")
	}
	if !ds.Dataplane().Contains(2) {
		t.Errorf("ContainsDataplane(2) should be true")
	}
}

func TestDeltaSet_Resync(t *testing.T) {
	RegisterTestingT(t)
	ds := NewSetDeltaTracker[int]()
	ds.Desired().Add(1)
	ds.Desired().Add(2)

	err := ds.Dataplane().ReplaceFromIter(func(f func(k int)) error {
		f(1)
		f(3)
		return nil
	})
	if err != nil {
		t.Errorf("Unexpected error from ReplaceAllIter: %v", err)
	}

	updates := set.New[int]()
	ds.IterPendingUpdates(func(k int) IterAction {
		if updates.Contains(k) {
			t.Errorf("IterPendingUpdates returned duplicate key: %v", k)
		}
		updates.Add(k)
		return IterActionUpdateDataplane
	})
	Expect(updates).To(Equal(set.From(2)))

	deletions := set.New[int]()
	ds.IterPendingDeletions(func(k int) IterAction {
		if deletions.Contains(k) {
			t.Errorf("IterPendingDeletions returned duplicate key: %v", k)
		}
		deletions.Add(k)
		return IterActionUpdateDataplane
	})
	Expect(deletions).To(Equal(set.From(3)))
}

func TestDeltaSet_ResyncError(t *testing.T) {
	RegisterTestingT(t)
	ds := NewSetDeltaTracker[int]()

	err := ds.Dataplane().ReplaceFromIter(func(f func(k int)) error {
		f(1)
		f(3)
		return fmt.Errorf("dummy error")
	})
	if err == nil {
		t.Errorf("Missing error from ReplaceAllIter")
	}
}
