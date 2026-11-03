// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ipsets

import "testing"

// drainMust pops the whole must tier into a slice, preserving pop order.
func (q *resyncQueue) drainMust() []string {
	var out []string
	for {
		name, ok := q.PopMust()
		if !ok {
			return out
		}
		out = append(out, name)
	}
}

// drainBackground pops the whole background tier into a slice, preserving pop order.
func (q *resyncQueue) drainBackground() []string {
	var out []string
	for {
		name, ok := q.PopBackground()
		if !ok {
			return out
		}
		out = append(out, name)
	}
}

func TestResyncQueue_FIFOPerTier(t *testing.T) {
	q := newResyncQueue()
	q.Add("a", resyncPriBackground)
	q.Add("b", resyncPriBackground)
	q.Add("c", resyncPriMust)
	q.Add("d", resyncPriMust)

	if got, want := q.Len(), 4; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}
	if got, want := q.MustLen(), 2; got != want {
		t.Fatalf("MustLen() = %d, want %d", got, want)
	}

	assertOrder(t, "must", q.drainMust(), "c", "d")
	assertOrder(t, "background", q.drainBackground(), "a", "b")
}

func TestResyncQueue_DedupeKeepsPosition(t *testing.T) {
	q := newResyncQueue()
	q.Add("a", resyncPriBackground)
	q.Add("b", resyncPriBackground)
	// Re-adding a at the same priority must not move it behind b.
	q.Add("a", resyncPriBackground)

	if got, want := q.Len(), 2; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}
	assertOrder(t, "background", q.drainBackground(), "a", "b")
}

func TestResyncQueue_PromotionMovesToMustTail(t *testing.T) {
	q := newResyncQueue()
	q.Add("a", resyncPriBackground)
	q.Add("b", resyncPriBackground)
	q.Add("x", resyncPriMust)
	// Promote a: it should leave the background tier and land at the must tail,
	// behind the already-queued x.
	q.Add("a", resyncPriMust)

	assertOrder(t, "must", q.drainMust(), "x", "a")
	assertOrder(t, "background", q.drainBackground(), "b")
}

func TestResyncQueue_NoDemotion(t *testing.T) {
	q := newResyncQueue()
	q.Add("a", resyncPriMust)
	// A background add of a must-tier entry is ignored.
	q.Add("a", resyncPriBackground)

	if got := q.drainBackground(); len(got) != 0 {
		t.Fatalf("background tier = %v, want empty", got)
	}
	assertOrder(t, "must", q.drainMust(), "a")
}

func TestResyncQueue_Remove(t *testing.T) {
	q := newResyncQueue()
	q.Add("a", resyncPriBackground)
	q.Add("b", resyncPriMust)
	q.Remove("a")
	q.Remove("b")
	q.Remove("missing") // no-op

	if got, want := q.Len(), 0; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}
	if _, ok := q.PopMust(); ok {
		t.Fatal("PopMust() returned an entry after Remove")
	}
	if _, ok := q.PopBackground(); ok {
		t.Fatal("PopBackground() returned an entry after Remove")
	}
}

func TestResyncQueue_PopOnEmpty(t *testing.T) {
	q := newResyncQueue()
	if name, ok := q.PopMust(); ok || name != "" {
		t.Fatalf("PopMust() on empty = (%q, %v), want (\"\", false)", name, ok)
	}
	if name, ok := q.PopBackground(); ok || name != "" {
		t.Fatalf("PopBackground() on empty = (%q, %v), want (\"\", false)", name, ok)
	}
}

func TestResyncQueue_Clear(t *testing.T) {
	q := newResyncQueue()
	q.Add("a", resyncPriBackground)
	q.Add("b", resyncPriMust)
	q.Clear()

	if got, want := q.Len(), 0; got != want {
		t.Fatalf("Len() after Clear = %d, want %d", got, want)
	}
	// The queue must still be usable after a Clear.
	q.Add("c", resyncPriMust)
	assertOrder(t, "must", q.drainMust(), "c")
}

func assertOrder(t *testing.T, tier string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s tier = %v, want %v", tier, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s tier = %v, want %v", tier, got, want)
		}
	}
}
