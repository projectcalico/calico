// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package steps

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDigestsByRepo(t *testing.T) {
	got := DigestsByRepo([]string{
		"quay.io/calico/node@sha256:aaa",
		"quay.io/calico/node@sha256:bbb",
		"quay.io/calico/cni@sha256:ccc",
		"not-a-ref",
	})
	// One repo, two tags, two digests: a tag counts as published when its
	// digest is among them.
	if len(got["quay.io/calico/node"]) != 2 {
		t.Errorf("node digests = %v, want 2", got["quay.io/calico/node"])
	}
	if _, ok := got["quay.io/calico/cni"]["sha256:ccc"]; !ok {
		t.Errorf("cni digest missing from %v", got)
	}
	if len(got) != 2 {
		t.Errorf("expected the malformed ref to be dropped, got %v", got)
	}
}

func TestGoLimit(t *testing.T) {
	const items = 20

	t.Run("caps what runs at once", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			limit    int
			wantPeak int
			minPeak  int
		}{
			{name: "a few at a time", limit: 4, wantPeak: 4, minPeak: 2},
			{name: "one at a time", limit: 1, wantPeak: 1, minPeak: 1},
			{name: "zero means no limit", limit: 0, wantPeak: items, minPeak: 2},
			{name: "negative means no limit", limit: -1, wantPeak: items, minPeak: 2},
			{name: "a limit above the item count", limit: items * 2, wantPeak: items, minPeak: 2},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var mu sync.Mutex
				var inFlight, peak int

				out, err := GoLimit(make([]int, items), tc.limit, func(int) (int, error) {
					mu.Lock()
					inFlight++
					peak = max(peak, inFlight)
					mu.Unlock()
					time.Sleep(time.Millisecond)
					mu.Lock()
					inFlight--
					mu.Unlock()
					return 1, nil
				})
				if err != nil {
					t.Fatalf("GoLimit: %v", err)
				}
				if len(out) != items {
					t.Errorf("got %d results, want %d", len(out), items)
				}
				if peak > tc.wantPeak {
					t.Errorf("peak concurrency %d, want at most %d", peak, tc.wantPeak)
				}
				// Without a lower bound, serialising everything would pass.
				if peak < tc.minPeak {
					t.Errorf("peak concurrency %d, want at least %d", peak, tc.minPeak)
				}
			})
		}
	})

	t.Run("runs every item whatever the limit", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			limit int
		}{
			{name: "bounded", limit: 2},
			{name: "unbounded", limit: 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var ran atomic.Int32
				_, err := GoLimit([]int{1, 2, 3, 4, 5}, tc.limit, func(i int) (int, error) {
					ran.Add(1)
					if i%2 == 0 {
						return 0, fmt.Errorf("item %d", i)
					}
					return i, nil
				})
				if err == nil {
					t.Fatal("expected the failures reported")
				}
				for _, want := range []string{"item 2", "item 4"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q missing %q", err, want)
					}
				}
				if got := ran.Load(); got != 5 {
					t.Errorf("ran %d items, want all 5", got)
				}
			})
		}
	})

	t.Run("keeps input order", func(t *testing.T) {
		got, err := Go([]int{1, 2, 3}, func(i int) (string, error) {
			return fmt.Sprintf("v%d", i), nil
		})
		if err != nil {
			t.Fatalf("Go: %v", err)
		}
		if want := []string{"v1", "v2", "v3"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("keeps a success at its index beside failures", func(t *testing.T) {
		got, err := Go([]int{1, 2, 3}, func(i int) (string, error) {
			if i%2 == 1 {
				return "", fmt.Errorf("item %d failed", i)
			}
			return "ok", nil
		})
		if err == nil {
			t.Fatal("expected the failures to be reported")
		}
		if got[1] != "ok" {
			t.Errorf("expected the successful item kept at its index, got %v", got)
		}
	})
}
