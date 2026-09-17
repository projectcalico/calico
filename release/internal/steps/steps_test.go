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
	"testing"
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

// Results are indexed, so a slow item cannot reorder the ones after it.
func TestGoKeepsInputOrder(t *testing.T) {
	got, err := Go([]int{1, 2, 3}, func(i int) (string, error) {
		return fmt.Sprintf("v%d", i), nil
	})
	if err != nil {
		t.Fatalf("ForEach: %v", err)
	}
	if want := []string{"v1", "v2", "v3"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// One failure must not hide the others, nor discard the results that worked.
func TestGoCollectsEveryError(t *testing.T) {
	got, err := Go([]int{1, 2, 3}, func(i int) (string, error) {
		if i%2 == 1 {
			return "", fmt.Errorf("item %d failed", i)
		}
		return "ok", nil
	})
	if err == nil {
		t.Fatal("expected the failures to be reported")
	}
	for _, want := range []string{"item 1", "item 3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected %q in %v", want, err)
		}
	}
	if got[1] != "ok" {
		t.Errorf("expected the successful item kept at its index, got %v", got)
	}
}
