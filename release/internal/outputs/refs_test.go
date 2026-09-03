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

package outputs

import (
	"fmt"
	"slices"
	"sync"
	"testing"
)

func TestRefsWriterAppends(t *testing.T) {
	base := t.TempDir()
	w, err := NewRefsWriter(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("NewRefsWriter: %v", err)
	}
	if err := w.Add("quay.io/calico/node@sha256:aaa"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := w.Add("quay.io/calico/node@sha256:bbb", "quay.io/calico/node@sha256:ccc"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := ReadRefs(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("ReadRefs: %v", err)
	}
	want := []string{
		"quay.io/calico/node@sha256:aaa",
		"quay.io/calico/node@sha256:bbb",
		"quay.io/calico/node@sha256:ccc",
	}
	if !slices.Equal(got, want) {
		t.Errorf("refs\n got %v\nwant %v", got, want)
	}
}

// A resumed run must add to the record, not replace it.
func TestRefsWriterSurvivesReopen(t *testing.T) {
	base := t.TempDir()
	first, err := NewRefsWriter(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("NewRefsWriter: %v", err)
	}
	if err := first.Add("quay.io/calico/node@sha256:aaa"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	second, err := NewRefsWriter(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("NewRefsWriter (resumed): %v", err)
	}
	if err := second.Add("quay.io/calico/whisker@sha256:bbb"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := ReadRefs(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("ReadRefs: %v", err)
	}
	want := []string{"quay.io/calico/node@sha256:aaa", "quay.io/calico/whisker@sha256:bbb"}
	if !slices.Equal(got, want) {
		t.Errorf("a resumed run lost the earlier record\n got %v\nwant %v", got, want)
	}
}

// A resumed run re-appends refs it already published.
func TestReadRefsDropsDuplicates(t *testing.T) {
	base := t.TempDir()
	w, err := NewRefsWriter(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("NewRefsWriter: %v", err)
	}
	for range 3 {
		if err := w.Add("quay.io/calico/node@sha256:aaa", "quay.io/calico/whisker@sha256:bbb"); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	got, err := ReadRefs(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("ReadRefs: %v", err)
	}
	want := []string{"quay.io/calico/node@sha256:aaa", "quay.io/calico/whisker@sha256:bbb"}
	if !slices.Equal(got, want) {
		t.Errorf("refs\n got %v\nwant %v", got, want)
	}
}

// Components publish concurrently; interleaved writes must not corrupt lines.
func TestRefsWriterConcurrent(t *testing.T) {
	base := t.TempDir()
	w, err := NewRefsWriter(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("NewRefsWriter: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := w.Add(fmt.Sprintf("quay.io/calico/img@sha256:%03d", i)); err != nil {
				t.Errorf("Add: %v", err)
			}
		}(i)
	}
	wg.Wait()

	got, err := ReadRefs(base, "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("ReadRefs: %v", err)
	}
	if len(got) != n {
		t.Fatalf("expected %d refs, got %d: %v", n, len(got), got)
	}
	for i := range n {
		want := fmt.Sprintf("quay.io/calico/img@sha256:%03d", i)
		if !slices.Contains(got, want) {
			t.Errorf("lost ref %s", want)
		}
	}
}

// A step that has not run is not an error.
func TestReadRefsMissingFile(t *testing.T) {
	got, err := ReadRefs(t.TempDir(), "images-publish", "v3.30.0")
	if err != nil {
		t.Fatalf("ReadRefs: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no refs, got %v", got)
	}
}
