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

//go:build fv

package github

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/distribution"
)

func TestReleasePublishRerun(t *testing.T) {
	// A release is re-run after a failure, so a second pass must not checksum the
	// sums file from the first, nor hand the same asset to the uploader twice.
	t.Run("a rerun is idempotent", func(t *testing.T) {
		dir := t.TempDir()
		for _, n := range []string{"release.tgz", "metadata.yaml"} {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// One service across both runs, so the second sees what the first attached.
		svc := &fakeReleases{}
		rels := testReleases(t, svc)

		var first string
		for run := range 2 {
			if err := distribution.SHA256Sums(dir); err != nil {
				t.Fatalf("run %d: SHA256Sums: %v", run, err)
			}
			svc.uploaded = nil
			d := Release{releases: rels, Tag: "v3.30.0", Draft: true}
			if err := d.Publish(context.Background(), dir); err != nil {
				t.Fatalf("run %d: Publish: %v", run, err)
			}
			slices.Sort(svc.uploaded)
			if got := slices.Compact(slices.Clone(svc.uploaded)); len(got) != len(svc.uploaded) {
				t.Errorf("run %d: an asset was uploaded twice: %v", run, svc.uploaded)
			}
			// The first run uploads everything; the second finds it all attached
			// and complete, so it resends nothing.
			var want []string
			if run == 0 {
				want = []string{distribution.SumsFileName, "metadata.yaml", "release.tgz"}
			}
			if !slices.Equal(svc.uploaded, want) {
				t.Errorf("run %d: uploaded %v, want %v", run, svc.uploaded, want)
			}
			bs, err := os.ReadFile(filepath.Join(dir, distribution.SumsFileName))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(bs), distribution.SumsFileName) {
				t.Errorf("run %d: the sums file checksums itself:\n%s", run, bs)
			}
			if run == 0 {
				first = string(bs)
			} else if string(bs) != first {
				t.Errorf("a second run changed the sums file:\nfirst:\n%s\nsecond:\n%s", first, bs)
			}
		}
	})
}
