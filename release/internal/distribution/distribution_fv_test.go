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

package distribution

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ghapi "github.com/google/go-github/v53/github"

	gh "github.com/projectcalico/calico/release/internal/github"
)

func TestPublishFlow(t *testing.T) {
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
		svc := &fakeReleaseService{draft: &ghapi.RepositoryRelease{ID: ghapi.Int64(1), Draft: ghapi.Bool(true)}}
		rels, err := gh.NewReleases(gh.Repo{Org: "projectcalico", Name: "calico"}, svc)
		if err != nil {
			t.Fatal(err)
		}

		var first string
		for run := range 2 {
			if err := SHA256Sums(dir); err != nil {
				t.Fatalf("run %d: SHA256Sums: %v", run, err)
			}
			svc.uploaded = nil
			d := GithubRelease{releases: rels, Tag: "v3.30.0", Draft: true}
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
				want = []string{sumsFileName, "metadata.yaml", "release.tgz"}
			}
			if !slices.Equal(svc.uploaded, want) {
				t.Errorf("run %d: uploaded %v, want %v", run, svc.uploaded, want)
			}
			bs, err := os.ReadFile(filepath.Join(dir, sumsFileName))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(bs), sumsFileName) {
				t.Errorf("run %d: the sums file checksums itself:\n%s", run, bs)
			}
			if run == 0 {
				first = string(bs)
			} else if string(bs) != first {
				t.Errorf("a second run changed the sums file:\nfirst:\n%s\nsecond:\n%s", first, bs)
			}
		}
	})

	// A sums file holding absolute paths verifies nowhere but the machine that
	// built it, so the names must stay relative to the release directory.
	t.Run("writes names relative to the directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "charts"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"release.tgz", "metadata.yaml", "charts/index.yaml"} {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		files, err := topLevelFiles(dir)
		if err != nil {
			t.Fatalf("topLevelFiles: %v", err)
		}
		if _, err := sha256Sums(dir, files); err != nil {
			t.Fatalf("sha256Sums: %v", err)
		}
		bs, err := os.ReadFile(filepath.Join(dir, sumsFileName))
		if err != nil {
			t.Fatal(err)
		}
		got := string(bs)
		for _, want := range []string{"  release.tgz", "  metadata.yaml"} {
			if !strings.Contains(got, want) {
				t.Errorf("expected %q, got:\n%s", want, got)
			}
		}
		if strings.Contains(got, dir) {
			t.Errorf("an absolute path was written:\n%s", got)
		}
		if strings.Contains(got, "charts") {
			t.Errorf("a directory was checksummed:\n%s", got)
		}
	})
}
