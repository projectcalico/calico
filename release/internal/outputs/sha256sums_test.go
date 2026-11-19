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
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/fsutil"
)

func TestSHA256Sums(t *testing.T) {
	reply := func(command.Call) (string, error) { return "abc  a.tgz\ndef  metadata.yaml", nil }
	write := func(t *testing.T, dir string, names ...string) {
		t.Helper()
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("writes the runner's output with names relative to dir", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "a.tgz", MetadataFileName)
		rec := &command.Recorder{Reply: reply}
		if err := SHA256Sums(rec, dir, fsutil.DirFiles); err != nil {
			t.Fatalf("SHA256Sums: %v", err)
		}
		want := []command.Call{{Name: "sha256sum", Args: []string{"a.tgz", MetadataFileName}, Dir: dir}}
		if diff := cmp.Diff(want, rec.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
		got, err := os.ReadFile(filepath.Join(dir, SumsFileName))
		if err != nil {
			t.Fatalf("reading sums: %v", err)
		}
		if string(got) != "abc  a.tgz\ndef  metadata.yaml" {
			t.Errorf("sums file = %q, want the runner's output", got)
		}
	})

	t.Run("replaces an earlier sums file without checksumming it", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "a.tgz", MetadataFileName)
		path := filepath.Join(dir, SumsFileName)
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
		rec := &command.Recorder{Reply: reply}
		if err := SHA256Sums(rec, dir, fsutil.DirFiles); err != nil {
			t.Fatalf("SHA256Sums: %v", err)
		}
		if calls := rec.Calls(); len(calls) != 1 || slices.Contains(calls[0].Args, SumsFileName) {
			t.Errorf("calls = %v, want one leaving out %s", calls, SumsFileName)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading sums: %v", err)
		}
		if string(got) == "stale" {
			t.Error("the earlier sums file was kept")
		}
	})

	t.Run("fails with no files and leaves no sums file", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, SumsFileName)
		rec := &command.Recorder{Reply: reply}
		if err := SHA256Sums(rec, dir, fsutil.DirFiles); err == nil {
			t.Fatal("SHA256Sums with no files succeeded")
		}
		if len(rec.Calls()) != 0 {
			t.Errorf("ran %v", rec.Calls())
		}
		if _, err := os.Stat(filepath.Join(dir, SumsFileName)); !os.IsNotExist(err) {
			t.Errorf("stat sums file: %v, want it removed", err)
		}
	})
}
