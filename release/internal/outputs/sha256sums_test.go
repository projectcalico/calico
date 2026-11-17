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
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/projectcalico/calico/release/internal/command"
)

func TestSHA256Sums(t *testing.T) {
	reply := func(command.Call) (string, error) { return "abc  a.tgz\ndef  b.tgz", nil }

	t.Run("writes the runner's output with names relative to dir", func(t *testing.T) {
		dir := t.TempDir()
		rec := &command.Recorder{Reply: reply}
		files := []string{filepath.Join(dir, "a.tgz"), filepath.Join(dir, "b.tgz")}
		if err := SHA256Sums(rec, files, dir); err != nil {
			t.Fatalf("SHA256Sums: %v", err)
		}
		want := []command.Call{{Name: "sha256sum", Args: []string{"a.tgz", "b.tgz"}, Dir: dir}}
		if diff := cmp.Diff(want, rec.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
		got, err := os.ReadFile(filepath.Join(dir, SumsFileName))
		if err != nil {
			t.Fatalf("reading sums: %v", err)
		}
		if string(got) != "abc  a.tgz\ndef  b.tgz" {
			t.Errorf("sums file = %q, want the runner's output", got)
		}
	})

	t.Run("replaces an earlier sums file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, SumsFileName)
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := SHA256Sums(&command.Recorder{Reply: reply}, []string{filepath.Join(dir, "a.tgz")}, dir); err != nil {
			t.Fatalf("SHA256Sums: %v", err)
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
		path := filepath.Join(dir, SumsFileName)
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
		rec := &command.Recorder{Reply: reply}
		if err := SHA256Sums(rec, nil, dir); err == nil {
			t.Fatal("SHA256Sums with no files succeeded")
		}
		if len(rec.Calls()) != 0 {
			t.Errorf("ran %v", rec.Calls())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("stat sums file: %v, want it removed", err)
		}
	})
}
