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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/utils"
)

func TestPublishFlow(t *testing.T) {
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
		files, err := utils.TopLevelFiles(dir, SumsFileName)
		if err != nil {
			t.Fatalf("topLevelFiles: %v", err)
		}
		if _, err := sha256Sums(dir, files); err != nil {
			t.Fatalf("sha256Sums: %v", err)
		}
		bs, err := os.ReadFile(filepath.Join(dir, SumsFileName))
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
