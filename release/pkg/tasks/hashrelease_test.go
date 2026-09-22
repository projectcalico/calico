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

package tasks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/archives"
	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/manifests"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
)

const reformatVersion = "v3.30.0-0.dev-1-gabc"

// The reformats a product ships. Enterprise appends its own.
var reformats = []reformat{{
	name: "hashrelease",
	run:  ReformatHashrelease,
	// The windows zip and the OCP bundle are relocated alongside the charts.
	wantFiles: []string{
		filepath.Join(archives.WindowsHashreleaseDir(""), archives.WindowsFileName(reformatVersion)),
		filepath.Join(manifests.Dir(""), manifests.OCPBundleFileName),
	},
}}

// reformat is one product's reformat, and what it is expected to leave behind.
type reformat struct {
	name string
	run  func(*pinnedversion.Pin, string) error

	// wantFiles are the non-chart artifacts it relocates, relative to the
	// output directory.
	wantFiles []string
}

// want is every path the reformat must produce: the unversioned charts it
// serves, the versioned ones the build left, and the files it relocates.
func (r reformat) want() []string {
	out := append(chartPaths(charts.Dir(""), ""), chartPaths(charts.OutputDir(""), reformatVersion)...)
	return append(out, r.wantFiles...)
}

// stage writes a built tree: the charts where the build leaves them, plus the
// windows zip and the OCP bundle.
func (r reformat) stage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeFile(t, filepath.Join(archives.WindowsDir(dir), archives.WindowsFileName(reformatVersion)))
	writeFile(t, manifests.BundlePath(dir))
	// The manifests step has already made this by the time a reformat runs.
	if err := os.MkdirAll(manifests.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range charts.All() {
		writeFile(t, filepath.Join(charts.OutputDir(dir), charts.FileName(name, reformatVersion)))
	}
	return dir
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReformatLayout(t *testing.T) {
	for _, tc := range reformats {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.stage(t)
			if err := tc.run(reformatPin(), dir); err != nil {
				t.Fatalf("reformat: %v", err)
			}

			for _, rel := range tc.want() {
				if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
					t.Errorf("expected %s: %v", rel, err)
				}
			}
			// The unversioned charts are served from charts/ alone; a copy at
			// the top level would reach the checksums and the release assets.
			for _, rel := range chartPaths("", "") {
				if _, err := os.Stat(filepath.Join(dir, rel)); !os.IsNotExist(err) {
					t.Errorf("expected no %s, stat returned %v", rel, err)
				}
			}
		})
	}
}

// A skipped chart ships an incomplete release, so fail loudly.
func TestReformatFailsWhenAChartIsMissing(t *testing.T) {
	for _, tc := range reformats {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.stage(t)
			missing := charts.All()[0]
			if err := os.Remove(filepath.Join(charts.OutputDir(dir), charts.FileName(missing, reformatVersion))); err != nil {
				t.Fatal(err)
			}

			err := tc.run(reformatPin(), dir)
			if err == nil {
				t.Fatal("reformat = nil, want an error naming the missing chart")
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("expected the error to name %q, got %v", missing, err)
			}
		})
	}
}

func reformatPin() *pinnedversion.Pin {
	return &pinnedversion.Pin{ProductVersion: reformatVersion}
}

// chartPaths names every release chart in dir, at the given version.
func chartPaths(dir, version string) []string {
	out := make([]string, 0, len(charts.All()))
	for _, name := range charts.All() {
		out = append(out, filepath.Join(dir, charts.FileName(name, version)))
	}
	return out
}
