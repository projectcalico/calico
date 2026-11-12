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

package archives

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/command"
)

func TestBuildFlow(t *testing.T) {
	t.Run("logs tar", func(t *testing.T) {
		outputDir := testOutputDir(t)
		logs := filepath.Join(t.TempDir(), "logs")

		a := testArchive(outputDir, testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}})
		if err := Build(a, WithRunner(command.RealRunner), WithLogsDir(logs)); err != nil {
			t.Fatalf("Build() = %v", err)
		}
		if _, err := os.Stat(filepath.Join(logs, buildStep, "tar.log")); err != nil {
			t.Errorf("tar log: %v", err)
		}
	})

	t.Run("places each contributor by name", func(t *testing.T) {
		outputDir := testOutputDir(t)

		a := testArchive(outputDir,
			testContent{name: "images", to: imagesDir, files: []string{"node.tar"}},
			testContent{name: "calicoctl", to: filepath.Join(binDir, "calicoctl"), files: []string{"calicoctl-linux-amd64"}},
			testContent{name: "felix", to: binDir, files: []string{"calico-bpf"}},
			testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}},
		)
		if err := Build(a); err != nil {
			t.Fatalf("Build() = %v", err)
		}

		// The exact set, not each entry: content that is added, or that widens
		// what it stages, changes what users download.
		want := []string{
			"bin/calico-bpf",
			"bin/calicoctl/calicoctl-linux-amd64",
			"images/node.tar",
			"manifests/calico.yaml",
		}
		if got := archiveContents(t, Path(a)); !slices.Equal(got, want) {
			t.Errorf("archive contents:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("places an unnamed contributor at the root", func(t *testing.T) {
		outputDir := testOutputDir(t)

		a := testArchive(outputDir, testContent{files: []string{"README.md"}})
		if err := Build(a); err != nil {
			t.Fatalf("Build() = %v", err)
		}
		want := []string{"README.md"}
		if got := archiveContents(t, Path(a)); !slices.Equal(got, want) {
			t.Errorf("archive contents:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("removes the staging tree", func(t *testing.T) {
		outputDir := testOutputDir(t)

		a := testArchive(outputDir, testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}})
		if err := Build(a); err != nil {
			t.Fatalf("Build() = %v", err)
		}
		if _, err := os.Stat(a.stagingDir()); !os.IsNotExist(err) {
			t.Errorf("staging dir %s survived the build", a.stagingDir())
		}
	})

	// A run killed before its cleanup leaves a staging tree behind. The next run
	// must not archive it.
	t.Run("ignores a leftover staging tree", func(t *testing.T) {
		outputDir := testOutputDir(t)

		a := testArchive(outputDir, testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}})
		stale := filepath.Join(a.stagingDir(), manifestsDir)
		if err := os.MkdirAll(stale, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stale, "stale.yaml"), []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := Build(a); err != nil {
			t.Fatalf("Build() = %v", err)
		}
		want := []string{"manifests/calico.yaml"}
		if got := archiveContents(t, Path(a)); !slices.Equal(got, want) {
			t.Errorf("archive contents:\n got %v\nwant %v", got, want)
		}
	})

	// Building twice into the same output dir gives the same archive: a release
	// retried after a failure must not ship a different tarball.
	t.Run("is repeatable", func(t *testing.T) {
		outputDir := testOutputDir(t)

		a := testArchive(outputDir, testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}})
		if err := Build(a); err != nil {
			t.Fatalf("first Build() = %v", err)
		}
		first := archiveContents(t, Path(a))
		if err := Build(a); err != nil {
			t.Fatalf("second Build() = %v", err)
		}
		if second := archiveContents(t, Path(a)); !slices.Equal(first, second) {
			t.Errorf("rebuild changed the archive:\nfirst  %v\nsecond %v", first, second)
		}
	})

	// A failed rebuild must not leave the previous run's archive behind: a retried
	// release would otherwise publish a stale tarball.
	t.Run("clears the archive when a rebuild fails", func(t *testing.T) {
		outputDir := testOutputDir(t)
		good := testArchive(outputDir, testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}})
		if err := Build(good); err != nil {
			t.Fatalf("Build() = %v", err)
		}

		bad := good
		bad.Sources = []Contributor{testContent{name: "manifests", err: errors.New("nothing built")}}
		if err := Build(bad); err == nil {
			t.Fatal("Build() = nil, want an error")
		}
		if _, err := os.Stat(Path(good)); !os.IsNotExist(err) {
			t.Error("a failed rebuild left the previous archive behind")
		}
	})
}

// Reads the archive back rather than the staging tree: the staging tree is
// deleted, and what users download is the only thing worth asserting.
func archiveContents(t *testing.T, path string) []string {
	t.Helper()
	out, err := command.RealRunner.Run("tar", []string{"-tzf", path})
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var files []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}
		// The single top-level directory is an artifact of how tar is called,
		// not part of the layout under test.
		_, rel, _ := strings.Cut(line, "/")
		files = append(files, rel)
	}
	slices.Sort(files)
	return files
}
