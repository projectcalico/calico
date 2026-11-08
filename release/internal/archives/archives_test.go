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

package archives

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/command"
)

const testVersion = "v1.2.3"

const (
	binDir       = "bin"
	imagesDir    = "images"
	manifestsDir = "manifests"
)

// A release's output dir sits inside a parent the staging tree shares, so the
// two are siblings.
func testOutputDir(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "output", "upload")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// A valid archive for a test that is not exercising validation. A var so a
// product whose validate() requires more can fill it in.
var testArchive = func(outputDir string, sources ...Contributor) Archive {
	return Archive{Version: testVersion, OutputDir: outputDir, Sources: sources}
}

// A valid archive for the verb that builds rather than stages.
var testWindowsArchive = func(repoRoot, outputDir string) Archive {
	return Archive{Version: testVersion, RepoRoot: repoRoot, OutputDir: outputDir}
}

// Writes the files it is given, so a test states what reaches the archive
// without a real source tree.
type testContent struct {
	name  string
	to    string
	files []string
	err   error
}

func (c testContent) Name() string { return c.name }

func (c testContent) Contribute(dir string) error {
	if c.err != nil {
		return c.err
	}
	for _, name := range c.files {
		path := filepath.Join(dir, c.to, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// One contributor failing fails the build: a partial archive must not ship.
func TestBuildFailsWhenAContributorFails(t *testing.T) {
	outputDir := testOutputDir(t)

	a := testArchive(outputDir,
		testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}},
		testContent{name: "felix", to: binDir, err: errors.New("nothing built")},
	)
	if err := Build(a); err == nil {
		t.Error("Build() = nil, want an error when a contributor fails")
	}
	if _, err := os.Stat(Path(a)); !os.IsNotExist(err) {
		t.Error("a failed build left an archive behind")
	}
}

// Path reads the name through FileName rather than spelling it, so replacing
// FileName is enough for a product that names its archive differently.
func TestPathNamesTheArchiveOnce(t *testing.T) {
	original := FileName
	t.Cleanup(func() { FileName = original })
	FileName = func(Archive) string { return "renamed" }

	a := Archive{Version: testVersion, OutputDir: "/out"}
	if got, want := Path(a), filepath.Join("/out", "renamed.tgz"); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

func TestFileNameUsesTheVersion(t *testing.T) {
	a := Archive{Version: testVersion, OutputDir: "/out"}
	if got, want := FileName(a), "release-"+testVersion; got != want {
		t.Errorf("FileName() = %q, want %q", got, want)
	}
}

func TestBuildValidates(t *testing.T) {
	outputDir := testOutputDir(t)
	content := []Contributor{testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}}}

	// The message is asserted, not just that it failed: an archive with nothing
	// to stage fails anyway, so "an error" would pass with no validation at all.
	for name, tc := range map[string]struct {
		archive Archive
		want    string
	}{
		"no version":      {Archive{OutputDir: outputDir, Sources: content}, "no version"},
		"no output dir":   {Archive{Version: testVersion, Sources: content}, "no output directory"},
		"no sources":      {Archive{Version: testVersion, OutputDir: outputDir}, "no content specified"},
		"nil contributor": {Archive{Version: testVersion, OutputDir: outputDir, Sources: []Contributor{nil}}, "nothing to contribute"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Build(tc.archive)
			if err == nil {
				t.Fatalf("Build() = nil, want an error for %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Build() = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Staging nothing is a release missing a component, not a success: the copy
// skips non-regular files, so an empty result would otherwise pass silently.
func TestDirSourceFailsWhenItStagesNothing(t *testing.T) {
	from := t.TempDir()
	if err := os.WriteFile(filepath.Join(from, "calico-felix"), []byte("felix"), 0o644); err != nil {
		t.Fatal(err)
	}

	d := DirSource{
		To:     binDir,
		From:   from,
		Filter: func(_, _, relPath string) bool { return relPath == "calico-bpf" },
	}
	if err := d.Contribute(t.TempDir()); err == nil {
		t.Error("Contribute() = nil, want an error when nothing is staged")
	}
}

// A filter matching a base name would pull a whole subdirectory in with it.
func TestDirSourceFilterMatchesTheWholeRelativePath(t *testing.T) {
	from := t.TempDir()
	for _, name := range []string{"calico-bpf", "bpf/calico-bpf"} {
		path := filepath.Join(from, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	dest := t.TempDir()
	d := DirSource{
		To:     binDir,
		From:   from,
		Filter: func(_, _, relPath string) bool { return relPath == "calico-bpf" },
	}
	if err := d.Contribute(dest); err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if want := []string{"bin/calico-bpf"}; !slices.Equal(stagedFiles(t, dest), want) {
		t.Errorf("staged %v, want %v", stagedFiles(t, dest), want)
	}
}

// The whole directory when no filter picks files out of it.
func TestDirSourceWithNoFilterTakesEverything(t *testing.T) {
	from := t.TempDir()
	for _, name := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(from, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	dest := t.TempDir()
	if err := (DirSource{To: binDir, From: from}).Contribute(dest); err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	want := []string{"bin/one", "bin/two"}
	if got := stagedFiles(t, dest); !slices.Equal(got, want) {
		t.Errorf("staged %v, want %v", got, want)
	}
}

func stagedFiles(t *testing.T, dir string) []string {
	t.Helper()
	var got []string
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		got = append(got, rel)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	return got
}

// windowsFixture's runner creates the made files where make would, defaulting
// to the archive and the install script.
func windowsFixture(t *testing.T, made ...string) (Archive, *command.Recorder) {
	t.Helper()
	root := t.TempDir()
	w := testWindowsArchive(root, testOutputDir(t))
	if len(made) == 0 {
		made = []string{WindowsFileName(testVersion), windowsScript}
	}
	dist := filepath.Join(root, windowsComponent, windowsDistDir)
	return w, &command.Recorder{Reply: func(command.Call) (string, error) {
		for _, f := range made {
			path := filepath.Join(dist, f)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(path, []byte(f), 0o644); err != nil {
				return "", err
			}
		}
		return "", nil
	}}
}

func TestBuildWindowsPlacesBothFilesInTheOutputDir(t *testing.T) {
	w, runner := windowsFixture(t)
	if err := BuildWindows(w, WithRunner(runner)); err != nil {
		t.Fatalf("BuildWindows() = %v", err)
	}
	for dir, name := range map[string]string{
		WindowsDir(w.OutputDir):       WindowsFileName(testVersion),
		WindowsScriptDir(w.OutputDir): windowsScript,
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBuildWindowsRunsBothTargets(t *testing.T) {
	w, runner := windowsFixture(t)
	if err := BuildWindows(w, WithRunner(runner)); err != nil {
		t.Fatalf("BuildWindows() = %v", err)
	}
	for _, target := range []string{windowsArchiveTarget, windowsScriptTarget} {
		var ran bool
		for _, c := range runner.Calls() {
			if slices.Contains(c.Args, target) {
				ran = true
			}
		}
		if !ran {
			t.Errorf("did not run %q, ran: %v", target, runner.Calls())
		}
	}
}

// The install script is a file target with no prerequisites, so make skips it
// when one exists: a stale script must be cleared or the old version survives.
func TestBuildWindowsClearsAStaleInstallScript(t *testing.T) {
	// The runner only writes the archive, so anything left is the stale file.
	w, runner := windowsFixture(t, WindowsFileName(testVersion))
	stale := filepath.Join(w.RepoRoot, windowsComponent, windowsScriptTarget)
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BuildWindows(w, WithRunner(runner)); err == nil {
		t.Error("BuildWindows() = nil, want an error when the script was not rebuilt")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("the stale install script survived")
	}
}

// An option that only implements WindowsOption must still reach the verb.
// WithRunner and WithLogsDir satisfy both interfaces, so they would pass even
// if applyTo had no Windows arm.
type windowsOnlyOption func(*settings) error

func (f windowsOnlyOption) applyWindows(s *settings) error { return f(s) }

func TestWindowsOnlyOptionsAreApplied(t *testing.T) {
	var applied bool
	opt := windowsOnlyOption(func(*settings) error {
		applied = true
		return nil
	})
	w, runner := windowsFixture(t)
	if err := BuildWindows(w, WithRunner(runner), opt); err != nil {
		t.Fatalf("BuildWindows() = %v", err)
	}
	if !applied {
		t.Error("a Windows-only option was not applied")
	}
}

func TestBuildWindowsValidates(t *testing.T) {
	out := testOutputDir(t)
	// The message is asserted, not just that it failed: without a repo root the
	// build fails anyway, so "an error" would pass with no validation at all.
	for name, tc := range map[string]struct {
		archive Archive
		want    string
	}{
		"no repo root":  {Archive{Version: testVersion, OutputDir: out}, "no repository root"},
		"no version":    {Archive{RepoRoot: t.TempDir(), OutputDir: out}, "no version"},
		"no output dir": {Archive{RepoRoot: t.TempDir(), Version: testVersion}, "no output directory"},
	} {
		t.Run(name, func(t *testing.T) {
			err := BuildWindows(tc.archive)
			if err == nil {
				t.Fatalf("BuildWindows() = nil, want an error for %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("BuildWindows() = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}
