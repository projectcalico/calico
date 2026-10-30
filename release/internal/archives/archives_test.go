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
	"os/exec"
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

// Reads the archive back rather than the staging tree: the staging tree is
// deleted, and what users download is the only thing worth asserting.
func archiveContents(t *testing.T, path string) []string {
	t.Helper()
	out, err := exec.Command("tar", "-tzf", path).CombinedOutput()
	if err != nil {
		t.Fatalf("reading %s: %v\n%s", path, err, out)
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
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

func TestBuildPlacesEachContributorByName(t *testing.T) {
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
}

func TestBuildPlacesAnUnnamedContributorAtTheRoot(t *testing.T) {
	outputDir := testOutputDir(t)

	a := testArchive(outputDir, testContent{files: []string{"README.md"}})
	if err := Build(a); err != nil {
		t.Fatalf("Build() = %v", err)
	}
	want := []string{"README.md"}
	if got := archiveContents(t, Path(a)); !slices.Equal(got, want) {
		t.Errorf("archive contents:\n got %v\nwant %v", got, want)
	}
}

func TestBuildRemovesTheStagingTree(t *testing.T) {
	outputDir := testOutputDir(t)

	a := testArchive(outputDir, testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}})
	if err := Build(a); err != nil {
		t.Fatalf("Build() = %v", err)
	}
	if _, err := os.Stat(a.stagingDir()); !os.IsNotExist(err) {
		t.Errorf("staging dir %s survived the build", a.stagingDir())
	}
}

// A run killed before its cleanup leaves a staging tree behind. The next run
// must not archive it.
func TestBuildIgnoresALeftoverStagingTree(t *testing.T) {
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
}

// Building twice into the same output dir gives the same archive: a release
// retried after a failure must not ship a different tarball.
func TestBuildIsRepeatable(t *testing.T) {
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

// A failed rebuild must not leave the previous run's archive behind: a retried
// release would otherwise publish a stale tarball.
func TestBuildClearsTheArchiveWhenARebuildFails(t *testing.T) {
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

func TestBuildLogsTar(t *testing.T) {
	outputDir := testOutputDir(t)
	logs := filepath.Join(t.TempDir(), "logs")

	a := testArchive(outputDir, testContent{name: "manifests", to: manifestsDir, files: []string{"calico.yaml"}})
	if err := Build(a, WithRunner(&command.RealCommandRunner{}), WithLogsDir(logs)); err != nil {
		t.Fatalf("Build() = %v", err)
	}
	if _, err := os.Stat(filepath.Join(logs, buildStep, "tar.log")); err != nil {
		t.Errorf("tar log: %v", err)
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

// A runner that records what it ran and creates the files make would produce.
type windowsRunner struct {
	calls []string
	dist  string
	made  []string
}

func (w *windowsRunner) Run(name string, args, env []string) (string, error) {
	return w.RunInDir("", name, args, env)
}

func (w *windowsRunner) RunInDir(_, name string, args, _ []string) (string, error) {
	w.calls = append(w.calls, name+" "+strings.Join(args, " "))
	for _, f := range w.made {
		path := filepath.Join(w.dist, f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, []byte(f), 0o644); err != nil {
			return "", err
		}
	}
	return "", nil
}

func (w *windowsRunner) RunInDirToFile(dir, name string, args, env []string, _ string) (string, error) {
	return w.RunInDir(dir, name, args, env)
}

func (w *windowsRunner) RunInDirNoCapture(dir, name string, args, env []string) error {
	_, err := w.RunInDir(dir, name, args, env)
	return err
}

func (w *windowsRunner) RunNoCapture(name string, args, env []string) error {
	return w.RunInDirNoCapture("", name, args, env)
}

func windowsFixture(t *testing.T) (Archive, *windowsRunner) {
	t.Helper()
	root := t.TempDir()
	w := testWindowsArchive(root, testOutputDir(t))
	return w, &windowsRunner{
		dist: filepath.Join(root, windowsComponent, windowsDistDir),
		made: []string{WindowsFileName(testVersion), windowsScript},
	}
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
		for _, c := range runner.calls {
			if strings.Contains(c, target) {
				ran = true
			}
		}
		if !ran {
			t.Errorf("did not run %q, ran: %v", target, runner.calls)
		}
	}
}

// The install script is a file target with no prerequisites, so make skips it
// when one exists: a stale script must be cleared or the old version survives.
func TestBuildWindowsClearsAStaleInstallScript(t *testing.T) {
	w, runner := windowsFixture(t)
	stale := filepath.Join(w.RepoRoot, windowsComponent, windowsScriptTarget)
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The runner only writes the archive, so anything left is the stale file.
	runner.made = []string{WindowsFileName(testVersion)}

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
