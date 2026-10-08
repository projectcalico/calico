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

package binaries

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/projectcalico/calico/release/internal/archives"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/utils"
)

// fakeRunner records every invocation and can fail a command a set number of
// times before succeeding, to exercise the retry.
type fakeRunner struct {
	mu    sync.Mutex
	calls []call
	// failures maps a component to how many times its build should fail.
	failures map[string]int
}

type call struct {
	name string
	args []string
	env  []string
	// logPath is empty when output was captured in memory.
	logPath string
}

func (f *fakeRunner) RunInDir(_, name string, args, env []string) (string, error) {
	return f.record(name, args, env, "")
}

func (f *fakeRunner) RunInDirToFile(_, name string, args, env []string, logPath string) (string, error) {
	return f.record(name, args, env, logPath)
}

func (f *fakeRunner) Run(name string, args, env []string) (string, error) {
	return f.record(name, args, env, "")
}

func (f *fakeRunner) record(name string, args, env []string, logPath string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{name: name, args: slices.Clone(args), env: slices.Clone(env), logPath: logPath})
	component := componentOf(args)
	if n, ok := f.failures[component]; ok && n > 0 {
		f.failures[component] = n - 1
		return "boom", fmt.Errorf("command failed")
	}
	return "ok", nil
}

func (f *fakeRunner) RunNoCapture(string, []string, []string) error              { return nil }
func (f *fakeRunner) RunInDirNoCapture(string, string, []string, []string) error { return nil }

// Reads the component out of `make -C <root>/<component> <target>`.
func componentOf(args []string) string {
	if len(args) < 2 || args[0] != "-C" {
		return ""
	}
	return filepath.Base(args[1])
}

func (f *fakeRunner) invocations() []string {
	var out []string
	for _, c := range f.calls {
		if c.name != "make" || len(c.args) < 3 {
			continue
		}
		out = append(out, componentOf(c.args)+" "+strings.Join(c.args[2:], " "))
	}
	slices.Sort(out)
	return out
}

// Neutral fixtures: the package takes its builders as data, so no product's
// real component names belong here.
func testBuilders(outputDir string) []Builder {
	return []Builder{
		releaseBinaries{name: "alpha", target: "build-all", outputDir: outputDir},
		releaseBinaries{name: "beta", target: "release-build"},
	}
}

func writeBinary(t *testing.T, repoRoot, component, name string) {
	t.Helper()
	dir := sourceDir(repoRoot, component)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestBuildRunsEveryBuildersTarget(t *testing.T) {
	f := &fakeRunner{}
	if err := Build("/repo", "v1.2.3", testBuilders(""), WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := []string{"alpha build-all", "beta release-build"}
	if got := f.invocations(); !slices.Equal(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
}

func TestBuildRunsEachTargetInItsComponentDirectory(t *testing.T) {
	f := &fakeRunner{}
	if err := Build("/repo", "v1.2.3", testBuilders(""), WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, c := range f.calls {
		want := filepath.Join("/repo", componentOf(c.args))
		if c.args[1] != want {
			t.Errorf("ran make in %q, want %q", c.args[1], want)
		}
	}
}

func TestBuildPassesTheVersion(t *testing.T) {
	f := &fakeRunner{}
	if err := Build("/repo", "v1.2.3", testBuilders(""), WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := utils.Env(utils.EnvVersion, "v1.2.3")
	for _, c := range f.calls {
		if !slices.Contains(c.env, want) {
			t.Errorf("call %v missing %q", c.args, want)
		}
	}
}

// A builder's own environment reaches only its target.
func TestBuildPassesABuildersEnv(t *testing.T) {
	f := &fakeRunner{}
	builders := []Builder{
		e2eBinaries{arches: []string{"amd64"}},
		releaseBinaries{name: "alpha", target: "build-all"},
	}
	if err := Build("/repo", "v1.2.3", builders, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := utils.Env(utils.EnvArches, "amd64")
	for _, c := range f.calls {
		if got := slices.Contains(c.env, want); got != (componentOf(c.args) == E2EComponent) {
			t.Errorf("%s built with %q = %v", componentOf(c.args), want, got)
		}
	}
}

// One builder failing must not hide the rest.
func TestBuildReportsEveryFailingBuilder(t *testing.T) {
	f := &fakeRunner{failures: map[string]int{"alpha": 99, "beta": 99}}
	err := Build("/repo", "v1.2.3", testBuilders(""), WithRunner(f))
	if err == nil {
		t.Fatal("Build succeeded, want an error")
	}
	for _, component := range []string{"alpha", "beta"} {
		if !strings.Contains(err.Error(), component) {
			t.Errorf("error %q does not name %s", err, component)
		}
	}
}

func TestBuildRetriesAFailedBuilder(t *testing.T) {
	f := &fakeRunner{failures: map[string]int{"alpha": 1}}
	if err := Build("/repo", "v1.2.3", testBuilders(""), WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	var alpha int
	for _, c := range f.calls {
		if componentOf(c.args) == "alpha" {
			alpha++
		}
	}
	if alpha != 2 {
		t.Errorf("ran alpha %d times, want 2 (one failure plus the retry)", alpha)
	}
}

// Concurrent builds interleave, so each needs a log of its own.
func TestBuildLogsPerComponent(t *testing.T) {
	f := &fakeRunner{}
	if err := Build("/repo", "v1.2.3", testBuilders(""), WithRunner(f), WithLogsDir("/logs")); err != nil {
		t.Fatalf("Build: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range f.calls {
		want := filepath.Join("/logs", buildStep, componentOf(c.args)+".log")
		if c.logPath != want {
			t.Errorf("logged to %q, want %q", c.logPath, want)
		}
		if seen[c.logPath] {
			t.Errorf("two builders share the log %q", c.logPath)
		}
		seen[c.logPath] = true
	}
}

// A Builder cannot carry an empty component or target, so the repo root is all
// that is left to check.
func TestBuildNeedsARepoRoot(t *testing.T) {
	f := &fakeRunner{}
	if err := Build("", "v1.2.3", testBuilders(""), WithRunner(f)); err == nil {
		t.Error("Build succeeded, want an error")
	}
	if len(f.calls) != 0 {
		t.Errorf("ran %v despite failing validation", f.calls)
	}
}

// A constructor returns nil when a product ships none of that kind, so a caller
// can append it without checking.
func TestBuildSkipsNilBuilders(t *testing.T) {
	f := &fakeRunner{}
	builders := []Builder{E2E([]string{"ppc64le"}, t.TempDir())}
	if err := Build("/repo", "v1.2.3", builders, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("ran %v, want nothing", f.calls)
	}
}

func TestBuildWithNoBuildersDoesNothing(t *testing.T) {
	f := &fakeRunner{}
	if err := Build("/repo", "v1.2.3", nil, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("ran %v, want nothing", f.calls)
	}
}

// A builder collects only when it names an output directory.
func TestBuildCollectsWhereTheBuilderSays(t *testing.T) {
	repoRoot, outputDir := t.TempDir(), t.TempDir()
	writeBinary(t, repoRoot, "alpha", "alpha-amd64")
	writeBinary(t, repoRoot, "beta", "beta-amd64")

	if err := Build(repoRoot, "v1.2.3", testBuilders(outputDir), WithRunner(&fakeRunner{})); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "alpha-amd64")); err != nil {
		t.Errorf("the collecting builder's binary is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "beta-amd64")); err == nil {
		t.Error("collected for a builder that named no output directory")
	}
}

// A copy would double the disk a release's binaries take, and the source has to
// survive for the archive to read.
func TestBuildCollectsByHardLink(t *testing.T) {
	repoRoot, outputDir := t.TempDir(), t.TempDir()
	writeBinary(t, repoRoot, "alpha", "alpha-amd64")
	writeBinary(t, repoRoot, "beta", "beta-amd64")

	if err := Build(repoRoot, "v1.2.3", testBuilders(outputDir), WithRunner(&fakeRunner{})); err != nil {
		t.Fatalf("Build: %v", err)
	}
	src, err := os.Stat(filepath.Join(sourceDir(repoRoot, "alpha"), "alpha-amd64"))
	if err != nil {
		t.Fatalf("collect removed the built binary: %v", err)
	}
	dst, err := os.Stat(filepath.Join(outputDir, "alpha-amd64"))
	if err != nil {
		t.Fatalf("stat collected: %v", err)
	}
	if !os.SameFile(src, dst) {
		t.Error("collected binary is a separate file, want a hard link")
	}
}

// The copy skips anything that is not a regular file, so a build that produced
// nothing would otherwise collect nothing and report success.
func TestBuildFailsWhenThereIsNothingToCollect(t *testing.T) {
	repoRoot, outputDir := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(sourceDir(repoRoot, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := Build(repoRoot, "v1.2.3", testBuilders(outputDir), WithRunner(&fakeRunner{}))
	if err == nil {
		t.Fatal("Build succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Errorf("error %q does not name the component", err)
	}
}

func writeE2EBinary(t *testing.T, repoRoot, name string) {
	t.Helper()
	dir := e2eSourceDir(repoRoot)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestE2EBuildsAndCollectsTheShippedBinaries(t *testing.T) {
	repoRoot, outputDir := t.TempDir(), t.TempDir()
	f := &fakeRunner{}
	for _, name := range []string{"e2e-linux-amd64.test", "e2e-linux-arm64.test", "e2e.test"} {
		writeE2EBinary(t, repoRoot, name)
	}

	builders := []Builder{E2E([]string{"amd64", "arm64"}, outputDir)}
	if err := Build(repoRoot, "v1.2.3", builders, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := f.invocations(); !slices.Equal(got, []string{E2EComponent + " " + e2eTarget}) {
		t.Errorf("ran %v, want the e2e build target", got)
	}
	for _, want := range []string{"e2e-linux-amd64.test", "e2e-linux-arm64.test"} {
		if _, err := os.Stat(filepath.Join(outputDir, want)); err != nil {
			t.Errorf("%s was not collected: %v", want, err)
		}
	}
	// The target leaves other suites beside the ones a hashrelease ships.
	if _, err := os.Stat(filepath.Join(outputDir, "e2e.test")); err == nil {
		t.Error("collected a binary the release does not ship")
	}
}

func TestE2ENarrowsToSupportedArches(t *testing.T) {
	repoRoot, outputDir := t.TempDir(), t.TempDir()
	f := &fakeRunner{}
	writeE2EBinary(t, repoRoot, "e2e-linux-amd64.test")

	builders := []Builder{E2E([]string{"amd64", "ppc64le"}, outputDir)}
	if err := Build(repoRoot, "v1.2.3", builders, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := utils.Env(utils.EnvArches, "amd64")
	for _, c := range f.calls {
		if !slices.Contains(c.env, want) {
			t.Errorf("built without %q, env: %v", want, c.env)
		}
		// lib.Makefile assigns VALIDARCHES with `=`, so setting it would be
		// ignored and the build would cover every arch.
		for _, e := range c.env {
			if strings.HasPrefix(e, "VALIDARCHES=") {
				t.Errorf("built with %q, want the arches restricted through ARCHES", e)
			}
		}
	}
}

// Nothing to build rather than a failed release.
func TestE2EIsNilWhenNoArchIsSupported(t *testing.T) {
	if got := E2E([]string{"ppc64le"}, "/out"); got != nil {
		t.Errorf("E2E = %v, want nil", got)
	}
}

func TestE2EFailsWhenTheBuildProducedNothing(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(e2eSourceDir(repoRoot), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	builders := []Builder{E2E(nil, t.TempDir())}
	if err := Build(repoRoot, "v1.2.3", builders, WithRunner(&fakeRunner{})); err == nil {
		t.Error("Build succeeded, want an error when nothing was built")
	}
}

func TestE2EArchitecturesNarrowsToSupported(t *testing.T) {
	if got := e2eArchitectures(nil); !slices.Equal(got, e2eArches()) {
		t.Errorf("E2EArchitectures(nil) = %v, want every supported arch", got)
	}
	if got := e2eArchitectures([]string{"amd64", "ppc64le", "s390x"}); !slices.Equal(got, []string{"amd64"}) {
		t.Errorf("E2EArchitectures = %v, want just amd64", got)
	}
}

// Neutral fixture: Dir nests a whole directory, Files takes named ones.
func testArchived(repoRoot string) []archives.DirSource {
	return []archives.DirSource{
		{
			Label: "alpha binary",
			To:    filepath.Join(binDirName, "alpha"),
			From:  sourceDir(repoRoot, "alpha"),
		},
		{
			Label:  "beta tool binary",
			To:     binDirName,
			From:   sourceDir(repoRoot, "beta"),
			Filter: func(_, _, relPath string) bool { return relPath == "tool" },
		},
	}
}

func TestArchiveLaysOutTheBinDir(t *testing.T) {
	repoRoot, dest := t.TempDir(), t.TempDir()
	prev := archived
	archived = testArchived
	t.Cleanup(func() { archived = prev })

	writeBinary(t, repoRoot, "alpha", "alpha-linux-amd64")
	writeBinary(t, repoRoot, "alpha", "alpha-darwin-amd64")
	writeBinary(t, repoRoot, "beta", "tool")
	writeBinary(t, repoRoot, "beta", "some-other-tool")

	for _, c := range Archive(repoRoot) {
		if err := c.Contribute(dest); err != nil {
			t.Fatalf("Contribute(%s): %v", c.Name(), err)
		}
	}
	for _, want := range []string{
		filepath.Join("bin", "alpha", "alpha-linux-amd64"),
		filepath.Join("bin", "alpha", "alpha-darwin-amd64"),
		filepath.Join("bin", "tool"),
	} {
		if _, err := os.Stat(filepath.Join(dest, want)); err != nil {
			t.Errorf("%s is not in the archive: %v", want, err)
		}
	}
	// A component naming its files ships only those.
	if _, err := os.Stat(filepath.Join(dest, "bin", "some-other-tool")); err == nil {
		t.Error("archived a file the component does not ship")
	}
}

func TestArchiveHardLinksRatherThanCopying(t *testing.T) {
	repoRoot, dest := t.TempDir(), t.TempDir()
	prev := archived
	archived = testArchived
	t.Cleanup(func() { archived = prev })

	writeBinary(t, repoRoot, "alpha", "alpha-linux-amd64")
	writeBinary(t, repoRoot, "beta", "tool")
	for _, c := range Archive(repoRoot) {
		if err := c.Contribute(dest); err != nil {
			t.Fatalf("Contribute(%s): %v", c.Name(), err)
		}
	}
	src, err := os.Stat(filepath.Join(sourceDir(repoRoot, "beta"), "tool"))
	if err != nil {
		t.Fatalf("stat source: %v", err)
	}
	dst, err := os.Stat(filepath.Join(dest, "bin", "tool"))
	if err != nil {
		t.Fatalf("stat archived: %v", err)
	}
	if !os.SameFile(src, dst) {
		t.Error("archived binary is a separate file, want a hard link")
	}
}

// Contributing into an empty dir is archives' own error, so this asserts only
// that it is rejected rather than the message.
func TestArchiveRejectsAnEmptyDir(t *testing.T) {
	for _, c := range Archive(t.TempDir()) {
		if err := c.Contribute(""); err == nil {
			t.Errorf("%s: Contribute succeeded, want an error", c.Name())
		}
	}
}

// The copy skips anything that is not a regular file, so a bin/ holding only
// symlinks would otherwise produce an empty archive and no error.
func TestArchiveFailsWhenNothingIsLinkable(t *testing.T) {
	repoRoot, dest := t.TempDir(), t.TempDir()
	prev := archived
	archived = func(root string) []archives.DirSource {
		return []archives.DirSource{{Label: "beta binary", To: binDirName, From: sourceDir(root, "beta")}}
	}
	t.Cleanup(func() { archived = prev })

	betaDir := sourceDir(repoRoot, "beta")
	if err := os.MkdirAll(betaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("tool"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(betaDir, "tool")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	for _, c := range Archive(repoRoot) {
		if err := c.Contribute(dest); err == nil {
			t.Errorf("%s: Contribute succeeded, want an error", c.Name())
		}
	}
}

// Archiving a component nothing builds would ship a release missing binaries.
// Archiving a component nothing builds would ship a release missing binaries.
func TestArchivedSourcesAreBuiltComponents(t *testing.T) {
	for _, a := range archived("/repo") {
		var built bool
		for component := range all() {
			if a.From == sourceDir("/repo", component) {
				built = true
			}
		}
		if !built {
			t.Errorf("%s reads %s, which no component builds", a.Label, a.From)
		}
	}
}

func TestSourceDirIsUnderTheComponent(t *testing.T) {
	if got, want := sourceDir("/repo", "alpha"), filepath.Join("/repo", "alpha", "bin"); got != want {
		t.Errorf("SourceDir = %q, want %q", got, want)
	}
}

// The e2e binaries share files/ with the other loose files a release serves,
// so the directory is named once rather than per tenant.
func TestE2EDirIsUnderTheHashreleaseFilesDir(t *testing.T) {
	want := filepath.Join("/out", outputs.FilesDirName, E2EComponent)
	if got := E2EDir("/out"); got != want {
		t.Errorf("E2EDir = %q, want %q", got, want)
	}
}

// OSS ships every calicoctl binary under its own directory, and only felix's
// BPF tool. Product data, so it lives outside the shared package test.
func TestArchivedIsTheOSSArchiveLayout(t *testing.T) {
	const root = "/repo"
	want := map[string]struct {
		to      string
		ships   []string
		rejects []string
	}{
		sourceDir(root, CalicoctlComponent): {
			to:    filepath.Join("bin", CalicoctlComponent),
			ships: []string{"calicoctl-linux-amd64", "calicoctl-darwin-arm64"},
		},
		sourceDir(root, FelixComponent): {
			to:      "bin",
			ships:   []string{FelixBinary},
			rejects: []string{"calico-felix", filepath.Join("bpf", FelixBinary)},
		},
	}
	archived := archived(root)
	if len(archived) != len(want) {
		t.Fatalf("archived() has %d entries, want %d: %+v", len(archived), len(want), archived)
	}
	for _, got := range archived {
		w, ok := want[got.From]
		if !ok {
			t.Errorf("%s is archived but not part of the OSS archive", got.From)
			continue
		}
		if got.To != w.to {
			t.Errorf("%s lands at %q, want %q", got.Label, got.To, w.to)
		}
		for _, name := range w.ships {
			if got.Filter != nil && !got.Filter("", "", name) {
				t.Errorf("%s does not ship %s", got.Label, name)
			}
		}
		for _, name := range w.rejects {
			if got.Filter == nil || got.Filter("", "", name) {
				t.Errorf("%s ships %s, want it excluded", got.Label, name)
			}
		}
	}
}
