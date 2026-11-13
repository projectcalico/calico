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

package calico

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/release/internal/binaries"
	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/defaults"
	"github.com/projectcalico/calico/release/internal/distribution"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/images"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/manifests"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/plan"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

// fakeResult is the canned response for a matched command.
type fakeResult struct {
	stdout string
	err    error
}

// fakeRunner returns canned output per command, so tests can drive what a
// step sees and assert what it ran.
type fakeRunner struct {
	*command.Recorder

	// responses maps a command key ("name arg1 arg2 ...") to its canned result.
	// A key that is a prefix of the invoked command also matches (longest-prefix
	// wins), so tests can match on a stable command head without spelling out
	// variable trailing args (a temp-file path, an enumerated asset list).
	// A key of "<dir> $ name args" matches only a command run in dir.
	responses map[string]fakeResult
}

func newFakeRunner() *fakeRunner {
	f := &fakeRunner{responses: map[string]fakeResult{}}
	f.Recorder = &command.Recorder{Reply: f.reply}
	return f
}

// errNoGitRef is git's exit status for a ref that names nothing.
var errNoGitRef = &command.Error{Err: errors.New("exit status 1"), ExitCode: 1}

// on registers a canned result for a command key.
func (f *fakeRunner) on(key, stdout string, err error) *fakeRunner {
	f.responses[key] = fakeResult{stdout: stdout, err: err}
	return f
}

func (f *fakeRunner) reply(c command.Call) (string, error) {
	if c.Dir != "" {
		if res, ok := f.lookup(dirKey(c)); ok {
			return res.stdout, res.err
		}
	}
	res, _ := f.lookup(callKey(c))
	return res.stdout, res.err
}

func (f *fakeRunner) lookup(cmd string) (fakeResult, bool) {
	if res, ok := f.responses[cmd]; ok {
		return res, true
	}
	var bestKey string
	for key := range f.responses {
		if strings.HasPrefix(cmd, key) && len(key) > len(bestKey) {
			bestKey = key
		}
	}
	res, ok := f.responses[bestKey]
	return res, ok && bestKey != ""
}

func callKey(c command.Call) string {
	return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
}

// dirKey names a call by where it ran as well as what ran: "<dir> $ <cmd>".
func dirKey(c command.Call) string {
	return c.Dir + " $ " + callKey(c)
}

func matches(c command.Call, prefix string) bool {
	return strings.HasPrefix(callKey(c), prefix) || strings.HasPrefix(dirKey(c), prefix)
}

func (f *fakeRunner) calls() []string {
	var out []string
	for _, c := range f.Calls() {
		out = append(out, callKey(c))
	}
	return out
}

// ran reports whether any recorded call starts with the given command prefix.
func (f *fakeRunner) ran(prefix string) bool {
	return f.count(prefix) > 0
}

// count returns how many recorded calls start with the given command prefix.
func (f *fakeRunner) count(prefix string) int {
	n := 0
	for _, c := range f.Calls() {
		if matches(c, prefix) {
			n++
		}
	}
	return n
}

// envFor returns the env of the first recorded call matching the given prefix.
func (f *fakeRunner) envFor(prefix string) []string {
	for _, c := range f.Calls() {
		if matches(c, prefix) {
			return c.Env
		}
	}
	return nil
}

func TestTagRelease(t *testing.T) {
	const (
		ver      = "v3.30.0"
		headSHA  = "1111111111111111111111111111111111111111"
		otherSHA = "2222222222222222222222222222222222222222"
	)

	tests := []struct {
		name        string
		tagCommit   string // canned `rev-parse refs/tags/<ver>^{commit}`; empty => tag missing
		tagErr      error  // canned error for that lookup
		wantTag     bool   // expect `git tag <ver>` to be issued
		wantErr     bool
		errContains []string
	}{
		{
			name:      "tag does not exist creates it",
			tagCommit: "",
			tagErr:    errNoGitRef,
			wantTag:   true,
		},
		{
			name:      "tag exists at HEAD skips",
			tagCommit: headSHA,
			wantTag:   false,
		},
		{
			name:        "tag exists at different commit errors",
			tagCommit:   otherSHA,
			wantTag:     false,
			wantErr:     true,
			errContains: []string{otherSHA, headSHA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			f.on("git rev-parse --abbrev-ref HEAD", "release-v3.30", nil)
			f.on("git rev-parse HEAD", headSHA, nil)
			f.on(fmt.Sprintf("git rev-parse --verify --quiet refs/tags/%s^{commit}", ver), tt.tagCommit, tt.tagErr)
			f.on(fmt.Sprintf("git tag -a -m Release %s %s", ver, ver), "", nil)

			r := &CalicoManager{runner: f, calicoVersion: testVersion(t, ver)}
			err := r.TagRelease()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("TagRelease() = nil, want error")
				}
				for _, sub := range tt.errContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not contain %q", err.Error(), sub)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("TagRelease() unexpected error: %v", err)
			}
			if got := f.ran("git tag -a "); got != tt.wantTag {
				t.Errorf("git tag issued = %v, want %v (calls: %v)", got, tt.wantTag, f.calls())
			}
		})
	}
}

func TestBuild(t *testing.T) {
	const (
		ver         = "v3.30.0"
		headSHA     = "1111111111111111111111111111111111111111"
		gitDescribe = "git describe --tags --always --long --abbrev=12 --dirty"
	)

	tests := []struct {
		name          string
		isHashRelease bool
		wantDelete    bool
	}{
		{
			name:       "a failed release deletes the tag it created",
			wantDelete: true,
		},
		{
			name:          "a failed hashrelease takes no tag and deletes none",
			isHashRelease: true,
			wantDelete:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			m, root := imageManager(t, f, "")
			m.calicoVersion = testVersion(t, ver)
			m.tmpDir = t.TempDir()
			m.isHashRelease = tt.isHashRelease
			m.images = false
			m.binaries = true
			f.on("git rev-parse --abbrev-ref HEAD", "release-v3.30", nil)
			f.on("git rev-parse HEAD", headSHA, nil)
			f.on(fmt.Sprintf("git rev-parse --verify --quiet refs/tags/%s^{commit}", ver), "", errNoGitRef)
			// Fail a binaries target so Build returns after the tag is taken.
			f.on(root+"/felix $ make release-build", "", fmt.Errorf("boom"))

			if err := m.Build(); err == nil {
				t.Fatal("Build() = nil, want error")
			}
			if got := f.ran("git tag -d " + ver); got != tt.wantDelete {
				t.Errorf("git tag -d issued = %v, want %v (calls: %v)", got, tt.wantDelete, f.calls())
			}
		})
	}

	release := func(t *testing.T) (*fakeRunner, *CalicoManager) {
		t.Helper()
		f := newFakeRunner()
		m, _ := imageManager(t, f, "")
		m.tmpDir = t.TempDir()
		m.images = false
		m.binaries = true
		m.tarball = true
		return f, m
	}

	t.Run("a plan-only build runs nothing", func(t *testing.T) {
		f, m := release(t)
		m.planOptions.Preview = true
		if err := m.Build(); err != nil {
			t.Fatalf("Build() unexpected error: %v", err)
		}
		if want := []string{gitDescribe}; !slices.Equal(f.calls(), want) {
			t.Errorf("ran %v, want %v", f.calls(), want)
		}
	})

	t.Run("a release whose manifests lag git fails before anything runs, the operator included", func(t *testing.T) {
		f, m := release(t)
		f.on("git describe", "v3.30.1-0.dev-1-g111111111111", nil)
		built := false
		m.operator = func() error { built = true; return nil }
		err := m.Build()
		if err == nil || !strings.Contains(err.Error(), "run release prep first") {
			t.Fatalf("Build() error = %v, want a prep mismatch", err)
		}
		if want := []string{gitDescribe}; !slices.Equal(f.calls(), want) || built {
			t.Errorf("ran %v, operator built = %v", f.calls(), built)
		}
	})

	t.Run("a plan-only release whose manifests lag git still lists its steps", func(t *testing.T) {
		f, m := release(t)
		f.on("git describe", "v3.30.1-0.dev-1-g111111111111", nil)
		m.planOptions.Preview = true
		if err := m.Build(); err != nil {
			t.Fatalf("Build() unexpected error: %v", err)
		}
		if want := []string{gitDescribe}; !slices.Equal(f.calls(), want) {
			t.Errorf("ran %v, want %v", f.calls(), want)
		}
	})

	t.Run("an unset records dir fails before anything runs, the operator included", func(t *testing.T) {
		f, m := release(t)
		m.recordsDir = ""
		built := false
		m.operator = func() error { built = true; return nil }
		err := m.Build()
		if err == nil || !strings.Contains(err.Error(), "no records directory specified") {
			t.Fatalf("Build() error = %v, want a missing records directory", err)
		}
		if want := []string{gitDescribe}; !slices.Equal(f.calls(), want) || built {
			t.Errorf("ran %v, operator built = %v", f.calls(), built)
		}
	})

	t.Run("skipping a step the archive stages fails before anything builds", func(t *testing.T) {
		f, m := release(t)
		m.planOptions.Skip = map[string]bool{binaries.Step: true}
		err := m.Build()
		if err == nil || !strings.Contains(err.Error(), `requires "binaries"`) {
			t.Fatalf("Build() error = %v, want a missing binaries requirement", err)
		}
		if want := []string{gitDescribe}; !slices.Equal(f.calls(), want) {
			t.Errorf("ran %v, want only %v", f.calls(), want)
		}
	})

	t.Run("nodes set on the manager replace the built-in ones, and skips still apply", func(t *testing.T) {
		f, m := release(t)
		var ran []string
		do := func(name string) func() error {
			return func() error { ran = append(ran, name); return nil }
		}
		m.buildNodes = func() []plan.Node {
			return []plan.Node{{Name: "custom", Do: do("custom")}, {Name: "skipped", Do: do("skipped")}}
		}
		m.planOptions.Skip = map[string]bool{"skipped": true}
		if err := m.Build(); err != nil {
			t.Fatalf("Build() unexpected error: %v", err)
		}
		if diff := cmp.Diff([]string{"custom"}, ran); diff != "" {
			t.Errorf("ran (-want +got):\n%s", diff)
		}
		if len(f.calls()) != 0 {
			t.Errorf("built-in steps ran: %v", f.calls())
		}
	})

	t.Run("an archive that cannot be built fails before the tag", func(t *testing.T) {
		f, m := release(t)
		m.archiveImages = true
		m.imageRegistries = nil
		if err := m.Build(); err == nil {
			t.Fatal("Build() = nil, want error")
		}
		if f.ran("git tag") {
			t.Errorf("tagged before validating the archive (calls: %v)", f.calls())
		}
	})
}

// The tag/HEAD comparison is consulted by both releasePrereqs (fail-fast) and
// TagRelease (authoritative), but the rev-parse must run only once per release.
func TestTagStateMemoized(t *testing.T) {
	const ver = "v3.30.0"
	f := newFakeRunner()
	f.on(fmt.Sprintf("git rev-parse --verify --quiet refs/tags/%s^{commit}", ver), "", errNoGitRef)

	r := &CalicoManager{runner: f, calicoVersion: testVersion(t, ver)}
	if tc := r.tagState(); tc.err != nil {
		t.Fatal(tc.err)
	}
	if tc := r.tagState(); tc.err != nil {
		t.Fatal(tc.err)
	}
	if got := f.count("git rev-parse --verify --quiet refs/tags/" + ver); got != 1 {
		t.Errorf("tag rev-parse ran %d times, want 1 (calls: %v)", got, f.calls())
	}
}

// releasePrereqs fails fast when the tag points at a different commit, before
// the build runs.
func TestReleasePrereqsTagConflict(t *testing.T) {
	const (
		ver      = "v3.30.0"
		headSHA  = "1111111111111111111111111111111111111111"
		otherSHA = "2222222222222222222222222222222222222222"
	)
	f := newFakeRunner()
	f.on("git rev-parse --abbrev-ref HEAD", "release-v3.30", nil)
	f.on("git rev-parse HEAD", headSHA, nil)
	f.on(fmt.Sprintf("git rev-parse --verify --quiet refs/tags/%s^{commit}", ver), otherSHA, nil)

	r := &CalicoManager{runner: f, calicoVersion: testVersion(t, ver), githubOrg: "myfork", repo: "calico"}
	err := r.releasePrereqs()
	if err == nil {
		t.Fatal("releasePrereqs() = nil, want conflict error")
	}
	for _, sub := range []string{otherSHA, headSHA} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q does not contain %q", err.Error(), sub)
		}
	}
}

func TestAssertImageVersions(t *testing.T) {
	t.Run("checks the images it is given without sweeping", func(t *testing.T) {
		const ver = "v3.30.0"
		f := newFakeRunner().on("docker inspect", ver, nil)
		r := &CalicoManager{
			runner:          f,
			calicoVersion:   testVersion(t, ver),
			imageRegistries: []string{"quay.io/calico"},
			releaseImages:   func() ([]string, error) { return []string{"whisker"}, nil },
		}
		if err := r.assertImageVersions(); err != nil {
			t.Fatalf("assertImageVersions: %v", err)
		}
		if f.ran("make") {
			t.Errorf("ran make, want the given list used: %v", f.calls())
		}
		if !f.ran("docker inspect") {
			t.Errorf("did not inspect whisker: %v", f.calls())
		}
	})
}

func TestPublishGitTag(t *testing.T) {
	const (
		ver       = "v3.30.0"
		remote    = "origin"
		localSHA  = "1111111111111111111111111111111111111111"
		remoteSHA = "2222222222222222222222222222222222222222"
		tagObjSHA = "3333333333333333333333333333333333333333"
	)

	tests := []struct {
		name        string
		lsRemote    string // canned `git ls-remote --tags <remote> refs/tags/<ver>`
		wantPush    bool
		wantErr     bool
		errContains []string
	}{
		{
			name:     "remote tag missing pushes",
			lsRemote: "",
			wantPush: true,
		},
		{
			name:     "remote tag matches local skips",
			lsRemote: fmt.Sprintf("%s\trefs/tags/%s", localSHA, ver),
			wantPush: false,
		},
		{
			name:        "remote tag differs errors",
			lsRemote:    fmt.Sprintf("%s\trefs/tags/%s", remoteSHA, ver),
			wantPush:    false,
			wantErr:     true,
			errContains: []string{localSHA, remoteSHA},
		},
		{
			name:     "annotated tag peeled line matches local skips",
			lsRemote: fmt.Sprintf("%s\trefs/tags/%s\n%s\trefs/tags/%s^{}", tagObjSHA, ver, localSHA, ver),
			wantPush: false,
		},
		{
			name:        "annotated tag peeled line differs errors",
			lsRemote:    fmt.Sprintf("%s\trefs/tags/%s\n%s\trefs/tags/%s^{}", tagObjSHA, ver, remoteSHA, ver),
			wantPush:    false,
			wantErr:     true,
			errContains: []string{localSHA, remoteSHA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			f.on(fmt.Sprintf("git ls-remote --tags %s refs/tags/%s", remote, ver), tt.lsRemote, nil)
			f.on(fmt.Sprintf("git rev-list -n1 %s", ver), localSHA, nil)
			f.on(fmt.Sprintf("git push %s %s", remote, ver), "", nil)

			r := &CalicoManager{runner: f, remote: remote, calicoVersion: testVersion(t, ver)}
			err := r.publishGitTag()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("publishGitTag() = nil, want error")
				}
				for _, sub := range tt.errContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not contain %q", err.Error(), sub)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("publishGitTag() unexpected error: %v", err)
			}
			if got := f.ran(fmt.Sprintf("git push %s %s", remote, ver)); got != tt.wantPush {
				t.Errorf("git push issued = %v, want %v (calls: %v)", got, tt.wantPush, f.calls())
			}
		})
	}
}

func TestPublishGithubReleaseSkipped(t *testing.T) {
	f := newFakeRunner()
	r := &CalicoManager{
		runner:        f,
		githubRelease: false,
		calicoVersion: testVersion(t, "v3.30.0"),
		githubOrg:     "projectcalico",
		repo:          "calico",
		outputDir:     t.TempDir(),
	}
	if upload := r.githubReleaseUpload(); !upload.Skip {
		t.Errorf("expected the upload skipped with the flag off, got %+v", upload)
	}
	if len(f.calls()) != 0 {
		t.Errorf("expected nothing run with the flag off, got %v", f.calls())
	}
}

func TestOwnerFromRemoteURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{
			name: "SSH with .git suffix",
			url:  "git@github.com:projectcalico/calico.git",
			want: "projectcalico",
		},
		{
			name: "SSH without .git suffix",
			url:  "git@github.com:projectcalico/calico",
			want: "projectcalico",
		},
		{
			name: "HTTPS with .git suffix",
			url:  "https://github.com/projectcalico/calico.git",
			want: "projectcalico",
		},
		{
			name: "HTTPS without .git suffix",
			url:  "https://github.com/projectcalico/calico",
			want: "projectcalico",
		},
		{
			name: "SSH fork",
			url:  "git@github.com:myFork/calico.git",
			want: "myFork",
		},
		{
			name: "HTTPS fork",
			url:  "https://github.com/myFork/calico.git",
			want: "myFork",
		},
		{
			name: "SSH with nested path",
			url:  "git@github.com:org/sub/repo.git",
			want: "sub",
		},
		{
			name:    "bare hostname no path",
			url:     "github.com",
			wantErr: true,
		},
		{
			name:    "empty string",
			url:     "",
			wantErr: true,
		},
		{
			name:    "local path",
			url:     "/tmp/repo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ownerFromRemoteURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ownerFromRemoteURL(%q) = %q, want error", tt.url, got)
				}
				return
			}
			if err != nil {
				t.Errorf("ownerFromRemoteURL(%q) error = %v", tt.url, err)
				return
			}
			if got != tt.want {
				t.Errorf("ownerFromRemoteURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

// TestCutPlanAdvancesMain asserts a cut off main emits no derived tag and
// advances main to the next minor.
func TestCutPlanAdvancesMain(t *testing.T) {
	f := newFakeRunner().on("git describe --tags --abbrev=0 master", "v3.33.0-0.dev", nil)
	m := &CalicoManager{runner: f}
	root := t.TempDir()
	for _, opt := range []Option{
		WithRepoRoot(root),
		WithMainBranch("master"),
		WithReleaseBranchPrefix("release"),
		WithDevTagIdentifier("0.dev"),
	} {
		require.NoError(t, opt(m))
	}

	plan, err := m.cutPlan()
	require.NoError(t, err)
	require.Equal(t, "release-v3.33", plan.Derived)

	var derivedTag, mainTag string
	for _, tt := range plan.TagTargets {
		switch tt.Branch {
		case "release-v3.33":
			derivedTag = tt.DevTag
		case "master":
			mainTag = tt.DevTag
		}
	}
	require.Empty(t, derivedTag, "the derived branch inherits main's tag, so no new derived tag")
	require.Equal(t, "v3.34.0-0.dev", mainTag, "main advances to the next minor")
}

func TestPrepareDerived(t *testing.T) {
	t.Run("rejects a branch that is not a release branch", func(t *testing.T) {
		f := newFakeRunner()
		r := &CalicoManager{runner: f, repoRoot: t.TempDir(), releaseBranchPrefix: "release"}
		if _, err := r.prepareDerived("master"); err == nil {
			t.Fatal("want an error")
		}
		if len(f.calls()) > 0 {
			t.Errorf("ran %v before rejecting the branch", f.calls())
		}
	})
}

func TestPrepareRelease(t *testing.T) {
	t.Run("beforePrep runs on the base branch and its error stops the prep", func(t *testing.T) {
		f := newFakeRunner()
		f.on("git rev-parse --abbrev-ref HEAD", "release-v3.30\n", nil)
		r := &CalicoManager{runner: f, repoRoot: t.TempDir(), calicoVersion: testVersion(t, "v3.30.0"), releaseBranchPrefix: "release"}
		r.beforePrep = func() error {
			if f.ran("git switch") {
				t.Errorf("switched branch before beforePrep (calls: %v)", f.calls())
			}
			return os.ErrInvalid
		}
		if _, err := r.PrepareRelease(); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("PrepareRelease() = %v, want beforePrep's error", err)
		}
		if f.ran("git switch") {
			t.Errorf("switched branch after beforePrep failed (calls: %v)", f.calls())
		}
	})

	t.Run("records the base branch in the prep commit", func(t *testing.T) {
		f := newFakeRunner()
		f.on("git rev-parse --abbrev-ref HEAD", "release-v3.30\n", nil)
		root := t.TempDir()
		values, err := filepath.Glob("../../../../charts/*/values.yaml")
		if err != nil || len(values) == 0 {
			t.Fatalf("find chart values: %v", err)
		}
		for _, src := range values {
			b, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(root, "charts", filepath.Base(filepath.Dir(src)), "values.yaml")
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		r := &CalicoManager{
			runner: f, repoRoot: root, calicoVersion: testVersion(t, "v3.30.0"),
			releaseBranchPrefix: "release", imageRegistries: []string{"quay.io/calico"},
			operatorImage: "tigera/operator", operatorVersion: "v1.38.0", operatorRegistry: "quay.io",
		}
		if _, err := r.PrepareRelease(); err != nil {
			t.Fatalf("PrepareRelease() unexpected error: %v", err)
		}
		if want := "git commit -m build: v3.30.0 release --trailer Release-branch: release-v3.30"; !f.ran(want) {
			t.Errorf("did not run %q (calls: %v)", want, f.calls())
		}
	})
}

func TestPrepPrereqs(t *testing.T) {
	for _, tc := range []struct {
		name           string
		remote         string
		validateBranch bool
		wantErr        bool
		wantWarn       bool
	}{
		{name: "main repo", remote: "git@github.com:projectcalico/calico.git", validateBranch: true},
		{name: "fork", remote: "git@github.com:someone/calico.git", validateBranch: true, wantErr: true},
		{name: "fork with the branch check off warns", remote: "git@github.com:someone/calico.git", wantWarn: true},
		{name: "main repo with the branch check off", remote: "git@github.com:projectcalico/calico.git"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner()
			f.on("git rev-parse --abbrev-ref HEAD", "release-v3.30\n", nil)
			f.on("git config --get remote.origin.url", tc.remote+"\n", nil)
			r := &CalicoManager{
				runner: f, repoRoot: "/repo", remote: "origin", githubOrg: "projectcalico",
				calicoVersion: testVersion(t, "v3.30.0"), operatorVersion: "v1.38.0",
				releaseBranchPrefix: "release", validate: true, validateBranch: tc.validateBranch,
				gitRef: true, dryRun: true,
			}
			hook := logtest.NewGlobal()
			t.Cleanup(hook.Reset)
			err := r.prepPrereqs()
			if got := err != nil && strings.Contains(err.Error(), "expected to be from"); got != tc.wantErr {
				t.Errorf("prepPrereqs() = %v, want fork error %v", err, tc.wantErr)
			}
			var warned bool
			for _, e := range hook.AllEntries() {
				warned = warned || e.Message == "Using the wrong branch"
			}
			if warned != tc.wantWarn {
				t.Errorf("warned = %v, want %v", warned, tc.wantWarn)
			}
		})
	}
}

func TestPushPrepBranch(t *testing.T) {
	const push = "git push --force-with-lease origin build-v3.30.0"
	for _, tc := range []struct {
		name     string
		gitRef   bool
		dryRun   bool
		wantPush string
		wantPR   bool
	}{
		{name: "pushes and opens a PR", gitRef: true, wantPush: push, wantPR: true},
		{name: "dry run checks the push and opens no PR", gitRef: true, dryRun: true, wantPush: push + " --dry-run"},
		{name: "no git ref pushes nothing", dryRun: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner()
			r := &CalicoManager{runner: f, remote: "origin", gitRef: tc.gitRef, dryRun: tc.dryRun}
			if err := r.pushPrepBranch("release-v3.30", "build-v3.30.0"); err != nil {
				t.Fatalf("pushPrepBranch() unexpected error: %v", err)
			}
			if got := slices.ContainsFunc(f.calls(), func(c string) bool { return strings.HasPrefix(c, "git push") }); got != (tc.wantPush != "") {
				t.Errorf("pushed = %v, want %v (calls: %v)", got, tc.wantPush != "", f.calls())
			}
			if tc.wantPush != "" && !slices.Contains(f.calls(), tc.wantPush) {
				t.Errorf("did not run %q (calls: %v)", tc.wantPush, f.calls())
			}
			if got := f.ran("./bin/gh pr create"); got != tc.wantPR {
				t.Errorf("opened a PR = %v, want %v (calls: %v)", got, tc.wantPR, f.calls())
			}
			if want := "git switch -f release-v3.30"; !f.ran(want) {
				t.Errorf("did not switch back to the base branch (calls: %v)", f.calls())
			}
		})
	}
}

func TestAssertReleaseNotesPresent(t *testing.T) {
	const ver = "v3.99.0"
	for _, tc := range []struct {
		name       string
		notes      string
		writeNotes bool
		wantErr    bool
	}{
		{name: "present", writeNotes: true, notes: "notes"},
		{name: "missing", wantErr: true},
		{name: "empty", writeNotes: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.writeNotes {
				path := outputs.ReleaseNoteFilePath(root, ver)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.notes), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			r := &CalicoManager{repoRoot: root}
			if err := r.assertReleaseNotesPresent(ver); (err != nil) != tc.wantErr {
				t.Errorf("assertReleaseNotesPresent() = %v, want error %v", err, tc.wantErr)
			}
		})
	}
	t.Run("build validation fails without notes", func(t *testing.T) {
		r := &CalicoManager{repoRoot: t.TempDir(), calicoVersion: testVersion(t, ver)}
		if err := r.PreReleaseValidate(); err == nil || !strings.Contains(err.Error(), "release notes") {
			t.Errorf("PreReleaseValidate() = %v, want a release notes error", err)
		}
	})
}

func TestBuildNodes(t *testing.T) {
	on := func(r *CalicoManager, name string) bool {
		t.Helper()
		for _, n := range r.buildPlan() {
			if n.Name == name {
				return n.When == nil || n.When()
			}
		}
		t.Fatalf("no %s node", name)
		return false
	}
	for _, tc := range []struct {
		name  string
		notes bool
		org   string
		repo  string
		want  bool
	}{
		{name: "release notes are on for the Calico repo", notes: true, org: defaults.ProjectCalicoOrg, repo: defaults.CalicoRepoName, want: true},
		{name: "release notes are off by flag", org: defaults.ProjectCalicoOrg, repo: defaults.CalicoRepoName},
		{name: "release notes are off for another repo", notes: true, org: "example", repo: "fork"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &CalicoManager{isHashRelease: true, releaseNotes: tc.notes, githubOrg: tc.org, repo: tc.repo}
			if got := on(r, outputs.ReleaseNotesStep); got != tc.want {
				t.Errorf("release-notes on = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("each mode's skip list names every step but the checks", func(t *testing.T) {
		for _, tc := range []struct {
			r    *CalicoManager
			want []string
		}{
			{r: &CalicoManager{}, want: BuildSteps()},
			{r: &CalicoManager{isHashRelease: true}, want: HashreleaseBuildSteps()},
		} {
			var names []string
			for _, n := range tc.r.buildPlan()[1:] {
				names = append(names, n.Name)
			}
			if diff := cmp.Diff(tc.want, names); diff != "" {
				t.Errorf("skip list (-want +got):\n%s", diff)
			}
		}
	})
}

func TestRequireOnMainBranch(t *testing.T) {
	const verify = "git rev-parse --verify --quiet refs/heads/release-v3.33"
	for _, tc := range []struct {
		name    string
		current string
		derived string
		wantErr bool
	}{
		{name: "a fresh cut on master is allowed", current: "master"},
		{name: "a fresh cut off master is rejected", current: "some-feature", wantErr: true},
		{name: "a resume is allowed off master once the derived branch exists", current: "release-v3.33", derived: "abc123"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner().on("git rev-parse --abbrev-ref HEAD", tc.current, nil)
			if tc.derived != "" {
				f.on(verify, tc.derived, nil)
			} else {
				f.on(verify, "", errNoGitRef)
			}
			m := &CalicoManager{runner: f, repoRoot: "/repo", mainBranch: "master", validate: true}
			err := m.requireOnMainBranch("release-v3.33")
			if (err != nil) != tc.wantErr {
				t.Fatalf("requireOnMainBranch() = %v, want error %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "must run on master") {
				t.Errorf("error %q does not name the main branch", err)
			}
		})
	}
}

// envForDir returns the environment of the first recorded make call in a
// component directory.
func (f *fakeRunner) envForDir(dir string) []string {
	for _, c := range f.Calls() {
		if strings.Contains(dirKey(c), dir) {
			return c.Env
		}
	}
	return nil
}

// logPathsForDir returns the log paths of every recorded make call in a
// component directory.
func (f *fakeRunner) logPathsForDir(dir string) []string {
	var out []string
	for _, c := range f.Calls() {
		// Only unit targets are logged to a file.
		if strings.Contains(dirKey(c), dir) && c.LogFile != "" {
			out = append(out, c.LogFile)
		}
	}
	return out
}

// unitCalls returns the calls that ran a unit's make target, ignoring the
// image-name queries.
func unitCalls(f *fakeRunner, target string) []string {
	var out []string
	for _, c := range f.calls() {
		if strings.Contains(c, " "+target) {
			out = append(out, c)
		}
	}
	return out
}

// felix builds no image, so the binary step is the only thing that produces
// felix/bin/calico-bpf for the release tarball.
func TestBuildBinariesBuildsFelixWhateverTheImagesFlagIs(t *testing.T) {
	for _, images := range []bool{true, false} {
		t.Run(fmt.Sprintf("images=%t", images), func(t *testing.T) {
			f := newFakeRunner()
			m, root := imageManager(t, f, "")
			m.images = images
			m.binaries = true
			// buildBinaries collects what it built, and the fake runner does
			// not produce files.
			bin := filepath.Join(root, binaries.CalicoctlComponent, binDir)
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "calicoctl-linux-amd64"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := m.buildBinaries(); err != nil {
				t.Fatalf("buildBinaries: %v", err)
			}
			for _, want := range []string{root + "/felix $ make release-build", root + "/calicoctl $ make build-all"} {
				if !f.ran(want) {
					t.Errorf("did not run %q, ran: %v", want, f.calls())
				}
			}
		})
	}
}

type e2eConfigCase struct {
	name          string
	isHashRelease bool
	e2eBinaries   bool
	wantArchive   bool
}

// Scheduled lanes read configs from the same upload as the e2e binary, so a
// hashrelease that builds the binary must also publish the config archive.
func TestBuildBinariesPublishesE2EConfigWithTheBinary(t *testing.T) {
	for _, tc := range []e2eConfigCase{
		{"hashrelease with e2e binaries", true, true, true},
		{"hashrelease without e2e binaries", true, false, false},
		{"release with e2e binaries", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner()
			mgr, root := imageManager(t, f, "")
			mgr.isHashRelease = tc.isHashRelease
			mgr.e2eBinaries = tc.e2eBinaries
			mgr.binaries = false
			bin := filepath.Join(root, binaries.E2EComponent, binDir, "k8s")
			cfg := filepath.Join(root, binaries.E2EComponent, "config", "iptables")
			for path, content := range map[string]string{
				filepath.Join(bin, "e2e-linux-amd64.test"): "x",
				filepath.Join(bin, "e2e-linux-arm64.test"): "x",
				filepath.Join(cfg, "xtables.yaml"):         "y",
			} {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := mgr.buildBinaries(); err != nil {
				t.Fatalf("buildBinaries: %v", err)
			}
			_, err := os.Stat(binaries.E2EConfigPath(mgr.uploadDir()))
			if tc.wantArchive && err != nil {
				t.Errorf("config archive not published: %v", err)
			}
			if !tc.wantArchive && err == nil {
				t.Error("published a config archive without the e2e binaries")
			}
		})
	}

	t.Run("fails when the configs are missing", func(t *testing.T) {
		f := newFakeRunner()
		m, root := imageManager(t, f, "")
		m.isHashRelease = true
		m.e2eBinaries = true
		m.binaries = false
		bin := filepath.Join(root, binaries.E2EComponent, binDir, "k8s")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "e2e-linux-amd64.test"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := m.buildBinaries(); err == nil {
			t.Fatal("buildBinaries succeeded without e2e/config, want an error")
		}
	})
}

// felix/bin is build output: only calico-bpf ships, and the bpf/ subdirectory
// must not reach the archive by matching on a base name.
func TestFelixContentShipsOnlyTheBPFTool(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, binaries.FelixComponent, binDir)
	for _, name := range []string{"calico-felix", binaries.FelixBinary, "bpf/" + binaries.FelixBinary} {
		path := filepath.Join(bin, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := &CalicoManager{repoRoot: root, binaries: true}
	dest := t.TempDir()
	sources, err := m.archiveSources()
	if err != nil {
		t.Fatalf("archiveSources: %v", err)
	}
	for _, c := range sources {
		if !strings.HasPrefix(c.Name(), binaries.FelixComponent) {
			continue
		}
		if err := c.Contribute(dest); err != nil {
			t.Fatalf("Contribute: %v", err)
		}
	}

	var got []string
	if err := filepath.WalkDir(dest, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dest, path)
		got = append(got, rel)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{filepath.Join(binDir, binaries.FelixBinary)}; !slices.Equal(got, want) {
		t.Errorf("staged %v, want %v", got, want)
	}
}

// A hashrelease archive reads manifests from the output dir, which is only
// populated by collectManifests. buildManifests must run it before the tarball
// is built, or the archive fails on a missing directory.
func TestHashreleaseManifestsAreCollectedBeforeTheArchiveReadsThem(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(t.TempDir(), "upload")
	if err := os.MkdirAll(filepath.Join(root, manifests.DirName), 0o755); err != nil {
		t.Fatal(err)
	}

	f := newFakeRunner()
	m := &CalicoManager{
		repoRoot:        root,
		outputDir:       out,
		manifests:       true,
		isHashRelease:   true,
		runner:          f,
		imageRegistries: defaultRegistries,
		calicoVersion:   testVersion(t, "v3.30.0"),
		operatorVersion: "v1.40.0",
		operatorImage:   "tigera/operator",
	}
	m.hashrelease.Source = out
	if err := m.buildManifests(); err != nil {
		t.Fatalf("buildManifests: %v", err)
	}

	// The archive reads the collected copy, so the copy has to happen while
	// building the manifests rather than in a later pass.
	gen := slices.IndexFunc(f.calls(), func(c string) bool { return strings.Contains(c, "gen-manifests") })
	copied := slices.IndexFunc(f.calls(), func(c string) bool {
		return strings.Contains(c, filepath.Join(out, manifests.DirName)) ||
			strings.HasSuffix(c, out)
	})
	if gen < 0 || copied < 0 {
		t.Fatalf("expected a manifest build and a copy, ran: %v", f.calls())
	}
	if copied < gen {
		t.Errorf("manifests were copied before they were generated, ran: %v", f.calls())
	}
}

func TestReleaseNoteNamesTheArtifactsThroughTheirAccessors(t *testing.T) {
	m := &CalicoManager{
		calicoVersion: testVersion(t, "v3.30.0"),
		githubRelease: true,
		githubOrg:     "projectcalico",
		repo:          "calico",
	}
	body := m.githubReleaseUpload().Handler.(distribution.GithubRelease).Body

	// Stated outright rather than computed from the accessors: the note tells a
	// user what to download, so it has to match the published asset names that
	// pkg/postrelease asserts against a real release.
	for _, want := range []string{"release-v3.30.0.tgz", "calico-windows-v3.30.0.zip"} {
		if !strings.Contains(body, want) {
			t.Errorf("release note does not name %q:\n%s", want, body)
		}
	}
}

func TestArchiveSourcesIsGatedPerSource(t *testing.T) {
	for name, tc := range map[string]struct {
		images, binaries, manifests bool
		want                        []string
	}{
		"all":            {true, true, true, []string{"images", "calicoctl binary", "felix calico-bpf binary", "manifests"}},
		"none":           {false, false, false, nil},
		"only images":    {true, false, false, []string{"images"}},
		"no images":      {false, true, true, []string{"calicoctl binary", "felix calico-bpf binary", "manifests"}},
		"only binaries":  {false, true, false, []string{"calicoctl binary", "felix calico-bpf binary"}},
		"no binaries":    {true, false, true, []string{"images", "manifests"}},
		"only manifests": {false, false, true, []string{"manifests"}},
		"no manifests":   {true, true, false, []string{"images", "calicoctl binary", "felix calico-bpf binary"}},
	} {
		t.Run(name, func(t *testing.T) {
			m := &CalicoManager{
				repoRoot:        t.TempDir(),
				calicoVersion:   testVersion(t, "v3.30.0"),
				imageRegistries: []string{"quay.io/calico"},
				archiveImages:   tc.images,
				binaries:        tc.binaries,
				manifests:       tc.manifests,
			}
			sources, err := m.archiveSources()
			if err != nil {
				t.Fatalf("archiveSources: %v", err)
			}
			var got []string
			for _, c := range sources {
				got = append(got, c.Name())
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("archiveSources() = %v, want %v", got, tc.want)
			}
		})
	}
}

// manifestRepo is a repo root holding the one manifest a release reads its
// registry from.
func manifestRepo(t *testing.T, image string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, manifests.DirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating manifests dir: %v", err)
	}
	doc := fmt.Sprintf("kind: Pod\nspec:\n  containers:\n    - name: calicoctl\n      image: %s\n", image)
	if err := os.WriteFile(filepath.Join(dir, manifests.RegistryFile), []byte(doc), 0o644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}
	return root
}

// Returns the repo root it built, since the registry now comes from a real
// file and callers assert on paths under it.
func imageManager(t *testing.T, f *fakeRunner, logsDir string) (*CalicoManager, string) {
	t.Helper()
	root := manifestRepo(t, "quay.io/calico/ctl:v3.30.0")
	// A publish asks each directory for its image names before recording refs.
	for _, dir := range images.VariantDirs(images.PublishVariants) {
		base := path.Base(dir)
		f.on(fmt.Sprintf("%s/%s $ make -s --no-print-directory build-images", root, dir), base+" "+base+"-windows", nil)
	}
	if _, ok := f.responses["git rev-parse --abbrev-ref HEAD"]; !ok {
		f.on("git rev-parse --abbrev-ref HEAD", "release-v3.30\n", nil)
	}
	if _, ok := f.responses["git describe"]; !ok {
		f.on("git describe", "v3.30.0-0.dev-1-g111111111111\n", nil)
	}
	return &CalicoManager{
		runner:              f,
		repoRoot:            root,
		calicoVersion:       testVersion(t, "v3.30.0"),
		imageRegistries:     []string{registry.DefaultProductRegistry},
		images:              true,
		operatorImage:       registry.OperatorImage,
		operatorRegistry:    registry.DefaultOperatorRegistry,
		operator:            func() error { return nil },
		logsDir:             logsDir,
		outputDir:           t.TempDir(),
		recordsDir:          t.TempDir(),
		releaseBranchPrefix: defaults.ReleaseBranchPrefix(),
		devTagIdentifier:    "0.dev",
		resolveDigest: func(string) (string, bool, error) {
			return "sha256:aaa", true, nil
		},
	}, root
}

// What the image tests below expect of this release.
var (
	imagePublishTarget = "release-publish"
)

// A publish must latch CONFIRM; DRYRUN pushes nothing and still reports
// success.
func TestPublishContainerImagesConfirms(t *testing.T) {
	f := newFakeRunner()
	m, root := imageManager(t, f, "")
	if err := m.publishContainerImages(); err != nil {
		t.Fatalf("publishContainerImages: %v", err)
	}
	if !f.ran(root + "/cmd/calico $ make " + imagePublishTarget) {
		t.Errorf("publish did not run %s in cmd/calico, calls: %v", imagePublishTarget, f.calls())
	}
	env := f.envForDir(root + "/cmd/calico ")
	if !slices.Contains(env, "CONFIRM=true") {
		t.Error("publish env missing CONFIRM=true")
	}
	if slices.Contains(env, "DRYRUN=true") {
		t.Error("publish env should not carry DRYRUN=true")
	}
}

func TestResolveContainerImages(t *testing.T) {
	withoutImages := func(t *testing.T, f *fakeRunner) *CalicoManager {
		m, _ := imageManager(t, f, "")
		m.images = false
		m.isHashRelease = true
		return m
	}
	readRefs := func(t *testing.T, m *CalicoManager, step string) []string {
		t.Helper()
		refs, err := outputs.ReadRefs(m.recordsDir, step)
		if err != nil {
			t.Fatalf("ReadRefs(%s): %v", step, err)
		}
		return refs
	}

	t.Run("records the images as resolved", func(t *testing.T) {
		f := newFakeRunner()
		m := withoutImages(t, f)
		if err := m.resolveContainerImages(); err != nil {
			t.Fatalf("resolveContainerImages: %v", err)
		}
		if len(readRefs(t, m, images.ResolveStep)) == 0 {
			t.Errorf("nothing recorded under %s", images.ResolveStep)
		}
		if refs := readRefs(t, m, "images-publish"); len(refs) != 0 {
			t.Errorf("a resolve wrote the publish record: %v", refs)
		}
		for _, c := range f.calls() {
			if strings.HasSuffix(c, " "+imagePublishTarget) {
				t.Errorf("a resolve ran the publish target: %s", c)
			}
		}
	})

	t.Run("a missing image fails after the rest are recorded", func(t *testing.T) {
		m := withoutImages(t, newFakeRunner())
		missing := registry.DefaultProductRegistry + "/calico:" + m.calicoVersion.String()
		m.resolveDigest = func(image string) (string, bool, error) {
			if image == missing {
				return "", false, nil
			}
			return "sha256:aaa", true, nil
		}
		err := m.resolveContainerImages()
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Fatalf("got %v, want an error naming %s", err, missing)
		}
		if len(readRefs(t, m, images.ResolveStep)) == 0 {
			t.Error("the images that exist were not recorded")
		}
	})

	t.Run("a dry run lets a missing image pass", func(t *testing.T) {
		m := withoutImages(t, newFakeRunner())
		m.dryRun = true
		missing := registry.DefaultProductRegistry + "/calico:" + m.calicoVersion.String()
		m.resolveDigest = func(image string) (string, bool, error) {
			if image == missing {
				return "", false, nil
			}
			return "sha256:aaa", true, nil
		}
		if err := m.resolveContainerImages(); err != nil {
			t.Fatalf("resolveContainerImages: %v", err)
		}
		if len(readRefs(t, m, images.ResolveStep)) == 0 {
			t.Error("the images that exist were not recorded")
		}
	})

	t.Run("a dry run with missing images still reports its scan", func(t *testing.T) {
		m := withoutImages(t, newFakeRunner())
		scans := enableScan(t, m)
		m.dryRun = true
		m.resolveDigest = func(string) (string, bool, error) { return "", false, nil }
		hook := logtest.NewGlobal()
		t.Cleanup(hook.Reset)
		if err := m.resolveContainerImages(); err != nil {
			t.Fatalf("resolveContainerImages: %v", err)
		}
		if got := len(scans.sent()); got != 0 {
			t.Errorf("a dry run sent %d scan requests", got)
		}
		var reported bool
		for _, e := range hook.AllEntries() {
			reported = reported || e.Message == "Dry run, not sending images to ISS"
		}
		if !reported {
			t.Error("the dry run did not report its scan")
		}
	})

	t.Run("a dry run still fails a failed lookup", func(t *testing.T) {
		m := withoutImages(t, newFakeRunner())
		m.dryRun = true
		m.resolveDigest = func(string) (string, bool, error) {
			return "", false, fmt.Errorf("unauthorized")
		}
		if err := m.resolveContainerImages(); err == nil {
			t.Fatal("expected the failed lookup to fail the run")
		}
	})

	t.Run("runs first, before metadata", func(t *testing.T) {
		var kinds []string
		for _, u := range withoutImages(t, newFakeRunner()).uploads() {
			kinds = append(kinds, u.Handler.Name())
		}
		resolve, meta := slices.Index(kinds, "images"), slices.Index(kinds, outputs.MetadataStep)
		if resolve != 0 || meta < resolve {
			t.Errorf("uploads %v: images must come first, before metadata", kinds)
		}
	})

	t.Run("the images upload scans once every image is found", func(t *testing.T) {
		m := withoutImages(t, newFakeRunner())
		scans := enableScan(t, m)
		if err := m.uploads()[0].Handler.Publish(context.Background(), ""); err != nil {
			t.Fatalf("images upload: %v", err)
		}
		if got := len(scans.sent()); got != 1 {
			t.Errorf("sent %d scan requests, want 1", got)
		}
	})

	t.Run("a dry run does not scan", func(t *testing.T) {
		m := withoutImages(t, newFakeRunner())
		scans := enableScan(t, m)
		m.dryRun = true
		if err := m.uploads()[0].Handler.Publish(context.Background(), ""); err != nil {
			t.Fatalf("images upload: %v", err)
		}
		if got := len(scans.sent()); got != 0 {
			t.Errorf("a dry run sent %d scan requests", got)
		}
	})

	t.Run("the prereqs look nothing up", func(t *testing.T) {
		m := withoutImages(t, newFakeRunner())
		m.operator = nil
		var lookups int
		m.resolveDigest = func(string) (string, bool, error) {
			lookups++
			return "", false, nil
		}
		if err := m.hashreleasePrereqs(); err != nil {
			t.Fatalf("hashreleasePrereqs: %v", err)
		}
		if lookups != 0 {
			t.Errorf("the prereqs resolved %d images", lookups)
		}
	})
}

func TestComponentImages(t *testing.T) {
	t.Run("scans the operator at the registry the run uses", func(t *testing.T) {
		m, _ := imageManager(t, newFakeRunner(), "")
		m.operatorRegistry = "quay.io/override"
		m.operatorVersion = "v1.40.0"
		m.components = map[string]registry.Component{
			m.operatorImage: {Registry: "quay.io/pinned", Image: m.operatorImage, Version: m.operatorVersion},
		}
		want := "quay.io/override/" + m.operatorImage + ":v1.40.0"
		if got := m.componentImages()[m.operatorImage]; got != want {
			t.Errorf("scans %s, want %s", got, want)
		}
	})

	t.Run("scans the pin's images and nothing it records by version", func(t *testing.T) {
		m, _ := imageManager(t, newFakeRunner(), "")
		pin := pinnedversion.Pin{
			Operator: registry.Component{Registry: m.operatorRegistry, Image: m.operatorImage, Version: m.operatorVersion},
			Components: map[string]registry.Component{
				"node":   {Version: m.calicoVersion.String()},
				"calico": {Version: m.calicoVersion.String()},
			},
		}
		m.components = pin.Released()
		got := slices.Sorted(maps.Keys(m.componentImages()))
		if want := slices.Sorted(maps.Keys(pin.Images())); !slices.Equal(got, want) {
			t.Errorf("scans %v, want the pin's images %v", got, want)
		}
	})
}

func TestReleasedComponents(t *testing.T) {
	m, _ := imageManager(t, newFakeRunner(), "")
	m.components = map[string]registry.Component{
		"node": {Image: "node", Version: m.calicoVersion.String()},
		"api":  {Version: m.calicoVersion.String()},
	}
	got := m.releasedComponents()

	t.Run("places an image the pin leaves unplaced at the run's registry", func(t *testing.T) {
		if got["node"].Registry != m.imageRegistries[0] {
			t.Errorf("node registry = %q, want %q", got["node"].Registry, m.imageRegistries[0])
		}
	})

	t.Run("keeps a component with no image by version alone", func(t *testing.T) {
		if want := (registry.Component{Version: m.calicoVersion.String()}); got["api"] != want {
			t.Errorf("api = %+v, want %+v", got["api"], want)
		}
		if _, ok := m.componentImages()["api"]; ok {
			t.Error("a component with no image was scanned")
		}
	})
}

func TestResolveOperator(t *testing.T) {
	newManager := func(t *testing.T, resolve func(string) (string, bool, error)) *CalicoManager {
		m, _ := imageManager(t, newFakeRunner(), "")
		m.images = false
		m.isHashRelease = true
		m.operator = nil
		m.operatorVersion = "v1.40.0"
		m.resolveDigest = resolve
		return m
	}
	scanOperator := func(t *testing.T, m *CalicoManager) *scanLog {
		t.Helper()
		scans := enableScan(t, m)
		m.components[m.operatorImage] = registry.Component{Registry: m.operatorRegistry, Image: m.operatorImage, Version: m.operatorVersion}
		return scans
	}
	operatorRef := func(m *CalicoManager) string { return m.operatorComponent().String() }
	missingOperator := func(m *CalicoManager) func(string) (string, bool, error) {
		return func(image string) (string, bool, error) {
			if strings.Contains(image, "/"+m.operatorImage+":") {
				return "", false, nil
			}
			return "sha256:aaa", true, nil
		}
	}

	t.Run("records an operator the run does not publish", func(t *testing.T) {
		m := newManager(t, func(string) (string, bool, error) { return "sha256:aaa", true, nil })
		unscanned, err := m.resolveOperator()
		if err != nil || len(unscanned) != 0 {
			t.Fatalf("resolveOperator() = %v, %v; want nothing left out", unscanned, err)
		}
		refs, err := outputs.ReadRefs(m.recordsDir, operator.ResolveStep)
		if err != nil {
			t.Fatalf("ReadRefs: %v", err)
		}
		want := m.operatorRegistry + "/" + m.operatorImage + ":" + m.operatorVersion + "@sha256:aaa"
		if !slices.Contains(refs, want) {
			t.Errorf("recorded %v, want %s", refs, want)
		}
	})

	t.Run("a missing operator only warns and leaves the scan", func(t *testing.T) {
		m := newManager(t, nil)
		m.resolveDigest = missingOperator(m)
		scans := scanOperator(t, m)
		if err := m.resolveContainerImages(); err != nil {
			t.Fatalf("resolveContainerImages: %v", err)
		}
		sent := scans.sent()
		if len(sent) != 1 || slices.Contains(sent[0], operatorRef(m)) {
			t.Errorf("sent %v, want one scan without %s", sent, operatorRef(m))
		}
	})

	t.Run("a missing operator leaves the scan under an overridden registry", func(t *testing.T) {
		m := newManager(t, nil)
		m.resolveDigest = missingOperator(m)
		scanOperator(t, m)
		m.operatorRegistry = "quay.io/override"
		unscanned, err := m.resolveOperator()
		if err != nil {
			t.Fatalf("resolveOperator: %v", err)
		}
		if !slices.Equal(unscanned, []string{operatorRef(m)}) {
			t.Errorf("left out %v, want %s", unscanned, operatorRef(m))
		}
	})

	t.Run("a failed lookup holds the scan and still records the product", func(t *testing.T) {
		m := newManager(t, nil)
		m.resolveDigest = func(image string) (string, bool, error) {
			if strings.Contains(image, "/"+m.operatorImage+":") {
				return "", false, fmt.Errorf("unauthorized")
			}
			return "sha256:aaa", true, nil
		}
		scans := scanOperator(t, m)
		if err := m.resolveContainerImages(); err == nil {
			t.Fatal("expected the failed lookup to fail the run")
		}
		if sent := scans.sent(); len(sent) != 0 {
			t.Errorf("sent %v from a failed attempt", sent)
		}
		refs, err := outputs.ReadRefs(m.recordsDir, images.ResolveStep)
		if err != nil || len(refs) == 0 {
			t.Errorf("the product images were not recorded: %v, %v", refs, err)
		}
	})

	t.Run("a retry that finds the operator scans it once", func(t *testing.T) {
		var unavailable atomic.Bool
		unavailable.Store(true)
		m := newManager(t, func(string) (string, bool, error) {
			if unavailable.Load() {
				return "", false, fmt.Errorf("unavailable")
			}
			return "sha256:aaa", true, nil
		})
		scans := scanOperator(t, m)
		if err := m.resolveContainerImages(); err == nil {
			t.Fatal("expected the first attempt to fail")
		}
		unavailable.Store(false)
		if err := m.resolveContainerImages(); err != nil {
			t.Fatalf("retry: %v", err)
		}
		sent := scans.sent()
		if len(sent) != 1 || !slices.Contains(sent[0], operatorRef(m)) {
			t.Errorf("sent %v, want one scan with %s", sent, operatorRef(m))
		}
	})

	t.Run("skips an operator the run publishes", func(t *testing.T) {
		var lookups atomic.Int32
		m := newManager(t, func(string) (string, bool, error) {
			lookups.Add(1)
			return "", false, nil
		})
		m.operator = func() error { return nil }
		if _, err := m.resolveOperator(); err != nil {
			t.Fatalf("resolveOperator: %v", err)
		}
		if n := lookups.Load(); n != 0 {
			t.Errorf("looked up %d images", n)
		}
	})
}

type scanLog struct {
	mu    sync.Mutex
	scans [][]string
}

func (l *scanLog) sent() [][]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.scans)
}

func enableScan(t *testing.T, m *CalicoManager) *scanLog {
	t.Helper()
	scans := &scanLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Images []string `json:"images"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		scans.mu.Lock()
		scans.scans = append(scans.scans, body.Images)
		scans.mu.Unlock()
		_, _ = w.Write([]byte(`{"results_link": "http://example.com/results"}`))
	}))
	t.Cleanup(srv.Close)
	m.imageScanning = true
	m.imageScanningConfig = imagescanner.Config{APIURL: srv.URL, Token: "token", Scanner: "scanner"}
	m.components = map[string]registry.Component{"calico": {Image: "calico", Version: m.calicoVersion.String()}}
	m.tmpDir = t.TempDir()
	return scans
}

// Each image unit gets its own log file; concurrent units would otherwise
// interleave into one stream.
func TestImageStepsWriteLogFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*CalicoManager) error
		want []string
	}{
		{"build", (*CalicoManager).buildContainerImages, []string{
			"/logs/images-build/node-windows.log",
			"/logs/images-build/node.log",
		}},
		{"publish", (*CalicoManager).publishContainerImages, []string{
			// The branch tag is a second publish, so it logs under its own step.
			"/logs/images-publish-branch/node-windows.log",
			"/logs/images-publish-branch/node.log",
			"/logs/images-publish/node-windows.log",
			"/logs/images-publish/node.log",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner()
			m, root := imageManager(t, f, "/logs")
			if err := tc.run(m); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			// node ships both variants, so its two units must not share a file.
			got := f.logPathsForDir(root + "/node ")
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("node log paths\n got %v\nwant %v", got, tc.want)
			}
		})
	}
}

func TestPublishBranchTag(t *testing.T) {
	t.Run("moves the tag", func(t *testing.T) {
		prefix, dev := defaults.ReleaseBranchPrefix(), defaults.DevTagSuffix()
		tests := []struct {
			name          string
			version       string
			branch        string
			trailer       string
			images        bool
			isHashRelease bool
			wantPublish   bool
			wantBranchTag bool
			wantTag       string
			prefix        string
			wantErr       bool
		}{
			{
				name:          "hashrelease also pushes the branch tag",
				version:       "v3.33.0-" + dev + "-1-gabcdef123456",
				branch:        prefix + "-v3.33",
				images:        true,
				isHashRelease: true,
				wantPublish:   true,
				wantBranchTag: true,
				wantTag:       prefix + "-v3.33",
			},
			{
				name:          "early preview keeps its stream suffix",
				version:       "v3.33.0-1.0-" + dev + "-1-gabcdef123456",
				branch:        prefix + "-v3.33-1",
				images:        true,
				isHashRelease: true,
				wantPublish:   true,
				wantBranchTag: true,
				wantTag:       prefix + "-v3.33-1",
			},
			{
				name:          "hashrelease on the default branch tags it",
				version:       "v3.34.0-" + dev + "-1-gabcdef123456",
				branch:        "master",
				images:        true,
				isHashRelease: true,
				wantPublish:   true,
				wantBranchTag: true,
				wantTag:       "master",
			},
			{
				name:          "hashrelease on any other branch has no branch tag",
				version:       "v3.34.0-" + dev + "-1-gabcdef123456",
				branch:        "fix-foo",
				images:        true,
				isHashRelease: true,
				wantPublish:   true,
				wantBranchTag: false,
			},
			{
				name:          "official release on its prep branch tags the recorded branch",
				version:       "v3.33.1",
				branch:        "build-v3.33.1",
				trailer:       prefix + "-v3.33-2\n",
				images:        true,
				isHashRelease: false,
				wantPublish:   true,
				wantBranchTag: true,
				wantTag:       prefix + "-v3.33-2",
			},
			{
				name:          "official release on a release branch tags it",
				version:       "v3.33.1",
				branch:        prefix + "-v3.33",
				images:        true,
				isHashRelease: false,
				wantPublish:   true,
				wantBranchTag: true,
				wantTag:       prefix + "-v3.33",
			},
			{
				name:          "official release on a prep branch with no recorded branch is an error",
				version:       "v3.33.1",
				branch:        "build-v3.33.1",
				prefix:        prefix,
				images:        true,
				isHashRelease: false,
				wantPublish:   true,
				wantErr:       true,
			},
			{
				// An unset prefix would silently tag images "-v3.33".
				name:          "missing branch prefix is an error",
				version:       "v3.33.0-" + dev + "-1-gabcdef123456",
				images:        true,
				isHashRelease: true,
				prefix:        "",
				wantPublish:   true,
				wantErr:       true,
			},
			{
				name:          "images disabled publishes nothing",
				version:       "v3.33.0-" + dev + "-1-gabcdef123456",
				images:        false,
				isHashRelease: true,
				wantPublish:   false,
				wantBranchTag: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFakeRunner()
				f.on("git rev-parse --abbrev-ref HEAD", tt.branch+"\n", nil)
				f.on("git log -1 -i --grep=^Release-branch: ", tt.trailer, nil)

				branchPrefix := tt.prefix
				if branchPrefix == "" && !tt.wantErr {
					branchPrefix = prefix
				}
				r, root := imageManager(t, f, "")
				r.images = tt.images
				r.isHashRelease = tt.isHashRelease
				// A hashrelease reads its registry from its own source tree.
				r.hashrelease.Source = root
				r.calicoVersion = testVersion(t, tt.version)
				r.releaseBranchPrefix = branchPrefix

				err := r.publishContainerImages()
				if tt.wantErr {
					if err == nil {
						t.Fatalf("publishContainerImages() = nil, want error")
					}
					return
				}
				if err != nil {
					t.Fatalf("publishContainerImages() unexpected error: %v", err)
				}

				if got := f.ran(root + "/cmd/calico $ make " + imagePublishTarget); got != tt.wantPublish {
					t.Errorf("%s ran = %v, want %v (calls: %v)", imagePublishTarget, got, tt.wantPublish, f.calls())
				}
				if got := f.ran(root + "/cmd/calico $ make " + branchTagTarget); got != tt.wantBranchTag {
					t.Errorf("branch tag publish ran = %v, want %v (calls: %v)", got, tt.wantBranchTag, f.calls())
				}
				if tt.wantBranchTag {
					if got := f.envFor(root + "/cmd/calico $ make " + branchTagTarget); !slices.Contains(got, "IMAGETAG="+tt.wantTag) {
						t.Errorf("branch tag env = %v, want IMAGETAG=%s", got, tt.wantTag)
					}
				}

				// The operator carries the branch tag too, published to its own registries.
				opTarget := root + "/operator $ make retag-build-images-with-registries"
				if got := f.ran(opTarget); got != tt.wantBranchTag {
					t.Errorf("operator branch tag publish ran = %v, want %v (calls: %v)", got, tt.wantBranchTag, f.calls())
				}
				if tt.wantBranchTag {
					env := f.envFor(opTarget)
					if !slices.Contains(env, "IMAGETAG="+tt.wantTag) {
						t.Errorf("operator branch tag env = %v, want IMAGETAG=%s", env, tt.wantTag)
					}
					// These targets iterate DEV_REGISTRIES, so it names the
					// destination rather than a retag source.
					want := "DEV_REGISTRIES=" + r.operatorRegistry
					if !slices.Contains(env, want) {
						t.Errorf("operator branch tag env = %v, want %s", env, want)
					}
				}
			})
		}
	})

	// The branch tag is a release-channel convention, so a build aimed at some
	// other registry must not push one there. The operator is gated separately
	// because it publishes to registries of its own.
	t.Run("skipped for a non-default product registry", func(t *testing.T) {
		f := newFakeRunner()
		r, root := imageManager(t, f, "")
		r.imageRegistries = []string{"quay.io/somewhere-else"}
		if err := r.publishContainerImages(); err != nil {
			t.Fatalf("publishContainerImages: %v", err)
		}
		if got := root + "/cmd/calico $ make " + branchTagTarget; f.ran(got) {
			t.Errorf("ran %q for a registry outside the default (calls: %v)", got, f.calls())
		}
	})

	t.Run("skipped when the operator is off", func(t *testing.T) {
		f := newFakeRunner()
		r, root := imageManager(t, f, "")
		r.operator = nil
		if err := r.publishContainerImages(); err != nil {
			t.Fatalf("publishContainerImages: %v", err)
		}
		if got := root + "/operator $ make " + branchTagTarget; f.ran(got) {
			t.Errorf("ran %q with the operator off (calls: %v)", got, f.calls())
		}
	})

	t.Run("skipped for a non-default operator registry", func(t *testing.T) {
		f := newFakeRunner()
		r, root := imageManager(t, f, "")
		r.operatorRegistry = "quay.io/somewhere-else"
		if err := r.publishContainerImages(); err != nil {
			t.Fatalf("publishContainerImages: %v", err)
		}
		if got := root + "/operator $ make " + branchTagTarget; f.ran(got) {
			t.Errorf("ran %q for a registry outside the defaults (calls: %v)", got, f.calls())
		}
	})

	// cni-plugin ships only a Windows image, so the standard branch tag target
	// there retags arch images that were never built.
	t.Run("windows split from standard", func(t *testing.T) {
		f := newFakeRunner()
		m, root := imageManager(t, f, "")
		if err := m.publishContainerImages(); err != nil {
			t.Fatalf("publishContainerImages: %v", err)
		}
		if got := root + "/cni-plugin $ make " + branchTagTarget; f.ran(got) {
			t.Errorf("branch tag ran %q, which has no arch images to retag (calls: %v)", got, f.calls())
		}
		want := root + "/cni-plugin $ make " + windowsBranchTagTarget
		if !f.ran(want) {
			t.Errorf("did not run %q, ran: %v", want, f.calls())
		}

		// The copy is registry side, so it needs the tag it copies from.
		if env := f.envFor(want); !slices.Contains(env, "DEV_TAG=v3.30.0") {
			t.Errorf("windows branch tag env = %v, want DEV_TAG=v3.30.0", env)
		}
	})

	t.Run("no windows dirs skips the windows tag", func(t *testing.T) {
		orig := windowsBranchTagDirs
		t.Cleanup(func() { windowsBranchTagDirs = orig })
		windowsBranchTagDirs = nil

		f := newFakeRunner()
		m, root := imageManager(t, f, "")
		if err := m.publishContainerImages(); err != nil {
			t.Fatalf("publishContainerImages: %v", err)
		}
		if got := root + "/cni-plugin $ make " + windowsBranchTagTarget; f.ran(got) {
			t.Errorf("ran %q with no windows dirs (calls: %v)", got, f.calls())
		}
		if got := root + "/cmd/calico $ make " + branchTagTarget; !f.ran(got) {
			t.Errorf("did not run %q, ran: %v", got, f.calls())
		}
	})
}

// Narrowing must scope the manager's image steps the same way the CLI does.
func TestImageStepsNarrowedToReleaseDirs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		run    func(*CalicoManager) error
		target string
	}{
		{"build", (*CalicoManager).buildContainerImages, "release-build"},
		{"publish", (*CalicoManager).publishContainerImages, "release-publish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner()
			m, root := imageManager(t, f, "")
			m.imageReleaseDirs = []string{"whisker"}
			if err := tc.run(m); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			units := unitCalls(f, tc.target)
			if len(units) != 1 {
				t.Fatalf("expected one unit for whisker, ran: %v", units)
			}
			if !f.ran(root + "/whisker $ make " + tc.target) {
				t.Errorf("did not run %s in whisker, ran: %v", tc.target, f.calls())
			}
		})
	}
}

// An empty list leaves every directory in play.
func TestImageStepsUnnarrowedByDefault(t *testing.T) {
	f := newFakeRunner()
	m, _ := imageManager(t, f, "")
	if err := m.publishContainerImages(); err != nil {
		t.Fatalf("publishContainerImages: %v", err)
	}
	want := len(images.VariantDirs([]images.Variant{images.PublishVariants[0]}))
	if got := len(unitCalls(f, imagePublishTarget)); got != want {
		t.Errorf("published %d dirs, want every one of %d: %v", got, want, f.calls())
	}
}

// The output directory is where the release writes its artifacts, so an unset
// one is an error whatever validation is set to.
func TestOutputDirRequiredEvenWithoutValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*CalicoManager) error
	}{
		{"build", (*CalicoManager).Build},
		{"publish prereqs", (*CalicoManager).publishPrereqs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &CalicoManager{
				runner:        newFakeRunner(),
				repoRoot:      "/repo",
				calicoVersion: testVersion(t, "v3.30.0"),
				validate:      false,
			}
			err := tc.run(m)
			if err == nil {
				t.Fatal("expected an error when no output directory is set")
			}
			if !strings.Contains(err.Error(), "output directory") {
				t.Errorf("error should name the output directory, got %q", err)
			}
		})
	}
}

func TestChartsAndIndexLocation(t *testing.T) {
	out := t.TempDir()
	for _, tt := range []struct {
		name        string
		hashrelease bool
	}{
		{name: "release"},
		{name: "hashrelease", hashrelease: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(out, "release", "v3.30.0")
			r := &CalicoManager{outputDir: dir, calicoVersion: testVersion(t, "v3.30.0"), isHashRelease: tt.hashrelease}
			if got, want := r.chart().BaseDir, charts.OutputDir(dir); got != want {
				t.Errorf("chart().BaseDir = %q, want %q", got, want)
			}
			want := filepath.Join(dir, "charts")
			if got := charts.IndexDir(dir); got != want {
				t.Errorf("IndexDir = %q, want %q", got, want)
			}
		})
	}
}

func TestAssertOperatorImageVersion(t *testing.T) {
	const version = "v1.42.0"
	for _, tt := range []struct {
		name    string
		label   string
		wantErr bool
	}{
		{name: "image reports the published version", label: version},
		{name: "image reports another version", label: "v1.41.0", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner().on("docker inspect", tt.label, nil)
			r := &CalicoManager{
				runner:           f,
				operatorRegistry: "quay.io/tigera",
				operatorImage:    "operator",
				operatorVersion:  version,
			}

			err := r.assertOperatorImageVersion()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, f.calls(), 1)
			require.Contains(t, f.calls()[0], "quay.io/tigera/operator:"+version)
		})
	}
}

// A release publish records what it pushed, so an interrupted run resumes on
// what is left rather than re-pushing.
func TestPublishHelmChartsRecordsWhatItPushed(t *testing.T) {
	out := t.TempDir()
	f := newFakeRunner()
	r := &CalicoManager{
		runner:         f,
		repoRoot:       "/repo",
		calicoVersion:  testVersion(t, "v3.30.0"),
		outputDir:      filepath.Join(out, "release", "v3.30.0"),
		recordsDir:     t.TempDir(),
		helmCharts:     true,
		helmRegistries: []string{"quay.test/charts"},
		resolveDigest:  func(string) (string, bool, error) { return "sha256:aaa", true, nil },
	}
	for _, name := range charts.All() {
		path := filepath.Join(r.chart().BaseDir, charts.FileName(name, "v3.30.0"))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("chart"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := r.publishHelmCharts(); err != nil {
		t.Fatalf("publishHelmCharts: %v", err)
	}

	refs, err := outputs.ReadRefs(r.recordsDir, charts.PublishStep)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != len(charts.All()) {
		t.Errorf("recorded %d refs, want %d", len(refs), len(charts.All()))
	}
}

// The flag decides whether a release goes public, so a wrong default either
// strands every release in draft or publishes one nobody approved.
func TestGithubReleaseDraftFlag(t *testing.T) {
	for _, tc := range []struct {
		name  string
		draft bool
	}{
		{name: "drafts when asked", draft: true},
		{name: "publishes when the draft flag is off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &CalicoManager{
				githubRelease: true,
				draftRelease:  tc.draft,
				calicoVersion: testVersion(t, "v3.30.0"),
				githubOrg:     "projectcalico",
				repo:          "calico",
				outputDir:     t.TempDir(),
			}
			upload := r.githubReleaseUpload()
			got, ok := upload.Handler.(distribution.GithubRelease)
			if !ok {
				t.Fatalf("handler is %T, want distribution.GithubRelease", upload.Handler)
			}
			if got.Draft != tc.draft {
				t.Errorf("Draft = %v, want %v", got.Draft, tc.draft)
			}
		})
	}
}

// The index is only written when both steps ran, so the upload has to say it
// may be absent rather than failing a release that did not build one.
func TestHelmIndexUploadAllowsAMissingIndex(t *testing.T) {
	for _, tc := range []struct {
		name       string
		helmCharts bool
		helmIndex  bool
		wantAllow  bool
	}{
		{name: "both steps ran", helmCharts: true, helmIndex: true},
		{name: "charts disabled", helmIndex: true, wantAllow: true},
		{name: "index disabled", helmCharts: true, wantAllow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &CalicoManager{
				helmCharts:    tc.helmCharts,
				helmIndex:     tc.helmIndex,
				calicoVersion: testVersion(t, "v3.30.0"),
				s3Bucket:      "bucket",
				outputDir:     t.TempDir(),
			}
			if got := r.helmIndexUpload().Skip; got != tc.wantAllow {
				t.Errorf("Skip = %v, want %v", got, tc.wantAllow)
			}
		})
	}
}

// aws s3 cp to a key with no trailing slash writes an object named for the
// prefix rather than a file inside it, so the index silently stops updating.
func TestHelmIndexUploadTargetsTheChartsPrefix(t *testing.T) {
	r := &CalicoManager{helmCharts: true, helmIndex: true, s3Bucket: "bucket", outputDir: t.TempDir()}
	got, ok := r.helmIndexUpload().Handler.(distribution.S3)
	if !ok {
		t.Fatalf("handler is %T, want distribution.S3", r.helmIndexUpload().Handler)
	}
	if want := "s3://bucket/charts/"; got.URI != want {
		t.Errorf("URI = %q, want %q", got.URI, want)
	}
}

func TestHelmIndexUploadSetsCachePolicy(t *testing.T) {
	r := &CalicoManager{helmCharts: true, helmIndex: true, s3Bucket: "bucket", outputDir: t.TempDir()}
	got, ok := r.helmIndexUpload().Handler.(distribution.S3)
	if !ok {
		t.Fatalf("handler is %T, want distribution.S3", r.helmIndexUpload().Handler)
	}
	if got.CachePolicy != distribution.MutableCachePolicy {
		t.Errorf("CachePolicy = %q, want %q", got.CachePolicy, distribution.MutableCachePolicy)
	}
}

func TestCheckCodeGeneration(t *testing.T) {
	const (
		status = "git status --porcelain"
		check  = "make generate check-dirty"
		reset  = "git checkout -- ."
		clean  = "git clean -fd"
	)
	for _, tc := range []struct {
		name    string
		status  string
		makeErr error
		wantErr string
		want    []string
	}{
		{name: "an up-to-date checkout passes", want: []string{status, check}},
		{
			name:    "stale generated files fail and are reset",
			makeErr: errors.New("check-dirty failed"),
			wantErr: "code generation error",
			want:    []string{status, check, reset, clean},
		},
		{
			name:    "a checkout with changes is left alone",
			status:  "?? notes.txt",
			wantErr: "checkout with changes",
			want:    []string{status},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner().on(status, tc.status, nil).on(check, "", tc.makeErr)
			r := &CalicoManager{runner: f, repoRoot: t.TempDir()}
			err := r.checkCodeGeneration()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("checkCodeGeneration: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("checkCodeGeneration() error = %v, want %q", err, tc.wantErr)
			}
			if len(f.calls()) != len(tc.want) {
				t.Fatalf("ran %v, want %v", f.calls(), tc.want)
			}
			for i, prefix := range tc.want {
				if !strings.HasPrefix(f.calls()[i], prefix) {
					t.Errorf("call %d = %q, want it to start with %q", i, f.calls()[i], prefix)
				}
			}
		})
	}
}

func TestPublishGitTagPreviewsThePushOnADryRun(t *testing.T) {
	f := newFakeRunner()
	f.on("git ls-remote --tags origin refs/tags/v3.30.0", "", nil)

	r := &CalicoManager{
		runner:        f,
		gitRef:        true,
		dryRun:        true,
		calicoVersion: testVersion(t, "v3.30.0"),
		remote:        "origin",
		repoRoot:      t.TempDir(),
	}
	if err := r.publishGitTag(); err != nil {
		t.Fatalf("publishGitTag() = %v, want nil", err)
	}
	if !f.ran("git push origin v3.30.0 --dry-run") {
		t.Errorf("expected a previewed push, got %v", f.calls())
	}
}

func TestGetRegistryFromManifests(t *testing.T) {
	for _, tc := range []struct {
		name  string
		image string
		want  string
	}{
		{"a plain registry", "quay.io/calico/calico:master", "quay.io/calico"},
		{"a registry with a path", "gcr.io/unique-caldron-775/cnx/tigera/calico:master", "gcr.io/unique-caldron-775/cnx/tigera"},
		{"no registry at all", "calico:master", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "manifests")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("creating manifests dir: %v", err)
			}
			// Several documents, image in the last, so a decoder that stops at
			// the first would fail here.
			doc := fmt.Sprintf("kind: ServiceAccount\n---\nkind: Pod\nspec:\n  containers:\n    - name: calicoctl\n      image: %s\n", tc.image)
			if err := os.WriteFile(filepath.Join(dir, "calicoctl.yaml"), []byte(doc), 0o644); err != nil {
				t.Fatalf("writing manifest: %v", err)
			}

			// A hashrelease reads its own source tree, so point the repo root
			// somewhere empty to catch a lookup that ignores the flag.
			for _, hashrelease := range []bool{false, true} {
				m := &CalicoManager{repoRoot: root}
				if hashrelease {
					m = &CalicoManager{
						repoRoot:      t.TempDir(),
						isHashRelease: true,
						hashrelease:   hashreleaseserver.Hashrelease{Source: root},
					}
				}
				assertRegistry(t, m, tc.want)
			}
		})
	}
}

func assertRegistry(t *testing.T, m *CalicoManager, want string) {
	t.Helper()
	got, err := m.getRegistryFromManifests()
	if err != nil {
		t.Fatalf("getRegistryFromManifests: %v", err)
	}
	if got != want {
		t.Errorf("registry = %q, want %q", got, want)
	}
}

func TestPublishNodes(t *testing.T) {
	names := func(r *CalicoManager) []string {
		var got []string
		for _, n := range r.publishPlan() {
			got = append(got, n.Name)
		}
		return got
	}

	t.Run("a release tags, then releases, then indexes the charts", func(t *testing.T) {
		r := &CalicoManager{calicoVersion: testVersion(t, "v3.30.0"), githubOrg: "projectcalico", repo: "calico", outputDir: t.TempDir()}
		want := []string{
			prepPublishStep, operator.Step, images.Step, charts.Step, outputs.MetadataStep, distribution.ChecksumStep,
			distribution.GithubTagStep, distribution.GithubReleaseStep, helmIndexStep,
		}
		if diff := cmp.Diff(want, names(r)); diff != "" {
			t.Errorf("nodes (-want +got):\n%s", diff)
		}
	})

	t.Run("a hashrelease ends with the hashrelease upload", func(t *testing.T) {
		r := &CalicoManager{isHashRelease: true, calicoVersion: testVersion(t, "v3.30.0"), outputDir: t.TempDir()}
		want := []string{prepPublishStep, operator.Step, images.Step, charts.Step, outputs.MetadataStep, distribution.ChecksumStep, distribution.HashreleasePublishStep}
		if diff := cmp.Diff(want, names(r)); diff != "" {
			t.Errorf("nodes (-want +got):\n%s", diff)
		}
	})

	t.Run("each mode's skip list names every step but the checks", func(t *testing.T) {
		for _, tc := range []struct {
			r    *CalicoManager
			want []string
		}{
			{r: &CalicoManager{calicoVersion: testVersion(t, "v3.30.0"), outputDir: t.TempDir()}, want: PublishSteps()},
			{r: &CalicoManager{isHashRelease: true, calicoVersion: testVersion(t, "v3.30.0"), outputDir: t.TempDir()}, want: HashreleasePublishSteps()},
		} {
			if diff := cmp.Diff(tc.want, names(tc.r)[1:]); diff != "" {
				t.Errorf("skip list (-want +got):\n%s", diff)
			}
		}
	})

	t.Run("the images upload requires the operator ISS scans", func(t *testing.T) {
		requires := func(r *CalicoManager) []string {
			for _, n := range r.publishPlan() {
				if n.Name == images.Step {
					return n.Requires
				}
			}
			t.Fatalf("no %s node", images.Step)
			return nil
		}

		t.Run("when the operator publishes", func(t *testing.T) {
			r := &CalicoManager{calicoVersion: testVersion(t, "v3.30.0"), outputDir: t.TempDir(), operator: func() error { return nil }}
			if diff := cmp.Diff([]string{operator.Step}, requires(r)); diff != "" {
				t.Errorf("requires (-want +got):\n%s", diff)
			}
			got := names(r)
			if slices.Index(got, operator.Step) >= slices.Index(got, images.Step) {
				t.Errorf("%s does not run before %s", operator.Step, images.Step)
			}
		})

		t.Run("not when it does not", func(t *testing.T) {
			r := &CalicoManager{calicoVersion: testVersion(t, "v3.30.0"), outputDir: t.TempDir()}
			if got := requires(r); got != nil {
				t.Errorf("requires %v with no operator publish", got)
			}
		})

		t.Run("not when the operator is skipped", func(t *testing.T) {
			r := &CalicoManager{
				calicoVersion: testVersion(t, "v3.30.0"), outputDir: t.TempDir(),
				operator:    func() error { return nil },
				planOptions: plan.Options{Skip: map[string]bool{operator.Step: true}},
			}
			if got := requires(r); got != nil {
				t.Errorf("requires %v with the operator skipped", got)
			}
		})
	})
}

func TestPublishRelease(t *testing.T) {
	t.Run("a failed check publishes nothing, the operator included", func(t *testing.T) {
		published := false
		r := &CalicoManager{
			calicoVersion: testVersion(t, "v3.30.0"),
			outputDir:     t.TempDir(),
			operator:      func() error { published = true; return nil },
		}
		err := r.PublishRelease()
		if err == nil || !strings.Contains(err.Error(), "no records directory specified") {
			t.Fatalf("PublishRelease() error = %v, want no records directory", err)
		}
		if published {
			t.Error("published the operator before the checks passed")
		}
	})

	t.Run("not pushing the tag fails a GitHub release before anything publishes", func(t *testing.T) {
		published := false
		r := &CalicoManager{
			calicoVersion: testVersion(t, "v3.30.0"),
			outputDir:     t.TempDir(),
			githubRelease: true,
			operator:      func() error { published = true; return nil },
		}
		err := r.PublishRelease()
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("requires %q, which is off", distribution.GithubTagStep)) {
			t.Fatalf("PublishRelease() error = %v, want the release to require the tag", err)
		}
		if published {
			t.Error("published the operator")
		}
	})

	t.Run("a missing local tag fails before anything publishes", func(t *testing.T) {
		published := false
		f := newFakeRunner().on("git rev-parse --verify --quiet refs/tags/v3.30.0", "", errNoGitRef)
		r := &CalicoManager{
			runner:        f,
			calicoVersion: testVersion(t, "v3.30.0"),
			outputDir:     t.TempDir(),
			gitRef:        true,
			githubRelease: true,
			operator:      func() error { published = true; return nil },
		}
		err := r.PublishRelease()
		if err == nil || !strings.Contains(err.Error(), "no local tag v3.30.0") {
			t.Fatalf("PublishRelease() error = %v, want a missing local tag", err)
		}
		if published {
			t.Error("published the operator")
		}
	})

	for _, step := range []string{outputs.MetadataStep, distribution.ChecksumStep, distribution.GithubTagStep} {
		t.Run("skipping "+step+" fails before anything publishes", func(t *testing.T) {
			published := false
			r := &CalicoManager{
				calicoVersion: testVersion(t, "v3.30.0"),
				outputDir:     t.TempDir(),
				githubRelease: true,
				operator:      func() error { published = true; return nil },
				planOptions:   plan.Options{Skip: map[string]bool{step: true}},
			}
			err := r.PublishRelease()
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("requires %q", step)) {
				t.Fatalf("PublishRelease() error = %v, want the release to require %s", err, step)
			}
			if published {
				t.Error("published the operator")
			}
		})
	}
}

func TestGetRegistryFromManifestsFallsBackWhenAbsent(t *testing.T) {
	m := &CalicoManager{
		repoRoot:        t.TempDir(),
		isHashRelease:   true,
		hashrelease:     hashreleaseserver.Hashrelease{Source: t.TempDir()},
		imageRegistries: []string{"gcr.io/unique-caldron-775/cnx"},
	}
	assertRegistry(t, m, "gcr.io/unique-caldron-775/cnx")
}

// Checksums ship with every release, not just the github one, so the step
// that writes them has to run on the hashrelease path too.
func TestChecksumsAreWrittenOnBothPaths(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hashrelease bool
	}{
		{name: "release"},
		{name: "hashrelease", hashrelease: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &CalicoManager{
				isHashRelease:      tc.hashrelease,
				publishHashrelease: tc.hashrelease,
				githubRelease:      true,
				helmCharts:         true,
				helmIndex:          true,
				calicoVersion:      testVersion(t, "v3.30.0"),
				githubOrg:          "projectcalico",
				repo:               "calico",
				s3Bucket:           "bucket",
				outputDir:          t.TempDir(),
			}
			var kinds []string
			for _, u := range r.uploads() {
				kinds = append(kinds, u.Handler.Name())
			}
			if !slices.Contains(kinds, "checksums") {
				t.Errorf("no checksums step in the pipeline: %v", kinds)
			}
		})
	}
}

func TestBuildMetadata(t *testing.T) {
	const (
		nodeDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		opDigest   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	nodeRef := registry.DefaultProductRegistry + "/node:v3.30.0"
	opRef := registry.DefaultOperatorRegistry + "/" + registry.OperatorImage + ":v1.38.0"
	record := func(t *testing.T, dir, step, ref string) {
		t.Helper()
		w, err := outputs.NewRefsWriter(dir, step)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Add(ref); err != nil {
			t.Fatal(err)
		}
	}
	newManager := func(t *testing.T) *CalicoManager {
		f := newFakeRunner()
		f.on("git rev-parse --abbrev-ref HEAD", "release-v3.30\n", nil)
		f.on("git rev-parse HEAD", "0123456789abcdef0123456789abcdef01234567\n", nil)
		records := t.TempDir()
		record(t, records, operator.PublishStep, opRef+"@"+opDigest)
		return &CalicoManager{
			runner:           f,
			githubOrg:        "projectcalico",
			repo:             "calico",
			calicoVersion:    testVersion(t, "v3.30.0"),
			operatorVersion:  "v1.38.0",
			operatorImage:    registry.OperatorImage,
			operatorRegistry: registry.DefaultOperatorRegistry,
			imageRegistries:  []string{registry.DefaultProductRegistry},
			outputDir:        t.TempDir(),
			recordsDir:       records,
			components: map[string]registry.Component{
				"node":                 {Image: "node", Version: "v3.30.0"},
				registry.OperatorImage: {Image: registry.OperatorImage, Version: "v1.38.0"},
			},
			resolveDigest: func(string) (string, bool, error) { return "", false, nil },
		}
	}
	build := func(t *testing.T, r *CalicoManager) (outputs.Metadata, error) {
		t.Helper()
		dir := t.TempDir()
		if err := r.BuildMetadata(dir); err != nil {
			return outputs.Metadata{}, err
		}
		b, err := os.ReadFile(filepath.Join(dir, "metadata.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var md outputs.Metadata
		if err := yaml.Unmarshal(b, &md); err != nil {
			t.Fatal(err)
		}
		return md, nil
	}

	t.Run("describes each component from the step that published it", func(t *testing.T) {
		r := newManager(t)
		record(t, r.recordsDir, images.PublishStep, nodeRef+"@"+nodeDigest)
		got, err := build(t, r)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]outputs.Component{
			"node":                 {Version: "v3.30.0", Image: nodeRef, Digest: nodeDigest},
			registry.OperatorImage: {Version: "v1.38.0", Image: opRef, Digest: opDigest},
		}
		if diff := cmp.Diff(want, got.Components); diff != "" {
			t.Errorf("components (-want +got):\n%s", diff)
		}
	})

	t.Run("a release fails on an unpublished image", func(t *testing.T) {
		if _, err := build(t, newManager(t)); err == nil || !strings.Contains(err.Error(), nodeRef) {
			t.Errorf("err = %v, want it to name %s", err, nodeRef)
		}
	})

	t.Run("a hashrelease leaves an unpublished digest out", func(t *testing.T) {
		r := newManager(t)
		r.isHashRelease = true
		got, err := build(t, r)
		if err != nil {
			t.Fatal(err)
		}
		if want := (outputs.Component{Version: "v3.30.0", Image: nodeRef}); got.Components["node"] != want {
			t.Errorf("node = %+v, want %+v", got.Components["node"], want)
		}
	})
}

func TestSourceMetadata(t *testing.T) {
	const headSHA = "0123456789abcdef0123456789abcdef01234567"
	newManager := func(t *testing.T, branch string) *CalicoManager {
		f := newFakeRunner()
		f.on("git rev-parse --abbrev-ref HEAD", branch+"\n", nil)
		f.on("git rev-parse HEAD", headSHA+"\n", nil)
		return &CalicoManager{runner: f, githubOrg: "projectcalico", repo: "calico", calicoVersion: testVersion(t, "v3.30.0"), gitRef: true}
	}

	t.Run("a release records its branch and tag", func(t *testing.T) {
		got, err := newManager(t, "release-v3.30").sourceMetadata()
		if err != nil {
			t.Fatal(err)
		}
		want := outputs.Source{Repository: "projectcalico/calico", Commit: headSHA, Branch: "release-v3.30", Tag: "v3.30.0"}
		if got != want {
			t.Errorf("source = %+v, want %+v", got, want)
		}
	})

	t.Run("a hashrelease records no tag", func(t *testing.T) {
		r := newManager(t, "master")
		r.isHashRelease = true
		got, err := r.sourceMetadata()
		if err != nil {
			t.Fatal(err)
		}
		if got.Tag != "" || got.Branch != "master" {
			t.Errorf("source = %+v, want branch master and no tag", got)
		}
	})

	t.Run("a release that pushes no tag records none", func(t *testing.T) {
		r := newManager(t, "release-v3.30")
		r.gitRef = false
		got, err := r.sourceMetadata()
		if err != nil {
			t.Fatal(err)
		}
		if got.Tag != "" {
			t.Errorf("tag = %q, want none", got.Tag)
		}
	})

	t.Run("a detached HEAD records no branch", func(t *testing.T) {
		got, err := newManager(t, "HEAD").sourceMetadata()
		if err != nil {
			t.Fatal(err)
		}
		if got.Branch != "" || got.Commit != headSHA {
			t.Errorf("source = %+v, want commit %s and no branch", got, headSHA)
		}
	})

	t.Run("fails when git cannot resolve HEAD", func(t *testing.T) {
		r := &CalicoManager{runner: newFakeRunner().on("git rev-parse HEAD", "", fmt.Errorf("not a git repository"))}
		if _, err := r.sourceMetadata(); err == nil || !strings.Contains(err.Error(), "not a git repository") {
			t.Errorf("err = %v, want it to contain %q", err, "not a git repository")
		}
	})
}

func TestChartsMetadata(t *testing.T) {
	unpublished := outputs.Digests{Resolve: func(string) (string, bool, error) { return "", false, nil }}
	newManager := func(t *testing.T) *CalicoManager {
		return &CalicoManager{
			recordsDir:     t.TempDir(),
			helmCharts:     true,
			helmIndex:      true,
			helmRepoURL:    "https://example.com/charts",
			helmRegistries: []string{"quay.io/calico/charts", "docker.io/calico/charts"},
			calicoVersion:  testVersion(t, "v3.30.0"),
		}
	}

	t.Run("records each chart at the first registry", func(t *testing.T) {
		got, err := newManager(t).chartsMetadata(unpublished)
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != "v3.30.0" || got.Index != "https://example.com/charts" {
			t.Errorf("charts = %+v, want version v3.30.0 and index https://example.com/charts", got)
		}
		if len(got.Entries) != len(charts.All()) {
			t.Errorf("entries = %d, want %d", len(got.Entries), len(charts.All()))
		}
		for _, name := range charts.All() {
			e := got.Entries[name]
			if want := "quay.io/calico/charts/" + name + ":v3.30.0"; e.Image != want {
				t.Errorf("%s image = %q, want %q", name, e.Image, want)
			}
			if !strings.HasSuffix(e.URL, "/"+charts.FileName(name, "v3.30.0")) {
				t.Errorf("%s url = %q, want it to end in the chart file", name, e.URL)
			}
		}
	})

	t.Run("leaves out the index when it is not built", func(t *testing.T) {
		r := newManager(t)
		r.helmIndex = false
		got, err := r.chartsMetadata(unpublished)
		if err != nil {
			t.Fatal(err)
		}
		if got.Index != "" {
			t.Errorf("index = %q, want none", got.Index)
		}
	})

	t.Run("points a hashrelease at the index it serves", func(t *testing.T) {
		r := newManager(t)
		r.isHashRelease = true
		r.hashrelease = hashreleaseserver.Hashrelease{Name: "hr"}
		got, err := r.chartsMetadata(unpublished)
		if err != nil {
			t.Fatal(err)
		}
		if want := r.hashrelease.URL() + "/charts"; got.Index != want {
			t.Errorf("index = %q, want %q", got.Index, want)
		}
	})

	t.Run("records nothing when charts are off", func(t *testing.T) {
		r := newManager(t)
		r.helmCharts = false
		got, err := r.chartsMetadata(unpublished)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Errorf("charts = %+v, want nil", got)
		}
	})

	t.Run("fails with no registry to name the charts by", func(t *testing.T) {
		r := newManager(t)
		r.helmRegistries = nil
		if _, err := r.chartsMetadata(unpublished); err == nil {
			t.Error("recorded charts with no registry")
		}
	})
}

func testVersion(t testing.TB, s string) version.Version {
	t.Helper()
	v, err := version.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCreatePrepPR(t *testing.T) {
	const existing = "https://github.com/someorg/somerepo/pull/42"
	tests := []struct {
		name    string
		ghErr   error
		wantErr bool
	}{
		{
			name: "existing PR switches back to the base branch",
			ghErr: &command.Error{
				Stderr: "a pull request for branch \"prep\" into branch \"master\" already exists:\n" + existing,
				Err:    errors.New("exit status 1"),
			},
		},
		{
			name:    "other failure is returned",
			ghErr:   &command.Error{Stderr: "HTTP 502", Err: errors.New("exit status 1")},
			wantErr: true,
		},
		{
			name:    "already exists outside stderr is not an existing PR",
			ghErr:   errors.New("already exists"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner().on("./bin/gh pr create", "", tt.ghErr)
			r := &CalicoManager{runner: f, githubOrg: "someorg", repo: "somerepo"}
			err := r.createPrepPR("master", "prep")
			if (err != nil) != tt.wantErr {
				t.Fatalf("createPrepPR() = %v, wantErr %v", err, tt.wantErr)
			}
			if got := f.ran("git switch -f master"); got == tt.wantErr {
				t.Errorf("switched back to base = %v, want %v", got, !tt.wantErr)
			}
		})
	}
}
