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
	"fmt"
	"io/fs"
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

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/release/internal/binaries"
	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/distribution"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/images"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/manifests"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/registry"
)

// fakeResult is the canned response for a matched command.
type fakeResult struct {
	stdout string
	err    error
}

// fakeRunner is a command.CommandRunner that returns canned output per command
// and records every invocation so tests can assert what was (and was not) run.
type fakeRunner struct {
	mu sync.Mutex

	// responses maps a command key ("name arg1 arg2 ...") to its canned result.
	// A key that is a prefix of the invoked command also matches (longest-prefix
	// wins), so tests can match on a stable command head without spelling out
	// variable trailing args (a temp-file path, an enumerated asset list).
	responses map[string]fakeResult

	// calls records every command invoked, as "name arg1 arg2 ...".
	calls []string

	// Parallel to calls, so a test can assert what a step passed to make.
	envs     [][]string
	logPaths []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{responses: map[string]fakeResult{}}
}

// on registers a canned result for a command key.
func (f *fakeRunner) on(key, stdout string, err error) *fakeRunner {
	f.responses[key] = fakeResult{stdout: stdout, err: err}
	return f
}

func (f *fakeRunner) record(name string, args []string) (string, error) {
	return f.recordFull(name, args, nil, "")
}

// Image steps run their units concurrently, so recording has to be locked.
func (f *fakeRunner) recordFull(name string, args, env []string, logPath string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, cmd)
	f.envs = append(f.envs, slices.Clone(env))
	f.logPaths = append(f.logPaths, logPath)
	if res, ok := f.responses[cmd]; ok {
		return res.stdout, res.err
	}
	var bestKey string
	for key := range f.responses {
		if strings.HasPrefix(cmd, key) && len(key) > len(bestKey) {
			bestKey = key
		}
	}
	if bestKey != "" {
		res := f.responses[bestKey]
		return res.stdout, res.err
	}
	return "", nil
}

func (f *fakeRunner) Run(name string, args, env []string) (string, error) {
	return f.recordFull(name, args, env, "")
}

func (f *fakeRunner) RunNoCapture(name string, args, env []string) error {
	_, err := f.record(name, args)
	return err
}

func (f *fakeRunner) RunInDir(dir, name string, args, env []string) (string, error) {
	return f.recordFull(name, args, env, "")
}

func (f *fakeRunner) RunInDirNoCapture(dir, name string, args, env []string) error {
	_, err := f.record(name, args)
	return err
}

func (f *fakeRunner) RunInDirToFile(dir, name string, args, env []string, logPath string) (string, error) {
	return f.recordFull(name, args, env, logPath)
}

// ran reports whether any recorded call starts with the given command prefix.
func (f *fakeRunner) ran(prefix string) bool {
	return f.count(prefix) > 0
}

// count returns how many recorded calls start with the given command prefix.
func (f *fakeRunner) count(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// envFor returns the env of the first recorded call matching the given prefix.
func (f *fakeRunner) envFor(prefix string) []string {
	for i, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return f.envs[i]
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
			tagErr:    fmt.Errorf("exit status 1"),
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
			f.on(fmt.Sprintf("git rev-parse -q --verify refs/tags/%s^{commit}", ver), tt.tagCommit, tt.tagErr)
			f.on(fmt.Sprintf("git tag -a -m Release %s %s", ver, ver), "", nil)

			r := &CalicoManager{runner: f, calicoVersion: ver}
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
				t.Errorf("git tag issued = %v, want %v (calls: %v)", got, tt.wantTag, f.calls)
			}
		})
	}
}

// The tag/HEAD comparison is consulted by both releasePrereqs (fail-fast) and
// TagRelease (authoritative), but the rev-parse must run only once per release.
func TestTagStateMemoized(t *testing.T) {
	const ver = "v3.30.0"
	f := newFakeRunner()
	f.on(fmt.Sprintf("git rev-parse -q --verify refs/tags/%s^{commit}", ver), "", fmt.Errorf("exit status 1"))

	r := &CalicoManager{runner: f, calicoVersion: ver}
	if tc := r.tagState(); tc.err != nil {
		t.Fatal(tc.err)
	}
	if tc := r.tagState(); tc.err != nil {
		t.Fatal(tc.err)
	}
	if got := f.count("git rev-parse -q --verify refs/tags/" + ver); got != 1 {
		t.Errorf("tag rev-parse ran %d times, want 1 (calls: %v)", got, f.calls)
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
	f.on(fmt.Sprintf("git rev-parse -q --verify refs/tags/%s^{commit}", ver), otherSHA, nil)

	r := &CalicoManager{runner: f, calicoVersion: ver, githubOrg: "myfork", repo: "calico"}
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
		gitRef      bool
		lsRemote    string // canned `git ls-remote --tags <remote> refs/tags/<ver>`
		wantPush    bool
		wantErr     bool
		errContains []string
	}{
		{
			name:     "skip flag disabled does nothing",
			gitRef:   false,
			wantPush: false,
		},
		{
			name:     "remote tag missing pushes",
			gitRef:   true,
			lsRemote: "",
			wantPush: true,
		},
		{
			name:     "remote tag matches local skips",
			gitRef:   true,
			lsRemote: fmt.Sprintf("%s\trefs/tags/%s", localSHA, ver),
			wantPush: false,
		},
		{
			name:        "remote tag differs errors",
			gitRef:      true,
			lsRemote:    fmt.Sprintf("%s\trefs/tags/%s", remoteSHA, ver),
			wantPush:    false,
			wantErr:     true,
			errContains: []string{localSHA, remoteSHA},
		},
		{
			name:     "annotated tag peeled line matches local skips",
			gitRef:   true,
			lsRemote: fmt.Sprintf("%s\trefs/tags/%s\n%s\trefs/tags/%s^{}", tagObjSHA, ver, localSHA, ver),
			wantPush: false,
		},
		{
			name:        "annotated tag peeled line differs errors",
			gitRef:      true,
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

			r := &CalicoManager{runner: f, gitRef: tt.gitRef, remote: remote, calicoVersion: ver}
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
				t.Errorf("git push issued = %v, want %v (calls: %v)", got, tt.wantPush, f.calls)
			}
		})
	}
}

func TestPublishGithubReleaseSkipped(t *testing.T) {
	f := newFakeRunner()
	r := &CalicoManager{
		runner:        f,
		githubRelease: false,
		calicoVersion: "v3.30.0",
		githubOrg:     "projectcalico",
		repo:          "calico",
		outputDir:     t.TempDir(),
	}
	upload := r.githubReleaseUpload()
	if upload != nil {
		t.Errorf("expected no upload with the flag off, got %+v", upload)
	}
	if len(f.calls) != 0 {
		t.Errorf("expected nothing run with the flag off, got %v", f.calls)
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
	root := t.TempDir()
	run := func(args ...string) {
		_, err := command.GitInDir(root, args...)
		require.NoError(t, err, "git %v", args)
	}
	run("init", "-q", "-b", "master")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	run("config", "commit.gpgsign", "false")
	run("config", "tag.gpgsign", "false")
	run("commit", "-q", "--allow-empty", "-m", "initial")
	run("tag", "--no-sign", "v3.33.0-0.dev")

	m := &CalicoManager{}
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

func TestRequireOnMainBranch(t *testing.T) {
	root := t.TempDir()
	run := func(args ...string) {
		_, err := command.GitInDir(root, args...)
		require.NoError(t, err, "git %v", args)
	}
	run("init", "-q", "-b", "master")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	run("config", "commit.gpgsign", "false")
	run("commit", "-q", "--allow-empty", "-m", "initial")

	m := &CalicoManager{}
	for _, opt := range []Option{WithRepoRoot(root), WithMainBranch("master"), WithValidation(true)} {
		require.NoError(t, opt(m))
	}

	// On master, a fresh cut (derived branch absent) is allowed.
	require.NoError(t, m.requireOnMainBranch("release-v3.33"), "on master the cut is allowed")

	// Off a non-main branch, a fresh cut (derived branch absent) is rejected.
	run("checkout", "-q", "-b", "some-feature")
	err := m.requireOnMainBranch("release-v3.33")
	require.Error(t, err, "a fresh cut off a non-main branch must be rejected")
	require.Contains(t, err.Error(), "must run on master")

	// Resume: the derived branch exists, so the rerun is allowed off it.
	run("checkout", "-q", "-b", "release-v3.33")
	require.NoError(t, m.requireOnMainBranch("release-v3.33"),
		"a resume must be allowed when the derived branch exists")
}

// envForDir returns the environment of the first recorded make call in a
// component directory.
func (f *fakeRunner) envForDir(dir string) []string {
	for i, c := range f.calls {
		if strings.Contains(c, dir) {
			return f.envs[i]
		}
	}
	return nil
}

// logPathsForDir returns the log paths of every recorded make call in a
// component directory.
func (f *fakeRunner) logPathsForDir(dir string) []string {
	var out []string
	for i, c := range f.calls {
		// Only unit targets are logged to a file.
		if strings.Contains(c, dir) && f.logPaths[i] != "" {
			out = append(out, f.logPaths[i])
		}
	}
	return out
}

// unitCalls returns the calls that ran a unit's make target, ignoring the
// image-name queries.
func unitCalls(f *fakeRunner, target string) []string {
	var out []string
	for _, c := range f.calls {
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
			for _, want := range []string{"make -C " + root + "/felix release-build", "make -C " + root + "/calicoctl build-all"} {
				if !f.ran(want) {
					t.Errorf("did not run %q, ran: %v", want, f.calls)
				}
			}
		})
	}
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
	for _, c := range m.archiveSources() {
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
		calicoVersion:   "v3.30.0",
		operatorVersion: "v1.40.0",
		operatorImage:   "tigera/operator",
	}
	m.hashrelease.Source = out
	if err := m.buildManifests(); err != nil {
		t.Fatalf("buildManifests: %v", err)
	}

	// The archive reads the collected copy, so the copy has to happen while
	// building the manifests rather than in a later pass.
	gen := slices.IndexFunc(f.calls, func(c string) bool { return strings.Contains(c, "gen-manifests") })
	copied := slices.IndexFunc(f.calls, func(c string) bool {
		return strings.Contains(c, filepath.Join(out, manifests.DirName)) ||
			strings.HasSuffix(c, out)
	})
	if gen < 0 || copied < 0 {
		t.Fatalf("expected a manifest build and a copy, ran: %v", f.calls)
	}
	if copied < gen {
		t.Errorf("manifests were copied before they were generated, ran: %v", f.calls)
	}
}

func TestReleaseNoteNamesTheArtifactsThroughTheirAccessors(t *testing.T) {
	m := &CalicoManager{
		calicoVersion: "v3.30.0",
		githubRelease: true,
		githubOrg:     "projectcalico",
		repo:          "calico",
	}
	up := m.githubReleaseUpload()
	if up == nil {
		t.Fatal("githubReleaseUpload() = nil")
	}
	body := up.Handler.(distribution.GithubRelease).Body

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
				repoRoot:      t.TempDir(),
				archiveImages: tc.images,
				binaries:      tc.binaries,
				manifests:     tc.manifests,
			}
			var got []string
			for _, c := range m.archiveSources() {
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
		f.on(fmt.Sprintf("make -C %s/%s -s build-images", root, dir), base+" "+base+"-windows", nil)
	}
	return &CalicoManager{
		runner:              f,
		repoRoot:            root,
		calicoVersion:       "v3.30.0",
		imageRegistries:     []string{registry.DefaultProductRegistry},
		images:              true,
		operatorImage:       registry.OperatorImage,
		operatorRegistry:    registry.DefaultOperatorRegistry,
		operator:            true,
		logsDir:             logsDir,
		outputDir:           t.TempDir(),
		recordsDir:          t.TempDir(),
		releaseBranchPrefix: "release",
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
	if !f.ran("make -C " + root + "/cmd/calico " + imagePublishTarget) {
		t.Errorf("publish did not run %s in cmd/calico, calls: %v", imagePublishTarget, f.calls)
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
		for _, c := range f.calls {
			if strings.HasSuffix(c, " "+imagePublishTarget) {
				t.Errorf("a resolve ran the publish target: %s", c)
			}
		}
	})

	t.Run("a missing image fails after the rest are recorded", func(t *testing.T) {
		m := withoutImages(t, newFakeRunner())
		missing := registry.DefaultProductRegistry + "/calico:" + m.calicoVersion
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

	t.Run("runs first, before metadata", func(t *testing.T) {
		var kinds []string
		for _, u := range withoutImages(t, newFakeRunner()).uploads() {
			kinds = append(kinds, u.Handler.Name())
		}
		resolve, meta := slices.Index(kinds, "images"), slices.Index(kinds, metadataKey)
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
		m.operator = false
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
		m.imageComponents = map[string]registry.Component{
			m.operatorImage: {Registry: "quay.io/pinned", Image: m.operatorImage, Version: m.operatorVersion},
		}
		want := "quay.io/override/" + m.operatorImage + ":v1.40.0"
		if got := m.componentImages()[m.operatorImage]; got != want {
			t.Errorf("scans %s, want %s", got, want)
		}
	})
}

func TestResolveOperator(t *testing.T) {
	newManager := func(t *testing.T, resolve func(string) (string, bool, error)) *CalicoManager {
		m, _ := imageManager(t, newFakeRunner(), "")
		m.images = false
		m.isHashRelease = true
		m.operator = false
		m.operatorVersion = "v1.40.0"
		m.resolveDigest = resolve
		return m
	}
	scanOperator := func(t *testing.T, m *CalicoManager) *scanLog {
		t.Helper()
		scans := enableScan(t, m)
		m.imageComponents[m.operatorImage] = registry.Component{Registry: m.operatorRegistry, Image: m.operatorImage, Version: m.operatorVersion}
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
		m.operator = true
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
	m.imageComponents = map[string]registry.Component{"calico": {Image: "calico", Version: m.calicoVersion}}
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
		tests := []struct {
			name          string
			version       string
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
				version:       "v3.33.0-0.dev-1-gabcdef123456",
				images:        true,
				isHashRelease: true,
				wantPublish:   true,
				wantBranchTag: true,
				wantTag:       "release-v3.33",
			},
			{
				name:          "early preview keeps its stream suffix",
				version:       "v3.33.0-1.0-0.dev-1-gabcdef123456",
				images:        true,
				isHashRelease: true,
				wantPublish:   true,
				wantBranchTag: true,
				wantTag:       "release-v3.33-1",
			},
			{
				name:          "an official release moves it too",
				version:       "v3.33.0",
				images:        true,
				isHashRelease: false,
				wantPublish:   true,
				wantBranchTag: true,
				wantTag:       "release-v3.33",
			},
			{
				// An unset prefix would silently tag images "-v3.33".
				name:          "missing branch prefix is an error",
				version:       "v3.33.0-0.dev-1-gabcdef123456",
				images:        true,
				isHashRelease: true,
				prefix:        "",
				wantPublish:   true,
				wantErr:       true,
			},
			{
				name:          "images disabled publishes nothing",
				version:       "v3.33.0-0.dev-1-gabcdef123456",
				images:        false,
				isHashRelease: true,
				wantPublish:   false,
				wantBranchTag: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFakeRunner()

				prefix := tt.prefix
				if prefix == "" && !tt.wantErr {
					prefix = "release"
				}
				r, root := imageManager(t, f, "")
				r.images = tt.images
				r.isHashRelease = tt.isHashRelease
				// A hashrelease reads its registry from its own source tree.
				r.hashrelease.Source = root
				r.calicoVersion = tt.version
				r.releaseBranchPrefix = prefix

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

				if got := f.ran("make -C " + root + "/cmd/calico " + imagePublishTarget); got != tt.wantPublish {
					t.Errorf("%s ran = %v, want %v (calls: %v)", imagePublishTarget, got, tt.wantPublish, f.calls)
				}
				if got := f.ran("make -C " + root + "/cmd/calico " + branchTagTarget); got != tt.wantBranchTag {
					t.Errorf("branch tag publish ran = %v, want %v (calls: %v)", got, tt.wantBranchTag, f.calls)
				}
				if tt.wantBranchTag {
					if got := f.envFor("make -C " + root + "/cmd/calico " + branchTagTarget); !slices.Contains(got, "IMAGETAG="+tt.wantTag) {
						t.Errorf("branch tag env = %v, want IMAGETAG=%s", got, tt.wantTag)
					}
				}

				// The operator carries the branch tag too, published to its own registries.
				opTarget := "make -C " + root + "/operator retag-build-images-with-registries"
				if got := f.ran(opTarget); got != tt.wantBranchTag {
					t.Errorf("operator branch tag publish ran = %v, want %v (calls: %v)", got, tt.wantBranchTag, f.calls)
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
		if got := "make -C " + root + "/cmd/calico " + branchTagTarget; f.ran(got) {
			t.Errorf("ran %q for a registry outside the default (calls: %v)", got, f.calls)
		}
	})

	t.Run("skipped when the operator is off", func(t *testing.T) {
		f := newFakeRunner()
		r, root := imageManager(t, f, "")
		r.operator = false
		if err := r.publishContainerImages(); err != nil {
			t.Fatalf("publishContainerImages: %v", err)
		}
		if got := "make -C " + root + "/operator " + branchTagTarget; f.ran(got) {
			t.Errorf("ran %q with the operator off (calls: %v)", got, f.calls)
		}
	})

	t.Run("skipped for a non-default operator registry", func(t *testing.T) {
		f := newFakeRunner()
		r, root := imageManager(t, f, "")
		r.operatorRegistry = "quay.io/somewhere-else"
		if err := r.publishContainerImages(); err != nil {
			t.Fatalf("publishContainerImages: %v", err)
		}
		if got := "make -C " + root + "/operator " + branchTagTarget; f.ran(got) {
			t.Errorf("ran %q for a registry outside the defaults (calls: %v)", got, f.calls)
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
		if got := "make -C " + root + "/cni-plugin " + branchTagTarget; f.ran(got) {
			t.Errorf("branch tag ran %q, which has no arch images to retag (calls: %v)", got, f.calls)
		}
		want := "make -C " + root + "/cni-plugin " + windowsBranchTagTarget
		if !f.ran(want) {
			t.Errorf("did not run %q, ran: %v", want, f.calls)
		}

		// The copy is registry side, so it needs the tag it copies from.
		if env := f.envFor(want); !slices.Contains(env, "DEV_TAG=v3.30.0") {
			t.Errorf("windows branch tag env = %v, want DEV_TAG=v3.30.0", env)
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
			if !f.ran("make -C " + root + "/whisker " + tc.target) {
				t.Errorf("did not run %s in whisker, ran: %v", tc.target, f.calls)
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
		t.Errorf("published %d dirs, want every one of %d: %v", got, want, f.calls)
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
				calicoVersion: "v3.30.0",
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
			r := &CalicoManager{outputDir: dir, calicoVersion: "v3.30.0", isHashRelease: tt.hashrelease}
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
			require.Len(t, f.calls, 1)
			require.Contains(t, f.calls[0], "quay.io/tigera/operator:"+version)
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
		calicoVersion:  "v3.30.0",
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
				calicoVersion: "v3.30.0",
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
				calicoVersion: "v3.30.0",
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

func TestPublishGitTagPreviewsThePushOnADryRun(t *testing.T) {
	f := newFakeRunner()
	f.on("git ls-remote --tags origin refs/tags/v3.30.0", "", nil)

	r := &CalicoManager{
		runner:        f,
		gitRef:        true,
		dryRun:        true,
		calicoVersion: "v3.30.0",
		remote:        "origin",
		repoRoot:      t.TempDir(),
	}
	if err := r.publishGitTag(); err != nil {
		t.Fatalf("publishGitTag() = %v, want nil", err)
	}
	if !f.ran("git push origin v3.30.0 --dry-run") {
		t.Errorf("expected a previewed push, got %v", f.calls)
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

// The chart index lists download URLs served by the github release, so
// publishing it first advertises links that 404 until the release is live.
func TestChartIndexPublishesAfterTheGithubRelease(t *testing.T) {
	r := &CalicoManager{
		githubRelease: true,
		helmCharts:    true,
		helmIndex:     true,
		calicoVersion: "v3.30.0",
		githubOrg:     "projectcalico",
		repo:          "calico",
		s3Bucket:      "bucket",
		outputDir:     t.TempDir(),
	}
	var names []string
	for _, u := range r.uploads() {
		names = append(names, u.Name)
	}
	index := slices.Index(names, "chart index")
	release := slices.Index(names, "github release")
	if index < 0 || release < 0 {
		t.Fatalf("expected both uploads, got %v", names)
	}
	if index < release {
		t.Errorf("chart index publishes before the github release: %v", names)
	}
}

// A hashrelease built with --no-manifests never writes a manifest copy, so the
// registry has to come from the flags rather than failing the publish.
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
				calicoVersion:      "v3.30.0",
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

func TestSourceMetadata(t *testing.T) {
	const headSHA = "0123456789abcdef0123456789abcdef01234567"
	newManager := func(branch string) *CalicoManager {
		f := newFakeRunner()
		f.on("git rev-parse --abbrev-ref HEAD", branch+"\n", nil)
		f.on("git rev-parse HEAD", headSHA+"\n", nil)
		return &CalicoManager{runner: f, githubOrg: "projectcalico", repo: "calico", calicoVersion: "v3.30.0"}
	}

	t.Run("a release records its branch and tag", func(t *testing.T) {
		got, err := newManager("release-v3.30").sourceMetadata()
		require.NoError(t, err)
		require.Equal(t, outputs.Source{Repository: "projectcalico/calico", Commit: headSHA, Branch: "release-v3.30", Tag: "v3.30.0"}, got)
	})

	t.Run("a hashrelease records no tag", func(t *testing.T) {
		r := newManager("master")
		r.isHashRelease = true
		got, err := r.sourceMetadata()
		require.NoError(t, err)
		require.Empty(t, got.Tag)
		require.Equal(t, "master", got.Branch)
	})

	t.Run("a detached HEAD records no branch", func(t *testing.T) {
		got, err := newManager("HEAD").sourceMetadata()
		require.NoError(t, err)
		require.Empty(t, got.Branch)
		require.Equal(t, headSHA, got.Commit)
	})

	t.Run("fails when git cannot resolve HEAD", func(t *testing.T) {
		r := &CalicoManager{runner: newFakeRunner().on("git rev-parse HEAD", "", fmt.Errorf("not a git repository"))}
		_, err := r.sourceMetadata()
		require.ErrorContains(t, err, "not a git repository")
	})
}

func TestChartsMetadata(t *testing.T) {
	newManager := func() *CalicoManager {
		return &CalicoManager{
			helmCharts:     true,
			helmIndex:      true,
			helmRepoURL:    "https://example.com/charts",
			helmRegistries: []string{"quay.io/calico/charts", "docker.io/calico/charts"},
			calicoVersion:  "v3.30.0",
		}
	}

	t.Run("records each chart at the first registry", func(t *testing.T) {
		got, err := newManager().chartsMetadata()
		require.NoError(t, err)
		require.Equal(t, "v3.30.0", got.Version)
		require.Equal(t, "https://example.com/charts", got.Index)
		require.Len(t, got.Entries, len(charts.All()))
		for _, name := range charts.All() {
			e := got.Entries[name]
			require.Equal(t, "quay.io/calico/charts/"+name+":v3.30.0", e.Image)
			require.True(t, strings.HasSuffix(e.URL, "/"+charts.FileName(name, "v3.30.0")), e.URL)
		}
	})

	t.Run("leaves out the index when it is not built", func(t *testing.T) {
		r := newManager()
		r.helmIndex = false
		got, err := r.chartsMetadata()
		require.NoError(t, err)
		require.Empty(t, got.Index)
	})

	t.Run("records nothing when charts are off", func(t *testing.T) {
		r := newManager()
		r.helmCharts = false
		got, err := r.chartsMetadata()
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("fails with no registry to name the charts by", func(t *testing.T) {
		r := newManager()
		r.helmRegistries = nil
		_, err := r.chartsMetadata()
		require.Error(t, err)
	})
}
