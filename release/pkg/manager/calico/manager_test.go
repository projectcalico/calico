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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/distribution"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/images"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
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

// manifestRepo is a repo root holding the one manifest a release reads its
// registry from.
func manifestRepo(t *testing.T, image string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, manifestsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating manifests dir: %v", err)
	}
	doc := fmt.Sprintf("kind: Pod\nspec:\n  containers:\n    - name: calicoctl\n      image: %s\n", image)
	if err := os.WriteFile(filepath.Join(dir, calicoctlManifest), []byte(doc), 0o644); err != nil {
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
		imageRegistries:     []string{"quay.io/tigera"},
		images:              true,
		logsDir:             logsDir,
		outputDir:           t.TempDir(),
		releaseBranchPrefix: "release",
		resolveDigest: func(string) (string, bool, error) {
			return "sha256:aaa", true, nil
		},
	}, root
}

// A publish must latch CONFIRM; DRYRUN pushes nothing and still reports
// success.
func TestPublishContainerImagesConfirms(t *testing.T) {
	f := newFakeRunner()
	m, root := imageManager(t, f, "")
	if err := m.publishContainerImages(); err != nil {
		t.Fatalf("publishContainerImages: %v", err)
	}
	if !f.ran("make -C " + root + "/cmd/calico release-publish") {
		t.Errorf("publish did not run release-publish in cmd/calico, calls: %v", f.calls)
	}
	env := f.envForDir(root + "/cmd/calico ")
	if !slices.Contains(env, "CONFIRM=true") {
		t.Error("publish env missing CONFIRM=true")
	}
	if slices.Contains(env, "DRYRUN=true") {
		t.Error("publish env should not carry DRYRUN=true")
	}
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

func TestPublishContainerImagesBranchTag(t *testing.T) {
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

			if got := f.ran("make -C " + root + "/cmd/calico release-publish"); got != tt.wantPublish {
				t.Errorf("release-publish ran = %v, want %v (calls: %v)", got, tt.wantPublish, f.calls)
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
				want := "DEV_REGISTRIES=" + strings.Join(operator.DefaultRegistries, " ")
				if !slices.Contains(env, want) {
					t.Errorf("operator branch tag env = %v, want %s", env, want)
				}
			}
		})
	}
}

// cni-plugin ships only a Windows image, so the standard branch tag target
// there retags arch images that were never built.
func TestPublishBranchTagSplitsWindowsFromStandard(t *testing.T) {
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
	if got := len(unitCalls(f, "release-publish")); got != want {
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

// TestE2EArchitectures covers the supported-arch intersection: an empty set
// means "all" (the tooling-wide convention), the four-arch default drops
// ppc64le/s390x, a narrowed build keeps only its supported arches, and an
// unsupported-only set yields none.
func TestE2EArchitectures(t *testing.T) {
	tests := []struct {
		name       string
		configured []string
		want       []string
	}{
		{"empty means all supported", nil, []string{"amd64", "arm64"}},
		{"default four arches drop ppc64le/s390x", []string{"amd64", "arm64", "ppc64le", "s390x"}, []string{"amd64", "arm64"}},
		{"narrowed build keeps only its supported arch", []string{"arm64"}, []string{"arm64"}},
		{"unsupported-only yields none", []string{"ppc64le", "s390x"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, e2eArchitectures(tt.configured))
		})
	}
}

// TestBuildE2EBinariesUsesARCHES asserts the e2e build is restricted through
// ARCHES, not VALIDARCHES (lib.Makefile assigns VALIDARCHES with `=`, so passing
// it via the environment is a no-op).
func TestBuildE2EBinariesUsesARCHES(t *testing.T) {
	repoRoot := t.TempDir()
	// Stage a built e2e binary so the post-build hard-link step succeeds.
	e2eBinDir := filepath.Join(repoRoot, "e2e", "bin", "k8s")
	require.NoError(t, os.MkdirAll(e2eBinDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(e2eBinDir, "e2e-linux-amd64.test"), []byte("x"), 0o644))

	f := newFakeRunner()
	r := &CalicoManager{
		runner:        f,
		repoRoot:      repoRoot,
		outputDir:     t.TempDir(),
		calicoVersion: "v3.34.0-0.dev-1-gabcdef123456",
		architectures: []string{"amd64", "arm64", "ppc64le", "s390x"},
	}

	require.NoError(t, r.buildE2EBinaries())

	makePrefix := "make -C " + filepath.Join(repoRoot, "e2e") + " build-all"
	env := f.envFor(makePrefix)
	require.NotNil(t, env, "e2e build-all was not run (calls: %v)", f.calls)
	// Only inspect the arch env vars: env also carries os.Environ(), which can
	// hold secrets that must not be printed on failure.
	var archEnv []string
	for _, e := range env {
		if strings.HasPrefix(e, "ARCHES=") || strings.HasPrefix(e, "VALIDARCHES=") {
			archEnv = append(archEnv, e)
		}
	}
	require.Contains(t, archEnv, "ARCHES=amd64 arm64")
	for _, e := range archEnv {
		require.False(t, strings.HasPrefix(e, "VALIDARCHES="),
			"e2e build-all should not set VALIDARCHES (lib.Makefile ignores it): %s", e)
	}
}

func TestChartsAndIndexShareADirectory(t *testing.T) {
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
			want := filepath.Join(dir, "charts")
			if got := r.chart().BaseDir; got != want {
				t.Errorf("chart().BaseDir = %q, want %q", got, want)
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

	refs, err := outputs.ReadRefs(r.outputDir, charts.PublishStep, "v3.30.0")
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
