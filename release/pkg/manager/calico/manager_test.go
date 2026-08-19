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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/release/internal/command"
)

// fakeResult is the canned response for a matched command.
type fakeResult struct {
	stdout string
	err    error
}

// fakeRunner is a command.CommandRunner that returns canned output per command
// and records every invocation so tests can assert what was (and was not) run.
type fakeRunner struct {
	// responses maps a command key ("name arg1 arg2 ...") to its canned result.
	// A key that is a prefix of the invoked command also matches (longest-prefix
	// wins), so tests can match on a stable command head without spelling out
	// variable trailing args (a temp-file path, an enumerated asset list).
	responses map[string]fakeResult

	// calls records every command invoked, as "name arg1 arg2 ...".
	calls []string

	// envs records the env passed alongside each recorded call, by index.
	envs [][]string
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
	return f.recordEnv(name, args, nil)
}

func (f *fakeRunner) recordEnv(name string, args, env []string) (string, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, cmd)
	f.envs = append(f.envs, env)
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
	return f.recordEnv(name, args, env)
}

func (f *fakeRunner) RunNoCapture(name string, args, env []string) error {
	_, err := f.record(name, args)
	return err
}

func (f *fakeRunner) RunInDir(dir, name string, args, env []string) (string, error) {
	return f.recordEnv(name, args, env)
}

func (f *fakeRunner) RunInDirNoCapture(dir, name string, args, env []string) error {
	_, err := f.record(name, args)
	return err
}

func (f *fakeRunner) RunInDirToFile(dir, name string, args, env []string, logPath string) (string, error) {
	return f.recordEnv(name, args, env)
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

func TestPublishGithubRelease(t *testing.T) {
	const (
		ver  = "v3.30.0"
		org  = "projectcalico"
		repo = "calico"
	)
	repoFlag := fmt.Sprintf("--repo %s/%s", org, repo)
	notFound := fmt.Errorf("release not found")

	tests := []struct {
		name          string
		githubRelease bool
		viewOut       string
		viewErr       error
		wantGhr       bool
		wantErr       bool
	}{
		{
			name:          "skip flag disabled does nothing",
			githubRelease: false,
		},
		{
			name:          "no release runs ghr",
			githubRelease: true,
			viewOut:       "release not found",
			viewErr:       notFound,
			wantGhr:       true,
		},
		{
			name:          "draft release runs ghr",
			githubRelease: true,
			viewOut:       `{"isDraft":true}`,
			wantGhr:       true,
		},
		{
			name:          "published release errors without running ghr",
			githubRelease: true,
			viewOut:       `{"isDraft":false}`,
			wantGhr:       false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			f.on(fmt.Sprintf("./bin/gh release view %s %s --json isDraft", ver, repoFlag), tt.viewOut, tt.viewErr)
			f.on("./bin/ghr", "", nil)

			r := &CalicoManager{
				runner:        f,
				githubRelease: tt.githubRelease,
				calicoVersion: ver,
				githubOrg:     org,
				repo:          repo,
				outputDir:     t.TempDir(),
			}
			err := r.publishGithubRelease()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("publishGithubRelease() = nil, want error")
				}
				if f.ran("./bin/ghr") {
					t.Errorf("ghr was invoked for a published release (calls: %v)", f.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("publishGithubRelease() unexpected error: %v", err)
			}
			if got := f.ran("./bin/ghr"); got != tt.wantGhr {
				t.Errorf("ghr issued = %v, want %v (calls: %v)", got, tt.wantGhr, f.calls)
			}
		})
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
			name:          "official release does not move the branch tag",
			version:       "v3.33.0",
			images:        true,
			isHashRelease: false,
			wantPublish:   true,
			wantBranchTag: false,
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
			r := &CalicoManager{
				runner:              f,
				images:              tt.images,
				isHashRelease:       tt.isHashRelease,
				calicoVersion:       tt.version,
				releaseBranchPrefix: prefix,
			}

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

			if got := f.ran("make -C cmd/calico release-publish"); got != tt.wantPublish {
				t.Errorf("release-publish ran = %v, want %v (calls: %v)", got, tt.wantPublish, f.calls)
			}
			if got := f.ran("make -C cmd/calico retag-build-images-with-registries"); got != tt.wantBranchTag {
				t.Errorf("branch tag publish ran = %v, want %v (calls: %v)", got, tt.wantBranchTag, f.calls)
			}
			if tt.wantBranchTag {
				if got := f.envFor("make -C cmd/calico retag-build-images-with-registries"); !slices.Contains(got, "IMAGETAG="+tt.wantTag) {
					t.Errorf("branch tag env = %v, want IMAGETAG=%s", got, tt.wantTag)
				}
				if got, want := f.count("make -C"), 2*len(imageReleaseDirs)+len(windowsReleaseDirs); got != want {
					t.Errorf("make invocations = %d, want %d (calls: %v)", got, want, f.calls)
				}
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

func TestCollectE2EBinaries(t *testing.T) {
	tests := []struct {
		name          string
		e2eBinaries   bool
		isHashRelease bool
		staged        []string
		preexisting   []string
		want          []string
		wantErr       bool
	}{
		{
			name:        "release flattens the staged binaries",
			e2eBinaries: true,
			staged:      []string{"e2e-linux-amd64.test", "e2e-linux-arm64.test"},
			want:        []string{"e2e-linux-amd64.test", "e2e-linux-arm64.test"},
		},
		{
			name:        "unrelated staged files are left behind",
			e2eBinaries: true,
			staged:      []string{"e2e-linux-amd64.test", "notes.txt"},
			want:        []string{"e2e-linux-amd64.test"},
		},
		{
			name:        "a rerun relinks over the previous build",
			e2eBinaries: true,
			staged:      []string{"e2e-linux-amd64.test"},
			preexisting: []string{"e2e-linux-amd64.test"},
			want:        []string{"e2e-linux-amd64.test"},
		},
		{
			name:        "staging with no binaries errors",
			e2eBinaries: true,
			staged:      []string{"notes.txt"},
			wantErr:     true,
		},
		{
			name:        "empty staging errors",
			e2eBinaries: true,
			wantErr:     true,
		},
		{
			name:          "hashrelease keeps only the files/e2e layout",
			e2eBinaries:   true,
			isHashRelease: true,
			staged:        []string{"e2e-linux-amd64.test"},
		},
		{
			name:        "disabled does nothing",
			e2eBinaries: false,
			staged:      []string{"e2e-linux-amd64.test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputDir := t.TempDir()
			e2eDir := filepath.Join(outputDir, "files", "e2e")
			require.NoError(t, os.MkdirAll(e2eDir, 0o755))
			for _, name := range tt.staged {
				require.NoError(t, os.WriteFile(filepath.Join(e2eDir, name), []byte(name), 0o755))
			}
			for _, name := range tt.preexisting {
				require.NoError(t, os.WriteFile(filepath.Join(outputDir, name), []byte("stale"), 0o755))
			}

			r := &CalicoManager{
				e2eBinaries:   tt.e2eBinaries,
				isHashRelease: tt.isHashRelease,
				outputDir:     outputDir,
			}
			err := r.collectE2EBinaries()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			entries, err := os.ReadDir(outputDir)
			require.NoError(t, err)
			var got []string
			for _, entry := range entries {
				if !entry.IsDir() {
					got = append(got, entry.Name())
				}
			}
			require.ElementsMatch(t, tt.want, got)

			// A collected binary must carry the staged content, not a stale leftover.
			for _, name := range tt.want {
				content, err := os.ReadFile(filepath.Join(outputDir, name))
				require.NoError(t, err)
				require.Equal(t, name, string(content))
			}
		})
	}
}

// A missing files/e2e directory means the build never staged anything, which
// would otherwise ship a release with no e2e binaries and no warning.
func TestCollectE2EBinariesUnstagedErrors(t *testing.T) {
	r := &CalicoManager{e2eBinaries: true, outputDir: t.TempDir()}
	require.Error(t, r.collectE2EBinaries())
}

// The staging layout is the whole reason a release and a hashrelease differ:
// ghr populates GitHub release assets from the top level of the upload dir and
// does not recurse, while the hashrelease server serves the directory tree.
func TestE2EStagingDir(t *testing.T) {
	tests := []struct {
		name          string
		isHashRelease bool
		want          string
	}{
		{name: "release stages flat for ghr", want: "out"},
		{name: "hashrelease stages under files/e2e", isHashRelease: true, want: filepath.Join("out", "files", "e2e")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &CalicoManager{outputDir: "out", isHashRelease: tt.isHashRelease}
			require.Equal(t, tt.want, r.e2eStagingDir())
		})
	}
}

// The e2e-binaries flag belongs to the build step and is never passed to
// publish, so the release note has to key off what was actually staged.
func TestPublishGithubReleaseE2ENote(t *testing.T) {
	const bullet = "e2e-linux-<arch>.test"

	tests := []struct {
		name        string
		staged      []string
		e2eBinaries bool
		wantNote    bool
	}{
		{
			name:        "staged binaries are listed",
			staged:      []string{"e2e-linux-amd64.test", "e2e-linux-arm64.test"},
			e2eBinaries: true,
			wantNote:    true,
		},
		{
			name:        "nothing staged is not listed even with the flag defaulted on",
			e2eBinaries: true,
			wantNote:    false,
		},
		{
			name:        "staged binaries are listed even with the flag off",
			staged:      []string{"e2e-linux-amd64.test"},
			e2eBinaries: false,
			wantNote:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputDir := t.TempDir()
			for _, name := range tt.staged {
				require.NoError(t, os.WriteFile(filepath.Join(outputDir, name), []byte(name), 0o755))
			}

			f := newFakeRunner()
			f.on("./bin/gh release view", "release not found", fmt.Errorf("release not found"))
			f.on("./bin/ghr", "", nil)

			r := &CalicoManager{
				runner:        f,
				githubRelease: true,
				e2eBinaries:   tt.e2eBinaries,
				calicoVersion: "v3.30.0",
				githubOrg:     "projectcalico",
				repo:          "calico",
				outputDir:     outputDir,
			}
			require.NoError(t, r.publishGithubRelease())

			var ghr string
			for _, c := range f.calls {
				if strings.HasPrefix(c, "./bin/ghr") {
					ghr = c
				}
			}
			require.NotEmpty(t, ghr, "ghr was not invoked (calls: %v)", f.calls)
			require.Equal(t, tt.wantNote, strings.Contains(ghr, bullet),
				"release note mentions %q = %v, want %v", bullet, strings.Contains(ghr, bullet), tt.wantNote)
		})
	}
}
