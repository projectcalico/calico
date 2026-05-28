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
	"strings"
	"testing"
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
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, cmd)
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
	return f.record(name, args)
}

func (f *fakeRunner) RunNoCapture(name string, args, env []string) error {
	_, err := f.record(name, args)
	return err
}

func (f *fakeRunner) RunInDir(dir, name string, args, env []string) (string, error) {
	return f.record(name, args)
}

func (f *fakeRunner) RunInDirNoCapture(dir, name string, args, env []string) error {
	_, err := f.record(name, args)
	return err
}

func (f *fakeRunner) RunInDirToFile(dir, name string, args, env []string, logPath string) (string, error) {
	return f.record(name, args)
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

			r := &CalicoManager{runner: f}
			err := r.TagRelease(ver)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("TagRelease(%q) = nil, want error", ver)
				}
				for _, sub := range tt.errContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not contain %q", err.Error(), sub)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("TagRelease(%q) unexpected error: %v", ver, err)
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
	if tc := r.tagState(ver); tc.err != nil {
		t.Fatal(tc.err)
	}
	if tc := r.tagState(ver); tc.err != nil {
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
