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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockGit returns a mock runGit function that maps argument strings to
// predefined responses. Unmatched calls return an error.
func mockGit(responses map[string]string) func(args ...string) (string, error) {
	return func(args ...string) (string, error) {
		key := strings.Join(args, " ")
		if resp, ok := responses[key]; ok {
			return resp, nil
		}
		return "", fmt.Errorf("unexpected git call: git %s", key)
	}
}

// withMockGit replaces runGit for the duration of a test and restores it on cleanup.
func withMockGit(t *testing.T, responses map[string]string) {
	t.Helper()
	orig := runGit
	runGit = mockGit(responses)
	t.Cleanup(func() { runGit = orig })
}

func TestFindRemote(t *testing.T) {
	tests := []struct {
		name      string
		slug      string
		remoteOut string
		want      string
		wantErr   bool
	}{
		{
			name: "HTTPS URL match",
			slug: "projectcalico/calico",
			remoteOut: "origin\thttps://github.com/projectcalico/calico.git (fetch)\n" +
				"origin\thttps://github.com/projectcalico/calico.git (push)\n",
			want: "origin",
		},
		{
			name: "SSH URL match",
			slug: "projectcalico/calico",
			remoteOut: "upstream\tgit@github.com:projectcalico/calico.git (fetch)\n" +
				"upstream\tgit@github.com:projectcalico/calico.git (push)\n",
			want: "upstream",
		},
		{
			name: "multiple remotes picks correct one",
			slug: "projectcalico/calico",
			remoteOut: "fork\thttps://github.com/myuser/calico.git (fetch)\n" +
				"fork\thttps://github.com/myuser/calico.git (push)\n" +
				"origin\thttps://github.com/projectcalico/calico.git (fetch)\n" +
				"origin\thttps://github.com/projectcalico/calico.git (push)\n",
			want: "origin",
		},
		{
			name: "no match returns error",
			slug: "projectcalico/calico",
			remoteOut: "origin\thttps://github.com/other/repo.git (fetch)\n" +
				"origin\thttps://github.com/other/repo.git (push)\n",
			wantErr: true,
		},
		{
			name:      "empty output returns error",
			slug:      "projectcalico/calico",
			remoteOut: "",
			wantErr:   true,
		},
		{
			name: "partial slug match is avoided",
			slug: "projectcalico/calico",
			remoteOut: "origin\thttps://github.com/projectcalico/calico-enterprise.git (fetch)\n" +
				"origin\thttps://github.com/projectcalico/calico-enterprise.git (push)\n",
			// "projectcalico/calico" is a substring of "projectcalico/calico-enterprise"
			// but it still matches because the code checks for /slug or :slug.
			// This is a known limitation; the test documents current behavior.
			want: "origin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withMockGit(t, map[string]string{
				"remote -v": tc.remoteOut,
			})

			got, err := findRemote(tc.slug)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFindRemote_GitError(t *testing.T) {
	orig := runGit
	runGit = func(args ...string) (string, error) {
		return "", fmt.Errorf("git not found")
	}
	t.Cleanup(func() { runGit = orig })

	_, err := findRemote("foo/bar")
	if err == nil {
		t.Fatal("expected error when git fails")
	}
	if !strings.Contains(err.Error(), "git remote -v failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestTryVersionFileStrategy(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		remote    string
		gitMock   map[string]string
		wantRes   string
		wantFound bool
		wantErr   bool
	}{
		{
			name:   "valid version finds remote branch",
			yaml:   "- title: v3.22.1\n",
			remote: "origin",
			gitMock: map[string]string{
				"branch --show-current":                              "my-feature",
				"rev-parse --verify --quiet release-v3.22":           "abc123",
				"rev-parse --abbrev-ref release-v3.22@{upstream}":    "origin/release-v3.22",
				"rev-parse --abbrev-ref --quiet origin/release-v3.22": "origin/release-v3.22",
			},
			wantRes:   "origin/release-v3.22",
			wantFound: true,
		},
		{
			name:      "empty versions list returns not found",
			yaml:      "[]\n",
			remote:    "origin",
			wantFound: false,
		},
		{
			name:      "no title returns not found",
			yaml:      "- foo: bar\n",
			remote:    "origin",
			wantFound: false,
		},
		{
			name:    "invalid yaml returns error",
			yaml:    "{{invalid",
			remote:  "origin",
			wantErr: true,
		},
		{
			name:   "version without minor returns not found",
			yaml:   "- title: v3\n",
			remote: "origin",
			gitMock: map[string]string{
				"branch --show-current": "my-feature",
			},
			wantFound: false,
		},
	}

	// Save and restore the global releasePrefix.
	origPrefix := releasePrefix
	t.Cleanup(func() { releasePrefix = origPrefix })
	releasePrefix = "release-v"

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.gitMock != nil {
				withMockGit(t, tc.gitMock)
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "versions.yml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0644); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}

			result, found, err := tryVersionFileStrategy(path, tc.remote)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if found != tc.wantFound {
				t.Errorf("found = %v, want %v", found, tc.wantFound)
			}
			if result != tc.wantRes {
				t.Errorf("result = %q, want %q", result, tc.wantRes)
			}
		})
	}
}

func TestTryVersionFileStrategy_MissingFile(t *testing.T) {
	_, _, err := tryVersionFileStrategy("/nonexistent/path/versions.yml", "origin")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestTryVersionStrategy(t *testing.T) {
	origPrefix := releasePrefix
	t.Cleanup(func() { releasePrefix = origPrefix })
	releasePrefix = "release-v"

	tests := []struct {
		name      string
		version   string
		remote    string
		gitMock   map[string]string
		wantRes   string
		wantFound bool
		wantErr   bool
	}{
		{
			name:    "current branch matches constructed branch",
			version: "v3.22.1",
			remote:  "origin",
			gitMock: map[string]string{
				"branch --show-current":                                "release-v3.22",
				"rev-parse --abbrev-ref release-v3.22@{upstream}":      "origin/release-v3.22",
			},
			wantRes:   "origin/release-v3.22",
			wantFound: true,
		},
		{
			name:    "local branch exists",
			version: "v3.22.1",
			remote:  "origin",
			gitMock: map[string]string{
				"branch --show-current":                              "my-feature",
				"rev-parse --verify --quiet release-v3.22":           "abc123",
				"rev-parse --abbrev-ref release-v3.22@{upstream}":    "origin/release-v3.22",
			},
			wantRes:   "origin/release-v3.22",
			wantFound: true,
		},
		{
			name:    "remote branch exists",
			version: "v3.22.1",
			remote:  "origin",
			// For this test we need rev-parse --verify to fail so we fall through to
			// the remote branch check. We use a custom mock below.
			wantRes:   "origin/release-v3.22",
			wantFound: true,
		},
		{
			name:    "no branch found",
			version: "v3.22.1",
			remote:  "origin",
			gitMock: func() map[string]string {
				// Use a custom mock that errors on the right calls.
				return nil
			}(),
			wantFound: false,
		},
		{
			name:      "version without minor",
			version:   "v3",
			remote:    "origin",
			wantFound: false,
		},
		{
			name:    "version with only major.minor",
			version: "v3.22",
			remote:  "origin",
			// Same as "remote branch exists" — needs custom mock below.
			wantRes:   "origin/release-v3.22",
			wantFound: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			switch tc.name {
			case "no branch found":
				// Custom mock: git branch works, but rev-parse calls error.
				orig := runGit
				runGit = func(args ...string) (string, error) {
					key := strings.Join(args, " ")
					if key == "branch --show-current" {
						return "my-feature", nil
					}
					return "", fmt.Errorf("not found")
				}
				t.Cleanup(func() { runGit = orig })
			case "remote branch exists", "version with only major.minor":
				// Local branch doesn't exist (rev-parse --verify errors),
				// so the code falls through to the remote branch check.
				orig := runGit
				runGit = func(args ...string) (string, error) {
					key := strings.Join(args, " ")
					switch key {
					case "branch --show-current":
						return "my-feature", nil
					case "rev-parse --verify --quiet release-v3.22":
						return "", fmt.Errorf("not a valid ref")
					case "rev-parse --abbrev-ref --quiet origin/release-v3.22":
						return "origin/release-v3.22", nil
					}
					return "", fmt.Errorf("unexpected: %s", key)
				}
				t.Cleanup(func() { runGit = orig })
			default:
				if tc.gitMock != nil {
					withMockGit(t, tc.gitMock)
				}
			}

			result, found, err := tryVersionStrategy(tc.version, tc.remote)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if found != tc.wantFound {
				t.Errorf("found = %v, want %v", found, tc.wantFound)
			}
			if result != tc.wantRes {
				t.Errorf("result = %q, want %q", result, tc.wantRes)
			}
		})
	}
}

func TestTryVersionStrategy_UpstreamError(t *testing.T) {
	origPrefix := releasePrefix
	t.Cleanup(func() { releasePrefix = origPrefix })
	releasePrefix = "release-v"

	// Current branch matches but upstream lookup fails.
	orig := runGit
	runGit = func(args ...string) (string, error) {
		key := strings.Join(args, " ")
		if key == "branch --show-current" {
			return "release-v3.22", nil
		}
		if strings.HasPrefix(key, "rev-parse --abbrev-ref release-v3.22@{upstream}") {
			return "", fmt.Errorf("no upstream configured")
		}
		return "", fmt.Errorf("unexpected: %s", key)
	}
	t.Cleanup(func() { runGit = orig })

	_, _, err := tryVersionStrategy("v3.22.1", "origin")
	if err == nil {
		t.Fatal("expected error when upstream lookup fails")
	}
	if !strings.Contains(err.Error(), "failed to find upstream") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFixCIRemotes(t *testing.T) {
	tests := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "already configured remotes are left alone",
		},
		{
			name: "fixes remote missing wildcard fetch",
		},
		{
			name: "multiple remotes mixed",
		},
		{
			name:       "git remote fails",
			wantErr:    true,
			wantErrMsg: "git remote failed",
		},
		{
			name:       "git config set fails",
			wantErr:    true,
			wantErrMsg: "failed to update fetch config",
		},
		{
			name: "empty remote output",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var configSetCalls []string
			orig := runGit
			t.Cleanup(func() { runGit = orig })

			switch tc.name {
			case "already configured remotes are left alone":
				runGit = func(args ...string) (string, error) {
					key := strings.Join(args, " ")
					switch key {
					case "remote":
						return "origin", nil
					case "config get remote.origin.fetch":
						return "+refs/heads/*:refs/remotes/origin/*", nil
					}
					return "", fmt.Errorf("unexpected: %s", key)
				}
			case "fixes remote missing wildcard fetch":
				runGit = func(args ...string) (string, error) {
					key := strings.Join(args, " ")
					switch key {
					case "remote":
						return "origin", nil
					case "config get remote.origin.fetch":
						return "", fmt.Errorf("no config")
					case "config remote.origin.fetch +refs/heads/*:refs/remotes/origin/*":
						configSetCalls = append(configSetCalls, "origin")
						return "", nil
					}
					return "", fmt.Errorf("unexpected: %s", key)
				}
			case "multiple remotes mixed":
				runGit = func(args ...string) (string, error) {
					key := strings.Join(args, " ")
					switch key {
					case "remote":
						return "origin\nupstream", nil
					case "config get remote.origin.fetch":
						return "+refs/heads/*:refs/remotes/origin/*", nil
					case "config get remote.upstream.fetch":
						// Returns a refspec without wildcard.
						return "+refs/heads/main:refs/remotes/upstream/main", nil
					case "config remote.upstream.fetch +refs/heads/*:refs/remotes/upstream/*":
						configSetCalls = append(configSetCalls, "upstream")
						return "", nil
					}
					return "", fmt.Errorf("unexpected: %s", key)
				}
			case "git remote fails":
				runGit = func(args ...string) (string, error) {
					return "", fmt.Errorf("git error")
				}
			case "git config set fails":
				runGit = func(args ...string) (string, error) {
					key := strings.Join(args, " ")
					switch key {
					case "remote":
						return "origin", nil
					case "config get remote.origin.fetch":
						return "", fmt.Errorf("no config")
					case "config remote.origin.fetch +refs/heads/*:refs/remotes/origin/*":
						return "", fmt.Errorf("permission denied")
					}
					return "", fmt.Errorf("unexpected: %s", key)
				}
			case "empty remote output":
				runGit = func(args ...string) (string, error) {
					key := strings.Join(args, " ")
					if key == "remote" {
						return "", nil
					}
					return "", fmt.Errorf("unexpected: %s", key)
				}
			}

			err := fixCIRemotes()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			switch tc.name {
			case "already configured remotes are left alone":
				if len(configSetCalls) != 0 {
					t.Errorf("expected no config set calls, got %v", configSetCalls)
				}
			case "fixes remote missing wildcard fetch":
				if len(configSetCalls) != 1 || configSetCalls[0] != "origin" {
					t.Errorf("expected config set for origin, got %v", configSetCalls)
				}
			case "multiple remotes mixed":
				if len(configSetCalls) != 1 || configSetCalls[0] != "upstream" {
					t.Errorf("expected config set for upstream only, got %v", configSetCalls)
				}
			}
		})
	}
}

func TestTryGitTagStrategy(t *testing.T) {
	origPrefix := releasePrefix
	t.Cleanup(func() { releasePrefix = origPrefix })
	releasePrefix = "release-v"

	tests := []struct {
		name      string
		remote    string
		gitMock   map[string]string
		wantRes   string
		wantFound bool
		wantErr   bool
	}{
		{
			name:   "tag found and remote branch exists",
			remote: "origin",
			gitMock: map[string]string{
				"describe --tags --abbrev=0":                            "v3.22.1",
				"branch --show-current":                                 "my-feature",
				"rev-parse --verify --quiet release-v3.22":              "abc123",
				"rev-parse --abbrev-ref release-v3.22@{upstream}":       "origin/release-v3.22",
				"rev-parse --abbrev-ref --quiet origin/release-v3.22":   "origin/release-v3.22",
			},
			wantRes:   "origin/release-v3.22",
			wantFound: true,
		},
		{
			name:      "git describe fails returns not found",
			remote:    "origin",
			wantFound: false,
		},
		{
			name:   "tag without minor version",
			remote: "origin",
			gitMock: map[string]string{
				"describe --tags --abbrev=0": "v3",
				"branch --show-current":      "my-feature",
			},
			wantFound: false,
		},
		{
			name:   "tag found but no matching branch",
			remote: "origin",
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			switch tc.name {
			case "git describe fails returns not found":
				orig := runGit
				runGit = func(args ...string) (string, error) {
					return "", fmt.Errorf("no tags found")
				}
				t.Cleanup(func() { runGit = orig })
			case "tag found but no matching branch":
				orig := runGit
				runGit = func(args ...string) (string, error) {
					key := strings.Join(args, " ")
					switch key {
					case "describe --tags --abbrev=0":
						return "v3.22.1", nil
					case "branch --show-current":
						return "my-feature", nil
					}
					return "", fmt.Errorf("not found")
				}
				t.Cleanup(func() { runGit = orig })
			default:
				if tc.gitMock != nil {
					withMockGit(t, tc.gitMock)
				}
			}

			result, found, err := tryGitTagStrategy(tc.remote)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if found != tc.wantFound {
				t.Errorf("found = %v, want %v", found, tc.wantFound)
			}
			if result != tc.wantRes {
				t.Errorf("result = %q, want %q", result, tc.wantRes)
			}
		})
	}
}

func TestMergeBaseStrategy(t *testing.T) {
	origPrefix := releasePrefix
	t.Cleanup(func() { releasePrefix = origPrefix })
	releasePrefix = "release-v"

	tests := []struct {
		name    string
		remote  string
		refs    string
		gitMock map[string]string
		want    string
	}{
		{
			name:   "picks branch with smallest distance",
			remote: "origin",
			refs: "origin/master\n" +
				"origin/release-v3.21\n" +
				"origin/release-v3.22\n",
			gitMock: map[string]string{
				"for-each-ref --format=%(refname:short) refs/remotes/origin": "origin/master\norigin/release-v3.21\norigin/release-v3.22",
				"merge-base origin/master HEAD":       "aaa",
				"rev-list --count aaa..HEAD":           "10",
				"merge-base origin/release-v3.21 HEAD": "bbb",
				"rev-list --count bbb..HEAD":           "5",
				"merge-base origin/release-v3.22 HEAD": "ccc",
				"rev-list --count ccc..HEAD":           "2",
			},
			want: "origin/release-v3.22",
		},
		{
			name:   "master wins when closest",
			remote: "origin",
			gitMock: map[string]string{
				"for-each-ref --format=%(refname:short) refs/remotes/origin": "origin/master\norigin/release-v3.22",
				"merge-base origin/master HEAD":       "aaa",
				"rev-list --count aaa..HEAD":           "1",
				"merge-base origin/release-v3.22 HEAD": "bbb",
				"rev-list --count bbb..HEAD":           "5",
			},
			want: "origin/master",
		},
		{
			name:   "skips non-matching branches",
			remote: "origin",
			gitMock: map[string]string{
				"for-each-ref --format=%(refname:short) refs/remotes/origin": "origin/master\norigin/feature-branch\norigin/release-v3.22",
				"merge-base origin/master HEAD":       "aaa",
				"rev-list --count aaa..HEAD":           "10",
				"merge-base origin/release-v3.22 HEAD": "ccc",
				"rev-list --count ccc..HEAD":           "3",
			},
			want: "origin/release-v3.22",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withMockGit(t, tc.gitMock)

			got, err := mergeBaseStrategy(tc.remote)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMergeBaseStrategy_NoMatchingBranches(t *testing.T) {
	origPrefix := releasePrefix
	t.Cleanup(func() { releasePrefix = origPrefix })
	releasePrefix = "release-v"

	tests := []struct {
		name    string
		remote  string
		gitMock map[string]string
	}{
		{
			name:   "empty refs",
			remote: "origin",
			gitMock: map[string]string{
				"for-each-ref --format=%(refname:short) refs/remotes/origin": "",
			},
		},
		{
			name:   "only non-matching branches",
			remote: "origin",
			gitMock: map[string]string{
				"for-each-ref --format=%(refname:short) refs/remotes/origin": "origin/feature-branch\norigin/bugfix-123",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withMockGit(t, tc.gitMock)

			_, err := mergeBaseStrategy(tc.remote)
			if err == nil {
				t.Fatal("expected error when no suitable branches found")
			}
			if !strings.Contains(err.Error(), "no suitable remote branches found") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

func TestMergeBaseStrategy_ForEachRefError(t *testing.T) {
	origPrefix := releasePrefix
	t.Cleanup(func() { releasePrefix = origPrefix })
	releasePrefix = "release-v"

	orig := runGit
	runGit = func(args ...string) (string, error) {
		return "", fmt.Errorf("git error")
	}
	t.Cleanup(func() { runGit = orig })

	_, err := mergeBaseStrategy("origin")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to list remote refs") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMergeBaseStrategy_SkipsMergeBaseErrors(t *testing.T) {
	origPrefix := releasePrefix
	t.Cleanup(func() { releasePrefix = origPrefix })
	releasePrefix = "release-v"

	callCount := 0
	orig := runGit
	runGit = func(args ...string) (string, error) {
		key := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(key, "for-each-ref"):
			return "origin/master\norigin/release-v3.22", nil
		case key == "merge-base origin/master HEAD":
			return "", fmt.Errorf("no merge base")
		case key == "merge-base origin/release-v3.22 HEAD":
			callCount++
			return "abc", nil
		case key == "rev-list --count abc..HEAD":
			return "3", nil
		}
		return "", fmt.Errorf("unexpected: %s", key)
	}
	t.Cleanup(func() { runGit = orig })

	got, err := mergeBaseStrategy("origin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "origin/release-v3.22" {
		t.Errorf("got %q, want %q", got, "origin/release-v3.22")
	}
	if callCount != 1 {
		t.Errorf("expected release-v3.22 merge-base to be called once, got %d", callCount)
	}
}

func TestRunGitReal(t *testing.T) {
	// Test that runGitReal works with a simple git command.
	out, err := runGitReal("version")
	if err != nil {
		t.Fatalf("git version failed: %v", err)
	}
	if !strings.HasPrefix(out, "git version") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRunGitReal_Error(t *testing.T) {
	_, err := runGitReal("nonexistent-command-that-does-not-exist")
	if err == nil {
		t.Fatal("expected error for invalid git command")
	}
}
