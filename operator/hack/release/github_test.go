// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v53/github"
	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/versions"
)

func fakeOperatorRepo(t testing.TB, calicoVer, enterpriseVer string) string {
	t.Helper()
	td := t.TempDir()

	// Simulate a git repository by creating a .git dir.
	if _, err := command.RunInDir(td, "git", []string{"init"}, nil); err != nil {
		t.Fatalf("failed to init dir (%s) as git repo: %v", td, err)
	}

	if err := os.MkdirAll(filepath.Join(td, filepath.Dir(versions.CalicoConfigPath)), 0o755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	// Create calico version file
	calicoContent := fmt.Sprintf("title: %s\n", calicoVer)
	if err := os.WriteFile(filepath.Join(td, versions.CalicoConfigPath), []byte(calicoContent), 0o644); err != nil {
		t.Fatalf("failed to write calico version file: %v", err)
	}
	// Create enterprise version file
	enterpriseContent := fmt.Sprintf("title: %s\n", enterpriseVer)
	if err := os.WriteFile(filepath.Join(td, versions.EnterpriseConfigPath), []byte(enterpriseContent), 0o644); err != nil {
		t.Fatalf("failed to write enterprise version file: %v", err)
	}
	return td
}

func fakeGithubServer(t testing.TB, pathResponseMap map[string]any) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for path, resp := range pathResponseMap {
			if r.URL.Path == path {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					t.Fatalf("failed to write response: %v", err)
				}
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestGenerateReleaseNotes(t *testing.T) {
	version := "v1.38.9"
	org := "tigera"
	repo := "operator"

	// Create fake operator repo with version files and make it the cwd so gitDir() can find it.
	td := fakeOperatorRepo(t, "v3.30.5", "v3.21.4")
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	if err := os.Chdir(td); err != nil {
		t.Fatalf("failed to chdir to temp repo: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	server := fakeGithubServer(t, map[string]any{
		fmt.Sprintf("/repos/%s/%s/milestones", org, repo): []map[string]interface{}{
			{
				"number": 340,
				"title":  version,
				"state":  "closed",
			},
		},
		fmt.Sprintf("/repos/%s/%s/issues", org, repo): []map[string]interface{}{
			{
				"number":   4261,
				"title":    "[v1.38] fix: allow deletion of CSRs for non-cluster hosts",
				"body":     "```release-note\nAllow non-cluster hosts to remove failed CSRs before generating new requests.\n```",
				"html_url": "https://github.com/tigera/operator/pull/4261",
				"user":     map[string]interface{}{"login": "hjiawei"},
				"labels": []map[string]interface{}{
					{"name": "release-note-required"},
				},
				"pull_request": map[string]interface{}{
					"url": fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/4261", org, repo),
				},
			},
		},
		fmt.Sprintf("/repos/%s/%s/pulls/4261", org, repo): map[string]interface{}{"number": 4261, "merged": true},
	})

	client := github.NewClient(server.Client())
	client.BaseURL, _ = url.Parse(server.URL + "/")

	r := &GithubRelease{
		Org:          org,
		Repo:         repo,
		Version:      version,
		githubClient: client,
	}
	dateRegex := regexp.MustCompile(`\b\d{2} [A-Za-z]{3} \d{4}\b`)
	cmpNormalizeDateOpt := cmp.Transformer("NormalizeDates", func(s string) string {
		return dateRegex.ReplaceAllString(s, "DD MMM YYYY")
	})
	want := `27 Nov 2026

#### Included Calico versions

Calico version: v3.30.5
Calico Enterprise version: v3.21.4

#### Other changes

- Allow non-cluster hosts to remove failed CSRs before generating new requests. [#4261](https://github.com/tigera/operator/pull/4261) (@hjiawei)
`

	t.Run("output to file", func(t *testing.T) {
		ctx := context.Background()
		outputDir := t.TempDir()
		if err := r.GenerateNotes(ctx, outputDir, true); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		// Verify the generated release notes file.
		releaseNotesFile := filepath.Join(outputDir, fmt.Sprintf("%s-release-notes.md", version))
		if _, err := os.Stat(releaseNotesFile); os.IsNotExist(err) {
			t.Fatalf("expected release notes file to be created, but it was not found")
		}
		content, err := os.ReadFile(releaseNotesFile)
		if err != nil {
			t.Fatalf("failed to read release notes file: %v", err)
		}
		if diff := cmp.Diff(string(content), want, cmpNormalizeDateOpt); diff != "" {
			t.Fatalf("unexpected release notes contents (-got +want):\n%s", diff)
		}
	})

	t.Run("no output dir", func(t *testing.T) {
		// Capture stdout
		oldStdout := os.Stdout
		rReader, wWriter, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create pipe: %v", err)
		}
		os.Stdout = wWriter

		restoreStdout := func() {
			_ = wWriter.Close()
			os.Stdout = oldStdout
		}

		ctx := context.Background()
		if err := r.GenerateNotes(ctx, "", true); err != nil {
			restoreStdout()
			t.Fatalf("expected no error, got: %v", err)
		}

		// Close writer and restore stdout, read output.
		restoreStdout()
		out, err := io.ReadAll(rReader)
		if err != nil {
			t.Fatalf("failed to read stdout: %v", err)
		}
		if diff := cmp.Diff(string(out), want, cmpNormalizeDateOpt); diff != "" {
			t.Fatalf("unexpected release notes contents (-got +want):\n%s", diff)
		}
	})
}

func TestMilestone(t *testing.T) {
	t.Parallel()
	version := "v1.2.3"
	org := "someorg"
	repo := "somerepo"

	t.Run("found", func(t *testing.T) {
		t.Parallel()

		// Server that returns a milestone matching the version.
		server := fakeGithubServer(t, map[string]any{
			fmt.Sprintf("/repos/%s/%s/milestones", org, repo): []map[string]interface{}{
				{
					"number": 1,
					"title":  version,
					"state":  "closed",
				},
			},
		})

		client := github.NewClient(server.Client())
		baseURL := server.URL + "/"
		client.BaseURL, _ = url.Parse(baseURL)

		r := &GithubRelease{
			Org:          org,
			Repo:         repo,
			Version:      version,
			githubClient: client,
		}

		ctx := context.Background()
		m, err := r.getMilestone(ctx)
		if err != nil {
			t.Fatalf("expected milestone, got error: %v", err)
		}
		if m.GetTitle() != version {
			t.Fatalf("expected milestone title %q, got %q", version, m.GetTitle())
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		version := "v1.2.3"
		org := "someorg"
		repo := "somerepo"

		// Server returns an empty list of milestones.
		server := fakeGithubServer(t, map[string]any{
			fmt.Sprintf("/repos/%s/%s/milestones", org, repo): []map[string]interface{}{{}},
		})

		client := github.NewClient(server.Client())
		client.BaseURL, _ = url.Parse(server.URL + "/")

		r := &GithubRelease{
			Org:          org,
			Repo:         repo,
			Version:      version,
			githubClient: client,
		}

		ctx := context.Background()
		m, err := r.getMilestone(ctx)
		if m != nil {
			t.Fatalf("expected no milestone, got: %v", m)
		}
		if err == nil {
			t.Fatalf("expected error when milestone not found")
		}
		want := fmt.Sprintf("milestone %q not found in %s/%s", version, org, repo)
		if err.Error() != want {
			t.Fatalf("unexpected error message: got %q want %q", err.Error(), want)
		}
	})
}

func TestReleaseNoteIssuesFiltersMergedPRs(t *testing.T) {
	t.Parallel()
	version := "v1.2.3"
	org := "someorg"
	repo := "somerepo"

	t.Run("filters merged PRs", func(t *testing.T) {
		t.Parallel()

		// Prepare a test HTTP server that returns a mix of issues:
		// - issue 10: is a PR and merged
		// - issue 11: is a PR and not merged
		// - issue 12: not a PR
		server := fakeGithubServer(t, map[string]any{
			fmt.Sprintf("/repos/%s/%s/milestones", org, repo): []map[string]interface{}{
				{
					"number": 1,
					"title":  version,
					"state":  "closed",
				},
			},
			fmt.Sprintf("/repos/%s/%s/issues", org, repo): []map[string]interface{}{
				{
					"number": 10,
					"title":  "merged pr",
					"pull_request": map[string]interface{}{
						"url": fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/10", org, repo),
					},
				},
				{
					"number": 11,
					"title":  "unmerged pr",
					"pull_request": map[string]interface{}{
						"url": fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/11", org, repo),
					},
				},
				{
					"number": 12,
					"title":  "regular issue",
				},
			},
			fmt.Sprintf("/repos/%s/%s/pulls/10", org, repo): map[string]interface{}{
				"number": 10,
				"merged": true,
			},
			fmt.Sprintf("/repos/%s/%s/pulls/11", org, repo): map[string]interface{}{
				"number": 11,
				"merged": false,
			},
		})

		client := github.NewClient(server.Client())
		client.BaseURL, _ = url.Parse(server.URL + "/")

		r := &GithubRelease{
			Org:          org,
			Repo:         repo,
			Version:      version,
			githubClient: client,
		}

		ctx := context.Background()
		issues, err := r.releaseNoteIssues(ctx)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(issues) != 1 {
			t.Fatalf("expected 1 merged PR, got %d", len(issues))
		}
		if issues[0].GetNumber() != 10 {
			t.Fatalf("expected issue number 10, got %d", issues[0].GetNumber())
		}
	})

	t.Run("propagates pull request error", func(t *testing.T) {
		t.Parallel()

		// Server returns one PR in the issues list, but returns an error for the pull request details.
		server := fakeGithubServer(t, map[string]any{
			fmt.Sprintf("/repos/%s/%s/milestones", org, repo): []map[string]interface{}{
				{
					"number": 1,
					"title":  version,
					"state":  "closed",
				},
			},
			fmt.Sprintf("/repos/%s/%s/issues", org, repo): []map[string]interface{}{
				{
					"number": 20,
					"title":  "pr with error",
					"pull_request": map[string]interface{}{
						"url": fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/20", org, repo),
					},
				},
			},
		})

		client := github.NewClient(server.Client())
		client.BaseURL, _ = url.Parse(server.URL + "/")

		r := &GithubRelease{
			Org:          org,
			Repo:         repo,
			githubClient: client,
		}

		ctx := context.Background()
		issues, err := r.releaseNoteIssues(ctx)
		if err == nil {
			t.Fatalf("expected error when pull request details endpoint fails, got issues: %#v", issues)
		}
	})
}

func TestDetermineIssueKind(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		labels []*github.Label
		want   issueKind
	}{
		{
			name:   "bug label",
			labels: []*github.Label{{Name: github.String("kind/bug")}},
			want:   issueKindBugFix,
		},
		{
			name:   "enhancement label",
			labels: []*github.Label{{Name: github.String("kind/enhancement")}},
			want:   issueKindEnhancement,
		},
		{
			name:   "other label",
			labels: []*github.Label{{Name: github.String("foo")}},
			want:   issueKind("other"),
		},
		{
			name:   "multiple labels picks kind prefix",
			labels: []*github.Label{{Name: github.String("foo")}, {Name: github.String("kind/bug")}},
			want:   issueKindBugFix,
		},
		{
			name:   "no labels",
			labels: nil,
			want:   issueKind("other"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issue := &github.Issue{Labels: tc.labels}
			got := determineIssueKind(issue)
			if got != tc.want {
				t.Fatalf("determineIssueKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractReleaseNoteFromIssue(t *testing.T) {
	t.Parallel()

	t.Run("single block", func(t *testing.T) {
		t.Parallel()
		issue := &github.Issue{
			Body:  github.String("some intro\n```release-note\nFixed the foobar bug\n```\ntrailer"),
			Title: github.String("title fallback"),
		}
		notes := extractReleaseNoteFromIssue(issue)
		if len(notes) != 1 {
			t.Fatalf("expected 1 note, got %d", len(notes))
		}
		if notes[0] != "Fixed the foobar bug" {
			t.Fatalf("unexpected note: %q", notes[0])
		}
	})

	t.Run("no block uses title", func(t *testing.T) {
		t.Parallel()
		issue := &github.Issue{
			Body:  github.String("no release note here"),
			Title: github.String("PR title as fallback"),
		}
		notes := extractReleaseNoteFromIssue(issue)
		if len(notes) != 1 {
			t.Fatalf("expected 1 note, got %d", len(notes))
		}
		if notes[0] != "PR title as fallback" {
			t.Fatalf("unexpected fallback note: %q", notes[0])
		}
	})

	t.Run("empty block", func(t *testing.T) {
		t.Parallel()
		issue := &github.Issue{
			Body: github.String(strings.Join([]string{
				"pre",
				"```release-note\n\n```",
				"post",
			}, "\n")),
			Title: github.String("PR title as fallback"),
		}
		notes := extractReleaseNoteFromIssue(issue)
		if len(notes) != 1 {
			t.Fatalf("expected 1 note, got %d", len(notes))
		}
		if notes[0] != "PR title as fallback" {
			t.Fatalf("unexpected fallback note: %q", notes[0])
		}
	})

	t.Run("TBD in block", func(t *testing.T) {
		t.Parallel()
		issue := &github.Issue{
			Body: github.String(strings.Join([]string{
				"pre",
				"```release-note\nTBD\n```",
				"post",
			}, "\n")),
			Title: github.String("PR title as fallback"),
		}
		notes := extractReleaseNoteFromIssue(issue)
		if len(notes) != 1 {
			t.Fatalf("expected 1 note, got %d", len(notes))
		}
		if notes[0] != "PR title as fallback" {
			t.Fatalf("unexpected fallback note: %q", notes[0])
		}
	})

	t.Run("multiple line block", func(t *testing.T) {
		t.Parallel()
		issue := &github.Issue{
			Body: github.String(strings.Join([]string{
				"pre",
				"```release-note\nFirst line note\nSecond line note\n```",
				"post",
			}, "\n")),
			Title: github.String("unused"),
		}
		notes := extractReleaseNoteFromIssue(issue)
		if len(notes) != 2 {
			t.Fatalf("expected 2 notes, got %d", len(notes))
		}
		if notes[0] != "First line note" {
			t.Fatalf("first note mismatch: %q", notes[0])
		}
		if notes[1] != "Second line note" {
			t.Fatalf("second note mismatch: %q", notes[1])
		}
	})

	t.Run("multiple blocks", func(t *testing.T) {
		t.Parallel()
		issue := &github.Issue{
			Body: github.String(strings.Join([]string{
				"pre",
				"```release-note\nFirst note\n```",
				"middle",
				"```release-note\nSecond note\n```",
				"post",
			}, "\n")),
			Title: github.String("unused"),
		}
		notes := extractReleaseNoteFromIssue(issue)
		if len(notes) != 2 {
			t.Fatalf("expected 2 notes, got %d", len(notes))
		}
		if notes[0] != "First note" {
			t.Fatalf("first note mismatch: %q", notes[0])
		}
		if notes[1] != "Second note" {
			t.Fatalf("second note mismatch: %q", notes[1])
		}
	})

	t.Run("multiple blocks with empty block", func(t *testing.T) {
		t.Parallel()
		issue := &github.Issue{
			Body: github.String(strings.Join([]string{
				"pre",
				"```release-note\n\n```",
				"middle",
				"```release-note\nDid a thing\n```",
				"post",
			}, "\n")),
			Title: github.String("unused"),
		}
		notes := extractReleaseNoteFromIssue(issue)
		if len(notes) != 1 {
			t.Fatalf("expected 1 note, got %d", len(notes))
		}
		if notes[0] != "Did a thing" {
			t.Fatalf("first note mismatch: %q", notes[0])
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		t.Parallel()
		issue := &github.Issue{
			Body:  github.String("```release-note\n   spaced note   \n```"),
			Title: github.String("unused"),
		}
		notes := extractReleaseNoteFromIssue(issue)
		if len(notes) != 1 {
			t.Fatalf("expected 1 note, got %d", len(notes))
		}
		if notes[0] != "spaced note" {
			t.Fatalf("expected trimmed note, got %q", notes[0])
		}
	})
}

func TestCollectReleaseNotes(t *testing.T) {
	version := "v1.2.3"
	org := "someorg"
	repo := "somerepo"

	// Create fake operator repo with version files and make it the cwd so gitDir() can find it.
	td := fakeOperatorRepo(t, "v3.25.0", "v3.20.0")
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	if err := os.Chdir(td); err != nil {
		t.Fatalf("failed to chdir to temp repo: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	// Prepare HTTP server to serve milestones, issues and pull request details.
	server := fakeGithubServer(t, map[string]any{
		fmt.Sprintf("/repos/%s/%s/milestones", org, repo): []map[string]interface{}{
			{
				"number": 1,
				"title":  version,
				"state":  "closed",
			},
		},
		fmt.Sprintf("/repos/%s/%s/issues", org, repo): []map[string]interface{}{
			{
				"number":   100,
				"title":    "bug pr",
				"body":     "intro\n```release-note\nFixed the foobar bug\n```\nend",
				"html_url": "https://github.com/someorg/somerepo/pull/100",
				"user":     map[string]interface{}{"login": "alice"},
				"labels": []map[string]interface{}{
					{"name": "release-note-required"},
					{"name": "kind/bug"},
				},
				"pull_request": map[string]interface{}{"url": fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/100", org, repo)},
			},
			{
				"number":   101,
				"title":    "enhancement pr",
				"body":     "```release-note\nAdded a cool feature\nLine two\n```",
				"html_url": "https://github.com/someorg/somerepo/pull/101",
				"user":     map[string]interface{}{"login": "carol"},
				"labels": []map[string]interface{}{
					{"name": "release-note-required"},
					{"name": "kind/enhancement"},
				},
				"pull_request": map[string]interface{}{"url": fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/101", org, repo)},
			},
			{
				"number":   102,
				"title":    "other change",
				"body":     "```release-note\nDid a thing\n```",
				"html_url": "https://github.com/someorg/somerepo/pull/102",
				"user":     map[string]interface{}{"login": "bob"},
				"labels": []map[string]interface{}{
					{"name": "release-note-required"},
				},
				"pull_request": map[string]interface{}{"url": fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/102", org, repo)},
			},
		},
		fmt.Sprintf("/repos/%s/%s/pulls/100", org, repo): map[string]interface{}{"number": 100, "merged": true},
		fmt.Sprintf("/repos/%s/%s/pulls/101", org, repo): map[string]interface{}{"number": 101, "merged": true},
		fmt.Sprintf("/repos/%s/%s/pulls/102", org, repo): map[string]interface{}{"number": 102, "merged": true},
	})

	client := github.NewClient(server.Client())
	client.BaseURL, _ = url.Parse(server.URL + "/")

	r := &GithubRelease{
		Org:          org,
		Repo:         repo,
		Version:      version,
		githubClient: client,
	}

	ctx := context.Background()
	got, err := r.collectReleaseNotes(ctx, true)
	if err != nil {
		t.Fatalf("unexpected error collecting release notes: %v", err)
	}

	want := &ReleaseNoteData{
		Date: time.Now().Format("02 Jan 2006"),
		Versions: map[string]string{
			"Calico":            "v3.25.0",
			"Calico Enterprise": "v3.20.0",
		},
		BugFixes: []ReleaseNoteItem{
			{
				ID:     100,
				Note:   "Fixed the foobar bug",
				Author: "alice",
				URL:    "https://github.com/someorg/somerepo/pull/100",
			},
		},
		Enhancements: []ReleaseNoteItem{
			{
				ID:     101,
				Note:   "Added a cool feature",
				Author: "carol",
				URL:    "https://github.com/someorg/somerepo/pull/101",
			},
			{
				ID:     101,
				Note:   "Line two",
				Author: "carol",
				URL:    "https://github.com/someorg/somerepo/pull/101",
			},
		},
		OtherChanges: []ReleaseNoteItem{
			{
				ID:     102,
				Author: "bob",
				Note:   "Did a thing",
				URL:    "https://github.com/someorg/somerepo/pull/102",
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("releaseNotesData mismatch (-want +got):\n%s", diff)
	}
}
