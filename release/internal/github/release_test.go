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

package github

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v53/github"
)

// fakeReleases records what a call did, so a test asserts on the request
// rather than on the client that made it.
type fakeReleases struct {
	byTag    map[string]*github.RepositoryRelease
	assets   []*github.ReleaseAsset
	getErr   error
	getResp  *github.Response
	uploaded []string
	deleted  []int64
	created  *github.RepositoryRelease
	edited   *github.RepositoryRelease
	listed   []*github.RepositoryRelease
}

func (f *fakeReleases) GetReleaseByTag(_ context.Context, _, _, tag string) (*github.RepositoryRelease, *github.Response, error) {
	if f.getErr != nil {
		return nil, f.getResp, f.getErr
	}
	rel, ok := f.byTag[tag]
	if !ok {
		return nil, &github.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, errors.New("not found")
	}
	return rel, nil, nil
}

func (f *fakeReleases) CreateRelease(_ context.Context, _, _ string, rel *github.RepositoryRelease) (*github.RepositoryRelease, *github.Response, error) {
	f.created = rel
	rel.ID = github.Int64(1)
	return rel, nil, nil
}

func (f *fakeReleases) EditRelease(_ context.Context, _, _ string, _ int64, rel *github.RepositoryRelease) (*github.RepositoryRelease, *github.Response, error) {
	f.edited = rel
	return rel, nil, nil
}

func (f *fakeReleases) ListReleases(_ context.Context, _, _ string, _ *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error) {
	return f.listed, nil, nil
}

// A draft is only reachable by listing, so a fake that serves byTag alone
// would let a duplicate-draft bug pass.
func (f *fakeReleases) draft(tag string, rel *github.RepositoryRelease) {
	rel.TagName = github.String(tag)
	f.listed = append(f.listed, rel)
}

func (f *fakeReleases) ListReleaseAssets(_ context.Context, _, _ string, _ int64, _ *github.ListOptions) ([]*github.ReleaseAsset, *github.Response, error) {
	return f.assets, nil, nil
}

func (f *fakeReleases) DeleteReleaseAsset(_ context.Context, _, _ string, id int64) (*github.Response, error) {
	f.deleted = append(f.deleted, id)
	return nil, nil
}

func (f *fakeReleases) UploadReleaseAsset(_ context.Context, _, _ string, _ int64, opts *github.UploadOptions, _ *os.File) (*github.ReleaseAsset, *github.Response, error) {
	f.uploaded = append(f.uploaded, opts.Name)
	return nil, nil, nil
}

func testReleases(t *testing.T, f *fakeReleases) *Releases {
	t.Helper()
	r, err := NewReleases(Repo{Org: "projectcalico", Name: "calico"}, f)
	if err != nil {
		t.Fatalf("NewReleases: %v", err)
	}
	return r
}

func TestNewReleasesRequiresRepo(t *testing.T) {
	for _, tc := range []struct {
		name string
		repo Repo
		want string
	}{
		{"no org", Repo{Name: "calico"}, "organization"},
		{"no name", Repo{Org: "projectcalico"}, "repository"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewReleases(tc.repo, &fakeReleases{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected an error naming %q, got %v", tc.want, err)
			}
		})
	}
}

// A missing tag is not an error: the caller decides whether absence is a
// problem, and a create has to be able to ask.
func TestGetAbsentTagIsNotAnError(t *testing.T) {
	got, found, err := testReleases(t, &fakeReleases{}).Get(context.Background(), "v3.30.0")
	if err != nil || found || got != nil {
		t.Errorf("got (%v, %v, %v), want (nil, false, nil)", got, found, err)
	}
}

// An auth or network failure must not read as "no such release", which would
// send the caller on to create one.
func TestGetDistinguishesFailureFromAbsence(t *testing.T) {
	f := &fakeReleases{
		getErr:  errors.New("bad credentials"),
		getResp: &github.Response{Response: &http.Response{StatusCode: http.StatusUnauthorized}},
	}
	if _, found, err := testReleases(t, f).Get(context.Background(), "v3.30.0"); err == nil || found {
		t.Errorf("expected the failure reported, got found=%v err=%v", found, err)
	}
}

func TestCreateDraft(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing *github.RepositoryRelease
		wantErr  string
		wantNew  bool
	}{
		{name: "creates when absent", wantNew: true},
		{
			name:     "reuses an existing draft",
			existing: &github.RepositoryRelease{ID: github.Int64(7), Draft: github.Bool(true)},
		},
		{
			name:     "refuses a published release",
			existing: &github.RepositoryRelease{ID: github.Int64(7), Draft: github.Bool(false)},
			wantErr:  "already published",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeReleases{}
			if tc.existing != nil {
				f.byTag = map[string]*github.RepositoryRelease{"v3.30.0": tc.existing}
			}
			rel, err := testReleases(t, f).CreateDraft(context.Background(), "v3.30.0", "v3.30.0", "notes")

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected an error containing %q, got %v", tc.wantErr, err)
				}
				if f.created != nil {
					t.Error("expected no release created")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateDraft: %v", err)
			}
			if tc.wantNew {
				if f.created == nil {
					t.Fatal("expected a release created")
				}
				if !f.created.GetDraft() {
					t.Error("expected the new release to be a draft")
				}
				return
			}
			if f.created != nil {
				t.Error("expected the existing draft reused, not a new one")
			}
			if rel.GetID() != tc.existing.GetID() {
				t.Errorf("got release %d, want the existing %d", rel.GetID(), tc.existing.GetID())
			}
		})
	}
}

// GitHub rejects a duplicate asset name, so a re-run has to replace rather
// than add.
func TestUploadAssetReplacesSameName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(path, []byte("sums"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	f := &fakeReleases{assets: []*github.ReleaseAsset{
		{ID: github.Int64(11), Name: github.String("SHA256SUMS")},
		{ID: github.Int64(12), Name: github.String("other.tgz")},
	}}

	if err := testReleases(t, f).UploadAsset(context.Background(), 1, path); err != nil {
		t.Fatalf("UploadAsset: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != 11 {
		t.Errorf("expected only the same-named asset deleted, got %v", f.deleted)
	}
	if len(f.uploaded) != 1 || f.uploaded[0] != "SHA256SUMS" {
		t.Errorf("uploaded = %v, want [SHA256SUMS]", f.uploaded)
	}
}

func TestPublish(t *testing.T) {
	for _, tc := range []struct {
		name       string
		latest     bool
		wantLatest string
	}{
		{name: "undrafts", latest: false},
		{name: "marks latest when newest", latest: true, wantLatest: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeReleases{byTag: map[string]*github.RepositoryRelease{
				"v3.30.0": {ID: github.Int64(7), Draft: github.Bool(true)},
			}}
			if err := testReleases(t, f).Publish(context.Background(), "v3.30.0", tc.latest); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			if f.edited.GetDraft() {
				t.Error("expected the release undrafted")
			}
			if got := f.edited.GetMakeLatest(); got != tc.wantLatest {
				t.Errorf("MakeLatest = %q, want %q", got, tc.wantLatest)
			}
		})
	}
}

func TestPublishAbsentReleaseFails(t *testing.T) {
	if err := testReleases(t, &fakeReleases{}).Publish(context.Background(), "v3.30.0", false); err == nil {
		t.Error("expected publishing a release that does not exist to fail")
	}
}

// Drafts and prereleases are skipped: the latest tag decides whether the
// release being published supersedes what users currently get.
func TestLatestTagSkipsDraftsAndPrereleases(t *testing.T) {
	f := &fakeReleases{listed: []*github.RepositoryRelease{
		{TagName: github.String("v3.31.0-rc1"), Prerelease: github.Bool(true)},
		{TagName: github.String("v3.30.1"), Draft: github.Bool(true)},
		{TagName: github.String("v3.30.0")},
	}}
	got, err := testReleases(t, f).LatestTag(context.Background())
	if err != nil {
		t.Fatalf("LatestTag: %v", err)
	}
	if got != "v3.30.0" {
		t.Errorf("LatestTag() = %q, want v3.30.0", got)
	}
}

func TestLatestTagNoReleases(t *testing.T) {
	got, err := testReleases(t, &fakeReleases{}).LatestTag(context.Background())
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

// The real client is only built when no service is injected, so this is where
// a missing token has to be caught.
func TestNewReleasesWithoutServiceNeedsAToken(t *testing.T) {
	for _, name := range tokenEnvVars {
		t.Setenv(name, "")
	}
	if _, err := NewReleases(Repo{Org: "projectcalico", Name: "calico"}, nil); err == nil ||
		!strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("expected an error naming the token env vars, got %v", err)
	}

	t.Setenv("GH_TOKEN", "t")
	if _, err := NewReleases(Repo{Org: "projectcalico", Name: "calico"}, nil); err != nil {
		t.Errorf("expected the fallback env var honoured, got %v", err)
	}
}

// A draft carries no git tag, so the by-tag lookup 404s on one. Without the
// listing fallback every run would create another draft for the same tag.
func TestCreateDraftReusesADraftTheTagLookupCannotSee(t *testing.T) {
	f := &fakeReleases{}
	f.draft("v3.30.0", &github.RepositoryRelease{ID: github.Int64(9), Draft: github.Bool(true)})

	rel, err := testReleases(t, f).CreateDraft(context.Background(), "v3.30.0", "v3.30.0", "notes")
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if f.created != nil {
		t.Error("expected the existing draft reused, not a second one created")
	}
	if rel.GetID() != 9 {
		t.Errorf("got release %d, want the existing draft 9", rel.GetID())
	}
}

func TestCreateDraftRefusesAPublishedReleaseFoundByListing(t *testing.T) {
	f := &fakeReleases{}
	f.draft("v3.30.0", &github.RepositoryRelease{ID: github.Int64(9), Draft: github.Bool(false)})

	if _, err := testReleases(t, f).CreateDraft(context.Background(), "v3.30.0", "v3.30.0", "notes"); err == nil ||
		!strings.Contains(err.Error(), "already published") {
		t.Errorf("expected a refusal to modify a published release, got %v", err)
	}
}

// A failed token lookup must keep failing with the same message, rather than
// handing back a client that panics at the first call.
func TestClientBuildFailureRepeats(t *testing.T) {
	for _, key := range tokenEnvVars {
		t.Setenv(key, "")
	}
	for range 2 {
		c, err := githubClient()
		if err == nil {
			t.Fatalf("expected an error with no token, got client=%v", c != nil)
		}
		if c != nil {
			t.Errorf("expected no client alongside the error, got %v", c)
		}
	}

	t.Setenv("GITHUB_TOKEN", "t")
	if c, err := githubClient(); err != nil || c == nil {
		t.Errorf("expected a client once the token is set, got (%v, %v)", c != nil, err)
	}
}
