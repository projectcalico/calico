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
	"slices"
	"strings"
	"sync"
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

	assetLists int

	mu sync.Mutex
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
	f.listed = append(f.listed, rel)
	return rel, nil, nil
}

func (f *fakeReleases) EditRelease(_ context.Context, _, _ string, _ int64, rel *github.RepositoryRelease) (*github.RepositoryRelease, *github.Response, error) {
	f.edited = rel
	return rel, nil, nil
}

func (f *fakeReleases) GetLatestRelease(_ context.Context, _, _ string) (*github.RepositoryRelease, *github.Response, error) {
	for _, rel := range f.listed {
		if !rel.GetDraft() && !rel.GetPrerelease() {
			return rel, nil, nil
		}
	}
	return nil, &github.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, errors.New("not found")
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assetLists++
	return slices.Clone(f.assets), nil, nil
}

func (f *fakeReleases) DeleteReleaseAsset(_ context.Context, _, _ string, id int64) (*github.Response, error) {
	f.deleted = append(f.deleted, id)
	return nil, nil
}

// Attaches what it received the way GitHub would, so a second publish sees
// the assets the first one attached.
func (f *fakeReleases) UploadReleaseAsset(_ context.Context, _, _ string, _ int64, opts *github.UploadOptions, file *os.File) (*github.ReleaseAsset, *github.Response, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploaded = append(f.uploaded, opts.Name)
	f.assets = append(f.assets, &github.ReleaseAsset{
		ID:    github.Int64(int64(len(f.assets) + 100)),
		Name:  github.String(opts.Name),
		State: github.String("uploaded"),
		Size:  github.Int(int(info.Size())),
	})
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

func TestNewReleases(t *testing.T) {
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

func TestGet(t *testing.T) {
	// A missing tag is not an error: the caller decides whether absence is a
	// problem, and a create has to be able to ask.
	t.Run("an absent tag is not an error", func(t *testing.T) {
		got, found, err := testReleases(t, &fakeReleases{}).Get(context.Background(), "v3.30.0")
		if err != nil || found || got != nil {
			t.Errorf("got (%v, %v, %v), want (nil, false, nil)", got, found, err)
		}
	})

	// An auth or network failure must not read as "no such release", which would
	// send the caller on to create one.
	t.Run("a failure is not read as absence", func(t *testing.T) {
		f := &fakeReleases{
			getErr:  errors.New("bad credentials"),
			getResp: &github.Response{Response: &http.Response{StatusCode: http.StatusUnauthorized}},
		}
		if _, found, err := testReleases(t, f).Get(context.Background(), "v3.30.0"); err == nil || found {
			t.Errorf("expected the failure reported, got found=%v err=%v", found, err)
		}
	})
}

func TestCreate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		existing   *github.RepositoryRelease
		prerelease bool
		published  bool
		wantErr    string
		wantNew    bool
	}{
		{name: "creates when absent", wantNew: true},
		{name: "creates a pre-release when asked", prerelease: true, wantNew: true},
		{name: "creates a published release when not a draft", published: true, wantNew: true},
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
			rel, err := testReleases(t, f).Create(context.Background(), CreateOptions{Draft: !tc.published, Tag: "v3.30.0", Name: "v3.30.0", Body: "notes", Prerelease: tc.prerelease})

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
				t.Fatalf("Create: %v", err)
			}
			if tc.wantNew {
				if f.created == nil {
					t.Fatal("expected a release created")
				}
				if got := f.created.GetDraft(); got == tc.published {
					t.Errorf("Draft = %v, want %v", got, !tc.published)
				}
				if got := f.created.GetPrerelease(); got != tc.prerelease {
					t.Errorf("Prerelease = %v, want %v", got, tc.prerelease)
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

	// A draft carries no git tag, so the by-tag lookup 404s on one. Without the
	// listing fallback every run would create another draft for the same tag.
	t.Run("reuses a draft the tag lookup cannot see", func(t *testing.T) {
		f := &fakeReleases{}
		f.draft("v3.30.0", &github.RepositoryRelease{ID: github.Int64(9), Draft: github.Bool(true)})

		rel, err := testReleases(t, f).Create(context.Background(), CreateOptions{Draft: true, Tag: "v3.30.0", Name: "v3.30.0", Body: "notes"})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if f.created != nil {
			t.Error("expected the existing draft reused, not a second one created")
		}
		if rel.GetID() != 9 {
			t.Errorf("got release %d, want the existing draft 9", rel.GetID())
		}
	})

	t.Run("refuses a published release found by listing", func(t *testing.T) {
		f := &fakeReleases{}
		f.draft("v3.30.0", &github.RepositoryRelease{ID: github.Int64(9), Draft: github.Bool(false)})

		if _, err := testReleases(t, f).Create(context.Background(), CreateOptions{Draft: true, Tag: "v3.30.0", Name: "v3.30.0", Body: "notes"}); err == nil ||
			!strings.Contains(err.Error(), "already published") {
			t.Errorf("expected a refusal to modify a published release, got %v", err)
		}
	})
}

// A re-run must resend only what is missing or arrived incomplete: resending
// what already landed wastes a large upload, and leaving a truncated asset
// ships a broken release.
func TestSyncAssets(t *testing.T) {
	asset := func(id int64, name, state string, size int) *github.ReleaseAsset {
		return &github.ReleaseAsset{
			ID: github.Int64(id), Name: github.String(name),
			State: github.String(state), Size: github.Int(size),
		}
	}
	for _, tc := range []struct {
		name        string
		assets      []*github.ReleaseAsset
		want        []Asset
		wantUpload  []string
		wantDeleted []int64
		wantLists   int
	}{
		{
			name:       "nothing attached yet",
			want:       []Asset{{Path: "d/a.tgz", Size: 10}, {Path: "d/b.zip", Size: 20}},
			wantUpload: []string{"a.tgz", "b.zip"},
			wantLists:  1,
		},
		{
			name:      "already complete, so nothing to do",
			assets:    []*github.ReleaseAsset{asset(1, "a.tgz", "uploaded", 10)},
			want:      []Asset{{Path: "d/a.tgz", Size: 10}},
			wantLists: 1,
		},
		{
			name:        "truncated, so replaced",
			assets:      []*github.ReleaseAsset{asset(1, "a.tgz", "uploaded", 3)},
			want:        []Asset{{Path: "d/a.tgz", Size: 10}},
			wantUpload:  []string{"a.tgz"},
			wantDeleted: []int64{1},
			wantLists:   1,
		},
		{
			name:        "upload never finished, so replaced",
			assets:      []*github.ReleaseAsset{asset(1, "a.tgz", "starter", 10)},
			want:        []Asset{{Path: "d/a.tgz", Size: 10}},
			wantUpload:  []string{"a.tgz"},
			wantDeleted: []int64{1},
			wantLists:   1,
		},
		{
			name: "a partial run resends only what is missing",
			assets: []*github.ReleaseAsset{
				asset(1, "a.tgz", "uploaded", 10),
				asset(2, "b.zip", "uploaded", 2),
			},
			want:        []Asset{{Path: "d/a.tgz", Size: 10}, {Path: "d/b.zip", Size: 20}, {Path: "d/c.txt", Size: 30}},
			wantUpload:  []string{"b.zip", "c.txt"},
			wantDeleted: []int64{2},
			wantLists:   1,
		},
		{
			name:   "an asset we are not uploading is left alone",
			assets: []*github.ReleaseAsset{asset(9, "keep.zip", "uploaded", 1)},
			want:   []Asset{{Path: "d/a.tgz", Size: 10}},
			// keep.zip is neither deleted nor uploaded.
			wantUpload: []string{"a.tgz"},
			wantLists:  1,
		},
		{
			name:   "no files does not even list",
			assets: []*github.ReleaseAsset{asset(1, "a.tgz", "uploaded", 10)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeReleases{assets: tc.assets}
			got, err := testReleases(t, f).SyncAssets(context.Background(), 1, tc.want)
			if err != nil {
				t.Fatalf("SyncAssets: %v", err)
			}
			var names []string
			for _, a := range got {
				names = append(names, a.Name())
			}
			if !slices.Equal(names, tc.wantUpload) {
				t.Errorf("to upload = %v, want %v", names, tc.wantUpload)
			}
			slices.Sort(f.deleted)
			if !slices.Equal(f.deleted, tc.wantDeleted) {
				t.Errorf("deleted = %v, want %v", f.deleted, tc.wantDeleted)
			}
			if f.assetLists != tc.wantLists {
				t.Errorf("listed %d times, want %d", f.assetLists, tc.wantLists)
			}
		})
	}
}

// A retry after a lost response must not resend a name GitHub already holds:
// the upload would be rejected as a duplicate.
func TestAssetState(t *testing.T) {
	for _, tc := range []struct {
		name         string
		assets       []*github.ReleaseAsset
		wantComplete bool
		wantDeleted  []int64
	}{
		{
			name:         "the upload landed after all",
			assets:       []*github.ReleaseAsset{{ID: github.Int64(1), Name: github.String("a.tgz"), State: github.String("uploaded"), Size: github.Int(10)}},
			wantComplete: true,
		},
		{
			name:        "it landed short, so the name is freed",
			assets:      []*github.ReleaseAsset{{ID: github.Int64(1), Name: github.String("a.tgz"), State: github.String("uploaded"), Size: github.Int(4)}},
			wantDeleted: []int64{1},
		},
		{name: "it did not land at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeReleases{assets: tc.assets}
			complete, err := testReleases(t, f).AssetState(context.Background(), 1, Asset{Path: "d/a.tgz", Size: 10})
			if err != nil {
				t.Fatalf("AssetState: %v", err)
			}
			if complete != tc.wantComplete {
				t.Errorf("complete = %v, want %v", complete, tc.wantComplete)
			}
			if !slices.Equal(f.deleted, tc.wantDeleted) {
				t.Errorf("deleted = %v, want %v", f.deleted, tc.wantDeleted)
			}
		})
	}
}

func TestUploadAsset(t *testing.T) {
	t.Run("attaches the file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "SHA256SUMS")
		if err := os.WriteFile(path, []byte("sums"), 0o644); err != nil {
			t.Fatalf("writing fixture: %v", err)
		}
		f := &fakeReleases{}
		if err := testReleases(t, f).UploadAsset(context.Background(), 1, path); err != nil {
			t.Fatalf("UploadAsset: %v", err)
		}
		if len(f.uploaded) != 1 || f.uploaded[0] != "SHA256SUMS" {
			t.Errorf("uploaded = %v, want [SHA256SUMS]", f.uploaded)
		}
	})
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

	t.Run("a missing release fails", func(t *testing.T) {
		if err := testReleases(t, &fakeReleases{}).Publish(context.Background(), "v3.30.0", false); err == nil {
			t.Error("expected publishing a release that does not exist to fail")
		}
	})

	// Publishing takes a draft live, and a draft is the one thing the by-tag
	// endpoint cannot see. Looking it up that way strands every release.
	t.Run("finds a draft the tag lookup cannot see", func(t *testing.T) {
		f := &fakeReleases{}
		f.draft("v3.30.0", &github.RepositoryRelease{ID: github.Int64(9), Draft: github.Bool(true)})

		if err := testReleases(t, f).Publish(context.Background(), "v3.30.0", false); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if f.edited == nil {
			t.Fatal("expected the draft edited")
		}
		if f.edited.GetDraft() {
			t.Error("expected the release undrafted")
		}
	})
}

func TestLatestTag(t *testing.T) {
	// GitHub serves the latest release itself, so ours is whatever it reports.
	t.Run("is what GitHub serves", func(t *testing.T) {
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
	})

	t.Run("is empty with no releases", func(t *testing.T) {
		got, err := testReleases(t, &fakeReleases{}).LatestTag(context.Background())
		if err != nil || got != "" {
			t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
		}
	})
}
