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

package distribution

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
	"time"

	"github.com/google/go-cmp/cmp"
	ghapi "github.com/google/go-github/v53/github"

	"github.com/projectcalico/calico/release/internal/command"
	gh "github.com/projectcalico/calico/release/internal/github"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/outputs"
)

func TestDestinationNames(t *testing.T) {
	if got := (S3{URI: "s3://b/k/"}).Name(); got != "s3://b/k/" {
		t.Errorf("S3 name = %q", got)
	}
	if got := (GCS{URI: "gs://b/k"}).Name(); got != "gs://b/k" {
		t.Errorf("GCS name = %q", got)
	}
	if got := (GithubRelease{Tag: "v3.30.0"}).Name(); !strings.Contains(got, "v3.30.0") {
		t.Errorf("github name = %q, want the tag in it", got)
	}
}

func TestS3Publish(t *testing.T) {
	ctx := context.Background()

	t.Run("excludes then includes, as aws did", func(t *testing.T) {
		store := newFakeStore(nil)
		d := S3{URI: "s3://bucket/debs/", Exclude: []string{"*"}, Include: []string{"dists/*"}, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "pool/a.deb", "dists/Release")); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"debs/dists/Release"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	t.Run("sync never deletes", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"x/old": {body: "old", modTime: time.Now()}})
		d := S3{URI: "s3://bucket/x/", Sync: true, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "new")); err != nil {
			t.Fatal(err)
		}
		if len(store.removes) != 0 {
			t.Errorf("removed %v", store.removes)
		}
	})

	t.Run("a dry run sends nothing", func(t *testing.T) {
		store := newFakeStore(nil)
		d := S3{URI: "s3://bucket/x/", DryRun: true, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
		if len(store.puts) != 0 {
			t.Errorf("sent %v", store.puts)
		}
	})

	t.Run("a dry-run copy needs no AWS config", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "no-such-profile")
		t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
		d := S3{URI: "s3://bucket/x/", DryRun: true}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an error names the destination", func(t *testing.T) {
		store := newFakeStore(nil)
		store.err = errors.New("denied")
		d := S3{URI: "s3://bucket/charts/", store: store}
		err := d.Publish(ctx, writeTree(t, time.Now(), "a"))
		if err == nil || !strings.Contains(err.Error(), "s3://bucket/charts/") {
			t.Errorf("error = %v, want it to name the destination", err)
		}
	})

	t.Run("a URI that is not s3 fails before any copy", func(t *testing.T) {
		store := newFakeStore(nil)
		if err := (S3{URI: "gs://bucket/x/", store: store}).Publish(ctx, writeTree(t, time.Now(), "a")); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestGCSPublish(t *testing.T) {
	ctx := context.Background()

	t.Run("sync deletes what the source dropped", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"hash/dropped": {body: "x", modTime: time.Now()}})
		d := GCS{URI: "gs://bucket/hash", Sync: true, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "kept")); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"hash/dropped"}, store.removes); diff != "" {
			t.Errorf("removes (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{"hash/kept"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	t.Run("a copy deletes nothing", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"x/other": {body: "x", modTime: time.Now()}})
		d := GCS{URI: "gs://bucket/x", store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
		if len(store.removes) != 0 {
			t.Errorf("removed %v", store.removes)
		}
	})

	t.Run("a dry-run copy needs no credentials", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
		d := GCS{URI: "gs://bucket/x", DryRun: true}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an error names the destination", func(t *testing.T) {
		store := newFakeStore(nil)
		store.err = errors.New("denied")
		err := (GCS{URI: "gs://bucket/hash", store: store}).Publish(ctx, writeTree(t, time.Now(), "a"))
		if err == nil || !strings.Contains(err.Error(), "gs://bucket/hash") {
			t.Errorf("error = %v, want it to name the destination", err)
		}
	})
}

// LatestTag returns an empty string when a repository has no published
// release. Parsing that as a version fails, so a first release could never
// be published.
func TestGithubReleaseMakeLatest(t *testing.T) {
	for _, tc := range []struct {
		name      string
		published string
		tag       string
		want      bool
	}{
		{name: "first release in an empty repository", tag: "v3.30.0", want: true},
		{name: "newer than what is published", published: "v3.29.0", tag: "v3.30.0", want: true},
		{name: "a patch for an older stream", published: "v3.30.0", tag: "v3.29.2"},
		// Trimming a "v" from both ends would corrupt this into 3.30.0-de.
		{name: "a tag ending in v", published: "v3.29.0", tag: "v3.30.0-dev", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rels := githubReleasesWithLatest(t, tc.published)
			got, err := GithubRelease{releases: rels, Tag: tc.tag}.makeLatest(context.Background())
			if err != nil {
				t.Fatalf("makeLatest: %v", err)
			}
			if got != tc.want {
				t.Errorf("makeLatest() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A destination holds a real *github.Releases, so the fake goes in at the
// service seam rather than the destination.
func githubReleasesWithLatest(t *testing.T, tag string) *gh.Releases {
	t.Helper()
	svc := &fakeReleaseService{}
	if tag != "" {
		svc.latest = &ghapi.RepositoryRelease{TagName: ghapi.String(tag)}
	}
	rels, err := gh.NewReleases(gh.Repo{Org: "projectcalico", Name: "calico"}, svc)
	if err != nil {
		t.Fatalf("NewReleases: %v", err)
	}
	return rels
}

type fakeReleaseService struct {
	gh.ReleaseService
	latest *ghapi.RepositoryRelease
	draft  *ghapi.RepositoryRelease

	mu       sync.Mutex
	uploaded []string
	attached []*ghapi.ReleaseAsset
}

func (f *fakeReleaseService) GetReleaseByTag(context.Context, string, string, string) (*ghapi.RepositoryRelease, *ghapi.Response, error) {
	return nil, &ghapi.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, errors.New("not found")
}

func (f *fakeReleaseService) ListReleases(context.Context, string, string, *ghapi.ListOptions) ([]*ghapi.RepositoryRelease, *ghapi.Response, error) {
	return nil, &ghapi.Response{}, nil
}

func (f *fakeReleaseService) CreateRelease(_ context.Context, _, _ string, r *ghapi.RepositoryRelease) (*ghapi.RepositoryRelease, *ghapi.Response, error) {
	return f.draft, nil, nil
}

func (f *fakeReleaseService) ListReleaseAssets(context.Context, string, string, int64, *ghapi.ListOptions) ([]*ghapi.ReleaseAsset, *ghapi.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.attached), &ghapi.Response{}, nil
}

// Records what it received the way GitHub would, so a second Publish sees the
// assets the first one attached.
func (f *fakeReleaseService) UploadReleaseAsset(_ context.Context, _, _ string, _ int64, opts *ghapi.UploadOptions, file *os.File) (*ghapi.ReleaseAsset, *ghapi.Response, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploaded = append(f.uploaded, opts.Name)
	f.attached = append(f.attached, &ghapi.ReleaseAsset{
		ID:    ghapi.Int64(int64(len(f.attached) + 1)),
		Name:  ghapi.String(opts.Name),
		State: ghapi.String("uploaded"),
		Size:  ghapi.Int(int(info.Size())),
	})
	return nil, nil, nil
}

func (f *fakeReleaseService) GetLatestRelease(context.Context, string, string) (*ghapi.RepositoryRelease, *ghapi.Response, error) {
	if f.latest == nil {
		return nil, &ghapi.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, errors.New("not found")
	}
	return f.latest, nil, nil
}

func TestSHA256Sums(t *testing.T) {
	t.Run("checksums through the given runner", func(t *testing.T) {
		dir := dirWith(t, "a.tgz", "b.tgz")
		r := &command.Recorder{Reply: func(command.Call) (string, error) { return "abc  a.tgz\ndef  b.tgz", nil }}
		if err := SHA256Sums(dir, WithRunner(r)); err != nil {
			t.Fatalf("SHA256Sums: %v", err)
		}
		want := []command.Call{{Name: "sha256sum", Args: []string{"a.tgz", "b.tgz"}, Dir: dir}}
		if diff := cmp.Diff(want, r.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
		got, err := os.ReadFile(filepath.Join(dir, sumsFileName))
		if err != nil {
			t.Fatalf("reading sums: %v", err)
		}
		if string(got) != "abc  a.tgz\ndef  b.tgz" {
			t.Errorf("sums file = %q, want the runner's output", got)
		}
	})
}

func TestArtifactFiles(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"release.tgz", sumsFileName, "charts/index.yaml"} {
		path := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	release := filepath.Join(dir, "release.tgz")
	githubRelease := GithubRelease{Repo: gh.Repo{Org: "projectcalico", Name: "calico"}, Tag: "v3.30.0"}
	hashrelease := HashreleaseServer{Release: &hashreleaseserver.Hashrelease{Name: "2026-10-05-v3-30-0"}}

	t.Run("lists a github release's top-level files at its download URL", func(t *testing.T) {
		got, err := artifactFiles([]Upload{{Source: dir, Handler: githubRelease}})
		if err != nil {
			t.Fatal(err)
		}
		url, err := gh.DownloadURL("projectcalico", "calico", "v3.30.0", "release.tgz")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]outputs.ArtifactFile{{Name: "release.tgz", Path: release, URL: url}}, got); diff != "" {
			t.Errorf("files (-want +got):\n%s", diff)
		}
	})

	t.Run("lists a hashrelease's top-level files at its URL", func(t *testing.T) {
		got, err := artifactFiles([]Upload{{Source: dir, Handler: hashrelease}})
		if err != nil {
			t.Fatal(err)
		}
		want := []outputs.ArtifactFile{{Name: "release.tgz", Path: release, URL: hashreleaseserver.HashreleaseURL("2026-10-05-v3-30-0") + "/release.tgz"}}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("files (-want +got):\n%s", diff)
		}
	})

	t.Run("lists nothing for a skipped upload or one that serves no files", func(t *testing.T) {
		got, err := artifactFiles([]Upload{
			{Source: dir, Handler: githubRelease, Skip: true},
			{Source: dir, Handler: S3{URI: "s3://bucket/charts/"}},
			{Handler: Preparer{Kind: "metadata"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("listed %v", got)
		}
	})

	t.Run("fails on a missing source", func(t *testing.T) {
		_, err := artifactFiles([]Upload{{Source: filepath.Join(dir, "missing"), Handler: hashrelease}})
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("err = %v, want it to wrap os.ErrNotExist", err)
		}
	})
}

func TestMetadata(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"release.tgz": "hello", "metadata.yaml": "version: v3.30.0"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hashrelease := HashreleaseServer{Release: &hashreleaseserver.Hashrelease{Name: "2026-10-05-v3-30-0"}}

	t.Run("hashes each published file except the metadata", func(t *testing.T) {
		got, err := Metadata([]Upload{{Source: dir, Handler: hashrelease}})
		if err != nil {
			t.Fatal(err)
		}
		want := []outputs.Artifact{{
			Name:   "release.tgz",
			Size:   5,
			SHA256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
			URL:    hashreleaseserver.HashreleaseURL("2026-10-05-v3-30-0") + "/release.tgz",
		}}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("artifacts (-want +got):\n%s", diff)
		}
	})
}
