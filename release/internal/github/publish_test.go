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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v53/github"

	"github.com/projectcalico/calico/release/internal/branch"
	"github.com/projectcalico/calico/release/internal/distribution"
	"github.com/projectcalico/calico/release/internal/fsutil"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/version"
)

func TestReleaseUpload(t *testing.T) {
	ver, err := version.New("v3.30.0")
	if err != nil {
		t.Fatal(err)
	}
	opts := ReleaseOptions{
		Repo:    Repo{Owner: "projectcalico", Name: "calico"},
		Version: ver,
		Source:  t.TempDir(),
		Notes:   ReleaseNotes{Link: Link{Text: "on GitHub", URL: "https://example.test/notes.md"}},
	}
	body := func(t *testing.T, o ReleaseOptions) string {
		t.Helper()
		got, err := ReleaseUpload(o).Handler.(Release).body()
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Run("lists every section", func(t *testing.T) {
		o := opts
		o.Notes.Artifacts = []ReleaseArtifact{{Name: "a.tgz", Description: "the a."}, {Name: "b.zip", Description: "the b."}}
		o.Notes.Notes = []string{"A note.", "[A link](https://example.test/more)"}
		approvals.VerifyString(t, body(t, o))
	})

	t.Run("leaves out empty sections", func(t *testing.T) {
		approvals.VerifyString(t, body(t, opts))
	})

	t.Run("notes without link text or a URL fail validation", func(t *testing.T) {
		for _, n := range []ReleaseNotes{{Link: Link{URL: "https://example.test/notes.md"}}, {Link: Link{Text: "on GitHub"}}} {
			o := opts
			o.Notes = n
			u := ReleaseUpload(o)
			if err := u.Handler.(distribution.Validator).Validate(u); err == nil {
				t.Errorf("Validate(%+v) = nil, want an error", n)
			}
		}
	})

	t.Run("a release without a repo fails validation", func(t *testing.T) {
		o := opts
		o.Repo = Repo{}
		u := ReleaseUpload(o)
		if err := u.Handler.(distribution.Validator).Validate(u); err == nil {
			t.Error("Validate() = nil, want an error")
		}
	})

	t.Run("a release without a valid tag fails validation", func(t *testing.T) {
		o := opts
		o.Version = version.Version{}
		u := ReleaseUpload(o)
		if err := u.Handler.(distribution.Validator).Validate(u); err == nil {
			t.Error("Validate() = nil, want an error")
		}
	})

	t.Run("passes the switches through", func(t *testing.T) {
		o := opts
		o.Skip, o.Draft, o.DryRun = true, true, true
		u := ReleaseUpload(o)
		h := u.Handler.(Release)
		if !u.Skip || !h.Draft || !h.DryRun {
			t.Errorf("Skip, Draft, DryRun = %v, %v, %v, want all true", u.Skip, h.Draft, h.DryRun)
		}
	})

	t.Run("waits for the required steps", func(t *testing.T) {
		u := ReleaseUpload(opts)
		if diff := cmp.Diff([]string{outputs.ChecksumStep, outputs.MetadataStep, branch.PushTagStep}, u.Requires); diff != "" {
			t.Errorf("Requires (-want +got):\n%s", diff)
		}
		if u.Name != ReleaseStep || u.Source != opts.Source {
			t.Errorf("Name, Source = %q, %q, want %q, %q", u.Name, u.Source, ReleaseStep, opts.Source)
		}
	})

	t.Run("a body-only release waits only for the tag", func(t *testing.T) {
		o := opts
		o.Source = ""
		if diff := cmp.Diff([]string{branch.PushTagStep}, ReleaseUpload(o).Requires); diff != "" {
			t.Errorf("Requires (-want +got):\n%s", diff)
		}
	})

	t.Run("also waits for the steps the caller names", func(t *testing.T) {
		want := []string{"extra", outputs.ChecksumStep, outputs.MetadataStep, branch.PushTagStep}
		if diff := cmp.Diff(want, ReleaseUpload(opts, "extra").Requires); diff != "" {
			t.Errorf("Requires (-want +got):\n%s", diff)
		}
	})
}

func TestReleasePublish(t *testing.T) {
	publish := func(t *testing.T, tag, src string) *fakeReleases {
		t.Helper()
		f := &fakeReleases{listed: []*github.RepositoryRelease{{TagName: github.String("v3.29.0")}}}
		d := Release{releases: testReleases(t, f), Tag: tag, Notes: ReleaseNotes{Link: Link{Text: "on GitHub", URL: "https://example.test/notes.md"}}}
		if err := d.Publish(context.Background(), src); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		return f
	}

	t.Run("sends the body", func(t *testing.T) {
		want := "[on GitHub](https://example.test/notes.md)"
		if got := publish(t, "v3.30.0", "").created.GetBody(); !strings.Contains(got, want) {
			t.Errorf("Body = %q, want it to contain %q", got, want)
		}
	})

	t.Run("a body-only release attaches nothing", func(t *testing.T) {
		if f := publish(t, "v3.30.0", ""); len(f.uploaded) != 0 {
			t.Errorf("uploaded %v, want nothing", f.uploaded)
		}
	})

	write := func(t *testing.T, names ...string) string {
		t.Helper()
		dir := t.TempDir()
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	t.Run("attaches every top-level file", func(t *testing.T) {
		useAssetsFilter(t, fsutil.DirFiles)
		f := publish(t, "v3.30.0", write(t, "release.tgz", outputs.MetadataFileName, outputs.SumsFileName))
		slices.Sort(f.uploaded)
		if diff := cmp.Diff([]string{outputs.SumsFileName, outputs.MetadataFileName, "release.tgz"}, f.uploaded); diff != "" {
			t.Errorf("uploaded (-want +got):\n%s", diff)
		}
	})

	notes := ReleaseNotes{Link: Link{Text: "on GitHub", URL: "https://example.test/notes.md"}}
	only := []fsutil.FileFilter{fsutil.DirFiles, fsutil.Include(outputs.MetadataFileName, outputs.SumsFileName)}

	t.Run("attaches only what the filter picks", func(t *testing.T) {
		useAssetsFilter(t, only...)
		f := &fakeReleases{listed: []*github.RepositoryRelease{{TagName: github.String("v3.29.0")}}}
		d := Release{releases: testReleases(t, f), Tag: "v3.30.0", Notes: notes}
		if err := d.Publish(context.Background(), write(t, "release.tgz", outputs.MetadataFileName, outputs.SumsFileName)); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		slices.Sort(f.uploaded)
		if diff := cmp.Diff([]string{outputs.SumsFileName, outputs.MetadataFileName}, f.uploaded); diff != "" {
			t.Errorf("uploaded (-want +got):\n%s", diff)
		}
	})

	t.Run("a failed listing creates no release", func(t *testing.T) {
		useAssetsFilter(t, only...)
		f := &fakeReleases{}
		d := Release{releases: testReleases(t, f), Tag: "v3.30.0", Notes: notes}
		if err := d.Publish(context.Background(), write(t, "release.tgz", outputs.MetadataFileName)); err == nil {
			t.Error("Publish with the sums file missing succeeded")
		}
		if f.created != nil {
			t.Error("created a release with a file missing")
		}
	})

	t.Run("an empty source creates no release", func(t *testing.T) {
		useAssetsFilter(t, fsutil.DirFiles)
		f := &fakeReleases{}
		d := Release{releases: testReleases(t, f), Tag: "v3.30.0", Notes: notes}
		if err := d.Publish(context.Background(), write(t)); err == nil {
			t.Error("Publish with no files succeeded")
		}
		if f.created != nil {
			t.Error("created a release with no files")
		}
	})

	for _, tc := range []struct {
		name           string
		tag            string
		wantPrerelease bool
		wantLatest     string
	}{
		{name: "a final release newer than the latest becomes latest", tag: "v3.30.0", wantLatest: "true"},
		{name: "a pre-release is never latest", tag: "v3.30.0-1.0", wantPrerelease: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := publish(t, tc.tag, "")
			if got := f.created.GetPrerelease(); got != tc.wantPrerelease {
				t.Errorf("Prerelease = %v, want %v", got, tc.wantPrerelease)
			}
			if got := f.edited.GetMakeLatest(); got != tc.wantLatest {
				t.Errorf("MakeLatest = %q, want %q", got, tc.wantLatest)
			}
		})
	}
}

// LatestTag returns an empty string when a repository has no published
// release. Parsing that as a version fails, so a first release could never
// be published.
func TestReleaseMakeLatest(t *testing.T) {
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
			f := &fakeReleases{}
			if tc.published != "" {
				f.listed = []*github.RepositoryRelease{{TagName: github.String(tc.published)}}
			}
			got, err := Release{releases: testReleases(t, f), Tag: tc.tag}.makeLatest(context.Background())
			if err != nil {
				t.Fatalf("makeLatest: %v", err)
			}
			if got != tc.want {
				t.Errorf("makeLatest() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReleaseName(t *testing.T) {
	if got := (Release{Tag: "v3.30.0"}).Name(); !strings.Contains(got, "v3.30.0") {
		t.Errorf("Name() = %q, want the tag in it", got)
	}
}

func useAssetsFilter(t testing.TB, filters ...fsutil.FileFilter) {
	t.Helper()
	saved := AssetsFilter
	AssetsFilter = filters
	t.Cleanup(func() { AssetsFilter = saved })
}
