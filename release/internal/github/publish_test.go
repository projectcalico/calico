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

	"github.com/projectcalico/calico/release/internal/distribution"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/version"
)

func TestReleaseUpload(t *testing.T) {
	ver, err := version.New("v3.30.0")
	if err != nil {
		t.Fatal(err)
	}
	opts := ReleaseOptions{
		Repo:    Repo{Org: "projectcalico", Name: "calico"},
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

	t.Run("lists the artifacts and links", func(t *testing.T) {
		o := opts
		o.Notes.Artifacts = []ReleaseArtifact{{Name: "a.tgz", Description: "the a."}, {Name: "b.zip", Description: "the b."}}
		o.Notes.AdditionalLinks = []Link{{Text: "More", URL: "https://example.test/more"}}
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

	t.Run("passes the switches through", func(t *testing.T) {
		o := opts
		o.Skip, o.Draft, o.DryRun = true, true, true
		u := ReleaseUpload(o)
		h := u.Handler.(Release)
		if !u.Skip || !h.Draft || !h.DryRun {
			t.Errorf("Skip, Draft, DryRun = %v, %v, %v, want all true", u.Skip, h.Draft, h.DryRun)
		}
	})

	t.Run("a release with files waits for the files and the tag", func(t *testing.T) {
		u := ReleaseUpload(opts)
		want := []string{outputs.MetadataStep, distribution.ChecksumStep, TagStep}
		if diff := cmp.Diff(want, u.Requires); diff != "" {
			t.Errorf("Requires (-want +got):\n%s", diff)
		}
		if u.Name != ReleaseStep || u.Source != opts.Source {
			t.Errorf("Name, Source = %q, %q, want %q, %q", u.Name, u.Source, ReleaseStep, opts.Source)
		}
	})

	t.Run("a body-only release waits only for the tag", func(t *testing.T) {
		o := opts
		o.Source = ""
		if diff := cmp.Diff([]string{TagStep}, ReleaseUpload(o).Requires); diff != "" {
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

	t.Run("attaches the files and the sums file", func(t *testing.T) {
		dir := t.TempDir()
		for _, n := range []string{"release.tgz", distribution.SumsFileName} {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		f := publish(t, "v3.30.0", dir)
		slices.Sort(f.uploaded)
		if diff := cmp.Diff([]string{distribution.SumsFileName, "release.tgz"}, f.uploaded); diff != "" {
			t.Errorf("uploaded (-want +got):\n%s", diff)
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

func TestReleaseArtifacts(t *testing.T) {
	d := Release{Repo: Repo{Org: "projectcalico", Name: "calico"}, Tag: "v3.30.0"}

	t.Run("lists the top-level files at the download URL", func(t *testing.T) {
		dir := t.TempDir()
		release := filepath.Join(dir, "release.tgz")
		if err := os.WriteFile(release, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := d.Artifacts(dir)
		if err != nil {
			t.Fatal(err)
		}
		url := "https://github.com/projectcalico/calico/releases/download/v3.30.0/release.tgz"
		if diff := cmp.Diff([]outputs.ArtifactFile{{Name: "release.tgz", Path: release, URL: url}}, got); diff != "" {
			t.Errorf("files (-want +got):\n%s", diff)
		}
	})

	t.Run("a body-only release lists nothing", func(t *testing.T) {
		got, err := d.Artifacts("")
		if err != nil || len(got) != 0 {
			t.Errorf("Artifacts(\"\") = %v, %v, want nothing", got, err)
		}
	})
}

func TestReleaseName(t *testing.T) {
	if got := (Release{Tag: "v3.30.0"}).Name(); !strings.Contains(got, "v3.30.0") {
		t.Errorf("Name() = %q, want the tag in it", got)
	}
}
