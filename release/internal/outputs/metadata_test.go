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

package outputs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/release/internal/registry"
)

type record struct {
	body        []byte
	describeErr error
	attestErr   error
	described   bool
}

func (r *record) describe(Describer) error {
	r.described = true
	return r.describeErr
}

func (r *record) attest() ([]byte, error) {
	if !r.described {
		return nil, errors.New("attested before describing")
	}
	return r.body, r.attestErr
}

func TestBuildMetadata(t *testing.T) {
	t.Run("writes the bytes the record produced once described", func(t *testing.T) {
		dir := t.TempDir()
		if err := BuildMetadata(&record{body: []byte("version: v3.30.0\n")}, Describer{}, dir); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, metadataFileName))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "version: v3.30.0\n" {
			t.Errorf("metadata = %q, want %q", got, "version: v3.30.0\n")
		}
	})

	for _, tc := range []struct {
		name string
		rec  *record
		want string
	}{
		{"writes nothing when describing fails", &record{describeErr: errors.New("unauthorized")}, "unauthorized"},
		{"writes nothing when the record fails", &record{attestErr: errors.New("no version specified")}, "no version specified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			wantErrContains(t, BuildMetadata(tc.rec, Describer{}, dir), tc.want)
			if _, err := os.Stat(filepath.Join(dir, metadataFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("stat metadata = %v, want it not to exist", err)
			}
		})
	}

	t.Run("needs a directory", func(t *testing.T) {
		if err := BuildMetadata(&record{body: []byte("x")}, Describer{}, ""); err == nil {
			t.Error("built metadata with no directory")
		}
	})

	t.Run("needs a record", func(t *testing.T) {
		if err := BuildMetadata(nil, Describer{}, t.TempDir()); err == nil {
			t.Error("built metadata with no record")
		}
	})
}

func TestMetadataDescribe(t *testing.T) {
	node := registry.Component{Registry: "quay.io/calico", Image: "node", Version: "v3.30.0"}

	t.Run("fills components from what was released", func(t *testing.T) {
		m := Metadata{Released: map[string]registry.Component{"node": node}}
		if err := m.describe(Describer{Images: ImageDescriber{Resolve: resolveTo("sha256:res", true, nil)}}); err != nil {
			t.Fatal(err)
		}
		want := map[string]Component{
			"node": {Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0", Digest: "sha256:res"},
		}
		if diff := cmp.Diff(want, m.Components); diff != "" {
			t.Errorf("components (-want +got):\n%s", diff)
		}
	})

	t.Run("keeps released out of the document", func(t *testing.T) {
		m := Metadata{
			Version:         "v3.30.0",
			OperatorVersion: "v1.38.0",
			Source:          Source{Repository: "https://github.com/projectcalico/calico", Commit: "abc123"},
			Released:        map[string]registry.Component{"node": node},
		}
		if err := m.describe(Describer{Images: ImageDescriber{Resolve: resolveTo("", false, nil)}}); err != nil {
			t.Fatal(err)
		}
		bs, err := m.attest()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(bs), "released") {
			t.Errorf("document holds released:\n%s", bs)
		}
	})

	t.Run("fills chart digests from the record before resolving", func(t *testing.T) {
		recorded := registry.NewDigestSource(registry.DigestsByRepo([]string{
			"quay.io/calico/charts/tigera-operator:v3.30.0@sha256:rec",
		}))
		m := Metadata{Charts: &Charts{Version: "v3.30.0", Entries: map[string]Chart{
			"tigera-operator": {Image: "quay.io/calico/charts/tigera-operator:v3.30.0"},
			"crds":            {Image: "quay.io/calico/charts/crds:v3.30.0"},
		}}}
		if err := m.describe(Describer{Images: ImageDescriber{Sources: []registry.DigestSource{recorded}, Resolve: resolveTo("sha256:res", true, nil)}}); err != nil {
			t.Fatal(err)
		}
		if got := m.Charts.Entries["tigera-operator"].Digest; got != "sha256:rec" {
			t.Errorf("tigera-operator digest = %q, want sha256:rec", got)
		}
		if got := m.Charts.Entries["crds"].Digest; got != "sha256:res" {
			t.Errorf("crds digest = %q, want sha256:res", got)
		}
	})

	t.Run("fails on a chart resolve error", func(t *testing.T) {
		m := Metadata{Charts: &Charts{Version: "v3.30.0", Entries: map[string]Chart{
			"crds": {Image: "quay.io/calico/charts/crds:v3.30.0"},
		}}}
		wantErrContains(t, m.describe(Describer{Images: ImageDescriber{Resolve: resolveTo("", false, fmt.Errorf("unauthorized"))}}), "chart crds")
	})

	t.Run("fills artifacts from the files published", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "release.tgz")
		if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		m := Metadata{}
		if err := m.describe(Describer{
			Images:    ImageDescriber{Resolve: resolveTo("", false, nil)},
			Artifacts: ArtifactDescriber{Files: []ArtifactFile{{Name: "release.tgz", Path: path, URL: "https://example.com/release.tgz"}}},
		}); err != nil {
			t.Fatal(err)
		}
		if len(m.Artifacts) != 1 || m.Artifacts[0].URL != "https://example.com/release.tgz" {
			t.Errorf("artifacts = %+v, want one at https://example.com/release.tgz", m.Artifacts)
		}
	})

	t.Run("fails with no image resolver", func(t *testing.T) {
		m := Metadata{Released: map[string]registry.Component{"node": node}}
		wantErrContains(t, m.describe(Describer{}), "no image resolver")
	})
}

func TestMetadataAttest(t *testing.T) {
	valid := func() Metadata {
		return Metadata{
			Version:         "v3.30.0",
			OperatorVersion: "v1.38.0",
			Source:          Source{Repository: "https://github.com/projectcalico/calico", Commit: "abc123", Branch: "release-v3.30", Tag: "v3.30.0"},
			Components: map[string]Component{
				"operator": {Version: "v1.38.0", Image: "quay.io/tigera/operator:v1.38.0", Digest: "sha256:aaa"},
				"node":     {Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0"},
			},
		}
	}
	sorted := cmpopts.SortSlices(func(a, b string) bool { return a < b })

	t.Run("renders images from components", func(t *testing.T) {
		m := valid()
		m.Images = []string{"stale/image:v0"}
		bs, err := m.attest()
		if err != nil {
			t.Fatal(err)
		}
		var got Metadata
		if err := yaml.Unmarshal(bs, &got); err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, c := range got.Components {
			want = append(want, c.Image)
		}
		if diff := cmp.Diff(want, got.Images, sorted); diff != "" {
			t.Errorf("images (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(valid().Components, got.Components); diff != "" {
			t.Errorf("components (-want +got):\n%s", diff)
		}
	})

	t.Run("allows a component without a digest", func(t *testing.T) {
		if _, err := valid().attest(); err != nil {
			t.Error(err)
		}
	})

	t.Run("lists no image for a version-only component", func(t *testing.T) {
		m := valid()
		m.Components["calicoctl"] = Component{Version: "v3.30.0"}
		m, err := m.attested()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"quay.io/tigera/operator:v1.38.0", "quay.io/calico/node:v3.30.0"}
		if diff := cmp.Diff(want, m.Images, sorted); diff != "" {
			t.Errorf("images (-want +got):\n%s", diff)
		}
	})

	t.Run("rejects an incomplete component", func(t *testing.T) {
		for desc, c := range map[string]Component{
			"no version":       {Image: "quay.io/calico/node:v3.30.0"},
			"digest, no image": {Version: "v3.30.0", Digest: "sha256:aaa"},
			"no image name":    {Version: "v3.30.0", Image: "quay.io/:v3.30.0"},
			"no tag":           {Version: "v3.30.0", Image: "quay.io/calico/node:"},
		} {
			t.Run(desc, func(t *testing.T) {
				m := valid()
				m.Components["node"] = c
				_, err := m.attest()
				wantErrContains(t, err, "component node")
			})
		}
	})

	t.Run("leaves out the tag of an untagged build", func(t *testing.T) {
		m := valid()
		m.Source.Tag = ""
		bs, err := m.attest()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(bs), "tag:") {
			t.Errorf("document holds a tag:\n%s", bs)
		}
	})

	t.Run("rejects a source without a repository or commit", func(t *testing.T) {
		for desc, src := range map[string]Source{
			"no repository": {Commit: "abc123"},
			"no commit":     {Repository: "https://github.com/projectcalico/calico"},
		} {
			t.Run(desc, func(t *testing.T) {
				m := valid()
				m.Source = src
				_, err := m.attest()
				wantErrContains(t, err, "source")
			})
		}
	})

	t.Run("marks superseded keys", func(t *testing.T) {
		bs, err := valid().attest()
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"# Deprecated, use components.operator.version instead.\noperatorVersion:",
			"# Deprecated, use components instead.\nimages:",
			"# Deprecated, use charts.version instead.\nhelmChartVersion:",
		} {
			if !strings.Contains(string(bs), want) {
				t.Errorf("document lacks %q:\n%s", want, bs)
			}
		}
	})

	t.Run("leaves out charts when none were released", func(t *testing.T) {
		bs, err := valid().attest()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(bs), "charts:") {
			t.Errorf("document holds charts:\n%s", bs)
		}
	})

	t.Run("renders charts", func(t *testing.T) {
		m := valid()
		m.Charts = &Charts{Version: "v3.30.0", Index: "https://example.com/charts", Entries: map[string]Chart{
			"crds": {Image: "quay.io/calico/charts/crds:v3.30.0", Digest: "sha256:aaa", URL: "https://example.com/crds-v3.30.0.tgz"},
		}}
		bs, err := m.attest()
		if err != nil {
			t.Fatal(err)
		}
		var got Metadata
		if err := yaml.Unmarshal(bs, &got); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(m.Charts, got.Charts); diff != "" {
			t.Errorf("charts (-want +got):\n%s", diff)
		}
	})

	t.Run("rejects incomplete charts", func(t *testing.T) {
		chart := Chart{Image: "quay.io/calico/charts/crds:v3.30.0", URL: "https://example.com/crds-v3.30.0.tgz"}
		for desc, c := range map[string]Charts{
			"no version":   {Entries: map[string]Chart{"crds": chart}},
			"no entries":   {Version: "v3.30.0"},
			"no tag":       {Version: "v3.30.0", Entries: map[string]Chart{"crds": {Image: "quay.io/calico/charts/crds", URL: chart.URL}}},
			"relative url": {Version: "v3.30.0", Entries: map[string]Chart{"crds": {Image: chart.Image, URL: "crds-v3.30.0.tgz"}}},
		} {
			t.Run(desc, func(t *testing.T) {
				m := valid()
				m.Charts = &c
				_, err := m.attest()
				wantErrContains(t, err, "charts")
			})
		}
	})

	t.Run("rejects an incomplete artifact", func(t *testing.T) {
		for desc, a := range map[string]Artifact{
			"no hash":      {Name: "release.tgz", URL: "https://example.com/release.tgz"},
			"relative url": {Name: "release.tgz", SHA256: "abc", URL: "release.tgz"},
		} {
			t.Run(desc, func(t *testing.T) {
				m := valid()
				m.Artifacts = []Artifact{a}
				_, err := m.attest()
				wantErrContains(t, err, "artifact release.tgz")
			})
		}
	})

	t.Run("rejects a document with no components", func(t *testing.T) {
		m := valid()
		m.Components = nil
		_, err := m.attest()
		wantErrContains(t, err, "no components")
	})
}

func TestArtifactDescriberDescribe(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	describe := func(files ...ArtifactFile) ([]Artifact, error) {
		return ArtifactDescriber{Files: files}.describe()
	}

	t.Run("records each file's size, hash and url", func(t *testing.T) {
		got, err := describe(ArtifactFile{Name: "release.tgz", Path: write("release.tgz", "hello"), URL: "https://example.com/v3.30.0/release.tgz"})
		if err != nil {
			t.Fatal(err)
		}
		want := []Artifact{{
			Name:   "release.tgz",
			Size:   5,
			SHA256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
			URL:    "https://example.com/v3.30.0/release.tgz",
		}}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("artifacts (-want +got):\n%s", diff)
		}
	})

	t.Run("names a file in a folder by its path below the upload", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(dir, "ocp"), 0o755); err != nil {
			t.Fatal(err)
		}
		got, err := describe(ArtifactFile{Name: "ocp/crs.yaml", Path: write("ocp/crs.yaml", "hello"), URL: "https://example.com/ocp/crs.yaml"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Name != "ocp/crs.yaml" {
			t.Errorf("artifacts = %+v, want one named ocp/crs.yaml", got)
		}
	})

	t.Run("leaves out the metadata file", func(t *testing.T) {
		got, err := describe(ArtifactFile{Name: metadataFileName, Path: write(metadataFileName, "version: v3.30.0"), URL: "https://example.com/" + metadataFileName})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("artifacts = %+v, want none", got)
		}
	})

	t.Run("fails on a file it cannot read", func(t *testing.T) {
		_, err := describe(ArtifactFile{Name: "missing.tgz", Path: filepath.Join(dir, "missing.tgz"), URL: "https://example.com/missing.tgz"})
		wantErrContains(t, err, "missing.tgz")
	})
}

func TestImageDescriberDescribe(t *testing.T) {
	node := registry.Component{Registry: "quay.io/calico", Image: "node", Version: "v3.30.0"}
	released := map[string]registry.Component{"node": node}
	recorded := registry.NewDigestSource(registry.DigestsByRepo([]string{
		"quay.io/calico/node:v3.30.0@sha256:rec",
	}))

	t.Run("prefers a record to a resolve", func(t *testing.T) {
		got, err := ImageDescriber{Sources: []registry.DigestSource{recorded}, Resolve: resolveTo("", false, fmt.Errorf("must not resolve"))}.describe(released)
		if err != nil {
			t.Fatal(err)
		}
		want := Component{Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0", Digest: "sha256:rec"}
		if diff := cmp.Diff(want, got["node"]); diff != "" {
			t.Errorf("node (-want +got):\n%s", diff)
		}
	})

	t.Run("resolves what no record holds", func(t *testing.T) {
		got, err := ImageDescriber{Resolve: resolveTo("sha256:res", true, nil)}.describe(released)
		if err != nil {
			t.Fatal(err)
		}
		if got["node"].Digest != "sha256:res" {
			t.Errorf("node digest = %q, want sha256:res", got["node"].Digest)
		}
	})

	t.Run("leaves out the digest of an unpublished image", func(t *testing.T) {
		got, err := ImageDescriber{Resolve: resolveTo("", false, nil)}.describe(released)
		if err != nil {
			t.Fatal(err)
		}
		want := Component{Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0"}
		if diff := cmp.Diff(want, got["node"]); diff != "" {
			t.Errorf("node (-want +got):\n%s", diff)
		}
	})

	t.Run("fails on an unpublished image when digests are required", func(t *testing.T) {
		_, err := ImageDescriber{Resolve: resolveTo("", false, nil), RequireDigests: true}.describe(released)
		wantErrContains(t, err, "quay.io/calico/node:v3.30.0 is not published")
	})

	t.Run("fails on a resolve error", func(t *testing.T) {
		_, err := ImageDescriber{Resolve: resolveTo("", false, fmt.Errorf("unauthorized"))}.describe(released)
		wantErrContains(t, err, "quay.io/calico/node:v3.30.0")
		wantErrContains(t, err, "unauthorized")
	})

	t.Run("records a component with no image by version alone", func(t *testing.T) {
		got, err := ImageDescriber{Resolve: resolveTo("", false, fmt.Errorf("must not resolve"))}.describe(map[string]registry.Component{
			"calico": {Version: "v3.30.0"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(Component{Version: "v3.30.0"}, got["calico"]); diff != "" {
			t.Errorf("calico (-want +got):\n%s", diff)
		}
	})
}

func resolveTo(digest string, exists bool, err error) registry.DigestResolver {
	return func(string) (string, bool, error) { return digest, exists, err }
}

func wantErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want it to contain %q", err, want)
	}
}
