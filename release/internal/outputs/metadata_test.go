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
	"testing"

	"github.com/stretchr/testify/require"
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
		require.NoError(t, BuildMetadata(&record{body: []byte("version: v3.30.0\n")}, Describer{}, dir))
		got, err := os.ReadFile(filepath.Join(dir, metadataFileName))
		require.NoError(t, err)
		require.Equal(t, "version: v3.30.0\n", string(got))
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
			require.ErrorContains(t, BuildMetadata(tc.rec, Describer{}, dir), tc.want)
			_, err := os.Stat(filepath.Join(dir, metadataFileName))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}

	t.Run("needs a directory", func(t *testing.T) {
		require.Error(t, BuildMetadata(&record{body: []byte("x")}, Describer{}, ""))
	})

	t.Run("needs a record", func(t *testing.T) {
		require.Error(t, BuildMetadata(nil, Describer{}, t.TempDir()))
	})
}

func TestMetadataDescribe(t *testing.T) {
	node := registry.Component{Registry: "quay.io/calico", Image: "node", Version: "v3.30.0"}

	t.Run("fills components from what was released", func(t *testing.T) {
		m := Metadata{Released: map[string]registry.Component{"node": node}}
		require.NoError(t, m.describe(Describer{Images: ImageDescriber{Resolve: resolveTo("sha256:res", true, nil)}}))
		require.Equal(t, map[string]Component{
			"node": {Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0", Digest: "sha256:res"},
		}, m.Components)
	})

	t.Run("keeps released out of the document", func(t *testing.T) {
		m := Metadata{
			Version:         "v3.30.0",
			OperatorVersion: "v1.38.0",
			Source:          Source{Repository: "https://github.com/projectcalico/calico", Commit: "abc123"},
			Released:        map[string]registry.Component{"node": node},
		}
		require.NoError(t, m.describe(Describer{Images: ImageDescriber{Resolve: resolveTo("", false, nil)}}))
		bs, err := m.attest()
		require.NoError(t, err)
		require.NotContains(t, string(bs), "released")
	})

	t.Run("fills chart digests from the record before resolving", func(t *testing.T) {
		recorded := registry.NewDigestSource(registry.DigestsByRepo([]string{
			"quay.io/calico/charts/tigera-operator:v3.30.0@sha256:rec",
		}))
		m := Metadata{Charts: &Charts{Version: "v3.30.0", Entries: map[string]Chart{
			"tigera-operator": {Image: "quay.io/calico/charts/tigera-operator:v3.30.0"},
			"crds":            {Image: "quay.io/calico/charts/crds:v3.30.0"},
		}}}
		require.NoError(t, m.describe(Describer{Images: ImageDescriber{Sources: []registry.DigestSource{recorded}, Resolve: resolveTo("sha256:res", true, nil)}}))
		require.Equal(t, "sha256:rec", m.Charts.Entries["tigera-operator"].Digest)
		require.Equal(t, "sha256:res", m.Charts.Entries["crds"].Digest)
	})

	t.Run("fails on a chart resolve error", func(t *testing.T) {
		m := Metadata{Charts: &Charts{Version: "v3.30.0", Entries: map[string]Chart{
			"crds": {Image: "quay.io/calico/charts/crds:v3.30.0"},
		}}}
		require.ErrorContains(t, m.describe(Describer{Images: ImageDescriber{Resolve: resolveTo("", false, fmt.Errorf("unauthorized"))}}), "chart crds")
	})

	t.Run("fills artifacts from the files published", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "release.tgz")
		require.NoError(t, os.WriteFile(path, []byte("hello"), 0o644))
		m := Metadata{}
		require.NoError(t, m.describe(Describer{
			Images:    ImageDescriber{Resolve: resolveTo("", false, nil)},
			Artifacts: ArtifactDescriber{Files: []ArtifactFile{{Path: path, URL: "https://example.com/release.tgz"}}},
		}))
		require.Len(t, m.Artifacts, 1)
		require.Equal(t, "https://example.com/release.tgz", m.Artifacts[0].URL)
	})

	t.Run("fails with no image resolver", func(t *testing.T) {
		m := Metadata{Released: map[string]registry.Component{"node": node}}
		require.ErrorContains(t, m.describe(Describer{}), "no image resolver")
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

	t.Run("renders images from components", func(t *testing.T) {
		m := valid()
		m.Images = []string{"stale/image:v0"}
		bs, err := m.attest()
		require.NoError(t, err)
		var got Metadata
		require.NoError(t, yaml.Unmarshal(bs, &got))
		var want []string
		for _, c := range got.Components {
			want = append(want, c.Image)
		}
		require.ElementsMatch(t, want, got.Images)
		require.Equal(t, valid().Components, got.Components)
	})

	t.Run("allows a component without a digest", func(t *testing.T) {
		_, err := valid().attest()
		require.NoError(t, err)
	})

	t.Run("lists no image for a version-only component", func(t *testing.T) {
		m := valid()
		m.Components["calicoctl"] = Component{Version: "v3.30.0"}
		m, err := m.attested()
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"quay.io/tigera/operator:v1.38.0", "quay.io/calico/node:v3.30.0"}, m.Images)
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
				require.ErrorContains(t, err, "component node")
			})
		}
	})

	t.Run("leaves out the tag of an untagged build", func(t *testing.T) {
		m := valid()
		m.Source.Tag = ""
		bs, err := m.attest()
		require.NoError(t, err)
		require.NotContains(t, string(bs), "tag:")
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
				require.ErrorContains(t, err, "source")
			})
		}
	})

	t.Run("leaves out charts when none were released", func(t *testing.T) {
		bs, err := valid().attest()
		require.NoError(t, err)
		require.NotContains(t, string(bs), "charts:")
	})

	t.Run("renders charts", func(t *testing.T) {
		m := valid()
		m.Charts = &Charts{Version: "v3.30.0", Index: "https://example.com/charts", Entries: map[string]Chart{
			"crds": {Image: "quay.io/calico/charts/crds:v3.30.0", Digest: "sha256:aaa", URL: "https://example.com/crds-v3.30.0.tgz"},
		}}
		bs, err := m.attest()
		require.NoError(t, err)
		var got Metadata
		require.NoError(t, yaml.Unmarshal(bs, &got))
		require.Equal(t, m.Charts, got.Charts)
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
				require.ErrorContains(t, err, "charts")
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
				require.ErrorContains(t, err, "artifact release.tgz")
			})
		}
	})

	t.Run("rejects a document with no components", func(t *testing.T) {
		m := valid()
		m.Components = nil
		_, err := m.attest()
		require.ErrorContains(t, err, "no components")
	})
}

func TestArtifactDescriberDescribe(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
		return path
	}
	describe := func(files ...ArtifactFile) ([]Artifact, error) {
		return ArtifactDescriber{Files: files}.describe()
	}

	t.Run("records each file's size, hash and url", func(t *testing.T) {
		got, err := describe(ArtifactFile{Path: write("release.tgz", "hello"), URL: "https://example.com/v3.30.0/release.tgz"})
		require.NoError(t, err)
		require.Equal(t, []Artifact{{
			Name:   "release.tgz",
			Size:   5,
			SHA256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
			URL:    "https://example.com/v3.30.0/release.tgz",
		}}, got)
	})

	t.Run("leaves out the metadata file", func(t *testing.T) {
		got, err := describe(ArtifactFile{Path: write(metadataFileName, "version: v3.30.0"), URL: "https://example.com/" + metadataFileName})
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("fails on a file it cannot read", func(t *testing.T) {
		_, err := describe(ArtifactFile{Path: filepath.Join(dir, "missing.tgz"), URL: "https://example.com/missing.tgz"})
		require.ErrorContains(t, err, "missing.tgz")
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
		require.NoError(t, err)
		require.Equal(t, Component{Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0", Digest: "sha256:rec"}, got["node"])
	})

	t.Run("resolves what no record holds", func(t *testing.T) {
		got, err := ImageDescriber{Resolve: resolveTo("sha256:res", true, nil)}.describe(released)
		require.NoError(t, err)
		require.Equal(t, "sha256:res", got["node"].Digest)
	})

	t.Run("leaves out the digest of an unpublished image", func(t *testing.T) {
		got, err := ImageDescriber{Resolve: resolveTo("", false, nil)}.describe(released)
		require.NoError(t, err)
		require.Equal(t, Component{Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0"}, got["node"])
	})

	t.Run("fails on a resolve error", func(t *testing.T) {
		_, err := ImageDescriber{Resolve: resolveTo("", false, fmt.Errorf("unauthorized"))}.describe(released)
		require.ErrorContains(t, err, "quay.io/calico/node:v3.30.0")
		require.ErrorContains(t, err, "unauthorized")
	})

	t.Run("records a component with no image by version alone", func(t *testing.T) {
		got, err := ImageDescriber{Resolve: resolveTo("", false, fmt.Errorf("must not resolve"))}.describe(map[string]registry.Component{
			"calico": {Version: "v3.30.0"},
		})
		require.NoError(t, err)
		require.Equal(t, Component{Version: "v3.30.0"}, got["calico"])
	})
}

func resolveTo(digest string, exists bool, err error) registry.DigestResolver {
	return func(string) (string, bool, error) { return digest, exists, err }
}
