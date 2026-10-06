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
		m := Metadata{Released: []registry.Component{node}}
		require.NoError(t, m.describe(Describer{Resolve: resolveTo("sha256:res", true, nil)}))
		require.Equal(t, map[string]Component{
			"node": {Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0", Digest: "sha256:res"},
		}, m.Components)
	})

	t.Run("keeps released out of the document", func(t *testing.T) {
		m := Metadata{Version: "v3.30.0", OperatorVersion: "v1.38.0", Released: []registry.Component{node}}
		require.NoError(t, m.describe(Describer{Resolve: resolveTo("", false, nil)}))
		bs, err := m.attest()
		require.NoError(t, err)
		require.NotContains(t, string(bs), "released")
	})
}

func TestMetadataAttest(t *testing.T) {
	valid := func() Metadata {
		return Metadata{
			Version:         "v3.30.0",
			OperatorVersion: "v1.38.0",
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

	t.Run("rejects a document with no components", func(t *testing.T) {
		m := valid()
		m.Components = nil
		_, err := m.attest()
		require.ErrorContains(t, err, "no components")
	})
}

func TestDescriberDescribe(t *testing.T) {
	node := registry.Component{Registry: "quay.io/calico", Image: "node", Version: "v3.30.0"}
	recorded := registry.NewDigestSource(registry.DigestsByRepo([]string{
		"quay.io/calico/node:v3.30.0@sha256:rec",
	}))

	t.Run("prefers a record to a resolve", func(t *testing.T) {
		got, err := Describer{Sources: []registry.DigestSource{recorded}, Resolve: resolveTo("", false, fmt.Errorf("must not resolve"))}.describe([]registry.Component{node})
		require.NoError(t, err)
		require.Equal(t, Component{Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0", Digest: "sha256:rec"}, got["node"])
	})

	t.Run("resolves what no record holds", func(t *testing.T) {
		got, err := Describer{Resolve: resolveTo("sha256:res", true, nil)}.describe([]registry.Component{node})
		require.NoError(t, err)
		require.Equal(t, "sha256:res", got["node"].Digest)
	})

	t.Run("leaves out the digest of an unpublished image", func(t *testing.T) {
		got, err := Describer{Resolve: resolveTo("", false, nil)}.describe([]registry.Component{node})
		require.NoError(t, err)
		require.Equal(t, Component{Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0"}, got["node"])
	})

	t.Run("fails on a resolve error", func(t *testing.T) {
		_, err := Describer{Resolve: resolveTo("", false, fmt.Errorf("unauthorized"))}.describe([]registry.Component{node})
		require.ErrorContains(t, err, "quay.io/calico/node:v3.30.0")
		require.ErrorContains(t, err, "unauthorized")
	})

	t.Run("rejects a component listed twice", func(t *testing.T) {
		_, err := Describer{Resolve: resolveTo("sha256:res", true, nil)}.describe([]registry.Component{node, node})
		require.ErrorContains(t, err, "listed twice")
	})
}

func resolveTo(digest string, exists bool, err error) registry.DigestResolver {
	return func(string) (string, bool, error) { return digest, exists, err }
}
