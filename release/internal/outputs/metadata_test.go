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
		m := Metadata{Released: []registry.Component{node}}
		if err := m.describe(Describer{Resolve: resolveTo("sha256:res", true, nil)}); err != nil {
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
		m := Metadata{Version: "v3.30.0", OperatorVersion: "v1.38.0", Released: []registry.Component{node}}
		if err := m.describe(Describer{Resolve: resolveTo("", false, nil)}); err != nil {
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

	t.Run("rejects a document with no components", func(t *testing.T) {
		m := valid()
		m.Components = nil
		_, err := m.attest()
		wantErrContains(t, err, "no components")
	})
}

func TestDescriberDescribe(t *testing.T) {
	node := registry.Component{Registry: "quay.io/calico", Image: "node", Version: "v3.30.0"}
	recorded := registry.NewDigestSource(registry.DigestsByRepo([]string{
		"quay.io/calico/node:v3.30.0@sha256:rec",
	}))

	t.Run("prefers a record to a resolve", func(t *testing.T) {
		got, err := Describer{Sources: []registry.DigestSource{recorded}, Resolve: resolveTo("", false, fmt.Errorf("must not resolve"))}.describe([]registry.Component{node})
		if err != nil {
			t.Fatal(err)
		}
		want := Component{Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0", Digest: "sha256:rec"}
		if diff := cmp.Diff(want, got["node"]); diff != "" {
			t.Errorf("node (-want +got):\n%s", diff)
		}
	})

	t.Run("resolves what no record holds", func(t *testing.T) {
		got, err := Describer{Resolve: resolveTo("sha256:res", true, nil)}.describe([]registry.Component{node})
		if err != nil {
			t.Fatal(err)
		}
		if got["node"].Digest != "sha256:res" {
			t.Errorf("node digest = %q, want sha256:res", got["node"].Digest)
		}
	})

	t.Run("leaves out the digest of an unpublished image", func(t *testing.T) {
		got, err := Describer{Resolve: resolveTo("", false, nil)}.describe([]registry.Component{node})
		if err != nil {
			t.Fatal(err)
		}
		want := Component{Version: "v3.30.0", Image: "quay.io/calico/node:v3.30.0"}
		if diff := cmp.Diff(want, got["node"]); diff != "" {
			t.Errorf("node (-want +got):\n%s", diff)
		}
	})

	t.Run("fails on a resolve error", func(t *testing.T) {
		_, err := Describer{Resolve: resolveTo("", false, fmt.Errorf("unauthorized"))}.describe([]registry.Component{node})
		wantErrContains(t, err, "quay.io/calico/node:v3.30.0")
		wantErrContains(t, err, "unauthorized")
	})

	t.Run("rejects a component listed twice", func(t *testing.T) {
		_, err := Describer{Resolve: resolveTo("sha256:res", true, nil)}.describe([]registry.Component{node, node})
		wantErrContains(t, err, "listed twice")
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
