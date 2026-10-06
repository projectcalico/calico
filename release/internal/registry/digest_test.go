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

package registry

import (
	"testing"
)

func TestDigestsByRepo(t *testing.T) {
	const (
		nodeV330 = "quay.io/calico/node:v3.30.0@sha256:aaa"
		nodeArm  = "quay.io/calico/node:v3.30.0-arm64@sha256:bbb"
		cni      = "quay.io/calico/cni:v3.30.0@sha256:ccc"
	)

	t.Run("one repo holds every tag's digest", func(t *testing.T) {
		got := DigestsByRepo([]string{nodeV330, nodeArm, cni})
		if len(got.Digests("quay.io/calico/node")) != 2 {
			t.Errorf("node digests = %v, want 2", got.Digests("quay.io/calico/node"))
		}
		if _, ok := got.Digests("quay.io/calico/cni")["sha256:ccc"]; !ok {
			t.Errorf("cni digest missing from %v", got.Digests("quay.io/calico/cni"))
		}
	})

	t.Run("a tagged ref keys on the same repo as an untagged one", func(t *testing.T) {
		tagged := DigestsByRepo([]string{nodeV330})
		untagged := DigestsByRepo([]string{"quay.io/calico/node@sha256:aaa"})
		if _, ok := tagged.Digests("quay.io/calico/node")["sha256:aaa"]; !ok {
			t.Error("tagged ref did not key on the bare repo")
		}
		if _, ok := untagged.Digests("quay.io/calico/node")["sha256:aaa"]; !ok {
			t.Error("untagged ref did not key on the bare repo")
		}
	})

	t.Run("a registry port is not a tag", func(t *testing.T) {
		got := DigestsByRepo([]string{
			"localhost:5000/calico/node:v3.30.0@sha256:aaa",
			"localhost:5000/calico/cni@sha256:ccc",
		})
		if _, ok := got.Digests("localhost:5000/calico/node")["sha256:aaa"]; !ok {
			t.Errorf("port read as a tag: %v", got.Digests("localhost:5000/calico/node"))
		}
		if _, ok := got.Digests("localhost:5000/calico/cni")["sha256:ccc"]; !ok {
			t.Error("untagged ref behind a port did not key on the bare repo")
		}
	})

	t.Run("a malformed ref records nothing", func(t *testing.T) {
		got := DigestsByRepo([]string{"quay.io/:v3.30.0@sha256:aaa", "quay.io/Calico/node:v3.30.0@sha256:bbb"})
		if !got.Empty() {
			t.Errorf("recorded a malformed ref: %+v", got)
		}
	})

	t.Run("a docker.io repo answers under the name it was recorded with", func(t *testing.T) {
		got := DigestsByRepo([]string{"docker.io/calico/node:v3.30.0@sha256:aaa"})
		if _, ok := got.Digests("docker.io/calico/node")["sha256:aaa"]; !ok {
			t.Errorf("docker.io/calico/node digests = %v, want sha256:aaa", got.Digests("docker.io/calico/node"))
		}
	})

	t.Run("a ref with no digest records nothing", func(t *testing.T) {
		got := DigestsByRepo([]string{"quay.io/calico/node:v3.30.0"})
		if _, ok := got.Digest("quay.io/calico/node:v3.30.0"); ok {
			t.Error("recorded a ref that carried no digest")
		}
	})
}

func TestRecordedDigestsDigest(t *testing.T) {
	recorded := DigestsByRepo([]string{
		"quay.io/calico/node:v3.30.0@sha256:aaa",
		"quay.io/calico/node:v3.30.0-arm64@sha256:bbb",
	})

	t.Run("answers for the tag asked for", func(t *testing.T) {
		got, ok := recorded.Digest("quay.io/calico/node:v3.30.0")
		if !ok || got != "sha256:aaa" {
			t.Errorf("Digest = %q, %v; want sha256:aaa, true", got, ok)
		}
	})

	t.Run("tells a repo's tags apart", func(t *testing.T) {
		got, ok := recorded.Digest("quay.io/calico/node:v3.30.0-arm64")
		if !ok || got != "sha256:bbb" {
			t.Errorf("Digest = %q, %v; want sha256:bbb, true", got, ok)
		}
	})

	t.Run("misses an unrecorded tag", func(t *testing.T) {
		if _, ok := recorded.Digest("quay.io/calico/node:v3.29.0"); ok {
			t.Error("answered for a tag that was never recorded")
		}
	})

	t.Run("misses a tagless record", func(t *testing.T) {
		old := DigestsByRepo([]string{"quay.io/calico/node@sha256:aaa"})
		if _, ok := old.Digest("quay.io/calico/node:v3.30.0"); ok {
			t.Error("a record without a tag answered a tagged lookup")
		}
		if _, ok := old.Digest("quay.io/calico/node:latest"); ok {
			t.Error("a record without a tag answered for latest")
		}
	})

	t.Run("misses a reference with no tag", func(t *testing.T) {
		if _, ok := recorded.Digest("quay.io/calico/node"); ok {
			t.Error("answered a lookup that named no tag")
		}
	})
}

func TestDigestSourceDigest(t *testing.T) {
	first := DigestsByRepo([]string{"quay.io/calico/node:v3.30.0@sha256:aaa"})
	second := DigestsByRepo([]string{
		"quay.io/calico/node:v3.30.0@sha256:bbb",
		"quay.io/calico/cni:v3.30.0@sha256:ccc",
	})
	src := NewDigestSource(first, second)

	t.Run("takes the first record that answers", func(t *testing.T) {
		got, ok := src.Digest("quay.io/calico/node:v3.30.0")
		if !ok || got != "sha256:aaa" {
			t.Errorf("Digest = %q, %v; want sha256:aaa, true", got, ok)
		}
	})

	t.Run("falls through to a later record", func(t *testing.T) {
		got, ok := src.Digest("quay.io/calico/cni:v3.30.0")
		if !ok || got != "sha256:ccc" {
			t.Errorf("Digest = %q, %v; want sha256:ccc, true", got, ok)
		}
	})

	t.Run("misses when no record answers", func(t *testing.T) {
		if got, ok := src.Digest("quay.io/calico/typha:v3.30.0"); ok {
			t.Errorf("Digest = %q, want a miss", got)
		}
	})
}
