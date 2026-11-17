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

package docs

import (
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/defaults"
	"github.com/projectcalico/calico/release/internal/version"
)

func site(t testing.TB, v string) Site {
	t.Helper()
	ver, err := version.New(v)
	if err != nil {
		t.Fatal(err)
	}
	return Site{Version: ver}
}

func TestURL(t *testing.T) {
	t.Run("is one page per minor stream", func(t *testing.T) {
		for name, tc := range map[string]struct {
			version string
			stream  string
		}{
			"release":        {"v3.30.0", "3.30"},
			"patch":          {"v3.30.1", "3.30"},
			"early preview":  {"v3.30.0-1.0", "3.30"},
			"second preview": {"v3.30.0-2.0", "3.30"},
			"dev build":      {"v3.30.0-0.dev-1-gabc123", "3.30"},
			"other stream":   {"v3.31.0", "3.31"},
		} {
			t.Run(name, func(t *testing.T) {
				got := site(t, tc.version).URL()
				want := baseURL.JoinPath(defaults.ProductSlug, tc.stream).String()
				if got != want {
					t.Errorf("URL() = %q, want %q", got, want)
				}
			})
		}
	})

	t.Run("adds a path below the stream", func(t *testing.T) {
		got := site(t, "v3.30.1").URL("release-notes")
		if want := baseURL.JoinPath(defaults.ProductSlug, "3.30", "release-notes").String(); got != want {
			t.Errorf("URL() = %q, want %q", got, want)
		}
	})

	t.Run("drops the version prefix", func(t *testing.T) {
		got := site(t, "v3.30.0").URL()
		if strings.Contains(got, "/v3.30") {
			t.Errorf("URL() = %q, want the stream without a v prefix", got)
		}
	})

	// Keeps the derived expectations above honest: without this, the code
	// could hardcode the OSS slug and they would still pass.
	t.Run("uses the product slug", func(t *testing.T) {
		original := defaults.ProductSlug
		t.Cleanup(func() { defaults.ProductSlug = original })
		defaults.ProductSlug = "other-product"

		got := site(t, "v3.30.0").URL()
		if want := "https://docs.tigera.io/other-product/3.30"; got != want {
			t.Errorf("URL() = %q, want %q", got, want)
		}
	})
}
