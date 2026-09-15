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

	"github.com/projectcalico/calico/release/internal/version"
)

func site(v string) Site {
	return Site{Version: version.Version(v)}
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
				got, err := site(tc.version).URL()
				if err != nil {
					t.Fatalf("URL() = %v", err)
				}
				want := BaseURL + "/" + ProductSlug + "/" + tc.stream
				if got != want {
					t.Errorf("URL() = %q, want %q", got, want)
				}
			})
		}
	})

	t.Run("drops the version prefix", func(t *testing.T) {
		got, err := site("v3.30.0").URL()
		if err != nil {
			t.Fatalf("URL() = %v", err)
		}
		if strings.Contains(got, "/v3.30") {
			t.Errorf("URL() = %q, want the stream without a v prefix", got)
		}
	})

	// Keeps the derived expectations above honest: without this, the code
	// could hardcode the OSS slug and they would still pass.
	t.Run("uses the product slug", func(t *testing.T) {
		original := ProductSlug
		t.Cleanup(func() { ProductSlug = original })
		ProductSlug = "other-product"

		got, err := site("v3.30.0").URL()
		if err != nil {
			t.Fatalf("URL() = %v", err)
		}
		if want := "https://docs.tigera.io/other-product/3.30"; got != want {
			t.Errorf("URL() = %q, want %q", got, want)
		}
	})
}

func TestDownloadsURL(t *testing.T) {
	t.Run("uses the exact version", func(t *testing.T) {
		for _, ver := range []string{"v3.30.0", "v3.30.1", "v3.30.0-1.0", "v3.30.0-0.dev-1-gabc123"} {
			t.Run(ver, func(t *testing.T) {
				got, err := site(ver).DownloadsURL()
				if err != nil {
					t.Fatalf("DownloadsURL() = %v", err)
				}
				if want := BaseArtifactsURL + "/" + ver; got != want {
					t.Errorf("DownloadsURL() = %q, want %q", got, want)
				}
			})
		}
	})

	t.Run("distinguishes patches that share a docs page", func(t *testing.T) {
		first, second := site("v3.30.0"), site("v3.30.1")

		firstDocs, err := first.URL()
		if err != nil {
			t.Fatal(err)
		}
		secondDocs, err := second.URL()
		if err != nil {
			t.Fatal(err)
		}
		if firstDocs != secondDocs {
			t.Fatalf("the two versions should share a docs page: %q and %q", firstDocs, secondDocs)
		}

		firstDownloads, err := first.DownloadsURL()
		if err != nil {
			t.Fatal(err)
		}
		secondDownloads, err := second.DownloadsURL()
		if err != nil {
			t.Fatal(err)
		}
		if firstDownloads == secondDownloads {
			t.Errorf("both versions download from %q", firstDownloads)
		}
	})

	// Keeps the derived expectations above honest: without this, the code
	// could hardcode the OSS URL and they would still pass.
	t.Run("uses the artifacts base URL", func(t *testing.T) {
		original := BaseArtifactsURL
		t.Cleanup(func() { BaseArtifactsURL = original })
		BaseArtifactsURL = "https://example.test/artifacts"

		got, err := site("v3.30.0").DownloadsURL()
		if err != nil {
			t.Fatalf("DownloadsURL() = %v", err)
		}
		if want := "https://example.test/artifacts/v3.30.0"; got != want {
			t.Errorf("DownloadsURL() = %q, want %q", got, want)
		}
	})
}
