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

package pinnedversion

import (
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/registry"
)

func TestRepoValidate(t *testing.T) {
	full := Repo{Component: "first-repo", Dir: "/repo", Branch: "master"}
	for _, tc := range []struct {
		name    string
		repo    Repo
		wantErr []string
	}{
		{name: "complete", repo: full},
		{
			name:    "no component",
			repo:    Repo{Dir: "/repo", Branch: "master"},
			wantErr: []string{"component"},
		},
		{
			name:    "no dir",
			repo:    Repo{Component: "first-repo", Branch: "master"},
			wantErr: []string{"dir"},
		},
		{
			name:    "no branch",
			repo:    Repo{Component: "first-repo", Dir: "/repo"},
			wantErr: []string{"branch"},
		},
		{
			name:    "empty reports every missing field at once",
			repo:    Repo{},
			wantErr: []string{"component", "dir", "branch"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.repo.Validate()
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("want no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want an error naming %v, got none", tc.wantErr)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// An invalid repo must fail the pin rather than pin an empty version.
func TestRepoComponentsRejectsInvalid(t *testing.T) {
	if _, err := repoComponents([]Repo{{Component: "first-repo"}}); err == nil {
		t.Error("want an error for a repo with no dir or branch, got none")
	}
}

// Every repo's failure is reported, not just the first to finish.
func TestRepoComponentsAggregatesErrors(t *testing.T) {
	_, err := repoComponents([]Repo{
		{Component: "first-repo"},
		{Component: "second-repo"},
	})
	if err == nil {
		t.Fatal("want an error, got none")
	}
	for _, want := range []string{"first-repo", "second-repo"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestRepoComponentsNoRepos(t *testing.T) {
	got, err := repoComponents(nil)
	if err != nil {
		t.Fatalf("want no error for no repos, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no components, got %v", got)
	}
}

// The hash is a build identity, so it must not vary with map or slice order.
func TestHashIsOrderIndependent(t *testing.T) {
	a := map[string]registry.Component{
		"first-repo":  {Version: "v1"},
		"second-repo": {Version: "v2"},
	}
	b := map[string]registry.Component{
		"second-repo": {Version: "v2"},
		"first-repo":  {Version: "v1"},
	}
	if hash("v3.31.0", a) != hash("v3.31.0", b) {
		t.Errorf("hash varies with map order: %q vs %q", hash("v3.31.0", a), hash("v3.31.0", b))
	}
}

func TestHash(t *testing.T) {
	for _, tc := range []struct {
		name  string
		repos map[string]registry.Component
		want  string
	}{
		{
			name: "no repos is the product version",
			want: "v3.31.0",
		},
		{
			name:  "one repo is suffixed",
			repos: map[string]registry.Component{"first-repo": {Version: "v1.2.3"}},
			want:  "v3.31.0-v1.2.3",
		},
		{
			name: "repos are suffixed in component order",
			repos: map[string]registry.Component{
				"second-repo": {Version: "v2"},
				"first-repo":  {Version: "v1"},
			},
			want: "v3.31.0-v1-v2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hash("v3.31.0", tc.repos); got != tc.want {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}

// Two repo versions on one product commit are different builds, so the hash
// must tell them apart. A collision would make the second look published.
func TestHashDistinguishesRepoVersions(t *testing.T) {
	product := "v3.31.0"
	first := hash(product, map[string]registry.Component{"first-repo": {Version: "v1"}})
	second := hash(product, map[string]registry.Component{"first-repo": {Version: "v2"}})
	if first == second {
		t.Errorf("same hash %q for different repo versions", first)
	}
	if bare := hash(product, nil); first == bare {
		t.Errorf("pinned repo did not change the hash: %q", bare)
	}
}

func TestNote(t *testing.T) {
	t.Run("records the product branch", func(t *testing.T) {
		got := hashreleaseNote("test-release", "master", nil)
		for _, want := range []string{"test-release", "master"} {
			if !strings.Contains(got, want) {
				t.Errorf("note does not mention %q: %q", want, got)
			}
		}
	})

	t.Run("records each repo branch", func(t *testing.T) {
		got := hashreleaseNote("test-release", "master", []Repo{
			{Component: "first-repo", Branch: "release-v3.31"},
		})
		for _, want := range []string{"first-repo", "release-v3.31"} {
			if !strings.Contains(got, want) {
				t.Errorf("note does not mention %q: %q", want, got)
			}
		}
	})

	t.Run("omits a repo with no branch", func(t *testing.T) {
		got := hashreleaseNote("test-release", "master", []Repo{{Component: "first-repo"}})
		if strings.Contains(got, "first-repo") {
			t.Errorf("note mentions a repo with no branch: %q", got)
		}
	})
}

func TestReleaseBranch(t *testing.T) {
	for _, tc := range []struct {
		productVer string
		want       string
	}{
		{"v3.31.0", "release-v3.31"},
		{"v3.31.5", "release-v3.31"},
		{"v3.31.0-1.0", "release-v3.31-1"},
	} {
		t.Run(tc.productVer, func(t *testing.T) {
			if got := releaseBranch("release", tc.productVer); got != tc.want {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}

// The branch decides the publish stream, so a pin read from a file has to
// recover it: from its own field, or from the note for files written before
// the field existed.
func TestPinRecoversBranch(t *testing.T) {
	const branch = "release-v3.33-2"
	for name, entry := range map[string]PinnedVersion{
		"field": {Title: "v3.33.0-2.0", Branch: branch},
		"note":  {Title: "v3.33.0-2.0", Note: "x - generated at Mon using " + branch + " release branch"},
	} {
		got := entry.pin()

		if got.branch != branch {
			t.Errorf("%s: branch %q, want %q", name, got.branch, branch)
		}
		// The stream is derived from the branch, so recovering it is what
		// this checks; how a product maps branch to stream is its own rule.
		if stream := got.Hashrelease("", false).Stream; stream == "" {
			t.Errorf("%s: no stream resolved from branch %q", name, got.branch)
		}
	}
	// A pin with neither has no branch to recover.
	bare := PinnedVersion{Title: "v3.33.0-2.0"}
	if got := bare.pin(); got.branch != "" {
		t.Errorf("want no branch, got %q", got.branch)
	}
}

// The branch survives a write so the next read does not need the note.
func TestPinnedFromCarriesBranch(t *testing.T) {
	const branch = "release-v3.33-3"
	p := &Pin{ProductVersion: "v3.33.0-2.0"}
	p.SetBranch(branch)
	if got := pinnedFrom(p).Branch; got != branch {
		t.Errorf("branch %q, want %q", got, branch)
	}
}

// The operator flags reach the pin, which is what the manifests are generated
// from. Ignoring them pushes the operator to one registry and points the
// manifests at another.
func TestOperatorComponentHonoursOverrides(t *testing.T) {
	def := operatorComponent(Config{}, testProductVersion)
	if def.Image == "" || def.Registry == "" {
		t.Fatalf("defaults not applied: %+v", def)
	}

	over := operatorComponent(Config{Operator: registry.Component{
		Image:    "custom/operator",
		Registry: "my.registry",
	}}, testProductVersion)
	if over.Image != "custom/operator" {
		t.Errorf("image override ignored: got %q", over.Image)
	}
	if over.Registry != "my.registry" {
		t.Errorf("registry override ignored: got %q", over.Registry)
	}
	if over.Version != testProductVersion {
		t.Errorf("version %q, want %q", over.Version, testProductVersion)
	}
}
