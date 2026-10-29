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

package calico

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/projectcalico/calico/release/internal/images"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/plan"
)

// requiredOpts returns the bare-minimum opts needed for NewManager to pass
// its constructor-level required-field checks. Tests layer additional opts
// on top to exercise specific behaviour.
func requiredOpts() []Option {
	return []Option{
		WithRepoRoot("/tmp"),
		WithGithubOrg("projectcalico"),
		WithRepoName("calico"),
		WithRepoRemote("origin"),
	}
}

func TestNewManager(t *testing.T) {
	// The defaults are a release's steps, so a flag left unset changes nothing.
	t.Run("steps default to a release's", func(t *testing.T) {
		m, err := NewManager(requiredOpts()...)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		checks := []struct {
			step string
			got  bool
			want bool
		}{
			{"validate", m.validate, true},
			{"validateBranch", m.validateBranch, true},
			{"images", m.images, true},
			{"archiveImages", m.archiveImages, true},
			{"manifests", m.manifests, true},
			{"binaries", m.binaries, true},
			{"ocpBundle", m.ocpBundle, true},
			{"tarball", m.tarball, true},
			{"windowsArchive", m.windowsArchive, true},
			{"helmCharts", m.helmCharts, true},
			{"helmIndex", m.helmIndex, true},
			{"e2eBinaries", m.e2eBinaries, true},
			{"gitRef", m.gitRef, true},
			{"githubRelease", m.githubRelease, true},
			{"releaseNotes", m.releaseNotes, false},
		}
		for _, c := range checks {
			if c.got != c.want {
				t.Errorf("%s defaults to %v, want %v", c.step, c.got, c.want)
			}
		}
	})

	skip := map[string]bool{operator.Step: true, images.Step: true}
	m, err := NewManager(append(requiredOpts(),
		WithOperator(func() error { return nil }),
		WithPlanOptions(plan.Options{Skip: skip}),
	)...)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Run("skipping the operator turns it off", func(t *testing.T) {
		if m.operator != nil {
			t.Error("operator is still on")
		}
	})
	t.Run("skipping images turns them off but keeps their step", func(t *testing.T) {
		if m.images {
			t.Error("images are still on")
		}
		if m.planOptions.Skip[images.Step] {
			t.Error("images step is still skipped")
		}
	})
	t.Run("the caller's skip list is unchanged", func(t *testing.T) {
		want := map[string]bool{operator.Step: true, images.Step: true}
		if diff := cmp.Diff(want, skip); diff != "" {
			t.Errorf("skip list (-want +got):\n%s", diff)
		}
	})
}

// TestCanBuildValidation covers the cross-flag invariants enforced at the
// manager layer. The test exercises the two non-trivial cases this PR
// introduces: image-registries required when images/archive-images are on,
// and ocp-bundle requires manifests on the hashrelease path.
func TestCanBuildValidation(t *testing.T) {
	cases := []struct {
		name      string
		opts      []Option
		wantErr   string // substring match; empty means "the asserted invariants do not fire"
		expectErr bool   // true if canBuildValidation must return non-nil
	}{
		{
			name: "happy path",
			opts: append(requiredOpts(),
				WithVersion("v3.99.0"),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries([]string{"example.com/calico"}),
			),
		},
		{
			name: "missing calico version",
			opts: append(requiredOpts(),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries([]string{"example.com/calico"}),
			),
			wantErr:   "no calico version specified",
			expectErr: true,
		},
		{
			name: "missing operator version",
			opts: append(requiredOpts(),
				WithVersion("v3.99.0"),
				WithImageRegistries([]string{"example.com/calico"}),
			),
			wantErr:   "no operator version specified",
			expectErr: true,
		},
		{
			name: "images on with no registries errors",
			opts: append(requiredOpts(),
				WithVersion("v3.99.0"),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries(nil),
			),
			wantErr:   "no image registries specified",
			expectErr: true,
		},
		{
			name: "images off + archive off skips registry check",
			opts: append(requiredOpts(),
				WithVersion("v3.99.0"),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries(nil),
				WithImages(false),
				WithArchiveImages(false),
			),
		},
		{
			name: "archive on with images off still requires registries",
			opts: append(requiredOpts(),
				WithVersion("v3.99.0"),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries(nil),
				WithImages(false),
			),
			wantErr:   "no image registries specified",
			expectErr: true,
		},
		{
			name: "hashrelease ocp-bundle requires manifests",
			opts: append(requiredOpts(),
				IsHashRelease(),
				WithVersion("v3.99.0"),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries([]string{"example.com/calico"}),
				WithManifests(false),
			),
			wantErr:   "cannot build OCP bundle without manifests",
			expectErr: true,
		},
		{
			name: "hashrelease manifests off + ocp-bundle off passes the cross-flag check",
			opts: append(requiredOpts(),
				IsHashRelease(),
				WithVersion("v3.99.0"),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries([]string{"example.com/calico"}),
				WithManifests(false),
				WithOCPBundle(false),
			),
			// PreHashreleaseValidate runs after canBuildValidation's gates
			// and may error on its own preconditions; we only assert that
			// the manifests/ocp-bundle gate above doesn't fire here.
		},
		{
			name: "non-hashrelease build with manifests off is allowed by canBuildValidation",
			opts: append(requiredOpts(),
				WithVersion("v3.99.0"),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries([]string{"example.com/calico"}),
				WithManifests(false),
			),
		},
	}
	// Substrings owned by canBuildValidation. Errors from downstream
	// validators (PreHashreleaseValidate / PreReleaseValidate) may surface
	// when no real repo is wired up; filter on the substrings we care about.
	guarded := []string{
		"no calico version specified",
		"no operator version specified",
		"no image registries specified",
		"cannot build OCP bundle without manifests",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewManager(tc.opts...)
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			err = m.canBuildValidation()
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
				return
			}
			// Not expecting a guarded-invariant failure. Allow downstream
			// validator errors to bubble up but fail if any guarded
			// substring shows up.
			if err == nil {
				return
			}
			for _, sub := range guarded {
				if strings.Contains(err.Error(), sub) {
					t.Fatalf("unexpected guarded-invariant error: %v", err)
				}
			}
		})
	}
}

func TestWithVersion(t *testing.T) {
	t.Run("rejects a non-semver version", func(t *testing.T) {
		if _, err := NewManager(append(requiredOpts(), WithVersion("release-v3.99"))...); err == nil {
			t.Error("want an error")
		}
	})
}

func TestWithDryRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
		want bool
	}{
		{name: "off by default"},
		{name: "on", opts: []Option{WithDryRun(true)}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewManager(append(requiredOpts(), tc.opts...)...)
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			if m.dryRun != tc.want {
				t.Errorf("dryRun = %v, want %v", m.dryRun, tc.want)
			}
		})
	}
}
