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

// TestNewManagerStepDefaults pins down the all-step-flags-default-to-true
// contract. CLI gating relies on these defaults being on at the manager
// layer; flipping a default silently breaks every release without a flag set.
func TestNewManagerStepDefaults(t *testing.T) {
	m := NewManager(requiredOpts()...)
	cases := []struct {
		name string
		got  bool
	}{
		{"validate", m.validate},
		{"validateBranch", m.validateBranch},
		{"images", m.images},
		{"archiveImages", m.archiveImages},
		{"manifests", m.manifests},
		{"binaries", m.binaries},
		{"ocpBundle", m.ocpBundle},
		{"tarball", m.tarball},
		{"windowsArchive", m.windowsArchive},
		{"helmCharts", m.helmCharts},
		{"helmIndex", m.helmIndex},
		{"e2eBinaries", m.e2eBinaries},
		{"gitRef", m.gitRef},
		{"githubRelease", m.githubRelease},
	}
	for _, tc := range cases {
		if !tc.got {
			t.Errorf("default %s: got false, want true", tc.name)
		}
	}
}

// TestPreBuildValidation covers the cross-flag invariants enforced at the
// manager layer. The test exercises the two non-trivial cases this PR
// introduces: image-registries required when images/archive-images are on,
// and ocp-bundle requires manifests on the hashrelease path.
func TestPreBuildValidation(t *testing.T) {
	cases := []struct {
		name      string
		opts      []Option
		wantErr   string // substring match; empty means "the asserted invariants do not fire"
		expectErr bool   // true if PreBuildValidation must return non-nil
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
			// PreHashreleaseValidate runs after PreBuildValidation's gates
			// and may error on its own preconditions; we only assert that
			// the manifests/ocp-bundle gate above doesn't fire here.
		},
		{
			name: "non-hashrelease build with manifests off is allowed by PreBuildValidation",
			opts: append(requiredOpts(),
				WithVersion("v3.99.0"),
				WithOperatorVersion("v9.99.0"),
				WithImageRegistries([]string{"example.com/calico"}),
				WithManifests(false),
			),
		},
	}
	// Substrings owned by PreBuildValidation. Errors from downstream
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
			m := NewManager(tc.opts...)
			err := m.PreBuildValidation()
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
