// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package main

import (
	"context"
	"strings"
	"testing"

	cli "github.com/urfave/cli/v3"
)

// runFlags builds a *cli.Command with the given flags and runs it with args.
// The Action is a no-op so any error returned comes from a flag-level Action
// (cross-flag invariants enforced via flag.Action callbacks).
func runFlags(t *testing.T, flags []cli.Flag, args ...string) error {
	t.Helper()
	cmd := &cli.Command{
		Name:  "test",
		Flags: flags,
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}
	return cmd.Run(context.Background(), append([]string{"test"}, args...))
}

// assertRun runs cmd with args and checks the resulting error against wantErr.
// Empty wantErr means "expect no error". Non-empty wantErr is a substring match.
func assertRun(t *testing.T, flags []cli.Flag, args []string, wantErr string) {
	t.Helper()
	err := runFlags(t, flags, args...)
	if wantErr == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", wantErr)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("expected error containing %q, got %q", wantErr, err.Error())
	}
}

func TestValidationFlagAction(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"defaults pass", nil, ""},
		{"--no-validation alone errors (default branch-check=true)", []string{"--no-validation"}, "--no-branch-check must be set"},
		{"--no-validation --no-branch-check but image-scan default true errors", []string{"--no-validation", "--no-branch-check"}, "--no-image-scan must be set"},
		{"all three negated passes", []string{"--no-validation", "--no-branch-check", "--no-image-scan"}, ""},
		{"--no-branch-check alone passes (dependent disabled, prerequisite still on)", []string{"--no-branch-check"}, ""},
		{"--no-image-scan alone passes", []string{"--no-image-scan"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRun(t, []cli.Flag{validationFlag, branchCheckFlag, imageScanFlag}, tc.args, tc.wantErr)
		})
	}
}

// TestValidationFlagActionWithoutImageScan covers the build-side case where
// imageScanFlag isn't registered. validationFlag.Action must skip the
// image-scan dependency check rather than misfire.
func TestValidationFlagActionWithoutImageScan(t *testing.T) {
	flags := []cli.Flag{validationFlag, branchCheckFlag}
	assertRun(t, flags, []string{"--no-validation", "--no-branch-check"}, "")
}

func TestHelmChartsFlagAction(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"defaults pass", nil, ""},
		{"--no-helm-charts alone errors (default helm-index=true)", []string{"--no-helm-charts"}, "--no-helm-index must be set"},
		{"--no-helm-charts --no-helm-index passes", []string{"--no-helm-charts", "--no-helm-index"}, ""},
		{"--no-helm-index alone passes (dependent disabled)", []string{"--no-helm-index"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags := []cli.Flag{
				helmChartsFlag(true, "TEST_BUILD_CHARTS"),
				helmIndexFlag("TEST_BUILD_HELM_INDEX"),
			}
			assertRun(t, flags, tc.args, tc.wantErr)
		})
	}
}

func TestImagesArchiveImagesFlagAction(t *testing.T) {
	// Default-true (release-style) defaults: images=true, archive=true.
	t.Run("release defaults", func(t *testing.T) {
		cases := []struct {
			name    string
			args    []string
			wantErr string
		}{
			{"defaults pass", nil, ""},
			{"--no-images alone errors (default archive=true)", []string{"--no-images"}, "cannot archive images without building them"},
			{"--no-images --no-archive-images passes", []string{"--no-images", "--no-archive-images"}, ""},
			{"--no-archive-images alone passes (warning only)", []string{"--no-archive-images"}, ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				flags := []cli.Flag{
					imagesFlag(true, "TEST_BUILD_IMAGES_R"),
					archiveImagesFlag(true, "TEST_BUILD_ARCHIVE_IMAGES_R"),
				}
				assertRun(t, flags, tc.args, tc.wantErr)
			})
		}
	})

	// Default-false (hashrelease-style) defaults: images=false, archive=false.
	t.Run("hashrelease defaults", func(t *testing.T) {
		cases := []struct {
			name    string
			args    []string
			wantErr string
		}{
			{"defaults pass", nil, ""},
			{"--archive-images alone errors (default images=false)", []string{"--archive-images"}, "cannot archive images without building them"},
			{"--images --archive-images passes", []string{"--images", "--archive-images"}, ""},
			{"--images alone passes (warning only)", []string{"--images"}, ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				flags := []cli.Flag{
					imagesFlag(false, "TEST_BUILD_IMAGES_H"),
					archiveImagesFlag(false, "TEST_BUILD_ARCHIVE_IMAGES_H"),
				}
				assertRun(t, flags, tc.args, tc.wantErr)
			})
		}
	})

	// On publish commands archive-images is not registered. images.Action
	// must skip the archive dependency check rather than misfire.
	t.Run("publish (no archive-images registered)", func(t *testing.T) {
		flags := []cli.Flag{imagesFlag(true, "TEST_PUBLISH_IMAGES")}
		assertRun(t, flags, []string{"--no-images"}, "")
		assertRun(t, flags, nil, "")
	})
}

func TestManifestsOCPBundleFlagAction(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"defaults pass", nil, ""},
		{"--no-manifests alone errors (default ocp-bundle=true)", []string{"--no-manifests"}, "--no-ocp-bundle must be set"},
		{"--no-manifests --no-ocp-bundle passes", []string{"--no-manifests", "--no-ocp-bundle"}, ""},
		{"--no-ocp-bundle alone passes (dependent disabled)", []string{"--no-ocp-bundle"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRun(t, []cli.Flag{manifestsFlag, ocpBundleFlag}, tc.args, tc.wantErr)
		})
	}
}

// TestEnvVarPrecedence pins down the legacy-alias-wins behaviour. The first
// env var listed in cli.EnvVars(...) takes precedence; legacy aliases like
// ARCHIVE_IMAGES, UPDATE_HELM_INDEX, and PUBLISH_GIT_TAG must be listed first
// in their respective Sources slices so existing CI configs keep winning over
// the new BUILD_*/PUBLISH_*/RELEASE_* names.
func TestEnvVarPrecedence(t *testing.T) {
	cases := []struct {
		name        string
		legacyKey   string
		legacyValue string
		newKey      string
		newValue    string
		flagFn      func() cli.Flag
		flagName    string
		want        bool
	}{
		{
			name:        "ARCHIVE_IMAGES wins over BUILD_IMAGES_ARCHIVE",
			legacyKey:   "ARCHIVE_IMAGES",
			legacyValue: "false",
			newKey:      "BUILD_IMAGES_ARCHIVE",
			newValue:    "true",
			flagFn: func() cli.Flag {
				return archiveImagesFlag(true, "ARCHIVE_IMAGES", "BUILD_IMAGES_ARCHIVE")
			},
			flagName: archiveImagesFlagName,
			want:     false,
		},
		{
			name:        "UPDATE_HELM_INDEX wins over BUILD_HELM_INDEX",
			legacyKey:   "UPDATE_HELM_INDEX",
			legacyValue: "false",
			newKey:      "BUILD_HELM_INDEX",
			newValue:    "true",
			flagFn: func() cli.Flag {
				return helmIndexFlag("UPDATE_HELM_INDEX", "BUILD_HELM_INDEX")
			},
			flagName: helmIndexFlagName,
			want:     false,
		},
		{
			name:        "PUBLISH_GIT_TAG wins over PUBLISH_GIT_REF",
			legacyKey:   "PUBLISH_GIT_TAG",
			legacyValue: "false",
			newKey:      "PUBLISH_GIT_REF",
			newValue:    "true",
			flagFn: func() cli.Flag {
				return &cli.BoolWithInverseFlag{
					Name:    "git-ref",
					Sources: cli.EnvVars("PUBLISH_GIT_TAG", "PUBLISH_GIT_REF"),
					Value:   true,
				}
			},
			flagName: "git-ref",
			want:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.legacyKey, tc.legacyValue)
			t.Setenv(tc.newKey, tc.newValue)
			var got bool
			cmd := &cli.Command{
				Name:  "test",
				Flags: []cli.Flag{tc.flagFn()},
				Action: func(_ context.Context, c *cli.Command) error {
					got = c.Bool(tc.flagName)
					return nil
				},
			}
			if err := cmd.Run(context.Background(), []string{"test"}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("env precedence broken: %s=%s vs %s=%s, got %v want %v", tc.legacyKey, tc.legacyValue, tc.newKey, tc.newValue, got, tc.want)
			}
		})
	}
}

func TestInverseFlagName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"validation", "no-validation"},
		{"helm-index", "no-helm-index"},
		{"", "no-"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := inverseFlagName(tc.in)
			if got != tc.want {
				t.Errorf("inverseFlagName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
