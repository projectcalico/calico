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

func TestValidateFlagAction(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string // substring match; empty means no error
	}{
		{"defaults pass", nil, ""},
		{"--no-validate alone errors (default validate-branch=true)", []string{"--no-validate"}, "--no-validate-branch must be set"},
		{"--no-validate --no-validate-branch but image-scan default true errors", []string{"--no-validate", "--no-validate-branch"}, "--no-image-scan must be set"},
		{"all three negated passes", []string{"--no-validate", "--no-validate-branch", "--no-image-scan"}, ""},
		{"--no-validate-branch alone passes (dependent disabled, prerequisite still on)", []string{"--no-validate-branch"}, ""},
		{"--no-image-scan alone passes", []string{"--no-image-scan"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runFlags(t, []cli.Flag{validateFlag, validateBranchFlag, imageScanFlag}, tc.args...)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
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
			err := runFlags(t, flags, tc.args...)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
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
				err := runFlags(t, flags, tc.args...)
				if tc.wantErr == "" {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
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
				err := runFlags(t, flags, tc.args...)
				if tc.wantErr == "" {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
			})
		}
	})
}

func TestInverseFlagName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"validate", "no-validate"},
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
