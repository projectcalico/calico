// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package utils

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/projectcalico/calico/release/internal/command"
)

func TestReleaseDirsImages(t *testing.T) {
	repoRoot, err := command.GitDir()
	if err != nil {
		t.Fatalf("failed to get repo root dir: %v", err)
	}
	for _, tc := range []struct {
		name           string
		repoRoot       string
		releaseDirs    []string
		wantErr        bool
		expectedImages []string
	}{
		{
			name:     "no release dirs",
			repoRoot: filepath.Join(repoRoot, "apiserver"),
			wantErr:  false,
			expectedImages: []string{
				"apiserver",
			},
		},
		{
			name: "single release dir",
			releaseDirs: []string{
				"apiserver",
			},
			expectedImages: []string{
				"apiserver",
			},
		},
		{
			name: "release dir with windows image",
			releaseDirs: []string{
				"cni-plugin",
			},
			expectedImages: []string{
				"cni",
				"cni-windows",
			},
		},
		{
			name: "release dir with no windows image",
			releaseDirs: []string{
				"apiserver",
			},
			expectedImages: []string{
				"apiserver",
			},
		},
		{
			name: "release dir with no output",
			releaseDirs: []string{
				"api",
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.repoRoot == "" {
				tc.repoRoot = repoRoot
			}
			images, err := BuildReleaseImageList(tc.repoRoot, tc.releaseDirs...)
			if err != nil && !tc.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && tc.wantErr {
				t.Fatal("expected error but got none")
			}
			if diff := cmp.Diff(tc.expectedImages, images, cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			})); diff != "" {
				t.Errorf("images mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
