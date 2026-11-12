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

//go:build fv

package images

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/projectcalico/calico/release/internal/command"
)

func TestImagesFromMake(t *testing.T) {
	t.Run("lists the images each release dir builds", func(t *testing.T) {
		root, err := command.Git(command.RealRunner).RepoRoot()
		if err != nil {
			t.Fatalf("repo root: %v", err)
		}
		for _, tc := range []struct {
			name    string
			dirs    []string
			want    []string
			wantErr bool
		}{
			{name: "one dir", dirs: []string{"cmd/calico"}, want: []string{"calico"}},
			{name: "a dir with a windows image", dirs: []string{"node"}, want: []string{"node", "node-windows"}},
			{name: "a dir with no windows image", dirs: []string{"whisker"}, want: []string{"whisker"}},
			{name: "several dirs", dirs: []string{"whisker", "cmd/calico"}, want: []string{"whisker", "calico"}},
			{name: "a dir with no images", dirs: []string{"api"}, wantErr: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := BuildImages(command.RealRunner, root, tc.dirs...)
				if tc.wantErr {
					if err == nil {
						t.Fatalf("got %q, want an error", got)
					}
					return
				}
				if err != nil {
					t.Fatalf("BuildImages: %v", err)
				}
				if !slices.Equal(got, tc.want) {
					t.Errorf("got %q, want %q", got, tc.want)
				}
			})
		}

		t.Run("under a parent make", func(t *testing.T) {
			t.Setenv("MAKEFLAGS", "w")
			got, err := BuildImages(command.RealRunner, root, "whisker")
			if err != nil {
				t.Fatalf("BuildImages: %v", err)
			}
			if want := []string{"whisker"}; !slices.Equal(got, want) {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	})

	t.Run("reads names and the tag prefix", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "comp"), 0o755); err != nil {
			t.Fatal(err)
		}
		makefile := "build-images:\n\t@echo comp comp-windows\nimage-tag-prefix:\n\t@echo pre-\n"
		if err := os.WriteFile(filepath.Join(root, "comp", "Makefile"), []byte(makefile), 0o644); err != nil {
			t.Fatal(err)
		}
		c := Image{RepoRoot: root}

		for _, makeflags := range []string{"", "w"} {
			t.Run("with MAKEFLAGS="+makeflags, func(t *testing.T) {
				t.Setenv("MAKEFLAGS", makeflags)
				u := unit{variant: StandardVariant, dir: "comp", env: os.Environ()}

				names, err := c.imageNames(u)
				if err != nil {
					t.Fatalf("imageNames: %v", err)
				}
				if want := []string{"comp"}; !slices.Equal(names, want) {
					t.Errorf("image names = %q, want %q", names, want)
				}

				prefix, err := c.tagPrefix(u)
				if err != nil {
					t.Fatalf("tagPrefix: %v", err)
				}
				if prefix != "pre-" {
					t.Errorf("tag prefix = %q, want %q", prefix, "pre-")
				}
			})
		}
	})
}
