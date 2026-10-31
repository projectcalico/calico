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

package main

import (
	"context"
	"testing"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/pinnedversion"
)

func TestPinnedManifests(t *testing.T) {
	t.Run("a release builds into the release output dir", func(t *testing.T) {
		const ver = "v3.30.0"
		cfg := &Config{RepoRootDir: fakeRepo(t, ver), OutputDir: t.TempDir()}
		c := &cli.Command{
			Name:   "build",
			Flags:  manifestsBuildFlags,
			Action: func(context.Context, *cli.Command) error { return nil },
		}
		if err := c.Run(context.Background(), []string{"build"}); err != nil {
			t.Fatalf("parse flags: %v", err)
		}
		noPin := func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
			t.Fatal("a release must not need a pin")
			return nil, nil
		}

		m, err := pinnedManifests(cfg, c, noPin)
		if err != nil {
			t.Fatalf("pinnedManifests: %v", err)
		}
		if want := releaseOutputDir(cfg.RepoRootDir, ver); m.OutputDir != want {
			t.Errorf("output dir = %q, want %q", m.OutputDir, want)
		}
	})
}
