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
	"strings"
	"testing"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
)

func TestPinnedOperator(t *testing.T) {
	pinned := registry.Component{
		Registry: "quay.io/pinned",
		Image:    "operator",
		Version:  "v1.44.0",
	}
	for _, tc := range []struct {
		name         string
		args         []string
		wantRegistry string
		wantImage    string
	}{
		{name: "unset flags leave the pin", args: []string{"publish"}, wantRegistry: "quay.io/pinned", wantImage: "operator"},
		{
			name:         "registry flag overrides the pin",
			args:         []string{"publish", "--operator-registry", "gcr.io/flagged"},
			wantRegistry: "gcr.io/flagged",
			wantImage:    "operator",
		},
		{
			name:         "image flag overrides the pin",
			args:         []string{"publish", "--operator-image", "flagged"},
			wantRegistry: "quay.io/pinned",
			wantImage:    "flagged",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{RepoRootDir: "/repo"}
			var got operator.Operator
			cmd := &cli.Command{
				Flags: freshFlags(operatorPublishFlags),
				Action: func(_ context.Context, c *cli.Command) error {
					got = pinnedOperator(cfg, c, pinned, "v3.34.0")
					return nil
				},
			}
			if err := cmd.Run(context.Background(), tc.args); err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := operator.Registry(got); got != tc.wantRegistry {
				t.Errorf("Registry() = %q, want %q", got, tc.wantRegistry)
			}
			if got.Image != tc.wantImage {
				t.Errorf("Image = %q, want %q", got.Image, tc.wantImage)
			}
			if got.Version != pinned.Version {
				t.Errorf("Version = %q, want %q", got.Version, pinned.Version)
			}
			if got.ProductVersion != "v3.34.0" {
				t.Errorf("ProductVersion = %q, want v3.34.0", got.ProductVersion)
			}
			if got := operator.Dir(got); got != "/repo/operator" {
				t.Errorf("Dir() = %q, want /repo/operator", got)
			}
		})
	}
}

func TestOperatorCommand(t *testing.T) {
	t.Run("custom product registry", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			args    []string
			wantErr bool
		}{
			{name: "neither set", args: []string{"build"}},
			{
				name:    "product registry alone",
				args:    []string{"build", "--registry", "gcr.io/mine"},
				wantErr: true,
			},
			{
				name: "both set",
				args: []string{"build", "--registry", "gcr.io/mine", "--operator-registry", "gcr.io/mine"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var got error
				cmd := &cli.Command{
					Flags: freshFlags([]cli.Flag{registryFlag, operatorRegistryFlag, ocpBundleFlag, manifestsFlag}),
					Action: func(_ context.Context, c *cli.Command) error {
						got = validateHashreleaseBuildFlags(c)
						return nil
					},
				}
				if err := cmd.Run(context.Background(), tc.args); err != nil {
					t.Fatalf("run: %v", err)
				}
				if tc.wantErr && got == nil {
					t.Fatal("expected an error, got nil")
				}
				if !tc.wantErr && got != nil {
					t.Fatalf("unexpected error: %v", got)
				}
			})
		}
	})

	// The publish commands build the operator from flags rather than a pin, so
	// one that does not register them publishes an unnamed image to nowhere.
	t.Run("publish flags", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			flags []cli.Flag
		}{
			{name: "release", flags: releasePublishFlags()},
			{name: "hashrelease", flags: hashreleasePublishFlags()},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg := &Config{RepoRootDir: fakeRepo(t, "v3.34.0")}
				var got *operator.Operator
				cmd := &cli.Command{
					Flags: freshFlags(tc.flags),
					Action: func(_ context.Context, c *cli.Command) error {
						var err error
						got, err = releaseOperator(cfg, c)
						return err
					},
				}
				if err := cmd.Run(context.Background(), []string{"publish"}); err != nil {
					t.Fatalf("run: %v", err)
				}
				if got.Image != registry.OperatorImage {
					t.Errorf("Image = %q, want %q", got.Image, registry.OperatorImage)
				}
				if reg := operator.Registry(*got); reg != registry.DefaultOperatorRegistry {
					t.Errorf("Registry() = %q, want %q", reg, registry.DefaultOperatorRegistry)
				}
			})
		}
	})

	t.Run("hashrelease", func(t *testing.T) {
		cfg := &Config{RepoRootDir: "/repo"}
		pin := func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
			return &pinnedversion.Pin{
				ProductVersion: "v3.34.0-pinned",
				Operator: registry.Component{
					Registry: "quay.io/pinned",
					Image:    "operator",
					Version:  "v1.44.0-pinned",
				},
			}, nil
		}
		var got *operator.Operator
		cmd := &cli.Command{
			Flags: freshFlags(operatorBuildFlags),
			Action: func(_ context.Context, c *cli.Command) error {
				var err error
				got, err = operatorFor(cfg, c, pin)
				return err
			},
		}
		if err := cmd.Run(context.Background(), []string{"build", "--hashrelease"}); err != nil {
			t.Fatalf("run: %v", err)
		}
		for _, tc := range []struct {
			field string
			got   string
			want  string
		}{
			{field: "Version", got: got.Version, want: "v1.44.0-pinned"},
			{field: "ProductVersion", got: got.ProductVersion, want: "v3.34.0-pinned"},
			{field: "Registry()", got: operator.Registry(*got), want: "quay.io/pinned"},
		} {
			if tc.got != tc.want {
				t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
			}
		}
	})
}

func TestOperatorLogsUnderTheProductVersion(t *testing.T) {
	t.Chdir(t.TempDir())
	r := &recordingRunner{}
	prevRunner, prevPin := commandRunner, pinForBuild
	commandRunner = r
	pinForBuild = func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
		return &pinnedversion.Pin{
			ProductVersion: "v3.34.0",
			Operator:       registry.Component{Registry: "quay.io/pinned", Image: "operator", Version: "v1.44.0"},
		}, nil
	}
	t.Cleanup(func() { commandRunner, pinForBuild = prevRunner, prevPin })

	cfg := &Config{RepoRootDir: t.TempDir(), LogsDir: "/logs"}
	cmd := &cli.Command{Flags: freshFlags(operatorBuildFlags), Action: operatorBuildAction(cfg)}
	if err := cmd.Run(context.Background(), []string{"build", "--hashrelease", "--no-validation"}); err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(r.logPaths) == 0 {
		t.Fatal("nothing ran")
	}
	for _, p := range r.logPaths {
		if !strings.HasPrefix(p, "/logs/v3.34.0/") {
			t.Errorf("log %q is not under /logs/v3.34.0", p)
		}
	}
}
