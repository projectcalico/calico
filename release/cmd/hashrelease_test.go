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
	"os"
	"path/filepath"
	"reflect"
	"testing"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/pinnedversion"
)

const builtPinFile = `- title: v3.31.0
  release_name: written-by-the-build
  full_hash: v3.31.0
  tigera-operator:
    version: v3.31.0
  components:
    node:
      version: v3.31.0
`

// Publish uploads under the name in the pin, so it must return the built pin
// rather than generate a new one, whatever the working tree looks like.
func TestBuiltPinDoesNotRegenerate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(pinnedversion.FilePath(dir), []byte(builtPinFile), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	got, err := builtPin(&Config{TmpDir: dir}, nil)
	if err != nil {
		t.Fatalf("builtPin: %v", err)
	}
	if got.ReleaseName != "written-by-the-build" {
		t.Errorf("would publish as %q, want the built pin", got.ReleaseName)
	}
	if got.Hash != "v3.31.0" {
		t.Errorf("would publish hash %q, want the built hash", got.Hash)
	}
}

// With no pin on disk there is nothing to publish, and the error has to say so
// rather than silently building a new one.
func TestBuiltPinRequiresAPin(t *testing.T) {
	if _, err := builtPin(&Config{TmpDir: t.TempDir()}, nil); err == nil {
		t.Error("want an error when the build wrote no pin, got none")
	}
}

func TestBuiltPinInAPlan(t *testing.T) {
	prev := loadPin
	loadPin = func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
		return &pinnedversion.Pin{ReleaseName: "a-build-would-write"}, nil
	}
	t.Cleanup(func() { loadPin = prev })

	for _, tc := range []struct {
		name    string
		built   bool
		plan    bool
		want    string
		wantErr bool
	}{
		{name: "a plan with no built pin uses the pin a build would write", plan: true, want: "a-build-would-write"},
		{name: "a plan still uses a built pin", built: true, plan: true, want: "written-by-the-build"},
		{name: "a real run with no built pin fails", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.built {
				if err := os.WriteFile(pinnedversion.FilePath(dir), []byte(builtPinFile), 0o644); err != nil {
					t.Fatalf("setup: %v", err)
				}
			}
			var got *pinnedversion.Pin
			var err error
			cmd := &cli.Command{
				Flags: []cli.Flag{&cli.BoolFlag{Name: planFlag.Name}},
				Action: func(_ context.Context, c *cli.Command) error {
					got, err = builtPin(&Config{TmpDir: dir}, c)
					return nil
				},
			}
			args := []string{"publish"}
			if tc.plan {
				args = append(args, "--plan")
			}
			if runErr := cmd.Run(context.Background(), args); runErr != nil {
				t.Fatalf("run: %v", runErr)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("builtPin() error = %v, want error %v", err, tc.wantErr)
			}
			if err == nil && got.ReleaseName != tc.want {
				t.Errorf("builtPin() = %q, want %q", got.ReleaseName, tc.want)
			}
		})
	}
}

// Publish must be wired to the loader that reads the built pin. Wiring it to
// the generating loader would upload under a name the artifacts do not match,
// which testing builtPin alone does not catch.
func TestPublishIsWiredToTheBuiltPin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(pinnedversion.FilePath(dir), []byte(builtPinFile), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	got, err := pinForPublish(&Config{TmpDir: dir}, nil)
	if err != nil {
		t.Fatalf("pinForPublish: %v", err)
	}
	if got.ReleaseName != "written-by-the-build" {
		t.Errorf("publish would upload as %q, not the built pin", got.ReleaseName)
	}
}

func TestBaseHashreleaseOutputDir(t *testing.T) {
	got := baseHashreleaseOutputDir("/repo")
	if want := filepath.Join("/repo", "release", "_output", "hashrelease"); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

func TestPinLoader(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want pinnedversion.Loader
	}{
		{name: "a build writes the pin", args: []string{"build"}, want: pinnedversion.LocalLoader{}},
		{name: "a plan leaves the pin on disk alone", args: []string{"build", "--plan"}, want: pinnedversion.PreviewLoader{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got pinnedversion.Loader
			cmd := &cli.Command{
				Flags: freshFlags(hashreleaseBuildFlags()),
				Action: func(_ context.Context, c *cli.Command) error {
					got = pinLoader(pinnedversion.Config{}, c)
					return nil
				},
			}
			if err := cmd.Run(context.Background(), tc.args); err != nil {
				t.Fatalf("run: %v", err)
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tc.want) {
				t.Errorf("loader is a %T, want a %T", got, tc.want)
			}
		})
	}
}

func TestBuildingCharts(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "on by default", want: true},
		{name: "off by flag", args: []string{"--no-helm-charts"}},
		{name: "off when its step is skipped", args: []string{"--skip", "charts"}},
		{name: "on when another step is skipped", args: []string{"--skip", "images"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got bool
			cmd := &cli.Command{
				Flags: []cli.Flag{
					&cli.BoolWithInverseFlag{Name: helmChartsFlagName, Value: true},
					&cli.StringSliceFlag{Name: skipFlagName},
				},
				Action: func(_ context.Context, c *cli.Command) error {
					got = buildingCharts(c)
					return nil
				},
			}
			if err := cmd.Run(context.Background(), append([]string{"build"}, tc.args...)); err != nil {
				t.Fatalf("run: %v", err)
			}
			if got != tc.want {
				t.Errorf("buildingCharts = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPublishingHashrelease(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "on by default", want: true},
		{name: "off by flag", args: []string{"--no-publish-to-hashrelease-server"}},
		{name: "off when its step is skipped", args: []string{"--skip", "hashrelease"}},
		{name: "on when another step is skipped", args: []string{"--skip", "images"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got bool
			cmd := &cli.Command{
				Flags: []cli.Flag{
					&cli.BoolWithInverseFlag{Name: publishHashreleaseFlag.Name, Value: true},
					&cli.StringSliceFlag{Name: skipFlagName},
				},
				Action: func(_ context.Context, c *cli.Command) error {
					got = publishingHashrelease(c)
					return nil
				},
			}
			if err := cmd.Run(context.Background(), append([]string{"publish"}, tc.args...)); err != nil {
				t.Fatalf("run: %v", err)
			}
			if got != tc.want {
				t.Errorf("publishingHashrelease = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateHashreleasePublishFlags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "latest from CI", args: []string{"--ci"}},
		{name: "latest locally", wantErr: true},
		{name: "latest locally in a local run", args: []string{"--local"}},
		{name: "latest locally in a plan", args: []string{"--plan"}},
		{name: "not latest locally", args: []string{"--latest=false"}},
		{name: "latest with a custom registry in a local run", args: []string{"--local", "--registry", "example.com/calico"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cli.Command{
				Flags: []cli.Flag{
					&cli.BoolWithInverseFlag{Name: publishHashreleaseFlag.Name, Value: true},
					&cli.StringSliceFlag{Name: skipFlagName},
					&cli.StringFlag{Name: hashreleaseServerBucketFlag.Name, Value: "bucket"},
					&cli.BoolFlag{Name: latestFlag.Name, Value: true},
					&cli.StringSliceFlag{Name: registryFlag.Name},
					&cli.BoolFlag{Name: ciFlag.Name},
					&cli.BoolFlag{Name: localFlag.Name},
					&cli.BoolFlag{Name: planFlag.Name},
				},
				Action: func(_ context.Context, c *cli.Command) error {
					return validateHashreleasePublishFlags(c)
				},
			}
			err := cmd.Run(context.Background(), append([]string{"publish"}, tc.args...))
			if (err != nil) != tc.wantErr {
				t.Errorf("validateHashreleasePublishFlags() = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
