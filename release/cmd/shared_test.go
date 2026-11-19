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
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
)

// fakeRunner runs nothing and records what it was asked to run.
type fakeRunner struct {
	*command.Recorder
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{&command.Recorder{Reply: func(c command.Call) (string, error) {
		// Stand in for helm: `repo index <dir>` writes the index into that dir.
		if len(c.Args) > 2 && c.Args[0] == "repo" && c.Args[1] == "index" {
			_ = os.WriteFile(filepath.Join(c.Args[2], "index.yaml"), []byte("entries:"), 0o644)
		}
		if slices.Contains(c.Args, "build-images") {
			// The publish asks each directory for its image names.
			return "calico calico-windows", nil
		}
		return "", nil
	}}}
}

// dirAndArgs lets a match name the dir a command ran in as if it were an arg.
func (r *fakeRunner) dirAndArgs() [][]string {
	var out [][]string
	for _, c := range r.Calls() {
		out = append(out, append([]string{c.Dir}, c.Args...))
	}
	return out
}

func (r *fakeRunner) args() [][]string {
	var out [][]string
	for _, c := range r.Calls() {
		out = append(out, c.Args)
	}
	return out
}

func (r *fakeRunner) envs() [][]string {
	var out [][]string
	for _, c := range r.Calls() {
		out = append(out, c.Env)
	}
	return out
}

func (r *fakeRunner) logPaths() []string {
	var out []string
	for _, c := range r.Calls() {
		out = append(out, c.LogFile)
	}
	return out
}

// envFor returns the environment of the first recorded call whose dir or args
// contain every one of want.
func (r *fakeRunner) envFor(want ...string) []string {
	for _, c := range r.Calls() {
		if containsAll(append([]string{c.Dir}, c.Args...), want) {
			return c.Env
		}
	}
	return nil
}

// ranExactly is ran for callers that pass whole arguments: a target name is a
// prefix of a longer one, so a substring match cannot tell them apart.
func (r *fakeRunner) ranExactly(want ...string) bool {
	return slices.ContainsFunc(r.dirAndArgs(), func(args []string) bool {
		for _, w := range want {
			if !slices.Contains(args, w) {
				return false
			}
		}
		return true
	})
}

// ran reports whether any recorded call's dir or args contain every one of want.
func (r *fakeRunner) ran(want ...string) bool {
	return slices.ContainsFunc(r.dirAndArgs(), func(args []string) bool {
		return containsAll(args, want)
	})
}

// cli flags are package-level and remember whether they were set, so a test
// sharing them sees what an earlier one parsed.
func freshFlags(flags []cli.Flag) []cli.Flag {
	out := make([]cli.Flag, 0, len(flags))
	for _, f := range flags {
		switch v := f.(type) {
		case *cli.StringFlag:
			c := *v
			out = append(out, &c)
		case *cli.StringSliceFlag:
			c := *v
			out = append(out, &c)
		case *cli.BoolFlag:
			c := *v
			out = append(out, &c)
		default:
			out = append(out, f)
		}
	}
	return out
}

func containsAll(args, want []string) bool {
	for _, w := range want {
		if !slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, w) }) {
			return false
		}
	}
	return true
}

// fakeRepo writes the manifests a version is resolved from, so the step
// commands run without a checkout. It is a var because a product reads a
// different image name, and may read more than these two files.
var fakeRepo = func(t *testing.T, version string) string {
	t.Helper()
	root := t.TempDir()
	manifests := filepath.Join(root, "manifests", "ocp")
	if err := os.MkdirAll(manifests, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write := func(path, content string) {
		if err := os.WriteFile(filepath.Join(root, "manifests", path), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(filepath.Join("ocp", "02-tigera-operator.yaml"), "          image: quay.io/calico/calico:"+version+"\n")
	write("tigera-operator.yaml", "          image: quay.io/calico/operator:"+version+"\n")
	writeChartValues(t, root)
	return root
}

// The values a release rewrites before packaging. Each chart carries the keys
// its edits target, so a fixture missing one fails the way the real tree would.
var fakeChartValues = map[string]string{
	"tigera-operator": `tigeraOperator:
  image: calico/operator
  version: master
  registry: quay.io
calicoctl:
  image: quay.io/calico/calico
  tag: master
`,
	"calico": `version: master
calico:
  registry: quay.io/calico
cniPlugins:
  registry: quay.io/calico
node:
  registry: quay.io/calico
flannelMigration:
  registry: quay.io/calico
`,
}

func writeChartValues(t *testing.T, root string) {
	t.Helper()
	for chart, values := range fakeChartValues {
		dir := filepath.Join(root, "charts", chart)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(values), 0o644); err != nil {
			t.Fatalf("write values: %v", err)
		}
	}
}

func TestHashreleaseBuilds(t *testing.T) {
	// A hashrelease build may generate its pin, which needs the branch prefix.
	t.Run("can generate the pin", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			flags []cli.Flag
		}{
			{name: "operator", flags: operatorBuildFlags},
			{name: "manifests", flags: manifestsBuildFlags},
			{name: "charts", flags: chartsBuildFlags},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var got pinnedversion.Config
				cmd := &cli.Command{
					Flags: freshFlags(tc.flags),
					Action: func(_ context.Context, c *cli.Command) error {
						got = pinConfig(&Config{RepoRootDir: "/repo"}, c)
						return nil
					},
				}
				if err := cmd.Run(context.Background(), []string{"build", "--hashrelease"}); err != nil {
					t.Fatalf("run: %v", err)
				}
				if got.ReleaseBranchPrefix != releaseBranchPrefixFlag.Value {
					t.Errorf("ReleaseBranchPrefix = %q, want %q", got.ReleaseBranchPrefix, releaseBranchPrefixFlag.Value)
				}
			})
		}
	})
}

func TestConfigReleaseImages(t *testing.T) {
	t.Run("sweeps once however often it is asked", func(t *testing.T) {
		r := newFakeRunner()
		prev := commandRunner
		commandRunner = r
		t.Cleanup(func() { commandRunner = prev })

		cfg := &Config{RepoRootDir: "/repo"}
		first, err := cfg.ReleaseImages()
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		sweep := len(r.Calls())
		second, err := cfg.ReleaseImages()
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if diff := cmp.Diff(first, second); diff != "" {
			t.Errorf("lists differ (-first +second):\n%s", diff)
		}
		if got := len(r.Calls()); got != sweep {
			t.Errorf("second call ran %d more commands, want 0", got-sweep)
		}
	})
}

func TestRecordsDir(t *testing.T) {
	cfg := &Config{OutputDir: t.TempDir()}
	parse := func(t *testing.T, args ...string) *cli.Command {
		t.Helper()
		c := &cli.Command{
			Name:   "publish",
			Flags:  []cli.Flag{hashreleaseFlag},
			Action: func(context.Context, *cli.Command) error { return nil },
		}
		if err := c.Run(context.Background(), append([]string{"publish"}, args...)); err != nil {
			t.Fatalf("parse flags: %v", err)
		}
		return c
	}
	pinWithHash := func(hash string) pinned {
		return func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
			return &pinnedversion.Pin{Hash: hash, Operator: registry.Component{Version: "v1.38.0"}}, nil
		}
	}
	noPin := func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
		t.Fatal("a release must not need a pin")
		return nil, nil
	}

	t.Run("a release records where the manager does", func(t *testing.T) {
		got, err := recordsDir(cfg, parse(t), noPin, "v3.30.0")
		if err != nil {
			t.Fatalf("recordsDir: %v", err)
		}
		if want := outputs.RecordsDir(cfg.OutputDir, "v3.30.0"); got != want {
			t.Errorf("records dir = %q, want %q", got, want)
		}
	})

	t.Run("a hashrelease records where the manager does", func(t *testing.T) {
		got, err := recordsDir(cfg, parse(t, "--hashrelease"), pinWithHash("abc"), "v1.38.0")
		if err != nil {
			t.Fatalf("recordsDir: %v", err)
		}
		if want := outputs.RecordsDir(cfg.OutputDir, "abc"); got != want {
			t.Errorf("records dir = %q, want %q", got, want)
		}
	})

	t.Run("hashreleases with the same operator version keep records apart", func(t *testing.T) {
		c := parse(t, "--hashrelease")
		a, err := recordsDir(cfg, c, pinWithHash("abc"), "v1.38.0")
		if err != nil {
			t.Fatalf("recordsDir: %v", err)
		}
		b, err := recordsDir(cfg, c, pinWithHash("def"), "v1.38.0")
		if err != nil {
			t.Fatalf("recordsDir: %v", err)
		}
		if a == b {
			t.Errorf("both hashreleases record into %q", a)
		}
	})
}

func TestPinForRelease(t *testing.T) {
	root := fakeRepo(t, "v3.30.0")
	operatorManifest := filepath.Join(root, "manifests", "tigera-operator.yaml")
	if err := os.WriteFile(operatorManifest, []byte("          image: quay.io/calico/operator:v1.38.0\n"), 0o644); err != nil {
		t.Fatalf("write operator manifest: %v", err)
	}
	prev := loadPin
	t.Cleanup(func() { loadPin = prev })

	t.Run("takes the operator version from the manifests", func(t *testing.T) {
		loadPin = func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
			return &pinnedversion.Pin{
				ProductVersion: "v3.30.0",
				Operator:       registry.Component{Image: registry.OperatorImage, Version: "v3.30.0"},
			}, nil
		}
		pin, err := pinForRelease(&Config{RepoRootDir: root}, nil)
		if err != nil {
			t.Fatalf("pinForRelease: %v", err)
		}
		if pin.Operator.Version != "v1.38.0" {
			t.Errorf("operator version = %q, want the manifests' v1.38.0", pin.Operator.Version)
		}
	})

	t.Run("fails when the manifests name no operator", func(t *testing.T) {
		loadPin = func(*Config, *cli.Command) (*pinnedversion.Pin, error) { return &pinnedversion.Pin{}, nil }
		if _, err := pinForRelease(&Config{RepoRootDir: t.TempDir()}, nil); err == nil {
			t.Error("pinForRelease succeeded without manifests")
		}
	})
}
