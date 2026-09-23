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
	"sync"
	"testing"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/pinnedversion"
)

// recordingRunner runs nothing and records what it was asked to run. Units run
// concurrently, so recording is locked.
type recordingRunner struct {
	mu       sync.Mutex
	args     [][]string
	envs     [][]string
	logPaths []string
}

func (r *recordingRunner) record(args, env []string, logPath string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Stand in for helm: `repo index <dir>` writes the index into that dir.
	if len(args) > 2 && args[0] == "repo" && args[1] == "index" {
		_ = os.WriteFile(filepath.Join(args[2], "index.yaml"), []byte("entries:"), 0o644)
	}
	r.args = append(r.args, slices.Clone(args))
	r.envs = append(r.envs, slices.Clone(env))
	r.logPaths = append(r.logPaths, logPath)
	return "", nil
}

func (r *recordingRunner) Run(_ string, args, env []string) (string, error) {
	return r.record(args, env, "")
}

func (r *recordingRunner) RunNoCapture(_ string, args, env []string) error {
	_, err := r.record(args, env, "")
	return err
}

func (r *recordingRunner) RunInDir(_, _ string, args, env []string) (string, error) {
	if slices.Contains(args, "build-images") {
		// The publish asks each directory for its image names before recording.
		if _, err := r.record(args, env, ""); err != nil {
			return "", err
		}
		return "calico calico-windows", nil
	}
	return r.record(args, env, "")
}

func (r *recordingRunner) RunInDirNoCapture(_, _ string, args, env []string) error {
	_, err := r.record(args, env, "")
	return err
}

func (r *recordingRunner) RunInDirToFile(_, _ string, args, env []string, logPath string) (string, error) {
	return r.record(args, env, logPath)
}

// envFor returns the environment of the first recorded make call whose args
// contain every one of want.
func (r *recordingRunner) envFor(want ...string) []string {
	for i, args := range r.args {
		if containsAll(args, want) {
			return r.envs[i]
		}
	}
	return nil
}

// ran reports whether any recorded call's args contain every one of want.
func (r *recordingRunner) ran(want ...string) bool {
	return slices.ContainsFunc(r.args, func(args []string) bool {
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
