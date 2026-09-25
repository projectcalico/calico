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
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/utils"
)

const binariesCLITestVersion = "v3.30.0"

// The components a release builds, and the target each is built with. Spelled
// out rather than read from the package, so a change to either is visible here.
var binariesCLIComponents = map[string]string{
	"calicoctl": "build-all",
	"felix":     "release-build",
}

// Where a build collects the binaries it attaches individually, and which
// components it attaches.
var (
	binariesCLICollectDir = func(outputDir string) string { return outputDir }

	binariesCLICollected = map[string]bool{
		"calicoctl": true,
		"felix":     false,
	}
)

// The recording runner does not run make, so the collect needs something to
// pick up.
func stageBuiltBinaries(t *testing.T, root string) {
	t.Helper()
	for component := range binariesCLIComponents {
		dir := filepath.Join(root, component, "bin")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, component+"-amd64"), []byte(component), 0o755); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func runBinaries(t *testing.T, root string, args ...string) *recordingRunner {
	t.Helper()
	stageBuiltBinaries(t, root)
	r := &recordingRunner{}
	prev := commandRunner
	commandRunner = r
	t.Cleanup(func() { commandRunner = prev })

	cfg := &Config{
		RepoRootDir: root,
		TmpDir:      filepath.Join(root, "tmp"),
		OutputDir:   filepath.Join(root, "_output"),
		LogsDir:     filepath.Join(root, "_logs"),
	}
	cmd := binariesCommand(cfg)
	if err := cmd.Run(context.Background(), append([]string{"binaries"}, args...)); err != nil {
		t.Fatalf("binaries %s: %v", strings.Join(args, " "), err)
	}
	return r
}

func TestBinariesBuildRunsEveryComponent(t *testing.T) {
	root := fakeRepo(t, binariesCLITestVersion)
	r := runBinaries(t, root, "build")

	for component, target := range binariesCLIComponents {
		if !r.ranExactly(filepath.Join(root, component), target) {
			t.Errorf("did not build %s with %s, ran: %v", component, target, r.args)
		}
	}
}

func TestBinariesBuildTakesTheVersionFromTheManifests(t *testing.T) {
	root := fakeRepo(t, binariesCLITestVersion)
	r := runBinaries(t, root, "build")

	want := utils.Env(utils.EnvVersion, binariesCLITestVersion)
	for component := range binariesCLIComponents {
		env := r.envFor(filepath.Join(root, component))
		if !slices.Contains(env, want) {
			t.Errorf("%s built without %q, env: %v", component, want, env)
		}
	}
}

func TestBinariesBuildMatchesTheManagerComponents(t *testing.T) {
	root := fakeRepo(t, binariesCLITestVersion)
	r := runBinaries(t, root, "build")

	var built []string
	for _, args := range r.args {
		if len(args) > 1 && args[0] == "-C" {
			built = append(built, filepath.Base(args[1]))
		}
	}
	slices.Sort(built)
	if want := slices.Sorted(maps.Keys(binariesCLIComponents)); !slices.Equal(built, want) {
		t.Errorf("built %v, want %v", built, want)
	}
}

func TestBinariesCollectDirMatchesTheReleaseFlow(t *testing.T) {
	root := fakeRepo(t, binariesCLITestVersion)
	cfg := &Config{
		RepoRootDir: root,
		OutputDir:   filepath.Join(root, "_output"),
	}
	cmd := binariesBuildCommand(cfg)
	if err := cmd.Run(context.Background(), []string{"build", "--help"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	got, err := outputDir(cfg, cmd, binariesCLITestVersion)
	if err != nil {
		t.Fatalf("outputDir: %v", err)
	}
	if want := releaseOutputDir(root, binariesCLITestVersion); got != want {
		t.Errorf("collect dir is %q, want the release flow's %q", got, want)
	}
}

func TestBinariesBuildCollectsIntoTheRightDir(t *testing.T) {
	root := fakeRepo(t, binariesCLITestVersion)
	runBinaries(t, root, "build")

	dir := binariesCLICollectDir(releaseOutputDir(root, binariesCLITestVersion))
	for component, collected := range binariesCLICollected {
		name := component + "-amd64"
		_, err := os.Stat(filepath.Join(dir, name))
		if collected && err != nil {
			t.Errorf("%s was not collected into %s: %v", name, dir, err)
		}
		if !collected && err == nil {
			t.Errorf("%s was collected into %s, want it left out", name, dir)
		}
	}
}
