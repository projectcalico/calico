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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
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
	return root
}
