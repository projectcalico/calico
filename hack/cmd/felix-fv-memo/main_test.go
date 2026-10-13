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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestReadLanes(t *testing.T) {
	lanes, err := readLanes(filepath.Join(repoRoot(t), ".argoci/modules/20-felix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	classes := map[class]int{}
	for _, l := range lanes {
		classes[l.class]++
	}
	if classes[classBPF] == 0 || classes[classNonBPF] == 0 {
		t.Errorf("want lanes of both classes, got %v", lanes)
	}
}

func TestReadLanesRejectsDuplicateGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "module.yaml")
	module := `
steps:
  - name: felix-fv
    matrix:
      - name: a
        env: [{name: FELIX_TEST_GROUP, value: 22.04-ipt}]
      - name: b
        env: [{name: FELIX_TEST_GROUP, value: 22.04-ipt}]
`
	if err := os.WriteFile(path, []byte(module), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readLanes(path); err == nil {
		t.Error("want an error for two lanes sharing a FELIX_TEST_GROUP")
	}
}

func TestClassOf(t *testing.T) {
	for group, want := range map[string]class{
		"22.04-ipt":                       classNonBPF,
		"22.04-nft":                       classNonBPF,
		"bpf-24.04-ipt-with-ut":           classBPF,
		"bpf-26.04-nft-with-ut-jitharden": classBPF,
	} {
		if got := classOf(group); got != want {
			t.Errorf("classOf(%q) = %s, want %s", group, got, want)
		}
	}
}

func TestHashOfSeparatesParts(t *testing.T) {
	if hashOf("ab", "c") == hashOf("a", "bc") {
		t.Error("hashOf must not collide when part boundaries move")
	}
}

// TestManifestInputs pins which repo files each class of lane is keyed on.
func TestManifestInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list over the FV binaries")
	}
	for _, tc := range []struct {
		class   class
		pattern string
		want    bool
	}{
		// A unit-test change cannot break an FV.
		{classNonBPF, `^felix/calc/[^/]*_test\.go$`, false},
		{classBPF, `^felix/calc/[^/]*_test\.go$`, false},
		{classNonBPF, `^felix/calc/[^/]*\.go$`, true},
		{classNonBPF, `^felix/fv/[^/]*_test\.go$`, true},
		// Only the BPF dataplane loads the bpf-gpl programs.
		{classNonBPF, `^felix/bpf-gpl/`, false},
		{classBPF, `^felix/bpf-gpl/`, true},
		{classNonBPF, `^felix/bpf-apache/`, true},
		{classBPF, `^felix/bpf/ut/`, true},
		{classNonBPF, `^felix/bpf/ut/`, false},
		// cmd/calico links every component, but FV only runs felix and typha.
		{classNonBPF, `^kube-controllers/`, false},
		{classNonBPF, `^typha/pkg/`, true},
		{classNonBPF, `^node/pkg/node/command\.go$`, true},
		{classNonBPF, `^api/config/crd/`, true},
	} {
		files := manifestFiles(t, tc.class)
		re := regexp.MustCompile(tc.pattern)
		got := false
		for _, f := range files {
			if re.MatchString(f) {
				got = true
				break
			}
		}
		if got != tc.want {
			t.Errorf("%s inputs match %s: got %v, want %v", tc.class, tc.pattern, got, tc.want)
		}
	}
}

var (
	manifestsOnce sync.Once
	manifests     map[class][]string
	manifestsErr  error
)

func manifestFiles(t *testing.T, c class) []string {
	t.Helper()
	root := repoRoot(t)
	manifestsOnce.Do(func() {
		manifests = map[class][]string{}
		for c, in := range map[class]inputs{classBPF: bpfInputs, classNonBPF: nonBPFInputs} {
			m, err := buildManifest(root, in)
			if err != nil {
				manifestsErr = err
				return
			}
			for line := range strings.Lines(string(m)) {
				manifests[c] = append(manifests[c], strings.Fields(line)[0])
			}
		}
	})
	if manifestsErr != nil {
		t.Fatal(manifestsErr)
	}
	return manifests[c]
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := gitOutput("rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}
