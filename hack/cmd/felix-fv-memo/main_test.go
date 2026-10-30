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
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

func TestGateMatches(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".argoci/deps.yaml"), `
components:
  a:
    in: ['^a/']
    exclude: ['_test\.go$', '^shared/']
  b:
    in: ['^shared/']
`)
	writeFile(t, filepath.Join(dir, "workflow.yaml"), `
dependencies: .argoci/deps.yaml
includes:
  - path: module.yaml
    changes:
      dependsOn: [a, b]
      in: ['^scripts/', '^a/fv_test\.go$']
      exclude: ['\.md$']
`)
	g, err := readGate(dir, filepath.Join(dir, "workflow.yaml"), "module.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"a/main.go":      true,
		"a/main_test.go": false,
		// One source's exclusions don't suppress another's inclusions.
		"a/fv_test.go":  true,
		"shared/lib.go": true,
		// The module's own exclusions apply to every source.
		"a/README.md":       false,
		"scripts/README.md": false,
		"scripts/run":       true,
		"other/x.go":        false,
	} {
		if got := g.matches(path); got != want {
			t.Errorf("matches(%q) = %v, want %v", path, got, want)
		}
	}

	writeFile(t, filepath.Join(dir, "workflow.yaml"), `
dependencies: .argoci/deps.yaml
includes:
  - path: module.yaml
    changes: {dependsOn: [c]}
`)
	if _, err := readGate(dir, filepath.Join(dir, "workflow.yaml"), "module.yaml"); err == nil {
		t.Error("want an error for an unknown component")
	}
}

func TestKeyFiles(t *testing.T) {
	g := gate{sources: []patterns{{in: []*regexp.Regexp{regexp.MustCompile(`^x/`)}}}}
	tracked := map[string]bool{}
	for _, f := range []string{"x/used.go", "x/unused.go", "x/script", "x/doc/a.txt", "x/doc/compiled.h", "y/used.go"} {
		tracked[f] = true
	}
	compiled := map[string]bool{"x/used.go": true, "x/doc/compiled.h": true}
	files, err := keyFiles(g, tracked, compiled, []string{`^x/doc/`})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"x/doc/compiled.h", "x/script", "x/used.go"}
	if got := slices.Sorted(maps.Keys(files)); !slices.Equal(got, want) {
		t.Errorf("keyFiles = %v, want %v", got, want)
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
		{classNonBPF, `^felix/fv/infrastructure/[^/]*\.go$`, true},
		// Only the BPF dataplane loads the bpf-gpl programs, but Felix's cgo
		// code compiles some of their headers.
		{classNonBPF, `^felix/bpf-gpl/[^/]*\.c$`, false},
		{classBPF, `^felix/bpf-gpl/[^/]*\.c$`, true},
		{classNonBPF, `^felix/bpf-gpl/globals\.h$`, true},
		{classNonBPF, `^felix/bpf-gpl/bpf_inline\.h$`, true},
		{classNonBPF, `^felix/bpf-apache/[^/]*\.c$`, true},
		// The BPF lanes' "ut" batch runs both of these.
		{classBPF, `^felix/bpf/ut/`, true},
		{classBPF, `^felix/bpf/bpf_test\.go$`, true},
		{classNonBPF, `^felix/bpf/ut/`, false},
		{classNonBPF, `^felix/bpf/bpf_test\.go$`, false},
		// Not compiled into anything FV runs.
		{classNonBPF, `^felix/bpf/mock/`, false},
		{classNonBPF, `^felix/k8sfv/`, false},
		{classNonBPF, `^felix/dataplane/windows/`, false},
		{classNonBPF, `^felix/docs/`, false},
		{classNonBPF, `(^|/)README`, false},
		// cmd/calico links every component, but FV only runs felix and typha.
		{classNonBPF, `^kube-controllers/`, false},
		{classNonBPF, `^cmd/calico/main\.go$`, true},
		{classNonBPF, `^typha/pkg/`, true},
		{classNonBPF, `^node/pkg/node/command\.go$`, true},
		{classNonBPF, `^api/config/crd/`, true},
		{classNonBPF, `^go\.sum$`, true},
		{classNonBPF, `^docker/calico/Dockerfile$`, true},
		{classNonBPF, `^\.semaphore/vms/`, true},
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
		g, err := readGate(root, filepath.Join(root, ".argoci/ciworkflow.yaml"), ".argoci/modules/20-felix.yaml")
		if err != nil {
			manifestsErr = err
			return
		}
		tracked, err := trackedFiles(root)
		if err != nil {
			manifestsErr = err
			return
		}
		for _, c := range []class{classBPF, classNonBPF} {
			files, err := classKeyFiles(root, g, tracked, c)
			if err != nil {
				manifestsErr = err
				return
			}
			manifests[c] = slices.Collect(maps.Keys(files))
		}
	})
	if manifestsErr != nil {
		t.Fatal(manifestsErr)
	}
	return manifests[c]
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := gitOutput("rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}
