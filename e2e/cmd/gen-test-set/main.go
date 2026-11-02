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

// gen-test-set records the specs each CI lane selects, by dry-running the e2e
// binary once per distinct selection.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/projectcalico/calico/e2e/pkg/cilanes"
)

func main() {
	repoRoot := flag.String("repo-root", ".", "path to the repository root")
	binary := flag.String("binary", "e2e/bin/k8s/e2e.test", "e2e test binary, relative to the repo root")
	outDir := flag.String("out", "e2e/testsets", "output directory, relative to the repo root")
	flag.Parse()

	if err := run(*repoRoot, *binary, *outDir); err != nil {
		fmt.Fprintln(os.Stderr, "gen-test-set:", err)
		os.Exit(1)
	}
}

func run(repoRoot, binary, outDir string) error {
	lanes, err := cilanes.Load(repoRoot)
	if err != nil {
		return err
	}

	// The dry runs execute in the repo root, where a relative binary path would
	// resolve a second time.
	binary, err = filepath.Abs(filepath.Join(repoRoot, binary))
	if err != nil {
		return err
	}

	sets, err := cilanes.ResolveSets(lanes)
	if err != nil {
		return err
	}

	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)

	var mu sync.Mutex
	specs := make(map[string][]string, len(sets))
	g := new(errgroup.Group)
	g.SetLimit(runtime.NumCPU())
	for _, name := range names {
		args, err := sets[name].SelectionArgs(repoRoot)
		if err != nil {
			return err
		}
		g.Go(func() error {
			found, err := dryRun(binary, repoRoot, args)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			mu.Lock()
			defer mu.Unlock()
			specs[name] = found
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	for _, name := range names {
		if len(specs[name]) == 0 {
			// An empty set is a lane burning a cluster on nothing, so report it
			// rather than failing the whole generation.
			fmt.Fprintf(os.Stderr, "%5s  %s\n", "EMPTY", name)
			continue
		}
		fmt.Fprintf(os.Stderr, "%5d  %s\n", len(specs[name]), name)
	}

	return cilanes.Write(filepath.Join(repoRoot, outDir), lanes, specs)
}

// ginkgoReport is the subset of ginkgo's JSON report that names the specs a run
// would execute.
type ginkgoReport struct {
	SpecReports []struct {
		ContainerHierarchyTexts []string `json:"ContainerHierarchyTexts"`
		LeafNodeText            string   `json:"LeafNodeText"`
		LeafNodeType            string   `json:"LeafNodeType"`
		State                   string   `json:"State"`
	} `json:"SpecReports"`
}

// dryRun returns the sorted spec names a selection would run. A dry run passes
// selected specs and skips filtered ones.
func dryRun(binary, workDir string, args []string) ([]string, error) {
	report, err := os.CreateTemp("", "gen-test-set-*.json")
	if err != nil {
		return nil, err
	}
	report.Close()
	defer os.Remove(report.Name())

	cmd := exec.Command(binary, append([]string{
		"--ginkgo.dry-run",
		"--ginkgo.json-report=" + report.Name(),
	}, args...)...)
	cmd.Dir = workDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w\n%s", err, out)
	}

	data, err := os.ReadFile(report.Name())
	if err != nil {
		return nil, err
	}
	var suites []ginkgoReport
	if err := json.Unmarshal(data, &suites); err != nil {
		return nil, err
	}

	var names []string
	for _, suite := range suites {
		for _, spec := range suite.SpecReports {
			if spec.LeafNodeType != "It" || spec.State != "passed" {
				continue
			}
			parts := append(append([]string{}, spec.ContainerHierarchyTexts...), spec.LeafNodeText)
			names = append(names, strings.Join(parts, " "))
		}
	}
	sort.Strings(names)
	return names, nil
}
