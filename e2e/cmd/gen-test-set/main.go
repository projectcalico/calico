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

// gen-test-set records the specs each CI lane selects and the ones it drops,
// by dry-running the e2e binary per distinct selection and writing a set and a
// drop list per lane.
package main

import (
	"flag"
	"fmt"
	"os"
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

	audits, err := auditSelections(binary, repoRoot, sets)
	if err != nil {
		return err
	}
	byName := make(map[string]cilanes.Audit, len(sets))
	for _, name := range names {
		byName[name] = audits[selectionKey(sets[name])]
	}

	for _, name := range names {
		a := byName[name]
		if len(a.Runs) == 0 {
			// An empty set is a lane burning a cluster on nothing, so report it
			// rather than failing the whole generation.
			fmt.Fprintf(os.Stderr, "%5s  %s\n", "EMPTY", name)
			continue
		}
		fmt.Fprintf(os.Stderr, "%5d  %s (%d dropped)\n", len(a.Runs), name, len(a.Drops))
	}

	return cilanes.Write(filepath.Join(repoRoot, outDir), lanes, byName)
}

// selectionKey identifies a lane's selection by its parsed config list, so two
// lanes listing the same configs with different whitespace share a dry run.
func selectionKey(l cilanes.Lane) string {
	return strings.Join(l.Configs(), " ")
}

// selectionAudits holds the audit of each distinct selection, keyed by
// selectionKey. The concurrent audits fill it in through record.
type selectionAudits struct {
	mu     sync.Mutex
	audits map[string]cilanes.Audit
}

// record stores the audit of one selection.
func (s *selectionAudits) record(key string, audit cilanes.Audit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits[key] = audit
}

// auditSelections audits one lane per distinct selection among the sets, since
// many lanes share one config list. It returns the audits keyed by
// selectionKey.
func auditSelections(binary, repoRoot string, sets map[string]cilanes.Lane) (map[string]cilanes.Audit, error) {
	byConfig := map[string]cilanes.Lane{}
	for _, l := range sets {
		byConfig[selectionKey(l)] = l
	}

	results := &selectionAudits{audits: make(map[string]cilanes.Audit, len(byConfig))}
	group := new(errgroup.Group)
	group.SetLimit(runtime.NumCPU())
	for config, l := range byConfig {
		group.Go(func() error {
			audit, err := cilanes.AuditLane(binary, repoRoot, l)
			if err != nil {
				return fmt.Errorf("%s: %w", config, err)
			}
			results.record(config, audit)
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return results.audits, nil
}
