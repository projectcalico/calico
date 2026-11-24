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

package testconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/e2e/pkg/area"
	"github.com/projectcalico/calico/e2e/pkg/cilanes"
)

const (
	configDir = "../../config"
	repoRoot  = "../../.."
)

func eachConfig(t *testing.T, fn func(t *testing.T, rel string, cfg *Config)) {
	t.Helper()
	var found int
	err := filepath.Walk(configDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(p) != ".yaml" {
			return err
		}
		found++
		rel, err := filepath.Rel(configDir, p)
		if err != nil {
			return err
		}
		t.Run(rel, func(t *testing.T) {
			cfg, err := Load(p)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			fn(t, rel, cfg)
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", configDir, err)
	}
	if found == 0 {
		t.Fatalf("no configs found under %s: wrong working directory?", configDir)
	}
}

// TestRepoConfigsAreValid loads and converts every config in e2e/config, so a
// malformed entry fails here rather than in a CI run that has already
// provisioned a cluster. A file without a kind skips the per-kind key checks,
// so every file must declare one.
func TestRepoConfigsAreValid(t *testing.T) {
	eachConfig(t, func(t *testing.T, rel string, cfg *Config) {
		if _, err := ToFlags(cfg); err != nil {
			t.Fatalf("to flags: %v", err)
		}
		switch cfg.Kind {
		case "":
			t.Error("no kind, so nothing checks which keys this file may carry")
		case KindSuite:
			if len(cfg.Include.Labels) == 0 && len(cfg.Include.NamePatterns) == 0 {
				t.Error("a suite with no include selects nothing")
			}
		case KindCluster:
			if cfg.Provides == nil {
				t.Error("a cluster fragment must declare provides, even as [], or its lane never filters on Requires labels")
			}
		}
	})
}

// coversArea matches the area in a Covers: label inside a label expression.
var coversArea = regexp.MustCompile(`Covers:([A-Za-z0-9-]+)`)

// unknownAreas returns the Covers: areas named in exprs that aren't in
// area.All. A suite selecting a misspelled area would select nothing
// and fail no check of its own.
func unknownAreas(exprs []string) []string {
	var unknown []string
	for _, e := range exprs {
		for _, m := range coversArea.FindAllStringSubmatch(e, -1) {
			if !area.IsKnown(area.Area(m[1])) {
				unknown = append(unknown, m[1])
			}
		}
	}
	return unknown
}

// TestConfigsCoverKnownAreas checks every Covers: label a config includes or
// excludes against the areas specs can declare, so the YAML side is held to
// the same list as describe.Covers.
func TestConfigsCoverKnownAreas(t *testing.T) {
	eachConfig(t, func(t *testing.T, rel string, cfg *Config) {
		var exprs []string
		for _, e := range cfg.Include.Labels {
			exprs = append(exprs, e.Label)
		}
		for _, e := range cfg.Exclude.Labels {
			exprs = append(exprs, e.Label)
		}
		if bad := unknownAreas(exprs); len(bad) > 0 {
			t.Errorf("Covers: areas not in area.All: %v", bad)
		}
	})
}

// TestUnknownAreasCatchesATypo proves the area check rejects a near miss and
// accepts the real name, so TestConfigsCoverKnownAreas can't pass vacuously.
func TestUnknownAreasCatchesATypo(t *testing.T) {
	got := unknownAreas([]string{"sig-calico && (Covers:TieredRBAC || Covers:Tiered-RBAC)"})
	if !slices.Equal(got, []string{"TieredRBAC"}) {
		t.Errorf("want only the misspelled TieredRBAC flagged, got %v", got)
	}
}

// TestThereIsOnePolicyFile keeps CI-wide label exclusions in one place, which
// every lane names.
func TestThereIsOnePolicyFile(t *testing.T) {
	if got := policyFiles(t); len(got) != 1 {
		t.Errorf("want exactly one policy file, found %v", got)
	}
}

// policyFiles lists the configs of kind policy, relative to e2e/config.
func policyFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	eachConfig(t, func(t *testing.T, rel string, cfg *Config) {
		if cfg.Kind == KindPolicy {
			files = append(files, rel)
		}
	})
	return files
}

// TestNeedsNameClusterFragments checks that every needs entry, which is
// relative to cluster/, names a cluster fragment that exists.
func TestNeedsNameClusterFragments(t *testing.T) {
	eachConfig(t, func(t *testing.T, rel string, cfg *Config) {
		for _, n := range cfg.Needs {
			needed, err := Load(filepath.Join(configDir, "cluster", n))
			if err != nil {
				t.Errorf("needs %q: %v", n, err)
				continue
			}
			if needed.Kind != KindCluster {
				t.Errorf("needs %q, which is a %s file, not a cluster fragment", n, needed.Kind)
			}
		}
	})
}

// TestNamePatternsSurviveYAML guards a silent failure: YAML double-quoted
// scalars expand escapes, so "Proxy\b" becomes a literal backspace, which still
// compiles as a regex and matches nothing. Patterns must be single-quoted.
func TestNamePatternsSurviveYAML(t *testing.T) {
	controlChars := regexp.MustCompile(`[\x00-\x1f\x7f]`)
	eachConfig(t, func(t *testing.T, rel string, cfg *Config) {
		entries := slices.Concat(cfg.Include.NamePatterns, cfg.Exclude.NamePatterns, cfg.Upstream)
		for _, entry := range entries {
			for _, p := range entry.AllPatterns() {
				if loc := controlChars.FindStringIndex(p); loc != nil {
					t.Errorf("pattern %q contains a control character at %d: YAML expanded a regex escape, so single-quote the pattern", p, loc[0])
				}
			}
		}
	})
}

// TestNoDuplicateEntries catches a label or capability listed twice in one
// file. Selection is unaffected, but the repeat shows up in the label filter
// an engineer reads when working out why a lane selected the wrong specs.
func TestNoDuplicateEntries(t *testing.T) {
	eachConfig(t, func(t *testing.T, rel string, cfg *Config) {
		lists := map[string][]string{
			"provides": cfg.Provides,
			"needs":    cfg.Needs,
		}
		for _, e := range cfg.Include.Labels {
			lists["include"] = append(lists["include"], e.Label)
		}
		for _, e := range cfg.Exclude.Labels {
			lists["exclude.labels"] = append(lists["exclude.labels"], e.Label)
		}
		for field, values := range lists {
			seen := map[string]bool{}
			for _, v := range values {
				if seen[v] {
					t.Errorf("%s lists %q more than once", field, v)
				}
				seen[v] = true
			}
		}
	})
}

// laneConfigs maps each config path, relative to e2e/config, to the lanes
// naming it, and each lane to its configs. cilanes resolves every lane CI
// runs, including the Makefile's kind lists and the flannel pre-migration run.
func laneConfigs(t *testing.T) (map[string][]string, map[string][]string) {
	t.Helper()
	lanes, err := cilanes.Load(repoRoot)
	if err != nil {
		t.Fatalf("loading CI lanes: %v", err)
	}
	byConfig, byLane := map[string][]string{}, map[string][]string{}
	for _, l := range lanes {
		lane := l.Source + ": " + l.Name
		for _, c := range l.Configs() {
			rel := filepath.Clean(strings.TrimPrefix(c, "e2e/config/"))
			byConfig[rel] = append(byConfig[rel], lane)
			byLane[lane] = append(byLane[lane], rel)
		}
	}
	if len(byLane) == 0 {
		t.Fatal("no CI lane names a config: wrong working directory?")
	}
	return byConfig, byLane
}

// TestLanesSelectWithValidConfigs loads each lane's list the way the e2e
// binary does. A list that names a missing file, or whose files clash once
// merged, otherwise fails only after a cluster has been provisioned.
func TestLanesSelectWithValidConfigs(t *testing.T) {
	_, byLane := laneConfigs(t)
	policy := policyFiles(t)
	if len(policy) != 1 {
		t.Fatalf("want exactly one policy file, found %v", policy)
	}
	for lane, configs := range byLane {
		t.Run(lane, func(t *testing.T) {
			paths := make([]string, 0, len(configs))
			for _, c := range configs {
				paths = append(paths, filepath.Join(configDir, c))
			}
			if _, err := LoadAll(paths); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(configs, policy[0]) {
				t.Errorf("does not name the policy file %s", policy[0])
			}
			if !slices.ContainsFunc(configs, func(c string) bool { return strings.HasPrefix(c, "suite/") }) {
				t.Error("names no suite, so it selects nothing")
			}
		})
	}
}

// TestLanesNameWhatTheirFragmentsNeed checks that a lane naming a cluster
// fragment also names the fragments it needs, such as BGP routing beside
// Calico CNI.
func TestLanesNameWhatTheirFragmentsNeed(t *testing.T) {
	_, byLane := laneConfigs(t)
	for lane, configs := range byLane {
		for _, c := range configs {
			cfg, err := Load(filepath.Join(configDir, c))
			if err != nil {
				t.Fatalf("%s: %v", lane, err)
			}
			for _, n := range cfg.Needs {
				if !slices.Contains(configs, filepath.Join("cluster", n)) {
					t.Errorf("%s names %s, which needs cluster/%s", lane, c, n)
				}
			}
		}
	}
}

// TestNoOrphanedConfigs checks that every config is named by some lane. One
// nobody names is dead weight that still reads as authoritative.
func TestNoOrphanedConfigs(t *testing.T) {
	byConfig, _ := laneConfigs(t)
	eachConfig(t, func(t *testing.T, rel string, cfg *Config) {
		if len(byConfig[rel]) == 0 {
			t.Error("no CI lane names this config")
		}
	})
}
