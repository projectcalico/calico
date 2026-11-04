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
	"strings"
	"testing"
)

const (
	suiteYAML = `
include:
  - sig-calico
exclude:
  labels:
    - label: Slow
      reason: "too slow"
`

	clusterYAML = `
include:
  - Conformance && sig-network
exclude:
  labels:
    - label: Slow
      reason: "repeated, so the merge must drop it"
    - label: RequiresBGP
      reason: "no BGP"
  namePatterns:
    - pattern: "DataPath"
      reason: "not a label"
`

	combinedYAML = `
extends: [suite.yaml, cluster.yaml]
`

	includeBaseYAML = `
include:
  - sig-calico
`

	excludeBaseYAML = `
exclude:
  labels:
    - label: RequiresBGP
      reason: "no BGP"
`

	extendsBaseYAML = `
extends: base.yaml
`

	namePatternsYAML = `
include:
  namePatterns:
    - pattern: "should serve a basic endpoint from pods"
      reason: "smoke check"
`
)

// Naming several configs selects what one config extending all of them would.
func TestLoadAllMatchesExtendingEveryConfig(t *testing.T) {
	dir := t.TempDir()
	suite := writeFile(t, dir, "suite.yaml", suiteYAML)
	cluster := writeFile(t, dir, "cluster.yaml", clusterYAML)
	combined := writeFile(t, dir, "combined.yaml", combinedYAML)

	got, err := LoadAll([]string{suite, cluster})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	want, err := Load(combined)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	gotFlags, err := ToFlags(got)
	if err != nil {
		t.Fatalf("ToFlags(LoadAll): %v", err)
	}
	wantFlags, err := ToFlags(want)
	if err != nil {
		t.Fatalf("ToFlags(Load): %v", err)
	}
	if gotFlags.LabelFilter != wantFlags.LabelFilter {
		t.Errorf("label filter = %q, want %q", gotFlags.LabelFilter, wantFlags.LabelFilter)
	}
	if gotFlags.SkipString() != wantFlags.SkipString() {
		t.Errorf("skip = %q, want %q", gotFlags.SkipString(), wantFlags.SkipString())
	}

	// Either file alone selects something narrower, so a loader that kept only
	// one config would fail the comparison above.
	alone, err := LoadAll([]string{suite})
	if err != nil {
		t.Fatalf("LoadAll(suite): %v", err)
	}
	aloneFlags, err := ToFlags(alone)
	if err != nil {
		t.Fatalf("ToFlags(suite): %v", err)
	}
	if aloneFlags.LabelFilter == wantFlags.LabelFilter {
		t.Errorf("one config alone produced the combined filter %q", aloneFlags.LabelFilter)
	}
}

// Each config resolves its own extends chain from its own directory, so configs
// from different directories can be combined.
func TestLoadAllResolvesEachExtendsChainSeparately(t *testing.T) {
	root := t.TempDir()
	dirA := filepath.Join(root, "a")
	dirB := filepath.Join(root, "b")
	for _, d := range []string{dirA, dirB} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	writeFile(t, dirA, "base.yaml", includeBaseYAML)
	first := writeFile(t, dirA, "lane.yaml", extendsBaseYAML)
	writeFile(t, dirB, "base.yaml", excludeBaseYAML)
	second := writeFile(t, dirB, "lane.yaml", extendsBaseYAML)

	cfg, err := LoadAll([]string{first, second})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(cfg.Include.Labels) != 1 || cfg.Include.Labels[0].Label != "sig-calico" {
		t.Errorf("includes = %v, want only sig-calico from a/base.yaml", cfg.Include.Labels)
	}
	if len(cfg.Exclude.Labels) != 1 || cfg.Exclude.Labels[0].Label != "RequiresBGP" {
		t.Errorf("excludes = %v, want only RequiresBGP from b/base.yaml", cfg.Exclude.Labels)
	}
}

// Ginkgo ANDs the label filter with the focus regex, so include labels in one
// config and include name patterns in another would select their intersection.
func TestLoadAllRejectsLabelsAndNamePatternsAcrossConfigs(t *testing.T) {
	dir := t.TempDir()
	labels := writeFile(t, dir, "labels.yaml", includeBaseYAML)
	patterns := writeFile(t, dir, "patterns.yaml", namePatternsYAML)

	for _, p := range []string{labels, patterns} {
		if _, err := LoadAll([]string{p}); err != nil {
			t.Fatalf("LoadAll(%s) alone: %v", filepath.Base(p), err)
		}
	}

	_, err := LoadAll([]string{labels, patterns})
	if err == nil || !strings.Contains(err.Error(), "include sets both labels") {
		t.Fatalf("LoadAll(labels, patterns) err = %v, want the labels and namePatterns clash", err)
	}
}

func TestLoadAllRequiresAPath(t *testing.T) {
	if _, err := LoadAll(nil); err == nil {
		t.Fatal("LoadAll(nil) succeeded, want an error")
	}
}
