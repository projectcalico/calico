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

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtendsAcceptsBareString(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.yaml", "exclude:\n  labels:\n    - label: Slow\n      reason: \"slow\"\n")
	child := write(t, dir, "child.yaml", "extends: base.yaml\ninclude:\n  - sig-calico\n")

	cfg, err := Load(child)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Exclude.Labels) != 1 || cfg.Exclude.Labels[0].Label != "Slow" {
		t.Errorf("excludes = %+v, want inherited Slow", cfg.Exclude.Labels)
	}
	if len(cfg.Include) != 1 || cfg.Include[0].Label != "sig-calico" {
		t.Errorf("includes = %+v", cfg.Include)
	}
}

// Parents fold left-to-right and the child's own entries land last, which is
// what lets a lane compose a pipeline scope with a shared platform exclusion.
func TestExtendsListFoldsInOrder(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.yaml", "exclude:\n  labels:\n    - label: Slow\n      reason: \"slow\"\n")
	write(t, dir, "pipeline.yaml", "extends: base.yaml\ninclude:\n  - sig-calico\n")
	write(t, dir, "platform/eks.yaml", `exclude:
  namePatterns:
    - group: "EKS gaps"
      patterns:
        - 'DNS.for.services'
`)
	child := write(t, dir, "lane.yaml", `extends: [pipeline.yaml, platform/eks.yaml]
exclude:
  labels:
    - label: ExternalNode
      reason: "no external node"
`)

	cfg, err := Load(child)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatalf("to flags: %v", err)
	}
	if want := "(sig-calico) && !Slow && !ExternalNode"; flags.LabelFilter != want {
		t.Errorf("label filter = %q, want %q", flags.LabelFilter, want)
	}
	if want := "(DNS.for.services)"; flags.SkipString() != want {
		t.Errorf("skip = %q, want %q", flags.SkipString(), want)
	}
}

// A shared exclusion reachable by two routes must appear once: `!Slow && !Slow`
// is the string someone reads while working out why a lane ran the wrong specs.
func TestMergeDedupsAcrossParents(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.yaml", "exclude:\n  labels:\n    - label: Slow\n      reason: \"from base\"\n")
	write(t, dir, "a.yaml", "extends: base.yaml\ninclude:\n  - sig-calico\n")
	write(t, dir, "b.yaml", "extends: base.yaml\ninclude:\n  - sig-calico\n")
	child := write(t, dir, "child.yaml", `extends: [a.yaml, b.yaml]
exclude:
  labels:
    - label: Slow
      reason: "restated by the child"
`)

	cfg, err := Load(child)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := len(cfg.Exclude.Labels); got != 1 {
		t.Fatalf("got %d exclude labels, want 1: %+v", got, cfg.Exclude.Labels)
	}
	if r := cfg.Exclude.Labels[0].Reason; r != "from base" {
		t.Errorf("reason = %q, want the first occurrence (%q)", r, "from base")
	}
	if got := len(cfg.Include); got != 1 {
		t.Errorf("got %d includes, want 1: %+v", got, cfg.Include)
	}
	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(flags.LabelFilter, "!Slow") != 1 {
		t.Errorf("label filter repeats an exclusion: %q", flags.LabelFilter)
	}
}

// A diamond is legitimate (two parents sharing a grandparent) and must not be
// mistaken for a cycle.
func TestExtendsDiamondIsNotCircular(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.yaml", "exclude:\n  labels:\n    - label: Slow\n      reason: \"slow\"\n")
	write(t, dir, "left.yaml", "extends: base.yaml\ninclude:\n  - sig-calico\n")
	write(t, dir, "right.yaml", "extends: base.yaml\ninclude:\n  - Conformance\n")
	child := write(t, dir, "child.yaml", "extends: [left.yaml, right.yaml]\n")

	cfg, err := Load(child)
	if err != nil {
		t.Fatalf("diamond should load, got: %v", err)
	}
	if len(cfg.Include) != 2 {
		t.Errorf("includes = %+v, want both parents' scopes", cfg.Include)
	}
}

func TestExtendsListDetectsCycle(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.yaml", "extends: [b.yaml]\n")
	write(t, dir, "b.yaml", "extends: [a.yaml]\n")

	if _, err := Load(filepath.Join(dir, "a.yaml")); err == nil {
		t.Fatal("expected a circular extends error")
	} else if !strings.Contains(err.Error(), "circular") {
		t.Errorf("error = %v, want it to mention a circular chain", err)
	}
}

func TestExtendsRejectsEmptyEntry(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.yaml", "include:\n  - sig-calico\n")
	child := write(t, dir, "child.yaml", "extends: [base.yaml, \"\"]\n")

	if _, err := Load(child); err == nil {
		t.Fatal("expected an error for an empty extends entry")
	}
}

func TestExtendsMissingParentReportsWhich(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.yaml", "include:\n  - sig-calico\n")
	child := write(t, dir, "child.yaml", "extends: [base.yaml, nope.yaml]\n")

	_, err := Load(child)
	if err == nil {
		t.Fatal("expected an error for a missing parent")
	}
	if !strings.Contains(err.Error(), "nope.yaml") {
		t.Errorf("error = %v, want it to name the missing parent", err)
	}
}
