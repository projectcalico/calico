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
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func depsFrom(incl, excl []string) *Deps {
	return &Deps{Inclusions: set.From(incl...), Exclusions: set.From(excl...)}
}

func mustParseGraph(t *testing.T, blocks []templateData) *blockGraph {
	t.Helper()
	g, err := parseBlockGraph(blocks)
	if err != nil {
		t.Fatalf("parseBlockGraph: %v", err)
	}
	return g
}

func TestMergeDepsSuperset(t *testing.T) {
	a := depsFrom([]string{"/a", "/b"}, []string{"/x", "/y"})
	b := depsFrom([]string{"/b", "/c"}, []string{"/y", "/z"})

	merged := mergeDepsSuperset([]*Deps{a, b})

	// Inclusions are unioned.
	for _, want := range []string{"/a", "/b", "/c"} {
		if !merged.Inclusions.Contains(want) {
			t.Errorf("merged inclusions missing %q", want)
		}
	}
	// Exclusions are intersected: only patterns in *every* input survive.
	if !merged.Exclusions.Contains("/y") {
		t.Error("merged exclusions should keep /y (in both inputs)")
	}
	for _, gone := range []string{"/x", "/z"} {
		if merged.Exclusions.Contains(gone) {
			t.Errorf("merged exclusions should drop %q (not in all inputs)", gone)
		}
	}
	// Soundness: the merge must never exclude something an input doesn't, so
	// merged.Exclusions ⊆ each input's exclusions.
	for _, in := range []*Deps{a, b} {
		for x := range merged.Exclusions.All() {
			if !in.Exclusions.Contains(x) {
				t.Errorf("merged exclusion %q not present in an input — would suppress its inclusions", x)
			}
		}
	}
}

func TestDropSubsumedInclusions(t *testing.T) {
	in := set.From(
		"/felix/**",           // whole-tree glob — subsumes everything under /felix/.
		"/felix/fv/*.go",      // subsumed.
		"/felix/bpf/nat/*.go", // subsumed (nested).
		"/felix/bpf-gpl",      // subsumed (non-go dep dir).
		"/felixfoo/*.go",      // NOT subsumed: /felix/ is not a prefix of /felixfoo/.
		"/typha/**",           // another whole-tree glob — kept.
		"/typha/pkg/*.go",     // subsumed by /typha/**.
		"/metadata.mk",        // unrelated — kept.
		"/**/*.md",            // wildcard prefix, not a subsumer and not subsumed.
	)

	got := dropSubsumedInclusions(in).Slice()

	want := set.From("/felix/**", "/felixfoo/*.go", "/typha/**", "/metadata.mk", "/**/*.md")
	if len(got) != want.Len() {
		t.Fatalf("got %v, want %v", got, want.Slice())
	}
	for _, g := range got {
		if !want.Contains(g) {
			t.Errorf("unexpected surviving inclusion %q", g)
		}
	}
}

func macroBlocks() []templateData {
	return []templateData{
		{
			originalPath: ".semaphore/semaphore.yml.d/blocks/10-prerequisites.yml",
			filename:     "10-prerequisites.yml",
			content: `- name: "Producer"
  run:
    when: "${CHANGE_IN_WITH_DEPENDENTS(non-go:/own/)}"
  dependencies: []
- name: "Consumer A"
  run:
    when: "${CHANGE_IN(d1)}"
  dependencies:
    - "Producer"
`,
		},
		{
			originalPath: ".semaphore/semaphore.yml.d/blocks/20-other.yml",
			filename:     "20-other.yml",
			content: `- name: "Consumer B"
  run:
    when: "${CHANGE_IN(d2)}"
  dependencies:
    - "Producer"
`,
		},
	}
}

func TestParseBlockGraph(t *testing.T) {
	g := mustParseGraph(t, macroBlocks())
	prod := g.byName["Producer"]
	if prod == nil || !prod.isMacro || prod.macroArg != "non-go:/own/" {
		t.Fatalf("producer not parsed as macro block: %+v", prod)
	}
	deps := g.dependents["Producer"]
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependents of Producer, got %d", len(deps))
	}
	// Consumer B lives in a different file — the reverse map must aggregate
	// across files.
	var files []string
	for _, d := range deps {
		files = append(files, d.file)
	}
	if files[0] == files[1] {
		t.Errorf("expected dependents from two different files, got %v", files)
	}
}

func TestParseBlockGraphUnknownDependency(t *testing.T) {
	blocks := []templateData{{
		originalPath: "x.yml", filename: "x.yml",
		content: `- name: "A"
  dependencies:
    - "Nonexistent"
`,
	}}
	if _, err := parseBlockGraph(blocks); err == nil {
		t.Error("expected error for dependency on unknown block")
	}
}

func TestParseBlockGraphDuplicateName(t *testing.T) {
	blocks := []templateData{{
		originalPath: "x.yml", filename: "x.yml",
		content: `- name: "A"
  dependencies: []
- name: "A"
  dependencies: []
`,
	}}
	if _, err := parseBlockGraph(blocks); err == nil {
		t.Error("expected error for duplicate block name")
	}
}

func TestCalculateDependentMacroDeps(t *testing.T) {
	g := mustParseGraph(t, macroBlocks())
	deps := map[string]*Deps{
		"d1": depsFrom([]string{"/d1/**"}, []string{"/**/*.md", "/d1/**/*_test.go"}),
		"d2": depsFrom([]string{"/d2/**"}, []string{"/**/*.md", "/d2/**/*_test.go"}),
	}

	macroDeps, err := calculateDependentMacroDeps(g, deps)
	if err != nil {
		t.Fatalf("calculateDependentMacroDeps: %v", err)
	}
	m := macroDeps["Producer"]
	if m == nil {
		t.Fatal("no merged deps for producer macro arg")
	}

	// Own spec + both dependents' inclusions + both dependents' block files.
	for _, want := range []string{
		"/own/", "/d1/**", "/d2/**",
		"/.semaphore/semaphore.yml.d/blocks/10-prerequisites.yml", // Consumer A's file
		"/.semaphore/semaphore.yml.d/blocks/20-other.yml",         // Consumer B's file
	} {
		if !m.Inclusions.Contains(want) {
			t.Errorf("merged inclusions missing %q", want)
		}
	}
	// Per-dependent test globs are dropped by the intersection; the shared
	// default exclusion survives.
	if !m.Exclusions.Contains("/**/*.md") {
		t.Error("expected shared default exclusion /**/*.md to survive intersection")
	}
	for _, gone := range []string{"/d1/**/*_test.go", "/d2/**/*_test.go"} {
		if m.Exclusions.Contains(gone) {
			t.Errorf("expected per-dependent exclusion %q to be dropped", gone)
		}
	}
	// Superset soundness: producer excludes nothing a dependent includes-and-
	// doesn't-exclude — i.e. its exclusions ⊆ each dependent's.
	for _, d := range []string{"d1", "d2"} {
		for x := range m.Exclusions.All() {
			if !deps[d].Exclusions.Contains(x) {
				t.Errorf("producer exclusion %q not in dependent %s — unsound", x, d)
			}
		}
	}
}

func TestCalculateDependentMacroDepsNoDependents(t *testing.T) {
	blocks := []templateData{{
		originalPath: "x.yml", filename: "x.yml",
		content: `- name: "Lonely"
  run:
    when: "${CHANGE_IN_WITH_DEPENDENTS(non-go:/own/)}"
  dependencies: []
`,
	}}
	g := mustParseGraph(t, blocks)
	macroDeps, err := calculateDependentMacroDeps(g, nil)
	if err != nil {
		t.Fatalf("calculateDependentMacroDeps: %v", err)
	}
	m := macroDeps["Lonely"]
	if m == nil || !m.Inclusions.Contains("/own/") {
		t.Fatalf("expected own-spec-only deps for dependent-less macro, got %+v", m)
	}
}

func TestCalculateDependentMacroDepsSharedArg(t *testing.T) {
	// Two producers may share an identical own-spec arg (e.g. both felix
	// producers use `felix`); results are keyed by block name, and
	// buildSemaphoreYAML disambiguates occurrences by document order.
	blocks := []templateData{{
		originalPath: "x.yml", filename: "x.yml",
		content: `- name: "P1"
  run:
    when: "${CHANGE_IN_WITH_DEPENDENTS(non-go:/shared/)}"
  dependencies: []
- name: "P2"
  run:
    when: "${CHANGE_IN_WITH_DEPENDENTS(non-go:/shared/)}"
  dependencies: []
`,
	}}
	g := mustParseGraph(t, blocks)
	macroDeps, err := calculateDependentMacroDeps(g, nil)
	if err != nil {
		t.Fatalf("expected shared arg to be allowed, got error: %v", err)
	}
	if macroDeps["P1"] == nil || macroDeps["P2"] == nil {
		t.Error("both blocks sharing an arg should resolve independently by name")
	}
}

func TestCalculateDependentMacroDepsConstOrDependentAccepted(t *testing.T) {
	// A dependent of the form `false or ${CHANGE_IN(...)}` (as Felix: Windows FV
	// uses) is accepted: the constant `or`-prefix is sound.
	blocks := []templateData{{
		originalPath: "x.yml", filename: "x.yml",
		content: `- name: "Producer"
  run:
    when: "${CHANGE_IN_WITH_DEPENDENTS(non-go:/own/)}"
  dependencies: []
- name: "Const-or Consumer"
  run:
    when: "false or ${CHANGE_IN(d1)}"
  dependencies:
    - "Producer"
`,
	}}
	g := mustParseGraph(t, blocks)
	deps := map[string]*Deps{"d1": depsFrom([]string{"/d1/**"}, []string{"/**/*.md"})}
	macroDeps, err := calculateDependentMacroDeps(g, deps)
	if err != nil {
		t.Fatalf("calculateDependentMacroDeps: %v", err)
	}
	if !macroDeps["Producer"].Inclusions.Contains("/d1/**") {
		t.Error("const-or dependent's CHANGE_IN should be merged into the producer")
	}
}

func TestCalculateDependentMacroDepsNonConstConditionRejected(t *testing.T) {
	// A dependent with a runtime condition (branch matching) can run when its
	// CHANGE_IN is false, which a single merged clause can't represent — reject.
	blocks := []templateData{{
		originalPath: "x.yml", filename: "x.yml",
		content: `- name: "Producer"
  run:
    when: "${CHANGE_IN_WITH_DEPENDENTS(non-go:/own/)}"
  dependencies: []
- name: "Branchy Consumer"
  run:
    when: "branch =~ 'release-.*' or ${CHANGE_IN(d1)}"
  dependencies:
    - "Producer"
`,
	}}
	g := mustParseGraph(t, blocks)
	deps := map[string]*Deps{"d1": depsFrom([]string{"/d1/**"}, nil)}
	if _, err := calculateDependentMacroDeps(g, deps); err == nil {
		t.Error("expected error: dependent's when has a non-constant condition")
	}
}

func TestCalculateDependentMacroDepsChain(t *testing.T) {
	// P1 <- P2 <- C: P2 is both a producer (for C) and a dependent (of P1).
	// P1's trigger must transitively cover C's trigger via P2's merged value.
	blocks := []templateData{{
		originalPath: ".semaphore/semaphore.yml.d/blocks/p.yml", filename: "p.yml",
		content: `- name: "P1"
  run:
    when: "${CHANGE_IN_WITH_DEPENDENTS(non-go:/p1own/)}"
  dependencies: []
- name: "P2"
  run:
    when: "${CHANGE_IN_WITH_DEPENDENTS(non-go:/p2own/)}"
  dependencies:
    - "P1"
- name: "C"
  run:
    when: "${CHANGE_IN(c)}"
  dependencies:
    - "P2"
`,
	}}
	g := mustParseGraph(t, blocks)
	deps := map[string]*Deps{"c": depsFrom([]string{"/c/**"}, []string{"/**/*.md"})}
	macroDeps, err := calculateDependentMacroDeps(g, deps)
	if err != nil {
		t.Fatalf("calculateDependentMacroDeps: %v", err)
	}
	p1 := macroDeps["P1"]
	// P1 must cover its own spec, P2's own spec, and (transitively) C's trigger.
	for _, want := range []string{"/p1own/", "/p2own/", "/c/**"} {
		if !p1.Inclusions.Contains(want) {
			t.Errorf("P1 trigger missing %q (chain not resolved transitively)", want)
		}
	}
}

func TestCalculateMacroOwnDepsEmpty(t *testing.T) {
	d, err := calculateMacroOwnDeps("")
	if err != nil {
		t.Fatalf("calculateMacroOwnDeps(\"\"): %v", err)
	}
	// Empty own-spec must not produce a bogus "//**" inclusion.
	if d.Inclusions.Contains("//**") || d.Inclusions.Contains("/**") {
		t.Error("empty own-spec produced a catch-all inclusion glob")
	}
	// Default inclusions/exclusions are still present.
	if !d.Exclusions.Contains("/**/*.md") {
		t.Error("expected default exclusions in empty own-spec deps")
	}
}
