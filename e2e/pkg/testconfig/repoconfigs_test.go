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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	configDir = "../../config"
	repoRoot  = "../../.."
)

// isFragment reports whether a config exists only to be composed into others.
// Fragments carry no include scope and are never named by a CI cell, so the
// scope checks below do not apply to them. Matched on the path relative to
// e2e/config, not the base name, so a stray base.yaml in a pipeline directory is
// still checked.
func isFragment(rel string) bool {
	return rel == "base.yaml" || strings.HasPrefix(rel, "platform"+string(filepath.Separator))
}

// isAbstractParent reports whether a config supplies scope to its siblings but
// is not itself named by a cell. These declare includes, so they are checked
// like any other config; they are called out only where being unreferenced is
// expected.
func isAbstractParent(rel string) bool {
	return filepath.Base(rel) == "pipeline.yaml"
}

func eachConfig(t *testing.T, fn func(t *testing.T, relPath, absPath string)) {
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
		t.Run(rel, func(t *testing.T) { fn(t, rel, p) })
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", configDir, err)
	}
	if found == 0 {
		t.Fatalf("no configs found under %s -- wrong working directory?", configDir)
	}
}

// TestRepoConfigsAreValid loads every config actually shipped in e2e/config and
// converts it, so a malformed or undocumented entry fails here rather than
// halfway through a CI e2e run that has already provisioned a cluster.
func TestRepoConfigsAreValid(t *testing.T) {
	eachConfig(t, func(t *testing.T, rel, abs string) {
		cfg, err := Load(abs)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		flags, err := ToFlags(cfg)
		if err != nil {
			t.Fatalf("to flags: %v", err)
		}
		if isFragment(rel) {
			return
		}
		if flags.LabelFilter == "" {
			t.Error("empty label filter: this config selects the entire suite")
		}
		if len(cfg.Include) == 0 {
			t.Error("no include scope, so selection is 'everything minus excludes'; " +
				"declare an include or extend a config that does")
		}
	})
}

// TestSkipPatternsSurviveYAML guards a silent failure: YAML double-quoted
// scalars expand escapes, so "Proxy\b" becomes a literal backspace, which still
// compiles as a regex and matches nothing. Patterns must be single-quoted.
func TestSkipPatternsSurviveYAML(t *testing.T) {
	controlChars := regexp.MustCompile(`[\x00-\x1f\x7f]`)
	eachConfig(t, func(t *testing.T, rel, abs string) {
		cfg, err := Load(abs)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		for _, entry := range cfg.Exclude.NamePatterns {
			for _, p := range entry.AllPatterns() {
				if loc := controlChars.FindStringIndex(p); loc != nil {
					t.Errorf("pattern %q contains a control character at %d -- "+
						"YAML expanded a regex escape; single-quote the pattern",
						p, loc[0])
				}
			}
		}
	})
}

// TestNoDuplicateExclusions checks that composition does not leave a label
// excluded twice. merge() dedups, so a failure here means a resolved config
// would render as `!X && !X` -- harmless to ginkgo, confusing to read when
// working out why a lane selected the wrong specs.
func TestNoDuplicateExclusions(t *testing.T) {
	eachConfig(t, func(t *testing.T, rel, abs string) {
		cfg, err := Load(abs)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		seen := map[string]bool{}
		for _, e := range cfg.Exclude.Labels {
			if seen[e.Label] {
				t.Errorf("label %q excluded more than once after merge", e.Label)
			}
			seen[e.Label] = true
		}
		inc := map[string]bool{}
		for _, e := range cfg.Include {
			if inc[e.Label] {
				t.Errorf("include %q appears more than once after merge", e.Label)
			}
			inc[e.Label] = true
		}
	})
}

// configReferences returns every e2e/config path named anywhere in CI, mapped to
// the files naming it. Deliberately matches any e2e/config path rather than only
// E2E_TEST_CONFIG values, so Makefile targets and docs are covered too.
func configReferences(t *testing.T) map[string][]string {
	t.Helper()
	ref := regexp.MustCompile(`e2e/config/[A-Za-z0-9._/-]+\.yaml`)
	seen := map[string][]string{}
	for _, dir := range []string{".argoci", ".semaphore", "Makefile"} {
		root := filepath.Join(repoRoot, dir)
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			switch filepath.Ext(p) {
			case ".yaml", ".yml", ".sh", ".md", "":
			default:
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range ref.FindAllString(string(data), -1) {
				rel, _ := filepath.Rel(repoRoot, p)
				seen[m] = append(seen[m], rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no e2e/config references in CI -- wrong working directory?")
	}
	return seen
}

// TestReferencedConfigsExist checks that every e2e/config path named in CI
// resolves to a real file. Renaming a config without updating its callers
// otherwise fails only at run time, after a cluster has been provisioned.
func TestReferencedConfigsExist(t *testing.T) {
	refs := configReferences(t)
	for cfgPath, referrers := range refs {
		if _, err := os.Stat(filepath.Join(repoRoot, cfgPath)); err != nil {
			t.Errorf("%s does not exist, referenced by: %s",
				cfgPath, strings.Join(referrers, ", "))
		}
	}
	t.Logf("checked %d distinct config references", len(refs))
}

// TestFragmentsAreNotUsedDirectly keeps composition-only configs out of CI. A
// fragment has no include scope, so a cell pointing at one would select
// everything the excludes happen not to catch.
func TestFragmentsAreNotUsedDirectly(t *testing.T) {
	refs := configReferences(t)
	for cfgPath, referrers := range refs {
		rel, err := filepath.Rel("e2e/config", cfgPath)
		if err != nil {
			continue
		}
		if isFragment(rel) || isAbstractParent(rel) {
			t.Errorf("%s is a composition-only config but is referenced by: %s",
				cfgPath, strings.Join(referrers, ", "))
		}
	}
}

// unwiredConfigs is the set of configs that no CI cell points at yet, because the
// whole tree lands ahead of the per-cron wiring. It is an allowlist that shrinks:
// each wiring PR deletes the entries it wires, and the last one deletes the map.
// Asserted in both directions below, so a config added without a cell fails
// immediately and a stale entry fails too.
var unwiredConfigs = map[string]bool{
	"bpf/bpf-encap-extnode-aws.yaml":                  true,
	"bpf/bpf-encap-nobgp-extnode-aws.yaml":            true,
	"bpf/bpf-extnode.yaml":                            true,
	"bpf/bpf-v3crd-extnode-aws.yaml":                  true,
	"bpf/bpf.yaml":                                    true,
	"bpf/eks-bpf-nobgp-extnode-aws.yaml":              true,
	"bpf/eks-xtables-encap-extnode-aws.yaml":          true,
	"bpf/kops-bpf-encap-extnode-aws.yaml":             true,
	"bpf/kops-bpf-extnode-aws.yaml":                   true,
	"bpf/kops-xtables-encap-extnode-aws.yaml":         true,
	"bpf/kops-xtables-extnode-aws.yaml":               true,
	"bpf/xtables-encap-extnode-aws.yaml":              true,
	"iptables/aks-xtables-encap.yaml":                 true,
	"iptables/aks-xtables-nobgp.yaml":                 true,
	"iptables/aks-xtables.yaml":                       true,
	"iptables/eks-xtables-aws.yaml":                   true,
	"iptables/gke-xtables-nobgp-v3crd.yaml":           true,
	"iptables/xtables-aws.yaml":                       true,
	"iptables/xtables-v3crd-aws.yaml":                 true,
	"patch-verification/aks-xtables-nobgp.yaml":       true,
	"patch-verification/bpf-aws.yaml":                 true,
	"patch-verification/bpf-encap-aws.yaml":           true,
	"patch-verification/bpf-encap.yaml":               true,
	"patch-verification/eks-bpf-encap-aws.yaml":       true,
	"patch-verification/eks-bpf-nobgp-aws.yaml":       true,
	"patch-verification/xtables-aws.yaml":             true,
	"patch-verification/xtables-encap-manifest.yaml":  true,
	"patch-verification/xtables-manifest.yaml":        true,
	"patch-verification/xtables.yaml":                 true,
	"test/bpf.yaml":                                   true,
	"upgrade/aks-xtables.yaml":                        true,
	"upgrade/bpf.yaml":                                true,
	"upgrade/eks-bpf-aws-manifest.yaml":               true,
	"upgrade/xtables-aws.yaml":                        true,
	"upgrade/xtables.yaml":                            true,
	"vpp/vpp-encap-extnode-aws.yaml":                  true,
	"vpp/vpp-encap-extnode.yaml":                      true,
	"vpp/xtables-encap-extnode-aws.yaml":              true,
	"windows/aks-xtables-nobgp.yaml":                  true,
	"windows/xtables-encap.yaml":                      true,
}

// TestNoOrphanedConfigs checks the reverse of TestReferencedConfigsExist: a config
// nobody names is dead weight that still reads as authoritative.
func TestNoOrphanedConfigs(t *testing.T) {
	referenced := map[string]bool{}
	for cfgPath := range configReferences(t) {
		if rel, err := filepath.Rel("e2e/config", cfgPath); err == nil {
			referenced[rel] = true
		}
	}

	seen := map[string]bool{}
	eachConfig(t, func(t *testing.T, rel, abs string) {
		if isFragment(rel) || isAbstractParent(rel) {
			return
		}
		seen[rel] = true
		switch {
		case referenced[rel] && unwiredConfigs[rel]:
			t.Error("now referenced by CI, so drop it from unwiredConfigs")
		case !referenced[rel] && !unwiredConfigs[rel]:
			t.Error("no CI cell, Makefile target or doc references this config")
		}
	})

	for rel := range unwiredConfigs {
		if !seen[rel] {
			t.Errorf("unwiredConfigs lists %q, which no longer exists", rel)
		}
	}
}

// TestExtendsStaysInTree keeps `extends` chains inside e2e/config. A config that
// reached outside the tree would resolve differently depending on the checkout
// layout that CI happens to use.
func TestExtendsStaysInTree(t *testing.T) {
	rootAbs, err := filepath.Abs(configDir)
	if err != nil {
		t.Fatal(err)
	}
	eachConfig(t, func(t *testing.T, rel, abs string) {
		data, err := os.ReadFile(abs)
		if err != nil {
			t.Fatal(err)
		}
		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("parse: %v", err)
		}
		for _, parent := range cfg.Extends {
			absParent, err := filepath.Abs(filepath.Join(filepath.Dir(abs), parent))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(absParent, rootAbs+string(filepath.Separator)) {
				t.Errorf("extends %q resolves to %s, outside e2e/config", parent, absParent)
			}
			if _, err := os.Stat(absParent); err != nil {
				t.Errorf("extends %q does not exist: %v", parent, err)
			}
		}
	})
}
