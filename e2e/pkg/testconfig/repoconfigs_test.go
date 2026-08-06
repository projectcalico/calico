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

const configDir = "../../config"

// abstractConfigs carry scope for their siblings to extend and are never named
// by a CI cell, so they are exempt from the label-filter check below.
var abstractConfigs = map[string]bool{
	"base.yaml": true,
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
		if flags.LabelFilter == "" {
			t.Error("empty label filter: this config selects the entire suite")
		}
		if base := filepath.Base(rel); !abstractConfigs[base] && len(cfg.Include) == 0 {
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

// TestReferencedConfigsExist checks that every e2e/config path named anywhere in
// CI resolves to a real file. Renaming a config without updating its callers
// otherwise fails only at run time, after a cluster has been provisioned.
func TestReferencedConfigsExist(t *testing.T) {
	repoRoot := "../../.."
	// Deliberately matches any e2e/config path, not just E2E_TEST_CONFIG values,
	// so Makefile targets and docs are covered too.
	ref := regexp.MustCompile(`e2e/config/[A-Za-z0-9._/-]+\.yaml`)
	scanDirs := []string{".argoci", ".semaphore", "Makefile"}

	seen := map[string][]string{}
	for _, dir := range scanDirs {
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
	for cfgPath, referrers := range seen {
		if _, err := os.Stat(filepath.Join(repoRoot, cfgPath)); err != nil {
			t.Errorf("%s does not exist, referenced by: %s",
				cfgPath, strings.Join(referrers, ", "))
		}
	}
	t.Logf("checked %d distinct config references", len(seen))
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
		if cfg.Extends == "" {
			return
		}
		absParent, err := filepath.Abs(filepath.Join(filepath.Dir(abs), cfg.Extends))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(absParent, rootAbs+string(filepath.Separator)) {
			t.Errorf("extends %q resolves to %s, outside e2e/config", cfg.Extends, absParent)
		}
		if _, err := os.Stat(absParent); err != nil {
			t.Errorf("extends %q does not exist: %v", cfg.Extends, err)
		}
	})
}
