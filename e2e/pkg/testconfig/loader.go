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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads a config file and resolves its extends chain, returning a
// fully merged Config. The extends chain is resolved relative to the
// directory of each config file in the chain. Circular extends are detected
// and reported as errors.
func Load(path string) (*Config, error) {
	return load(path, nil)
}

func load(path string, seen []string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path %q: %w", path, err)
	}

	for _, s := range seen {
		if s == absPath {
			return nil, fmt.Errorf("circular extends chain: %v -> %s", seen, absPath)
		}
	}
	// Copy rather than append in place: sibling parents would otherwise share a
	// backing array and write over each other's entry.
	seen = append(append([]string(nil), seen...), absPath)

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", absPath, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", absPath, err)
	}

	if err := validate(&cfg, absPath); err != nil {
		return nil, err
	}

	if len(cfg.Extends) == 0 {
		if len(cfg.Enable) > 0 {
			return nil, fmt.Errorf("%s: enable[0] (%q) has no effect: this config extends nothing", absPath, cfg.Enable[0].Label)
		}
		return &cfg, nil
	}

	// Fold parents left-to-right, then append this config's own entries, so a
	// later parent's exclusions stack onto an earlier one's scope.
	inherited := &Config{}
	for _, rel := range cfg.Extends {
		parentPath := filepath.Join(filepath.Dir(absPath), rel)
		parent, err := load(parentPath, seen)
		if err != nil {
			return nil, fmt.Errorf("loading parent %q of %q: %w", rel, absPath, err)
		}
		inherited = merge(inherited, parent)
	}

	for i, e := range cfg.Enable {
		if !excludesLabel(inherited, e.Label) {
			return nil, fmt.Errorf("%s: enable[%d] (%q) is not excluded by any config it extends", absPath, i, e.Label)
		}
	}

	return merge(inherited, &cfg), nil
}

func excludesLabel(cfg *Config, label string) bool {
	for _, e := range cfg.Exclude.Labels {
		if e.Label == label {
			return true
		}
	}
	return false
}

// merge combines a parent and child config. The child's `enable` entries drop
// matching labels from the inherited exclusions, which is the only way a lane
// re-selects something a parent excluded. Its includes and excludes are appended
// to the parent's, dropping repeats: with composition a shared
// exclusion easily arrives by two routes, and `!Slow && !Slow` in the generated
// label filter is the string an engineer reads when a lane selects the wrong
// specs. First occurrence wins, so the earliest reason is the one kept.
func merge(parent, child *Config) *Config {
	merged := &Config{
		Include: IncludeList{
			Labels:       make([]IncludeEntry, 0, len(parent.Include.Labels)+len(child.Include.Labels)),
			NamePatterns: make([]NamePatternEntry, 0, len(parent.Include.NamePatterns)+len(child.Include.NamePatterns)),
		},
		Exclude: Exclude{
			Labels:       make([]ExcludeLabel, 0, len(parent.Exclude.Labels)+len(child.Exclude.Labels)),
			NamePatterns: make([]NamePatternEntry, 0, len(parent.Exclude.NamePatterns)+len(child.Exclude.NamePatterns)),
		},
	}

	seenInclude := map[string]bool{}
	for _, src := range [][]IncludeEntry{parent.Include.Labels, child.Include.Labels} {
		for _, e := range src {
			if seenInclude[e.Label] {
				continue
			}
			seenInclude[e.Label] = true
			merged.Include.Labels = append(merged.Include.Labels, e)
		}
	}

	seenFocus := map[string]bool{}
	for _, src := range [][]NamePatternEntry{parent.Include.NamePatterns, child.Include.NamePatterns} {
		for _, e := range src {
			key := patternKey(e)
			if seenFocus[key] {
				continue
			}
			seenFocus[key] = true
			merged.Include.NamePatterns = append(merged.Include.NamePatterns, e)
		}
	}

	enabled := map[string]bool{}
	for _, e := range child.Enable {
		enabled[e.Label] = true
	}

	seenLabel := map[string]bool{}
	for _, src := range [][]ExcludeLabel{parent.Exclude.Labels, child.Exclude.Labels} {
		for _, e := range src {
			if seenLabel[e.Label] || enabled[e.Label] {
				continue
			}
			seenLabel[e.Label] = true
			merged.Exclude.Labels = append(merged.Exclude.Labels, e)
		}
	}

	seenPattern := map[string]bool{}
	for _, src := range [][]NamePatternEntry{parent.Exclude.NamePatterns, child.Exclude.NamePatterns} {
		for _, e := range src {
			key := patternKey(e)
			if seenPattern[key] {
				continue
			}
			seenPattern[key] = true
			merged.Exclude.NamePatterns = append(merged.Exclude.NamePatterns, e)
		}
	}

	return merged
}

func patternKey(e NamePatternEntry) string {
	return e.Group + "\x00" + e.Pattern + "\x00" + strings.Join(e.AllPatterns(), "\x00")
}

// validate checks the structural validity of a config file.
func validate(cfg *Config, path string) error {
	for i, entry := range cfg.Include.Labels {
		if entry.Label == "" {
			return fmt.Errorf("%s: include.labels[%d] must have a non-empty label expression", path, i)
		}
	}

	for i, entry := range cfg.Enable {
		if entry.Label == "" {
			return fmt.Errorf("%s: enable[%d] must have a 'label' field", path, i)
		}
		if entry.Reason == "" {
			return fmt.Errorf("%s: enable[%d] (%q) must have a 'reason'", path, i, entry.Label)
		}
	}

	if err := validatePatterns(cfg.Include.NamePatterns, path, "include"); err != nil {
		return err
	}

	for i, entry := range cfg.Exclude.Labels {
		if entry.Label == "" {
			return fmt.Errorf("%s: exclude.labels[%d] must have a 'label' field", path, i)
		}
		if entry.Reason == "" {
			return fmt.Errorf("%s: exclude.labels[%d] (%q) must have a 'reason'", path, i, entry.Label)
		}
	}

	return validatePatterns(cfg.Exclude.NamePatterns, path, "exclude")
}

func validatePatterns(entries []NamePatternEntry, path, section string) error {
	for i, entry := range entries {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("%s: %s.namePatterns[%d]: %w", path, section, i, err)
		}
		for _, p := range entry.AllPatterns() {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("%s: %s.namePatterns[%d]: invalid regex %q: %w", path, section, i, p, err)
			}
		}
	}
	return nil
}
