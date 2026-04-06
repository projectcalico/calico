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
	seen = append(seen, absPath)

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

	if cfg.Extends == "" {
		return &cfg, nil
	}

	// Resolve the parent path relative to this config file's directory.
	parentPath := filepath.Join(filepath.Dir(absPath), cfg.Extends)
	parent, err := load(parentPath, seen)
	if err != nil {
		return nil, fmt.Errorf("loading parent of %q: %w", absPath, err)
	}

	return merge(parent, &cfg), nil
}

// merge combines a parent and child config. The child's includes and excludes
// are appended to the parent's.
func merge(parent, child *Config) *Config {
	merged := &Config{
		Include: make([]IncludeEntry, 0, len(parent.Include)+len(child.Include)),
		Exclude: Exclude{
			Labels:       make([]ExcludeLabel, 0, len(parent.Exclude.Labels)+len(child.Exclude.Labels)),
			NamePatterns: make([]NamePatternEntry, 0, len(parent.Exclude.NamePatterns)+len(child.Exclude.NamePatterns)),
		},
	}

	merged.Include = append(merged.Include, parent.Include...)
	merged.Include = append(merged.Include, child.Include...)

	merged.Exclude.Labels = append(merged.Exclude.Labels, parent.Exclude.Labels...)
	merged.Exclude.Labels = append(merged.Exclude.Labels, child.Exclude.Labels...)

	merged.Exclude.NamePatterns = append(merged.Exclude.NamePatterns, parent.Exclude.NamePatterns...)
	merged.Exclude.NamePatterns = append(merged.Exclude.NamePatterns, child.Exclude.NamePatterns...)

	return merged
}

// validate checks the structural validity of a config file.
func validate(cfg *Config, path string) error {
	for i, entry := range cfg.Include {
		if entry.Label == "" {
			return fmt.Errorf("%s: include[%d] must have a non-empty label expression", path, i)
		}
	}

	for i, entry := range cfg.Exclude.Labels {
		if entry.Label == "" {
			return fmt.Errorf("%s: exclude.labels[%d] must have a 'label' field", path, i)
		}
		if entry.Reason == "" {
			return fmt.Errorf("%s: exclude.labels[%d] (%q) must have a 'reason'", path, i, entry.Label)
		}
	}

	for i, entry := range cfg.Exclude.NamePatterns {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("%s: exclude.namePatterns[%d]: %w", path, i, err)
		}
	}

	return nil
}
