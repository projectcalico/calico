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
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kind is the role a config file plays in a lane. A suite selects specs, a
// cluster fragment describes what the lane's cluster has, a quarantine file
// records broken specs, and the one policy file holds CI-wide label exclusions.
type Kind string

const (
	KindSuite      Kind = "suite"
	KindCluster    Kind = "cluster"
	KindQuarantine Kind = "quarantine"
	KindPolicy     Kind = "policy"
)

// kindRule is where a kind of file sits and the top-level keys it may carry
// besides kind itself.
type kindRule struct {
	// section is the tree a file of this kind sits in, as section returns it.
	section string

	// where describes section for an error message.
	where string

	keys []string
}

var kindRules = map[Kind]kindRule{
	KindSuite:      {section: "suite", where: "in suite/", keys: []string{"include"}},
	KindCluster:    {section: "cluster", where: "in cluster/<dimension>/", keys: []string{"provides", "needs"}},
	KindQuarantine: {section: "quarantine", where: "in quarantine/", keys: []string{"exclude"}},
	KindPolicy:     {section: "", where: "outside suite/, cluster/ and quarantine/", keys: []string{"exclude"}},
}

// validateKind enforces the naming law on a file that declares a kind: the
// file must sit in its kind's directory and carry only that kind's keys. The
// keys are read from the YAML itself, because decoding into Config silently
// drops a misspelled one.
func validateKind(cfg *Config, data []byte, path string) error {
	if cfg.Kind == "" {
		return nil
	}
	rule, ok := kindRules[cfg.Kind]
	if !ok {
		return fmt.Errorf("%s: kind %q is not one of suite, cluster, quarantine or policy", path, cfg.Kind)
	}
	if section(path) != rule.section {
		return fmt.Errorf("%s: a %s file belongs %s", path, cfg.Kind, rule.where)
	}

	// upstream is the one key that depends on the directory, not just the kind.
	allowed := append([]string{"kind"}, rule.keys...)
	if cfg.Kind == KindCluster && filepath.Base(filepath.Dir(path)) == "platform" {
		allowed = append(allowed, "upstream")
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing config %q: %w", path, err)
	}
	root := doc.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i]
		if slices.Contains(allowed, key.Value) {
			continue
		}
		if key.Value == "upstream" && cfg.Kind == KindCluster {
			return fmt.Errorf("%s: upstream (line %d) is allowed only in a cluster/platform/ file", path, key.Line)
		}
		return fmt.Errorf("%s: %s (line %d) is not allowed in a %s file, which carries only %s", path, key.Value, key.Line, cfg.Kind, strings.Join(allowed, ", "))
	}

	// Keys are fine, but exclude carries two lists and each kind owns one.
	switch {
	case cfg.Kind == KindQuarantine && len(cfg.Exclude.Labels) > 0:
		return fmt.Errorf("%s: exclude.labels[0] (%q): a quarantine file excludes by name only, and label exclusions belong in the policy file", path, cfg.Exclude.Labels[0].Label)
	case cfg.Kind == KindPolicy && len(cfg.Exclude.NamePatterns) > 0:
		return fmt.Errorf("%s: exclude.namePatterns[0]: the policy file excludes by label only, and a broken spec belongs in a quarantine file", path)
	}
	return nil
}

// section is the tree a config file sits in: suite or quarantine when its
// directory has that name, and cluster when its directory's parent is named
// cluster, since a cluster fragment's directory is the dimension it sets.
// Anything else is the empty section.
func section(path string) string {
	dir := filepath.Dir(path)
	switch base := filepath.Base(dir); base {
	case "suite", "quarantine":
		return base
	}
	if filepath.Base(filepath.Dir(dir)) == "cluster" {
		return "cluster"
	}
	return ""
}
