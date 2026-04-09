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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type PathLabelRule struct {
	Paths    []string `yaml:"paths"`
	Profiles []string `yaml:"profiles"`
	Labels   string   `yaml:"labels"`
	Reason   string   `yaml:"reason"`
}

type pathLabelsFile struct {
	PathLabels []PathLabelRule `yaml:"path_labels"`
}

// loadPathLabels reads the e2e-path-labels.yaml file.
func loadPathLabels(path string) ([]PathLabelRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading path-labels: %w", err)
	}
	var plf pathLabelsFile
	if err := yaml.Unmarshal(data, &plf); err != nil {
		return nil, fmt.Errorf("parsing path-labels: %w", err)
	}
	return plf.PathLabels, nil
}

// suggestLabels returns a combined label-filter expression and reason string
// by matching changed files against path-label rules for the given profile.
func suggestLabels(rules []PathLabelRule, profile string, changedFiles []string) (string, string) {
	var labels []string
	var reasons []string

	for _, rule := range rules {
		if !containsString(rule.Profiles, profile) {
			continue
		}
		if !anyFileMatches(rule.Paths, changedFiles) {
			continue
		}
		if rule.Labels != "" && !containsString(labels, rule.Labels) {
			labels = append(labels, rule.Labels)
		}
		if rule.Reason != "" && !containsString(reasons, rule.Reason) {
			reasons = append(reasons, rule.Reason)
		}
	}

	return strings.Join(labels, " || "), strings.Join(reasons, ", ")
}

// anyFileMatches returns true if any changed file matches any of the glob patterns.
func anyFileMatches(patterns []string, files []string) bool {
	for _, f := range files {
		for _, pat := range patterns {
			if matched, _ := filepath.Match(pat, f); matched {
				return true
			}
			// filepath.Match doesn't handle subdirectory globs like "felix/bpf-*"
			// matching "felix/bpf-maps/map.go". Match against just the file's
			// directory prefix components too.
			dir := f
			for dir != "." && dir != "/" {
				if matched, _ := filepath.Match(pat, dir); matched {
					return true
				}
				dir = filepath.Dir(dir)
			}
		}
	}
	return false
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
