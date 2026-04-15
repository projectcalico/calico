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
	"strings"
)

// GinkgoFlags holds the ginkgo CLI flag values generated from a Config.
type GinkgoFlags struct {
	// LabelFilter is the value for --ginkgo.label-filter.
	LabelFilter string

	// SkipPatterns is the list of regex patterns for --ginkgo.skip.
	SkipPatterns []string
}

// SkipString returns the combined skip patterns as a single regex string
// suitable for --ginkgo.skip, or empty string if there are no patterns.
func (f *GinkgoFlags) SkipString() string {
	if len(f.SkipPatterns) == 0 {
		return ""
	}
	return "(" + strings.Join(f.SkipPatterns, "|") + ")"
}

// ToFlags converts a resolved Config into GinkgoFlags.
func ToFlags(cfg *Config) (*GinkgoFlags, error) {
	flags := &GinkgoFlags{}

	labelFilter, err := buildLabelFilter(cfg)
	if err != nil {
		return nil, err
	}
	flags.LabelFilter = labelFilter

	for _, entry := range cfg.Exclude.NamePatterns {
		flags.SkipPatterns = append(flags.SkipPatterns, entry.AllPatterns()...)
	}

	return flags, nil
}

// buildLabelFilter constructs the --ginkgo.label-filter expression from the
// config's include and exclude labels.
func buildLabelFilter(cfg *Config) (string, error) {
	if len(cfg.Include) == 0 && len(cfg.Exclude.Labels) == 0 {
		return "", nil
	}

	var parts []string

	// Build the include expression: (expr1 || expr2 || ...)
	// Each entry is wrapped in parens to preserve precedence when entries
	// contain && or || operators internally.
	if len(cfg.Include) > 0 {
		var includeExprs []string
		for _, entry := range cfg.Include {
			includeExprs = append(includeExprs, "("+entry.Label+")")
		}

		includeStr := strings.Join(includeExprs, " || ")
		if len(includeExprs) > 1 && len(cfg.Exclude.Labels) > 0 {
			includeStr = "(" + includeStr + ")"
		}
		parts = append(parts, includeStr)
	}

	// Append exclude labels: && !Label1 && !Label2 ...
	for _, entry := range cfg.Exclude.Labels {
		label := entry.Label
		if strings.ContainsAny(label, " |&!()") {
			return "", fmt.Errorf("exclude label %q contains operators; use simple labels only", label)
		}
		parts = append(parts, "!"+label)
	}

	return strings.Join(parts, " && "), nil
}
