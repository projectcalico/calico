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

	"gopkg.in/yaml.v3"
)

// Config is the top-level structure for an e2e test selection config file.
// It defines which tests to include and exclude using Ginkgo v2 labels and
// test name patterns.
type Config struct {
	// Extends is an optional path to a parent config file (relative to this
	// file's directory). The parent's include and exclude lists are inherited
	// and appended to by this config.
	Extends string `yaml:"extends,omitempty"`

	// Include is a list of label expressions. Tests matching ANY of these
	// expressions are selected to run. When a parent config is extended,
	// include entries are appended (OR'd together).
	Include []IncludeEntry `yaml:"include,omitempty"`

	// Exclude defines labels and name patterns to exclude from the selected
	// tests. When a parent config is extended, exclude entries are appended.
	Exclude Exclude `yaml:"exclude,omitempty"`
}

// IncludeEntry is a label expression to include in the test selection. It
// supports two YAML forms:
//
//	# Simple form - bare string
//	- sig-calico
//
//	# Object form - with optional reason
//	- label: Conformance && sig-network
//	  reason: "only run networking conformance tests"
type IncludeEntry struct {
	Label  string `yaml:"label"`
	Reason string `yaml:"reason,omitempty"`
}

// UnmarshalYAML implements custom unmarshaling for IncludeEntry to support
// both bare string and object forms.
func (e *IncludeEntry) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		e.Label = value.Value
		return nil
	}

	type raw IncludeEntry
	var r raw
	if err := value.Decode(&r); err != nil {
		return fmt.Errorf("invalid include entry: %w", err)
	}
	if r.Label == "" {
		return fmt.Errorf("include entry must have a 'label' field (line %d)", value.Line)
	}
	*e = IncludeEntry(r)
	return nil
}

// Exclude defines what to exclude from the test selection.
type Exclude struct {
	// Labels is a list of label exclusions. Each label is AND'd into the
	// label-filter as a negation (e.g., !Slow && !Disruptive). A reason is
	// required to document why the label is excluded.
	Labels []ExcludeLabel `yaml:"labels,omitempty"`

	// NamePatterns is a list of test name regex patterns to exclude via
	// --ginkgo.skip. These are used for upstream tests that don't have
	// appropriate Ginkgo labels.
	NamePatterns []NamePatternEntry `yaml:"namePatterns,omitempty"`
}

// ExcludeLabel is a label to exclude from the test selection.
type ExcludeLabel struct {
	// Label is the Ginkgo label to exclude (e.g., "Slow", "Feature:SCTP").
	Label string `yaml:"label"`

	// Reason documents why this label is excluded. Required.
	Reason string `yaml:"reason"`
}

// NamePatternEntry is a test name pattern to exclude. It supports two forms:
//
//	# Single pattern
//	- pattern: "DataPath"
//	  reason: "directory-based test name, not a Ginkgo label"
//
//	# Group of patterns sharing a reason
//	- group: "EKS control plane can't reach pod network"
//	  link: "https://docs.tigera.io/..."
//	  patterns:
//	    - "both.pod.and.service.Proxy"
//	    - "DNS.for.*"
type NamePatternEntry struct {
	// Single pattern form.
	Pattern string `yaml:"pattern,omitempty"`
	Reason  string `yaml:"reason,omitempty"`

	// Group form - multiple patterns sharing a reason.
	Group    string   `yaml:"group,omitempty"`
	Link     string   `yaml:"link,omitempty"`
	Patterns []string `yaml:"patterns,omitempty"`
}

// Validate checks that the entry has either a single pattern (which must
// carry a reason) or a group with patterns (where the group name itself
// documents the shared reason, supplemented by an optional link). Both forms
// satisfy the requirement that every exclusion is documented.
func (e *NamePatternEntry) Validate() error {
	hasSingle := e.Pattern != ""
	hasGroup := e.Group != "" || len(e.Patterns) > 0

	if hasSingle && hasGroup {
		return fmt.Errorf("namePattern entry cannot have both 'pattern' and 'group'/'patterns'")
	}
	if !hasSingle && !hasGroup {
		return fmt.Errorf("namePattern entry must have either 'pattern' or 'group' with 'patterns'")
	}
	if hasSingle && e.Reason == "" {
		return fmt.Errorf("namePattern %q must have a 'reason'", e.Pattern)
	}
	if hasGroup && e.Group == "" {
		return fmt.Errorf("namePattern group entries must set the 'group' field")
	}
	if hasGroup && len(e.Patterns) == 0 {
		return fmt.Errorf("namePattern group %q must have at least one pattern", e.Group)
	}
	return nil
}

// AllPatterns returns the list of regex patterns from this entry, regardless
// of whether it's a single pattern or a group.
func (e *NamePatternEntry) AllPatterns() []string {
	if e.Pattern != "" {
		return []string{e.Pattern}
	}
	return e.Patterns
}
