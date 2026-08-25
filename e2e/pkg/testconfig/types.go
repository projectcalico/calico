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
	// Extends names parent config files (relative to this file's directory)
	// whose include and exclude lists this config inherits. Parents are merged
	// left-to-right and this config's own entries are appended last, so a lane
	// can compose a pipeline's scope with a shared platform exclusion list.
	Extends ExtendsList `yaml:"extends,omitempty"`

	// Include selects which tests run, by label expression and, where a lane
	// needs a spec the labels cannot reach, by test name pattern. When a parent
	// config is extended, include entries are appended (OR'd together).
	Include IncludeList `yaml:"include,omitempty"`

	// Exclude defines labels and name patterns to exclude from the selected
	// tests. When a parent config is extended, exclude entries are appended.
	Exclude Exclude `yaml:"exclude,omitempty"`

	// Enable cancels a label exclusion this config inherits, for a lane whose
	// cluster does provide what the label needs. Each entry must match a label
	// an ancestor excludes.
	Enable []EnableLabel `yaml:"enable,omitempty"`
}

// ExtendsList is the parent list for a config. It accepts a bare string for the
// single-parent case and a sequence for composition:
//
//	extends: pipeline.yaml
//	extends: [pipeline.yaml, ../platform/eks.yaml]
type ExtendsList []string

// UnmarshalYAML implements custom unmarshaling for ExtendsList to support both
// the bare string and sequence forms.
func (e *ExtendsList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*e = ExtendsList{value.Value}
		return nil
	}

	var parents []string
	if err := value.Decode(&parents); err != nil {
		return fmt.Errorf("invalid extends (want a path or a list of paths): %w", err)
	}
	for i, p := range parents {
		if p == "" {
			return fmt.Errorf("extends[%d] is empty (line %d)", i, value.Line)
		}
	}
	*e = parents
	return nil
}

// IncludeList is the include section of a config. It accepts a bare sequence
// of label expressions for the common case, and a mapping when a config also
// needs name patterns:
//
//	include:
//	  - Conformance && sig-network
//
//	include:
//	  labels:
//	    - Conformance && sig-network
//	  namePatterns:
//	    - pattern: "should serve a basic endpoint from pods"
//	      reason: "smoke check before the dataplane exists"
type IncludeList struct {
	// Labels is a list of label expressions. Tests matching ANY of these
	// expressions are selected to run.
	Labels []IncludeEntry `yaml:"labels,omitempty"`

	// NamePatterns is a list of test name regex patterns to select via
	// --ginkgo.focus, for specs no label expression can reach.
	NamePatterns []NamePatternEntry `yaml:"namePatterns,omitempty"`
}

// UnmarshalYAML implements custom unmarshaling for IncludeList to support both
// the bare sequence and mapping forms.
func (l *IncludeList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		return value.Decode(&l.Labels)
	}

	type raw IncludeList
	var r raw
	if err := value.Decode(&r); err != nil {
		return fmt.Errorf("invalid include (want a list of labels or a mapping): %w", err)
	}
	*l = IncludeList(r)
	return nil
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

// EnableLabel is an inherited label exclusion to cancel.
type EnableLabel struct {
	// Label is the Ginkgo label to re-include (e.g., "Feature:Wireguard").
	Label string `yaml:"label"`

	// Reason documents what this lane provides that the label needs. Required.
	Reason string `yaml:"reason"`
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
