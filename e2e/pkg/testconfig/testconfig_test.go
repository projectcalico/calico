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
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestLoadSimpleConfig(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
include:
  - sig-calico
  - label: Conformance && sig-network
    reason: "only networking conformance"
exclude:
  labels:
    - label: Slow
      reason: "too slow for CI"
    - label: Disruptive
      reason: "breaks cluster state"
  namePatterns:
    - pattern: "DataPath"
      reason: "not a label"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Include) != 2 {
		t.Fatalf("expected 2 includes, got %d", len(cfg.Include))
	}
	if cfg.Include[0].Label != "sig-calico" {
		t.Errorf("include[0] = %q, want sig-calico", cfg.Include[0].Label)
	}
	if cfg.Include[1].Label != "Conformance && sig-network" {
		t.Errorf("include[1] = %q, want Conformance && sig-network", cfg.Include[1].Label)
	}
	if cfg.Include[1].Reason != "only networking conformance" {
		t.Errorf("include[1].reason = %q", cfg.Include[1].Reason)
	}

	if len(cfg.Exclude.Labels) != 2 {
		t.Fatalf("expected 2 exclude labels, got %d", len(cfg.Exclude.Labels))
	}
	if cfg.Exclude.Labels[0].Label != "Slow" {
		t.Errorf("exclude.labels[0] = %q, want Slow", cfg.Exclude.Labels[0].Label)
	}

	if len(cfg.Exclude.NamePatterns) != 1 {
		t.Fatalf("expected 1 namePattern, got %d", len(cfg.Exclude.NamePatterns))
	}
	if cfg.Exclude.NamePatterns[0].Pattern != "DataPath" {
		t.Errorf("namePattern = %q, want DataPath", cfg.Exclude.NamePatterns[0].Pattern)
	}
}

func TestLoadWithExtends(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, "base.yaml", `
include:
  - sig-calico
exclude:
  labels:
    - label: Slow
      reason: "too slow"
`)

	path := writeFile(t, dir, "child.yaml", `
extends: base.yaml
include:
  - Dataplane:BPF
exclude:
  labels:
    - label: Feature:SCTP
      reason: "not supported"
  namePatterns:
    - pattern: "DataPath"
      reason: "not a label"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Includes should be merged: parent's sig-calico + child's Dataplane:BPF
	if len(cfg.Include) != 2 {
		t.Fatalf("expected 2 includes, got %d", len(cfg.Include))
	}
	if cfg.Include[0].Label != "sig-calico" {
		t.Errorf("include[0] = %q, want sig-calico", cfg.Include[0].Label)
	}
	if cfg.Include[1].Label != "Dataplane:BPF" {
		t.Errorf("include[1] = %q, want Dataplane:BPF", cfg.Include[1].Label)
	}

	// Exclude labels should be merged: parent's Slow + child's Feature:SCTP
	if len(cfg.Exclude.Labels) != 2 {
		t.Fatalf("expected 2 exclude labels, got %d", len(cfg.Exclude.Labels))
	}
	if cfg.Exclude.Labels[0].Label != "Slow" {
		t.Errorf("exclude.labels[0] = %q, want Slow", cfg.Exclude.Labels[0].Label)
	}
	if cfg.Exclude.Labels[1].Label != "Feature:SCTP" {
		t.Errorf("exclude.labels[1] = %q, want Feature:SCTP", cfg.Exclude.Labels[1].Label)
	}

	// Name patterns should come from child only (parent had none)
	if len(cfg.Exclude.NamePatterns) != 1 {
		t.Fatalf("expected 1 namePattern, got %d", len(cfg.Exclude.NamePatterns))
	}
}

func TestLoadThreeLevelExtends(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, "base.yaml", `
include:
  - sig-calico
exclude:
  labels:
    - label: Slow
      reason: "too slow"
`)

	writeFile(t, dir, "eks.yaml", `
extends: base.yaml
exclude:
  labels:
    - label: Feature:SCTP
      reason: "not supported on EKS"
  namePatterns:
    - group: "EKS control plane can't reach pods"
      patterns:
        - "DNS.for.*"
        - "Proxy.version.v1"
`)

	path := writeFile(t, dir, "bpf-eks.yaml", `
extends: eks.yaml
include:
  - Dataplane:BPF
exclude:
  namePatterns:
    - pattern: "IPAM.StrictAffinity"
      reason: "not supported with Calico CNI on EKS"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Includes: base's sig-calico + bpf-eks's Dataplane:BPF
	if len(cfg.Include) != 2 {
		t.Fatalf("expected 2 includes, got %d", len(cfg.Include))
	}

	// Exclude labels: base's Slow + eks's Feature:SCTP
	if len(cfg.Exclude.Labels) != 2 {
		t.Fatalf("expected 2 exclude labels, got %d", len(cfg.Exclude.Labels))
	}

	// Name patterns: eks's group (2 patterns) + bpf-eks's single
	if len(cfg.Exclude.NamePatterns) != 2 {
		t.Fatalf("expected 2 namePattern entries, got %d", len(cfg.Exclude.NamePatterns))
	}
}

func TestLoadCircularExtends(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, "a.yaml", `
extends: b.yaml
include:
  - sig-calico
`)
	writeFile(t, dir, "b.yaml", `
extends: a.yaml
include:
  - Dataplane:BPF
`)

	_, err := Load(filepath.Join(dir, "a.yaml"))
	if err == nil {
		t.Fatal("expected error for circular extends")
	}
}

func TestLoadMissingReason(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "bad.yaml", `
exclude:
  labels:
    - label: Slow
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing reason")
	}
}

func TestLoadNamePatternMissingReason(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "bad.yaml", `
exclude:
  namePatterns:
    - pattern: "DataPath"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for namePattern missing reason")
	}
}

func TestLoadGroupNamePattern(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
exclude:
  namePatterns:
    - group: "EKS limitations"
      link: "https://docs.tigera.io/..."
      patterns:
        - "DNS.for.*"
        - "Proxy.version.v1"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	entry := cfg.Exclude.NamePatterns[0]
	if entry.Group != "EKS limitations" {
		t.Errorf("group = %q", entry.Group)
	}
	patterns := entry.AllPatterns()
	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(patterns))
	}
	if patterns[0] != "DNS.for.*" {
		t.Errorf("patterns[0] = %q", patterns[0])
	}
}

func TestToFlagsSimple(t *testing.T) {
	cfg := &Config{
		Include: []IncludeEntry{
			{Label: "sig-calico"},
		},
		Exclude: Exclude{
			Labels: []ExcludeLabel{
				{Label: "Slow", Reason: "too slow"},
				{Label: "Disruptive", Reason: "breaks things"},
			},
		},
	}

	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatalf("ToFlags: %v", err)
	}

	expected := "sig-calico && !Slow && !Disruptive"
	if flags.LabelFilter != expected {
		t.Errorf("LabelFilter = %q, want %q", flags.LabelFilter, expected)
	}
	if flags.SkipString() != "" {
		t.Errorf("SkipString = %q, want empty", flags.SkipString())
	}
}

func TestToFlagsMultipleIncludes(t *testing.T) {
	cfg := &Config{
		Include: []IncludeEntry{
			{Label: "sig-calico"},
			{Label: "Conformance && sig-network"},
			{Label: "Dataplane:BPF"},
		},
		Exclude: Exclude{
			Labels: []ExcludeLabel{
				{Label: "Slow", Reason: "too slow"},
			},
			NamePatterns: []NamePatternEntry{
				{Pattern: "DataPath", Reason: "not a label"},
				{
					Group:    "EKS limitations",
					Patterns: []string{"DNS.for.*", "Proxy.version.v1"},
				},
			},
		},
	}

	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatalf("ToFlags: %v", err)
	}

	expected := "(sig-calico || Conformance && sig-network || Dataplane:BPF) && !Slow"
	if flags.LabelFilter != expected {
		t.Errorf("LabelFilter = %q, want %q", flags.LabelFilter, expected)
	}

	expectedSkip := "(DataPath|DNS.for.*|Proxy.version.v1)"
	if flags.SkipString() != expectedSkip {
		t.Errorf("SkipString = %q, want %q", flags.SkipString(), expectedSkip)
	}
}

func TestToFlagsExcludeOnly(t *testing.T) {
	cfg := &Config{
		Exclude: Exclude{
			Labels: []ExcludeLabel{
				{Label: "Slow", Reason: "too slow"},
			},
		},
	}

	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatalf("ToFlags: %v", err)
	}

	if flags.LabelFilter != "!Slow" {
		t.Errorf("LabelFilter = %q, want !Slow", flags.LabelFilter)
	}
}

func TestToFlagsEmpty(t *testing.T) {
	cfg := &Config{}

	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatalf("ToFlags: %v", err)
	}

	if flags.LabelFilter != "" {
		t.Errorf("LabelFilter = %q, want empty", flags.LabelFilter)
	}
	if flags.SkipString() != "" {
		t.Errorf("SkipString = %q, want empty", flags.SkipString())
	}
}

func TestToFlagsRejectsComplexExcludeLabels(t *testing.T) {
	cfg := &Config{
		Exclude: Exclude{
			Labels: []ExcludeLabel{
				{Label: "Slow || Disruptive", Reason: "compound"},
			},
		},
	}

	_, err := ToFlags(cfg)
	if err == nil {
		t.Fatal("expected error for complex exclude label")
	}
}
