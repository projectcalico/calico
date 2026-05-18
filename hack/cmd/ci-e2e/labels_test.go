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
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPathLabels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "path-labels.yaml")
	os.WriteFile(path, []byte(`path_labels:
  - paths: ["felix/bpf-*", "felix/bpf_*"]
    profiles: ["bpf-gcp"]
    labels: "Feature:BPF"
    reason: "BPF dataplane changes"
  - paths: ["felix/rules*", "felix/calc*"]
    profiles: ["bpf-gcp", "iptables-gcp"]
    labels: "Feature:Policy"
    reason: "policy calculation changes"
`), 0o644)

	rules, err := loadPathLabels(path)
	if err != nil {
		t.Fatalf("loadPathLabels: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestSuggestLabels(t *testing.T) {
	rules := []PathLabelRule{
		{
			Paths:    []string{"felix/bpf-*", "felix/bpf_*"},
			Profiles: []string{"bpf-gcp"},
			Labels:   "Feature:BPF",
			Reason:   "BPF dataplane changes",
		},
		{
			Paths:    []string{"felix/rules*", "felix/calc*"},
			Profiles: []string{"bpf-gcp", "iptables-gcp"},
			Labels:   "Feature:Policy",
			Reason:   "policy calculation changes",
		},
	}

	tests := []struct {
		name         string
		profile      string
		changedFiles []string
		wantLabel    string
		wantReason   string
	}{
		{
			name:         "BPF file matches BPF profile",
			profile:      "bpf-gcp",
			changedFiles: []string{"felix/bpf-maps/map.go"},
			wantLabel:    "Feature:BPF",
			wantReason:   "BPF dataplane changes",
		},
		{
			name:         "calc file matches multiple profiles",
			profile:      "iptables-gcp",
			changedFiles: []string{"felix/calc/calc.go"},
			wantLabel:    "Feature:Policy",
			wantReason:   "policy calculation changes",
		},
		{
			name:         "no match returns empty",
			profile:      "bpf-gcp",
			changedFiles: []string{"node/pkg/something.go"},
			wantLabel:    "",
			wantReason:   "",
		},
		{
			name:         "wrong profile returns empty",
			profile:      "windows",
			changedFiles: []string{"felix/bpf-maps/map.go"},
			wantLabel:    "",
			wantReason:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, reason := suggestLabels(rules, tt.profile, tt.changedFiles)
			if label != tt.wantLabel {
				t.Errorf("label = %q, want %q", label, tt.wantLabel)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestSuggestLabelsMultipleMatches(t *testing.T) {
	rules := []PathLabelRule{
		{
			Paths:    []string{"felix/bpf-*"},
			Profiles: []string{"bpf-gcp"},
			Labels:   "Feature:BPF",
			Reason:   "BPF dataplane changes",
		},
		{
			Paths:    []string{"felix/calc*"},
			Profiles: []string{"bpf-gcp"},
			Labels:   "Feature:Policy",
			Reason:   "policy calculation changes",
		},
	}

	label, _ := suggestLabels(rules, "bpf-gcp", []string{
		"felix/bpf-maps/map.go",
		"felix/calc/graph.go",
	})
	if label != "Feature:BPF || Feature:Policy" {
		t.Errorf("expected combined labels, got %q", label)
	}
}
