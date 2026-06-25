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

func TestLoadProfiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	os.WriteFile(path, []byte(`profiles:
  bpf-gcp:
    description: "BPF dataplane on GCP kubeadm"
    semaphore_pipeline: end-to-end/pipelines/bpf.yml
    default_label_filter: ""
  iptables-gcp:
    description: "iptables dataplane on GCP kubeadm"
    semaphore_pipeline: end-to-end/pipelines/iptables.yml
    default_label_filter: "Feature:IPTables"
`), 0o644)

	profiles, err := loadProfiles(path)
	if err != nil {
		t.Fatalf("loadProfiles: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
	p, ok := profiles["bpf-gcp"]
	if !ok {
		t.Fatal("missing bpf-gcp profile")
	}
	if p.Description != "BPF dataplane on GCP kubeadm" {
		t.Errorf("unexpected description: %s", p.Description)
	}
	if p.SemaphorePipeline != "end-to-end/pipelines/bpf.yml" {
		t.Errorf("unexpected pipeline: %s", p.SemaphorePipeline)
	}
}

func TestLoadProfilesFileNotFound(t *testing.T) {
	_, err := loadProfiles("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateProfile(t *testing.T) {
	profiles := map[string]Profile{
		"bpf-gcp": {Description: "BPF", SemaphorePipeline: "bpf.yml"},
	}

	if _, err := validateProfile(profiles, "bpf-gcp"); err != nil {
		t.Errorf("expected valid profile: %v", err)
	}
	if _, err := validateProfile(profiles, "nonexistent"); err == nil {
		t.Error("expected error for unknown profile")
	}
}
