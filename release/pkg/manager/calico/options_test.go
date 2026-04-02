// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package calico

import (
	"testing"
)

func TestWithImages(t *testing.T) {
	m := &CalicoManager{}
	if err := WithImages(true)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.images {
		t.Error("expected images=true")
	}
	if err := WithImages(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.images {
		t.Error("expected images=false")
	}
}

func TestWithArchiveImages(t *testing.T) {
	m := &CalicoManager{}
	if err := WithArchiveImages(true)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.archiveImages {
		t.Error("expected archiveImages=true")
	}
}

func TestWithHelmCharts(t *testing.T) {
	m := &CalicoManager{}
	if err := WithHelmCharts(true)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.helmCharts {
		t.Error("expected helmCharts=true")
	}
	if err := WithHelmCharts(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.helmCharts {
		t.Error("expected helmCharts=false")
	}
}

func TestWithHelmIndex(t *testing.T) {
	m := &CalicoManager{}
	if err := WithHelmIndex(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.helmIndex {
		t.Error("expected helmIndex=false")
	}
}

func TestWithManifests(t *testing.T) {
	m := &CalicoManager{}
	if err := WithManifests(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.manifests {
		t.Error("expected manifests=false")
	}
}

func TestWithBinaries(t *testing.T) {
	m := &CalicoManager{}
	if err := WithBinaries(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.binaries {
		t.Error("expected binaries=false")
	}
}

func TestWithOCPBundle(t *testing.T) {
	m := &CalicoManager{}
	if err := WithOCPBundle(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.ocpBundle {
		t.Error("expected ocpBundle=false")
	}
}

func TestWithTarball(t *testing.T) {
	m := &CalicoManager{}
	if err := WithTarball(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.tarball {
		t.Error("expected tarball=false")
	}
}

func TestWithGitRef(t *testing.T) {
	m := &CalicoManager{}
	if err := WithGitRef(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.gitRef {
		t.Error("expected gitRef=false")
	}
}

func TestWithGithubRelease(t *testing.T) {
	m := &CalicoManager{}
	if err := WithGithubRelease(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.githubRelease {
		t.Error("expected githubRelease=false")
	}
}

func TestWithWindowsArchive(t *testing.T) {
	m := &CalicoManager{}
	if err := WithWindowsArchive(false)(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.windowsArchive {
		t.Error("expected windowsArchive=false")
	}
}
