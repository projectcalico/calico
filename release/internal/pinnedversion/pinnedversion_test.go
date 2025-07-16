// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package pinnedversion

import (
	"os"
	"path/filepath"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/google/go-cmp/cmp"

	"github.com/projectcalico/calico/release/internal/registry"
)

func TestGeneratePinnedVersionFileFromTemplate(t *testing.T) {
	data := &calicoTemplateData{
		ReleaseName:    "test-release",
		BaseDomain:     "example.com",
		ProductVersion: "vX.Y.Z",
		Operator: registry.Component{
			Version:  "vA.B.C",
			Image:    "tigera/operator",
			Registry: "docker.io",
		},
		Hash:          "vX.Y.Z-vA.B.C",
		Note:          "Test note",
		ReleaseBranch: "release-v1.0",
	}
	outputDir := t.TempDir()

	err := generatePinnedVersionFile(data, outputDir)
	if err != nil {
		t.Fatalf("failed to generate pinned version file: %v", err)
	}

	pinnedVersionPath := PinnedVersionFilePath(outputDir)
	if _, err := os.Stat(pinnedVersionPath); err != nil {
		t.Fatalf("pinned version file not created: %v", err)
	}
	content, err := os.ReadFile(pinnedVersionPath)
	if err != nil {
		t.Fatalf("failed to read pinned version file: %v", err)
	}
	approvals.VerifyString(t, string(content))
}

func TestGenerateOperatorComponents(t *testing.T) {
	dir := t.TempDir()
	data := &calicoTemplateData{
		ReleaseName:    "test-release",
		BaseDomain:     "example.com",
		ProductVersion: "vX.Y.Z",
		Operator: registry.Component{
			Version:  "vA.B.C",
			Image:    "tigera/operator",
			Registry: "docker.io",
		},
		Hash:          "vX.Y.Z-vA.B.C",
		Note:          "Test note",
		ReleaseBranch: "release-v1.0",
	}
	err := generatePinnedVersionFile(data, dir)
	if err != nil {
		t.Fatalf("failed to generate pinned version file: %v", err)
	}
	op, path, err := GenerateOperatorComponents(dir, dir)
	if err != nil {
		t.Fatalf("failed to generate operator components: %v", err)
	}
	expectedOperator := registry.OperatorComponent{
		Component: registry.Component{
			Version:  "vA.B.C",
			Image:    "tigera/operator",
			Registry: "docker.io",
		},
	}
	if op != expectedOperator {
		t.Errorf("expected operator %v, got %v", expectedOperator, op)
	}
	expectedPath := filepath.Join(dir, operatorComponentsFileName)
	if path != expectedPath {
		t.Errorf("expected operator components file path %s, got %s", expectedPath, path)
	}
	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read operator components file: %v", err)
	}
	approvals.VerifyString(t, string(content))
}

func TestRetrieveImageComponents(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		dir := t.TempDir()
		data := &calicoTemplateData{
			ReleaseName:    "test-release",
			BaseDomain:     "example.com",
			ProductVersion: "vX.Y.Z",
			Operator: registry.Component{
				Version:  "vA.B.C",
				Image:    "tigera/operator",
				Registry: "docker.io",
			},
			Hash:          "vX.Y.Z-vA.B.C",
			Note:          "Test note",
			ReleaseBranch: "release-v1.0",
		}
		err := generatePinnedVersionFile(data, dir)
		if err != nil {
			t.Fatalf("failed to generate pinned version file: %v", err)
		}
		retrievedComponents, err := RetrieveImageComponents(dir)
		if err != nil {
			t.Fatalf("failed to retrieve image components: %v", err)
		}
		expectedComponents := map[string]registry.Component{
			"typha":                            {Version: "vX.Y.Z", Image: "typha"},
			"calicoctl":                        {Version: "vX.Y.Z", Image: "ctl"},
			"calico/node":                      {Version: "vX.Y.Z", Image: "node"},
			"calico/cni":                       {Version: "vX.Y.Z", Image: "cni"},
			"calico/apiserver":                 {Version: "vX.Y.Z", Image: "apiserver"},
			"calico/kube-controllers":          {Version: "vX.Y.Z", Image: "kube-controllers"},
			"calico/goldmane":                  {Version: "vX.Y.Z", Image: "goldmane"},
			"calico/dikastes":                  {Version: "vX.Y.Z", Image: "dikastes"},
			"calico/envoy-gateway":             {Version: "vX.Y.Z", Image: "envoy-gateway"},
			"calico/envoy-proxy":               {Version: "vX.Y.Z", Image: "envoy-proxy"},
			"calico/envoy-ratelimit":           {Version: "vX.Y.Z", Image: "envoy-ratelimit"},
			"flexvol":                          {Version: "vX.Y.Z", Image: "pod2daemon-flexvol"},
			"key-cert-provisioner":             {Version: "vX.Y.Z", Image: "key-cert-provisioner"},
			"calico/csi":                       {Version: "vX.Y.Z", Image: "csi"},
			"calico/csi-node-driver-registrar": {Version: "vX.Y.Z", Image: "node-driver-registrar"},
			"calico/cni-windows":               {Version: "vX.Y.Z", Image: "cni-windows"},
			"calico/node-windows":              {Version: "vX.Y.Z", Image: "node-windows"},
			"calico/guardian":                  {Version: "vX.Y.Z", Image: "guardian"},
			"calico/whisker":                   {Version: "vX.Y.Z", Image: "whisker"},
			"calico/whisker-backend":           {Version: "vX.Y.Z", Image: "whisker-backend"},
			"tigera/operator":                  {Version: "vA.B.C", Image: "tigera/operator", Registry: "docker.io"},
			"tigera/operator-init":             {Version: "vA.B.C", Image: "tigera/operator-init", Registry: "docker.io"},
		}
		if cmp.Equal(expectedComponents, retrievedComponents) {
			t.Errorf("expected components to be same, but they differ: %s", cmp.Diff(expectedComponents, retrievedComponents))
		}
	})

	t.Run("operator in calico namespace", func(t *testing.T) {
		dir := t.TempDir()
		data := &calicoTemplateData{
			ReleaseName:    "test-release",
			BaseDomain:     "example.com",
			ProductVersion: "vX.Y.Z",
			Operator: registry.Component{
				Version: "vA.B.C",
				Image:   "calico/operator",
			},
			Hash:          "vX.Y.Z-vA.B.C",
			Note:          "Test note",
			ReleaseBranch: "release-v1.0",
		}
		err := generatePinnedVersionFile(data, dir)
		if err != nil {
			t.Fatalf("failed to generate pinned version file: %v", err)
		}
		retrievedComponents, err := RetrieveImageComponents(dir)
		if err != nil {
			t.Fatalf("failed to retrieve image components: %v", err)
		}
		expectedComponents := map[string]registry.Component{
			"typha":                            {Version: "vX.Y.Z", Image: "typha"},
			"calicoctl":                        {Version: "vX.Y.Z", Image: "ctl"},
			"calico/node":                      {Version: "vX.Y.Z", Image: "node"},
			"calico/cni":                       {Version: "vX.Y.Z", Image: "cni"},
			"calico/apiserver":                 {Version: "vX.Y.Z", Image: "apiserver"},
			"calico/kube-controllers":          {Version: "vX.Y.Z", Image: "kube-controllers"},
			"calico/goldmane":                  {Version: "vX.Y.Z", Image: "goldmane"},
			"calico/dikastes":                  {Version: "vX.Y.Z", Image: "dikastes"},
			"calico/envoy-gateway":             {Version: "vX.Y.Z", Image: "envoy-gateway"},
			"calico/envoy-proxy":               {Version: "vX.Y.Z", Image: "envoy-proxy"},
			"calico/envoy-ratelimit":           {Version: "vX.Y.Z", Image: "envoy-ratelimit"},
			"flexvol":                          {Version: "vX.Y.Z", Image: "pod2daemon-flexvol"},
			"key-cert-provisioner":             {Version: "vX.Y.Z", Image: "key-cert-provisioner"},
			"calico/csi":                       {Version: "vX.Y.Z", Image: "csi"},
			"calico/csi-node-driver-registrar": {Version: "vX.Y.Z", Image: "node-driver-registrar"},
			"calico/cni-windows":               {Version: "vX.Y.Z", Image: "cni-windows"},
			"calico/node-windows":              {Version: "vX.Y.Z", Image: "node-windows"},
			"calico/guardian":                  {Version: "vX.Y.Z", Image: "guardian"},
			"calico/whisker":                   {Version: "vX.Y.Z", Image: "whisker"},
			"calico/whisker-backend":           {Version: "vX.Y.Z", Image: "whisker-backend"},
			"calico/operator":                  {Version: "vA.B.C", Image: "calico/operator"},
			"calico/operator-init":             {Version: "vA.B.C", Image: "calico/operator-init"},
		}
		if cmp.Equal(expectedComponents, retrievedComponents) {
			t.Errorf("expected components to be same, but they differ: %s", cmp.Diff(expectedComponents, retrievedComponents))
		}
	})
}

func TestNormalizeComponent(t *testing.T) {
	for _, tt := range []struct {
		componentName string
		component     registry.Component
		expected      registry.Component
	}{
		// components in registry.ImageMap
		{
			componentName: "typha",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "typha",
			},
		},
		{
			componentName: "calicoctl",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "ctl",
			},
		},
		{
			componentName: "flannel",
			component: registry.Component{
				Version:  "v0.14.0",
				Registry: "quay.io",
			},
			expected: registry.Component{
				Version:  "v0.14.0",
				Image:    "coreos/flannel",
				Registry: "quay.io",
			},
		},
		{
			componentName: "flexvol",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "pod2daemon-flexvol",
			},
		},
		{
			componentName: "key-cert-provisioner",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "key-cert-provisioner",
			},
		},
		{
			componentName: "csi-node-driver-registrar",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "node-driver-registrar",
			},
		},
		// components not in registry.ImageMap
		{
			componentName: "calico/cni",
			component: registry.Component{
				Version: "v1.0.0",
				Image:   "cni",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "cni",
			},
		},
	} {
		t.Run(tt.componentName, func(t *testing.T) {
			got := normalizeComponent(tt.componentName, tt.component)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}
