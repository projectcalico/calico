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
	"testing"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/google/go-cmp/cmp"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

var dateApprovalScrubber = approvals.NewDateScrubber(`[a-zA-Z]{3}, \d{1,2} [a-zA-Z]{3} \d{4} \d{2}:\d{2}:\d{2} [A-Z]{3}`)

func TestImageComponents(t *testing.T) {
	dir := t.TempDir()
	rootDir, err := command.GitDir()
	if err != nil {
		t.Fatalf("failed to get git root dir: %v", err)
	}
	c := &CalicoPinnedVersions{
		Dir:                 dir,
		RootDir:             rootDir,
		ReleaseBranchPrefix: "release",
		OperatorCfg: OperatorConfig{
			Image:    "tigera/operator",
			Registry: "docker.io",
			Branch:   "release-v1.40",
		},
		releaseName:   "test-release",
		productBranch: "release-v3.31",
		versionData:   version.NewHashreleaseVersions(version.New("v3.31.0"), "v1.40.0"),
	}
	if err := generatePinnedVersionFile(c); err != nil {
		t.Fatalf("failed to generate pinned version file: %v", err)
	}

	p, err := retrievePinnedVersion(dir)
	if err != nil {
		t.Fatalf("failed to retrieve pinned version: %v", err)
	}
	// The combined calico image (from cmd/calico) bundles typha, apiserver,
	// kube-controllers, dikastes, goldmane, guardian, whisker-backend,
	// key-cert-provisioner, CSI, flexvol, webhooks, and the Linux CNI
	// plugin. Those components no longer get independent entries.
	// "calico" is listed in the pinned version file as a meta-component
	// representing the product release, but it is filtered out by
	// ImageComponents (see noImageComponents), so the expected maps below
	// do not include it.
	commonComponents := map[string]registry.Component{
		"node":              {Version: "v3.31.0", Image: "node"},
		"node-windows":      {Version: "v3.31.0", Image: "node-windows"},
		"cni-windows":       {Version: "v3.31.0", Image: "cni-windows"},
		"flannel":           {Version: "v0.12.0", Image: "coreos/flannel", Registry: "quay.io"},
		"envoy-gateway":     {Version: "v3.31.0", Image: "envoy-gateway"},
		"envoy-proxy":       {Version: "v3.31.0", Image: "envoy-proxy"},
		"envoy-ratelimit":   {Version: "v3.31.0", Image: "envoy-ratelimit"},
		"whisker":           {Version: "v3.31.0", Image: "whisker"},
		"istio-install-cni": {Version: "v3.31.0", Image: "istio-install-cni"},
		"istio-pilot":       {Version: "v3.31.0", Image: "istio-pilot"},
		"istio-proxyv2":     {Version: "v3.31.0", Image: "istio-proxyv2"},
		"istio-ztunnel":     {Version: "v3.31.0", Image: "istio-ztunnel"},
	}
	t.Run("without operator", func(t *testing.T) {
		expectedComponents := map[string]registry.Component{}
		for k, v := range commonComponents {
			expectedComponents[k] = v
		}
		actualComponents := p.ImageComponents(false)
		if diff := cmp.Diff(expectedComponents, actualComponents); diff != "" {
			t.Errorf("expected components to be same, but they differ: %s", diff)
		}
	})
	t.Run("with operator", func(t *testing.T) {
		expectedComponents := map[string]registry.Component{
			"tigera/operator": {Version: "v1.40.0-v3.31.0", Image: "tigera/operator", Registry: "docker.io"},
		}
		for k, v := range commonComponents {
			expectedComponents[k] = v
		}
		actualComponents := p.ImageComponents(true)
		if diff := cmp.Diff(expectedComponents, actualComponents); diff != "" {
			t.Errorf("expected components to be same, but they differ: %s", diff)
		}
	})
}

func TestGeneratePinnedVersionFile(t *testing.T) {
	dir := t.TempDir()
	rootDir, err := command.GitDir()
	if err != nil {
		t.Fatalf("failed to get git root dir: %v", err)
	}
	p := &CalicoPinnedVersions{
		Dir:                 dir,
		RootDir:             rootDir,
		ReleaseBranchPrefix: "release",
		OperatorCfg: OperatorConfig{
			Image:    "tigera/operator",
			Registry: "docker.io",
			Branch:   "release-v1.40",
		},
		releaseName:   "test-release",
		productBranch: "release-v3.31",
		versionData:   version.NewHashreleaseVersions(version.New("v3.31.0"), "v1.40.0"),
	}
	if err := generatePinnedVersionFile(p); err != nil {
		t.Fatalf("failed to generate pinned version file: %v", err)
	}
	pinnedVersionPath := PinnedVersionFilePath(dir)
	if _, err := os.Stat(pinnedVersionPath); err != nil {
		t.Fatalf("pinned version file not created: %v", err)
	}
	content, err := os.ReadFile(pinnedVersionPath)
	if err != nil {
		t.Fatalf("failed to read pinned version file: %v", err)
	}
	approvals.VerifyString(t, string(content), approvals.Options().WithScrubber(dateApprovalScrubber))
}
