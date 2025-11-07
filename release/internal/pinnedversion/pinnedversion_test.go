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
	t.Run("without operator", func(t *testing.T) {
		expectedComponents := map[string]registry.Component{
			"typha":                        {Version: "v3.31.0", Image: "typha"},
			"calicoctl":                    {Version: "v3.31.0", Image: "ctl"},
			"node":                         {Version: "v3.31.0", Image: "node"},
			"cni":                          {Version: "v3.31.0", Image: "cni"},
			"apiserver":                    {Version: "v3.31.0", Image: "apiserver"},
			"kube-controllers":             {Version: "v3.31.0", Image: "kube-controllers"},
			"goldmane":                     {Version: "v3.31.0", Image: "goldmane"},
			"flannel":                      {Version: "v0.12.0", Image: "coreos/flannel", Registry: "quay.io"},
			"flannel-migration-controller": {Version: "v3.31.0", Image: "flannel-migration-controller"},
			"dikastes":                     {Version: "v3.31.0", Image: "dikastes"},
			"envoy-gateway":                {Version: "v3.31.0", Image: "envoy-gateway"},
			"envoy-proxy":                  {Version: "v3.31.0", Image: "envoy-proxy"},
			"envoy-ratelimit":              {Version: "v3.31.0", Image: "envoy-ratelimit"},
			"flexvol":                      {Version: "v3.31.0", Image: "pod2daemon-flexvol"},
			"key-cert-provisioner":         {Version: "v3.31.0", Image: "key-cert-provisioner"},
			"test-signer":                  {Version: "v3.31.0", Image: "test-signer"},
			"csi":                          {Version: "v3.31.0", Image: "csi"},
			"csi-node-driver-registrar":    {Version: "v3.31.0", Image: "node-driver-registrar"},
			"cni-windows":                  {Version: "v3.31.0", Image: "cni-windows"},
			"node-windows":                 {Version: "v3.31.0", Image: "node-windows"},
			"guardian":                     {Version: "v3.31.0", Image: "guardian"},
			"whisker":                      {Version: "v3.31.0", Image: "whisker"},
			"whisker-backend":              {Version: "v3.31.0", Image: "whisker-backend"},
		}
		actualComponents := p.ImageComponents(false)
		if diff := cmp.Diff(expectedComponents, actualComponents); diff != "" {
			t.Errorf("expected components to be same, but they differ: %s", diff)
		}
	})
	t.Run("with operator", func(t *testing.T) {
		expectedComponents := map[string]registry.Component{
			"typha":                        {Version: "v3.31.0", Image: "typha"},
			"calicoctl":                    {Version: "v3.31.0", Image: "ctl"},
			"node":                         {Version: "v3.31.0", Image: "node"},
			"cni":                          {Version: "v3.31.0", Image: "cni"},
			"apiserver":                    {Version: "v3.31.0", Image: "apiserver"},
			"kube-controllers":             {Version: "v3.31.0", Image: "kube-controllers"},
			"goldmane":                     {Version: "v3.31.0", Image: "goldmane"},
			"flannel":                      {Version: "v0.12.0", Image: "coreos/flannel", Registry: "quay.io"},
			"flannel-migration-controller": {Version: "v3.31.0", Image: "flannel-migration-controller"},
			"dikastes":                     {Version: "v3.31.0", Image: "dikastes"},
			"envoy-gateway":                {Version: "v3.31.0", Image: "envoy-gateway"},
			"envoy-proxy":                  {Version: "v3.31.0", Image: "envoy-proxy"},
			"envoy-ratelimit":              {Version: "v3.31.0", Image: "envoy-ratelimit"},
			"flexvol":                      {Version: "v3.31.0", Image: "pod2daemon-flexvol"},
			"key-cert-provisioner":         {Version: "v3.31.0", Image: "key-cert-provisioner"},
			"test-signer":                  {Version: "v3.31.0", Image: "test-signer"},
			"csi":                          {Version: "v3.31.0", Image: "csi"},
			"csi-node-driver-registrar":    {Version: "v3.31.0", Image: "node-driver-registrar"},
			"cni-windows":                  {Version: "v3.31.0", Image: "cni-windows"},
			"node-windows":                 {Version: "v3.31.0", Image: "node-windows"},
			"guardian":                     {Version: "v3.31.0", Image: "guardian"},
			"whisker":                      {Version: "v3.31.0", Image: "whisker"},
			"whisker-backend":              {Version: "v3.31.0", Image: "whisker-backend"},
			"tigera/operator":              {Version: "v1.40.0-v3.31.0", Image: "tigera/operator", Registry: "docker.io"},
			"tigera/operator-init":         {Version: "v1.40.0-v3.31.0", Image: "tigera/operator-init", Registry: "docker.io"},
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

func TestGenerateOperatorComponents(t *testing.T) {
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
	op, path, err := GenerateOperatorComponents(dir, dir)
	if err != nil {
		t.Fatalf("failed to generate operator components: %v", err)
	}
	expectedOperator := registry.OperatorComponent{
		Component: registry.Component{
			Version:  "v1.40.0-v3.31.0",
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
	approvals.VerifyString(t, string(content), approvals.Options().WithScrubber(dateApprovalScrubber))
}
