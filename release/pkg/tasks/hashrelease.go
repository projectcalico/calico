// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package tasks

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/utils"
)

// HashreleasePublished checks if the hashrelease has already been published.
// If it has, the process is halted.
func HashreleasePublished(cfg *hashreleaseserver.Config, hash string, ci bool) (bool, error) {
	if !cfg.Valid() {
		// Check if we're running in CI - if so, we should fail if this configuration is missing.
		// Otherwise, we should just log and continue.
		if ci {
			return false, fmt.Errorf("missing hashrelease server configuration")
		}
		logrus.Info("Missing hashrelease server configuration, skipping remote hashrelease check")
		return false, nil
	}

	return hashreleaseserver.HasHashrelease(hash, cfg), nil
}

// ReformatHashrelease modifies the generated release output to match
// the "legacy" format our CI tooling expects. This should be temporary until
// we can update the tooling to expect the new format.
// Specifically, we need to do two things:
// - Copy the windows zip file to files/windows/calico-windows-<ver>.zip
// - Copy tigera-operator-<ver>.tgz to tigera-operator.tgz
// - Copy ocp.tgz to manifests/ocp.tgz
func ReformatHashrelease(hashreleaseDir, tmpDir string) error {
	logrus.Info("Modifying hashrelease output to match legacy format")
	pinned, err := pinnedversion.New(map[string]any{}, tmpDir).(*pinnedversion.CalicoPinnedVersions).Get()
	if err != nil {
		return err
	}

	// Copy the windows zip file to files/windows/calico-windows-<ver>.zip
	if err := os.MkdirAll(filepath.Join(hashreleaseDir, "files", "windows"), 0o755); err != nil {
		return err
	}
	windowsZip := filepath.Join(hashreleaseDir, fmt.Sprintf("calico-windows-%s.zip", pinned.ProductVersion()))
	windowsZipDst := filepath.Join(hashreleaseDir, "files", "windows", fmt.Sprintf("calico-windows-%s.zip", pinned.ProductVersion()))
	if err := utils.CopyFile(windowsZip, windowsZipDst); err != nil {
		return err
	}

	// Copy the ocp.tgz to manifests/ocp.tgz
	ocpTarball := filepath.Join(hashreleaseDir, "ocp.tgz")
	ocpTarballDst := filepath.Join(hashreleaseDir, "manifests", "ocp.tgz")
	if err := utils.CopyFile(ocpTarball, ocpTarballDst); err != nil {
		return err
	}

	// Copy the operator tarball to tigera-operator.tgz
	operatorTarball := filepath.Join(hashreleaseDir, fmt.Sprintf("tigera-operator-%s.tgz", pinned.HelmChartVersion()))
	operatorTarballDst := filepath.Join(hashreleaseDir, "tigera-operator.tgz")
	if err := utils.CopyFile(operatorTarball, operatorTarballDst); err != nil {
		return err
	}
	return nil
}
