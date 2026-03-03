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
func HashreleasePublished(cfg *hashreleaseserver.Config, hash string, ci bool) (bool, error) {
	if !cfg.Valid() {
		// Check if we're running in CI - if so, we should fail if this configuration is missing.
		// Otherwise, we should just log and continue.
		if ci {
			return false, fmt.Errorf("missing hashrelease server configuration")
		}
		logrus.Warn("Missing hashrelease server configuration, skipping remote hashrelease check")
		return false, nil
	}

	return hashreleaseserver.HasHashrelease(hash, cfg)
}

// ReformatHashrelease modifies the generated release output to match
// the "legacy" format our CI tooling expects. This should be temporary until
// we can update the tooling to expect the new format.
// Specifically, we need to do the following:
// - Copy the windows zip file to files/windows/calico-windows-<ver>.zip
// - Add a copy of the tigera operator chart without version in its name i.e. tigera-operator-<ver>.tgz to tigera-operator.tgz
// - Copy ocp.tgz to manifests/ocp.tgz
func ReformatHashrelease(hashreleaseOutputDir, tmpDir string) error {
	logrus.Info("Modifying hashrelease output to match legacy format")
	versions, err := pinnedversion.RetrieveVersions(tmpDir)
	if err != nil {
		return fmt.Errorf("failed to retrieve pinned versions: %w", err)
	}

	// Copy the windows zip file to files/windows/calico-windows-<ver>.zip
	if err := os.MkdirAll(filepath.Join(hashreleaseOutputDir, "files", "windows"), 0o755); err != nil {
		return err
	}
	windowsZip := filepath.Join(hashreleaseOutputDir, fmt.Sprintf("calico-windows-%s.zip", versions.ProductVersion()))
	windowsZipDst := filepath.Join(hashreleaseOutputDir, "files", "windows", fmt.Sprintf("calico-windows-%s.zip", versions.ProductVersion()))
	if err := utils.CopyFile(windowsZip, windowsZipDst); err != nil {
		return err
	}

	// Copy the ocp.tgz to manifests/ocp.tgz
	ocpTarball := filepath.Join(hashreleaseOutputDir, "ocp.tgz")
	ocpTarballDst := filepath.Join(hashreleaseOutputDir, "manifests", "ocp.tgz")
	if err := utils.CopyFile(ocpTarball, ocpTarballDst); err != nil {
		return err
	}

	// Add copy of the Tigera operator chart without version in name.
	operatorTarball := filepath.Join(hashreleaseOutputDir, fmt.Sprintf("%s-%s.tgz", utils.TigeraOperatorChart, versions.HelmChartVersion()))
	operatorTarballDst := filepath.Join(hashreleaseOutputDir, fmt.Sprintf("%s.tgz", utils.TigeraOperatorChart))
	if err := utils.CopyFile(operatorTarball, operatorTarballDst); err != nil {
		return err
	}
	return nil
}
