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

	"github.com/projectcalico/calico/release/internal/archives"
	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/manifests"
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
// - Copy all release Helm charts to charts/<chart>.tgz (without the version in the filename)
// - Copy ocp.tgz to manifests/ocp.tgz
func ReformatHashrelease(pin *pinnedversion.Pin, hashreleaseOutputDir string) error {
	logrus.Info("Modifying hashrelease output to match legacy format")

	windowsDir := archives.WindowsHashreleaseDir(hashreleaseOutputDir)
	if err := os.MkdirAll(windowsDir, 0o755); err != nil {
		return err
	}
	windowsZipName := archives.WindowsFileName(pin.ProductVersion)
	windowsZip := filepath.Join(archives.WindowsDir(hashreleaseOutputDir), windowsZipName)
	if err := copyIfExists(windowsZip, filepath.Join(windowsDir, windowsZipName)); err != nil {
		return err
	}

	// Copy the ocp.tgz to manifests/ocp.tgz
	ocpTarball := manifests.BundlePath(hashreleaseOutputDir)
	ocpTarballDst := filepath.Join(manifests.Dir(hashreleaseOutputDir), manifests.OCPBundleFileName)
	if err := copyIfExists(ocpTarball, ocpTarballDst); err != nil {
		return err
	}

	return unversionedCharts(pin, charts.OutputDir(hashreleaseOutputDir), charts.Dir(hashreleaseOutputDir))
}

// A chart the build was asked to produce is not optional
func unversionedCharts(pin *pinnedversion.Pin, srcDir, dstDir string) error {
	if err := os.MkdirAll(dstDir, utils.DirPerms); err != nil {
		return err
	}
	for _, chart := range charts.All() {
		src := filepath.Join(srcDir, charts.FileName(chart, pin.HelmChartVersion()))
		dst := filepath.Join(dstDir, charts.FileName(chart, ""))
		if err := utils.CopyFile(src, dst); err != nil {
			return fmt.Errorf("copying %s chart: %w", chart, err)
		}
	}
	return nil
}

// copyIfExists copies src to dst, logging and skipping if src is missing.
// Missing sources are expected when the caller skipped the step-control flag
// that would have produced the artifact.
func copyIfExists(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			logrus.WithField("file", src).Warn("Source missing, skipping reformat copy")
			return nil
		}
		return fmt.Errorf("stat %s: %w", src, err)
	}
	return utils.CopyFile(src, dst)
}
